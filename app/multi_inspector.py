import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from app.pdf_inspector import inspect_pdf_bytes


SUPPORTED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".docx", ".xlsx"}

IMAGE_OFFICE_DANGEROUS_PATTERNS = [
    (b"<script", "<script"),
    (b"<?php", "<?php"),
    (b"eval(", "eval("),
    (b"wscript", "WScript"),
    (b"activexobject", "ActiveXObject"),
    (b"powershell", "powershell"),
    (b"cmd.exe", "cmd.exe"),
    (b"/bin/sh", "/bin/sh"),
    (b"http://", "http://"),
    (b"https://", "https://"),
    (b"PK\x03\x04", "PK\\x03\\x04 (Embedded ZIP)"),
    (b"MZ\x90\x00", "MZ\\x90\\x00 (Embedded PE)"),
]

BENIGN_METADATA_URLS = (
    b"http://www.w3.org",
    b"https://www.w3.org",
    b"http://ns.adobe.com",
    b"https://ns.adobe.com",
    b"http://purl.org",
    b"https://purl.org",
    b"http://iptc.org",
    b"https://iptc.org",
    b"http://schemas.openxmlformats.org",
    b"https://schemas.openxmlformats.org",
    b"http://schemas.microsoft.com",
    b"https://schemas.microsoft.com",
    b"http://xml.org",
    b"https://xml.org",
)

STANDARD_PNG_CHUNKS = {
    b"IHDR",
    b"PLTE",
    b"IDAT",
    b"IEND",
    b"tRNS",
    b"cHRM",
    b"gAMA",
    b"iCCP",
    b"sBIT",
    b"sRGB",
    b"iTXt",
    b"tEXt",
    b"zTXt",
    b"bKGD",
    b"pHYs",
    b"sPLT",
    b"hIST",
    b"tIME",
    b"eXIf",
    b"acTL",
    b"fcTL",
    b"fdAT",
}

EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".dll",
    ".bat",
    ".ps1",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".cmd",
    ".scr",
    ".hta",
    ".jar",
    ".lnk",
    ".msi",
    ".com",
    ".pif",
    ".xll",
    ".wll",
    ".chm",
    ".class",
    ".sh",
    ".py",
    ".elf",
    ".apk",
)

MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB


@dataclass
class MultiInspectionResult:
    filename: str
    file_size: int
    file_format: str  # PDF | JPEG | PNG | DOCX | XLSX | UNKNOWN
    magic_bytes_valid: bool
    dangerous_tags_found: List[str] = field(default_factory=list)
    matched_vaccines: List[str] = field(default_factory=list)
    verdict: str = "CLEAN"  # CLEAN | INFECTED
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, object] = field(default_factory=dict)


def detect_magic_format(raw_bytes: bytes) -> str:
    if raw_bytes.startswith(b"%PDF-"):
        return "PDF"
    if raw_bytes.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if raw_bytes.startswith(b"PK\x03\x04"):
        return "OOXML"
    return "UNKNOWN"


def _expected_format_for_ext(ext: str) -> str | None:
    if ext == ".pdf":
        return "PDF"
    if ext in (".jpg", ".jpeg"):
        return "JPEG"
    if ext == ".png":
        return "PNG"
    if ext in (".docx", ".xlsx"):
        return "OOXML"
    return None


def _find_jpeg_eoi_end(raw_bytes: bytes) -> int | None:
    """
    Menemukan posisi akhir marker EOI (FF D9) pada gambar JPEG sesuai standar ITU-T T.81:
    Melewati deretan fill-bytes 0xFF (mis. FF FF E0) dan melewati APP1 thumbnail secara akurat.
    Tidak menggunakan rfind(FF D9) palsu agar evasi fill-byte + trailing FF D9 terdeteksi.
    """
    n = len(raw_bytes)
    if n < 4 or raw_bytes[:2] != b"\xff\xd8":
        return None
    pos = 2
    while pos < n:
        if raw_bytes[pos] != 0xFF:
            return None
        while pos < n and raw_bytes[pos] == 0xFF:
            pos += 1
        if pos >= n:
            return None
        marker = raw_bytes[pos]
        pos += 1
        if marker == 0x00:
            return None
        if marker == 0xD9:  # EOI
            return pos
        if marker == 0xD8 or (0xD0 <= marker <= 0xD7) or marker == 0x01:
            continue
        if marker == 0xDA:  # Start of Scan (SOS)
            if pos + 2 > n:
                return None
            seg_len = int.from_bytes(raw_bytes[pos : pos + 2], "big")
            if seg_len < 2 or pos + seg_len > n:
                return None
            pos += seg_len
            while pos < n:
                if raw_bytes[pos] != 0xFF:
                    pos += 1
                    continue
                while pos < n and raw_bytes[pos] == 0xFF:
                    pos += 1
                if pos >= n:
                    return None
                nxt = raw_bytes[pos]
                pos += 1
                if nxt == 0x00 or (0xD0 <= nxt <= 0xD7):
                    continue
                if nxt == 0xD9:
                    return pos
                # Marker segmen baru dimulai sebelum nxt
                pos -= 2
                break
            continue
        if pos + 2 > n:
            return None
        seg_len = int.from_bytes(raw_bytes[pos : pos + 2], "big")
        if seg_len < 2 or pos + seg_len > n:
            return None
        pos += seg_len
    return None


def _validate_png_chunks(raw_bytes: bytes) -> tuple[int | None, List[str], bool]:
    """
    Memvalidasi urutan chunk PNG dari header hingga IEND (+ 4 byte CRC),
    serta mendeteksi chunk privat/asing (mis. prVt) sebelum IEND.
    """
    n = len(raw_bytes)
    if n < 8 or not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return None, [], True
    pos = 8
    suspicious_chunks: List[str] = []
    seen_ihdr = False
    while pos + 12 <= n:
        length = int.from_bytes(raw_bytes[pos : pos + 4], "big")
        chunk_type = raw_bytes[pos + 4 : pos + 8]
        chunk_end = pos + 12 + length
        if length < 0 or chunk_end > n or chunk_end <= pos:
            return None, suspicious_chunks, True
        if not seen_ihdr:
            if chunk_type != b"IHDR" or length != 13:
                return None, suspicious_chunks, True
            seen_ihdr = True
        if chunk_type not in STANDARD_PNG_CHUNKS:
            label = chunk_type.decode("latin-1", errors="replace")
            if label not in suspicious_chunks:
                suspicious_chunks.append(label)
        if chunk_type == b"IEND":
            return chunk_end, suspicious_chunks, False
        pos = chunk_end
    return None, suspicious_chunks, True


def _find_png_iend_end(raw_bytes: bytes) -> int | None:
    """Menemukan posisi akhir chunk IEND (+ 4 byte CRC) pada gambar PNG."""
    iend_end, _, malformed = _validate_png_chunks(raw_bytes)
    return None if malformed else iend_end


def _is_benign_motion_photo_trailer(trailing_bytes: bytes) -> bool:
    """Mengizinkan kontainer video MP4 Motion Photo / Live Photo standar setelah EOI JPEG."""
    if len(trailing_bytes) < 16 or trailing_bytes[4:8] != b"ftyp":
        return False
    brand = trailing_bytes[8:12]
    if brand not in (b"mp42", b"isom", b"mp41", b"M4V ", b"qt  ", b"avc1", b"iso2"):
        return False
    lower_t = trailing_bytes.lower()
    for pat_bytes, _ in IMAGE_OFFICE_DANGEROUS_PATTERNS:
        if pat_bytes.lower() in lower_t:
            return False
    return True


def _scrub_benign_urls(data: bytes) -> bytes:
    scrubbed = data
    for benign in BENIGN_METADATA_URLS:
        scrubbed = re.sub(re.escape(benign), b"", scrubbed, flags=re.IGNORECASE)
    return scrubbed


def _scan_vaccines(raw_bytes: bytes, active_vaccine_patterns: List[dict] | None) -> List[str]:
    matched: List[str] = []
    if not active_vaccine_patterns:
        return matched
    lower_raw = raw_bytes.lower()
    for vac in active_vaccine_patterns:
        if not vac.get("enabled", True):
            continue
        pat_str = (vac.get("pattern") or "").strip()
        if not pat_str:
            continue
        pattern = pat_str.encode("utf-8", errors="ignore").lower()
        if pattern in lower_raw:
            matched.append(vac["rule_name"])
    return matched


def _inspect_image_bytes(
    raw_bytes: bytes,
    filename: str,
    fmt: str,
    active_vaccine_patterns: List[dict] | None = None,
) -> MultiInspectionResult:
    reasons: List[str] = []
    dangerous_tags: List[str] = []
    trailing_bytes = b""
    is_motion_photo = False

    if fmt == "JPEG":
        end_offset = _find_jpeg_eoi_end(raw_bytes)
        if end_offset is None:
            dangerous_tags.append("MALFORMED_IMAGE")
            reasons.append("Struktur segmen JPEG rusak/tidak valid atau penanda EOI FF D9 dipalsukan.")
        elif end_offset < len(raw_bytes):
            trailing_bytes = raw_bytes[end_offset:]
            if _is_benign_motion_photo_trailer(trailing_bytes):
                is_motion_photo = True
            elif len(trailing_bytes.strip(b"\x00")) > 0:
                dangerous_tags.append("TRAILING_POLYGLOT")
                reasons.append(
                    f"Polyglot / Trailing Bytes terdeteksi setelah EOI FF D9: "
                    f"{len(trailing_bytes)} byte tersembunyi."
                )
    else:
        end_offset, suspicious_chunks, malformed = _validate_png_chunks(raw_bytes)
        if malformed or end_offset is None:
            dangerous_tags.append("MALFORMED_IMAGE")
            reasons.append("Struktur chunk PNG rusak atau tidak memiliki penanda IEND yang sah.")
        else:
            if suspicious_chunks:
                dangerous_tags.append("SUSPICIOUS_PNG_CHUNK")
                reasons.append(
                    f"Chunk privat/non-standar mencurigakan ditemukan pada PNG sebelum IEND: {', '.join(suspicious_chunks)}"
                )
            if end_offset < len(raw_bytes):
                trailing_bytes = raw_bytes[end_offset:]
                if len(trailing_bytes.strip(b"\x00")) > 0:
                    dangerous_tags.append("TRAILING_POLYGLOT")
                    reasons.append(
                        f"Polyglot / Trailing Bytes terdeteksi setelah IEND + CRC: "
                        f"{len(trailing_bytes)} byte tersembunyi."
                    )

    scan_region = raw_bytes[:end_offset] if (is_motion_photo and end_offset) else raw_bytes
    scrubbed_region = _scrub_benign_urls(scan_region)
    lower_bytes = scrubbed_region.lower()

    for pat_bytes, label in IMAGE_OFFICE_DANGEROUS_PATTERNS:
        target = scrubbed_region if label.startswith(("PK", "MZ")) else lower_bytes
        needle = pat_bytes if label.startswith(("PK", "MZ")) else pat_bytes.lower()
        if needle in target:
            dangerous_tags.append(label)
            reasons.append(f"Pola mencurigakan ditemukan di metadata/trailing gambar: {label}")

    matched_vaccines = _scan_vaccines(raw_bytes, active_vaccine_patterns)
    for rname in matched_vaccines:
        reasons.append(f"Diblokir oleh Vaksin Aktif: {rname}")

    verdict = "INFECTED" if (dangerous_tags or matched_vaccines) else "CLEAN"
    trailing_preview = ""
    if trailing_bytes and not is_motion_photo:
        txt = trailing_bytes.decode("latin-1", errors="replace").strip()
        trailing_preview = txt[:300] + ("..." if len(txt) > 300 else "")

    details = {
        "filename": filename,
        "file_size": len(raw_bytes),
        "file_format": fmt,
        "magic_bytes_valid": True,
        "trailing_bytes_count": 0 if is_motion_photo else len(trailing_bytes),
        "trailing_preview": trailing_preview,
        "dangerous_tags_found": dangerous_tags,
        "matched_vaccines": matched_vaccines,
        "verdict": verdict,
        "reasons": reasons,
    }
    return MultiInspectionResult(
        filename=filename,
        file_size=len(raw_bytes),
        file_format=fmt,
        magic_bytes_valid=True,
        dangerous_tags_found=dangerous_tags,
        matched_vaccines=matched_vaccines,
        verdict=verdict,
        reasons=reasons,
        details=details,
    )


def _inspect_ooxml_bytes(
    raw_bytes: bytes,
    filename: str,
    ext: str,
    active_vaccine_patterns: List[dict] | None = None,
) -> MultiInspectionResult:
    fmt = "DOCX" if ext == ".docx" else "XLSX"
    reasons: List[str] = []
    dangerous_tags: List[str] = []
    matched_vaccines = _scan_vaccines(raw_bytes, active_vaccine_patterns)

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            infolist = zf.infolist()
            names = [i.filename for i in infolist]

            if len(infolist) > MAX_ZIP_ENTRIES:
                dangerous_tags.append("ZIP_BOMB_SUSPECTED")
                reasons.append(f"Jumlah entri ZIP ({len(infolist)}) melebihi batas aman ({MAX_ZIP_ENTRIES}).")

            total_uncompressed = sum(max(i.file_size, 0) for i in infolist)
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                if "ZIP_BOMB_SUSPECTED" not in dangerous_tags:
                    dangerous_tags.append("ZIP_BOMB_SUSPECTED")
                reasons.append(
                    f"Ukuran dekompresi arsip ({total_uncompressed} byte) melebihi batas aman 100 MB."
                )

            lower_names = [n.lower().replace("\\", "/") for n in names]
            has_content_types = "[content_types].xml" in lower_names
            has_core_doc = any(
                core in lower_names
                for core in ("word/document.xml", "xl/workbook.xml", "ppt/presentation.xml")
            )
            if not (has_content_types and has_core_doc):
                dangerous_tags.append("INVALID_OOXML_STRUCTURE")
                reasons.append(
                    "Arsip ZIP bukan dokumen Office OOXML sah ([Content_Types].xml atau body dokumen utama tidak ditemukan)."
                )

            for info in infolist[:MAX_ZIP_ENTRIES]:
                name = info.filename
                norm_name = name.replace("\\", "/")
                lower_name = norm_name.lower()

                if ".." in norm_name.split("/") or norm_name.startswith("/"):
                    if "ZIP_PATH_TRAVERSAL" not in dangerous_tags:
                        dangerous_tags.append("ZIP_PATH_TRAVERSAL")
                    reasons.append(f"Path traversal berbahaya terdeteksi di dalam arsip: {name}")

                if lower_name.endswith("vbaproject.bin"):
                    if "VBA_MACRO" not in dangerous_tags:
                        dangerous_tags.append("VBA_MACRO")
                    reasons.append(f"Macro VBA berbahaya terdeteksi: {name}")

                if "oleobject" in lower_name or "/embeddings/" in lower_name or lower_name.startswith("embeddings/"):
                    if "OLE_OBJECT" not in dangerous_tags:
                        dangerous_tags.append("OLE_OBJECT")
                    reasons.append(f"Objek tertanam OLE berbahaya terdeteksi: {name}")

                if "activex" in lower_name:
                    if "ACTIVEX_CONTROL" not in dangerous_tags:
                        dangerous_tags.append("ACTIVEX_CONTROL")
                    reasons.append(f"Kontrol ActiveX berbahaya terdeteksi: {name}")

                if "macrosheets/" in lower_name or "dialogsheets/" in lower_name:
                    if "XLM_MACROSHEET" not in dangerous_tags:
                        dangerous_tags.append("XLM_MACROSHEET")
                    reasons.append(f"Excel 4.0 XLM Macrosheet terdeteksi: {name}")

                if lower_name.endswith(EXECUTABLE_EXTENSIONS):
                    tag_label = f"EMBEDDED_SCRIPT:{Path(name).suffix.lower()}"
                    if tag_label not in dangerous_tags:
                        dangerous_tags.append(tag_label)
                    reasons.append(f"File executable/script tersembunyi di arsip Office: {name}")

                if info.file_size <= 10 * 1024 * 1024 and (
                    lower_name.endswith(".rels") or lower_name.endswith(".xml")
                ):
                    member_bytes = zf.read(name)
                    if lower_name.endswith(".rels"):
                        if re.search(
                            rb'TargetMode\s*=\s*["\']External["\']|mhtml:|ms-msdt:',
                            member_bytes,
                            re.IGNORECASE,
                        ):
                            if "EXTERNAL_RELS" not in dangerous_tags:
                                dangerous_tags.append("EXTERNAL_RELS")
                            reasons.append(f"Remote Template / External Link Injection pada {name}")

                    if lower_name.endswith(".xml"):
                        if re.search(rb"\bDDEAUTO\b", member_bytes, re.IGNORECASE) or (
                            re.search(rb"fldSimple", member_bytes, re.IGNORECASE)
                            and re.search(rb"\bDDE\b", member_bytes, re.IGNORECASE)
                        ):
                            if "DDE_INJECTION" not in dangerous_tags:
                                dangerous_tags.append("DDE_INJECTION")
                            reasons.append(f"Injeksi perintah DDE / DDEAUTO terdeteksi pada {name}")

                    if active_vaccine_patterns:
                        for rname in _scan_vaccines(member_bytes, active_vaccine_patterns):
                            if rname not in matched_vaccines:
                                matched_vaccines.append(rname)
    except zipfile.BadZipFile:
        dangerous_tags.append("CORRUPT_OOXML")
        reasons.append("Arsip OOXML rusak atau bukan ZIP valid.")

    for rname in matched_vaccines:
        reasons.append(f"Diblokir oleh Vaksin Aktif: {rname}")

    verdict = "INFECTED" if (dangerous_tags or matched_vaccines) else "CLEAN"
    details = {
        "filename": filename,
        "file_size": len(raw_bytes),
        "file_format": fmt,
        "magic_bytes_valid": True,
        "dangerous_tags_found": dangerous_tags,
        "matched_vaccines": matched_vaccines,
        "verdict": verdict,
        "reasons": reasons,
    }
    return MultiInspectionResult(
        filename=filename,
        file_size=len(raw_bytes),
        file_format=fmt,
        magic_bytes_valid=True,
        dangerous_tags_found=dangerous_tags,
        matched_vaccines=matched_vaccines,
        verdict=verdict,
        reasons=reasons,
        details=details,
    )


def inspect_file_bytes(
    raw_bytes: bytes,
    filename: str,
    active_vaccine_patterns: List[dict] | None = None,
) -> MultiInspectionResult:
    """
    Dispatcher inspeksi multi-format berbasis Magic Bytes:
    - PDF (%PDF-) -> inspect_pdf_bytes()
    - JPEG (FF D8 FF) & PNG (89 50 4E 47 0D 0A 1A 0A) -> _inspect_image_bytes()
    - DOCX / XLSX (PK 03 04) -> _inspect_ooxml_bytes()
    - Mismatch ekstensi vs magic bytes -> INFECTED (Extension Spoofing / Magic Bytes Mismatch)
    """
    ext = Path(filename).suffix.lower()
    detected_magic = detect_magic_format(raw_bytes)
    expected = _expected_format_for_ext(ext)

    if expected is None or detected_magic != expected:
        reason = (
            f"Extension Spoofing / Magic Bytes Mismatch: "
            f"ekstensi '{ext or 'none'}' tidak cocok dengan header '{detected_magic}'."
        )
        details = {
            "filename": filename,
            "file_size": len(raw_bytes),
            "file_format": detected_magic,
            "magic_bytes_valid": False,
            "dangerous_tags_found": ["FAKE_FILE_MAGIC_MISMATCH"],
            "matched_vaccines": [],
            "verdict": "INFECTED",
            "reasons": [reason],
        }
        return MultiInspectionResult(
            filename=filename,
            file_size=len(raw_bytes),
            file_format=detected_magic,
            magic_bytes_valid=False,
            dangerous_tags_found=["FAKE_FILE_MAGIC_MISMATCH"],
            matched_vaccines=[],
            verdict="INFECTED",
            reasons=[reason],
            details=details,
        )

    if detected_magic == "PDF":
        pdf_res = inspect_pdf_bytes(raw_bytes, filename, active_vaccine_patterns=active_vaccine_patterns)
        details = {**pdf_res.__dict__, "file_format": "PDF", "magic_bytes_valid": True}
        return MultiInspectionResult(
            filename=filename,
            file_size=pdf_res.file_size,
            file_format="PDF",
            magic_bytes_valid=True,
            dangerous_tags_found=pdf_res.dangerous_tags_found,
            matched_vaccines=pdf_res.matched_vaccines,
            verdict=pdf_res.verdict,
            reasons=pdf_res.reasons,
            details=details,
        )

    if detected_magic in ("JPEG", "PNG"):
        return _inspect_image_bytes(
            raw_bytes,
            filename,
            detected_magic,
            active_vaccine_patterns=active_vaccine_patterns,
        )

    return _inspect_ooxml_bytes(
        raw_bytes,
        filename,
        ext,
        active_vaccine_patterns=active_vaccine_patterns,
    )
