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
    (b"eval(", "eval("),
    (b"wscript", "WScript"),
    (b"powershell", "powershell"),
    (b"http://", "http://"),
    (b"https://", "https://"),
    (b"PK\x03\x04", "PK\\x03\\x04 (Embedded ZIP)"),
]

EXECUTABLE_EXTENSIONS = (".exe", ".bat", ".ps1", ".js", ".vbs", ".cmd", ".scr", ".hta")


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
    """Menemukan posisi akhir marker EOI (FF D9) pada gambar JPEG."""
    pos = 2
    n = len(raw_bytes)
    while pos < n - 1:
        if raw_bytes[pos] != 0xFF:
            pos += 1
            continue
        marker = raw_bytes[pos + 1]
        if marker == 0xD9:  # EOI
            return pos + 2
        if marker == 0x00 or (0xD0 <= marker <= 0xD8):
            pos += 2
            continue
        if marker == 0xDA:  # Start of Scan -> cari FF D9 pertama setelah entropy stream
            scan_pos = pos + 2
            if scan_pos + 2 <= n:
                seg_len = int.from_bytes(raw_bytes[scan_pos : scan_pos + 2], "big")
                scan_pos += seg_len
            while scan_pos < n - 1:
                if raw_bytes[scan_pos] == 0xFF:
                    nxt = raw_bytes[scan_pos + 1]
                    if nxt == 0xD9:
                        return scan_pos + 2
                    if nxt != 0x00:
                        # Marker lain (misal RSTn)
                        if 0xD0 <= nxt <= 0xD7:
                            scan_pos += 2
                            continue
                scan_pos += 1
            break
        if pos + 4 <= n:
            seg_len = int.from_bytes(raw_bytes[pos + 2 : pos + 4], "big")
            pos += 2 + max(seg_len, 2)
        else:
            break
    idx = raw_bytes.rfind(b"\xff\xd9")
    return idx + 2 if idx != -1 else None


def _find_png_iend_end(raw_bytes: bytes) -> int | None:
    """Menemukan posisi akhir chunk IEND (+ 4 byte CRC) pada gambar PNG."""
    pos = 8
    n = len(raw_bytes)
    while pos + 12 <= n:
        length = int.from_bytes(raw_bytes[pos : pos + 4], "big")
        chunk_type = raw_bytes[pos + 4 : pos + 8]
        chunk_end = pos + 12 + length
        if chunk_type == b"IEND":
            return chunk_end if chunk_end <= n else n
        if chunk_end <= pos:
            break
        pos = chunk_end
    return None


def _scan_vaccines(raw_bytes: bytes, active_vaccine_patterns: List[dict] | None) -> List[str]:
    matched: List[str] = []
    if not active_vaccine_patterns:
        return matched
    for vac in active_vaccine_patterns:
        if not vac.get("enabled", True):
            continue
        pattern = vac["pattern"].encode("utf-8")
        if pattern in raw_bytes:
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

    end_offset = _find_jpeg_eoi_end(raw_bytes) if fmt == "JPEG" else _find_png_iend_end(raw_bytes)
    if end_offset is not None and end_offset < len(raw_bytes):
        trailing_bytes = raw_bytes[end_offset:]
        if len(trailing_bytes.strip()) > 8:
            marker_label = "EOI FF D9" if fmt == "JPEG" else "IEND + CRC"
            dangerous_tags.append("TRAILING_POLYGLOT")
            reasons.append(
                f"Polyglot / Trailing Bytes terdeteksi setelah {marker_label}: "
                f"{len(trailing_bytes)} byte tersembunyi."
            )

    lower_bytes = raw_bytes.lower()
    for pat_bytes, label in IMAGE_OFFICE_DANGEROUS_PATTERNS:
        target = raw_bytes if label.startswith("PK") else lower_bytes
        if pat_bytes in target:
            dangerous_tags.append(label)
            reasons.append(f"Pola mencurigakan ditemukan di metadata/trailing gambar: {label}")

    matched_vaccines = _scan_vaccines(raw_bytes, active_vaccine_patterns)
    for rname in matched_vaccines:
        reasons.append(f"Diblokir oleh Vaksin Aktif: {rname}")

    verdict = "INFECTED" if (dangerous_tags or matched_vaccines) else "CLEAN"
    trailing_preview = ""
    if trailing_bytes:
        txt = trailing_bytes.decode("latin-1", errors="replace").strip()
        trailing_preview = txt[:300] + ("..." if len(txt) > 300 else "")

    details = {
        "filename": filename,
        "file_size": len(raw_bytes),
        "file_format": fmt,
        "magic_bytes_valid": True,
        "trailing_bytes_count": len(trailing_bytes),
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
            names = zf.namelist()
            for name in names:
                lower_name = name.lower()
                if lower_name.endswith("vbaproject.bin"):
                    dangerous_tags.append("VBA_MACRO")
                    reasons.append(f"Macro VBA berbahaya terdeteksi: {name}")

                if lower_name.endswith(EXECUTABLE_EXTENSIONS):
                    dangerous_tags.append(f"EMBEDDED_SCRIPT:{Path(name).suffix}")
                    reasons.append(f"File executable/script tersembunyi di arsip Office: {name}")

                if lower_name.endswith(".rels"):
                    rels_bytes = zf.read(name)
                    if re.search(rb'TargetMode\s*=\s*["\']External["\']', rels_bytes, re.IGNORECASE):
                        dangerous_tags.append("EXTERNAL_RELS")
                        reasons.append(f"Remote Template / External Link Injection pada {name}")

                if active_vaccine_patterns:
                    member_bytes = zf.read(name)
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
