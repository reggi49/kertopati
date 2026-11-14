import re
import zlib
from dataclasses import dataclass, field
from typing import Dict, List


DANGEROUS_PDF_TAGS = [
    b"/JS",
    b"/JavaScript",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/EmbeddedFiles",
    b"/RichMedia",
    b"/XFA",
    b"/SubmitForm",
    b"/ImportData",
    b"/GoToR",
    b"/GoToE",
]

OCG_PDF_TAGS = [
    b"/OCProperties",
    b"/OCGs",
    b"/OCG",
]

MAX_DECOMPRESSED_STREAM_BYTES = 256 * 1024  # 256 KB per stream
MAX_TOTAL_DECOMPRESSED_BYTES = 2 * 1024 * 1024  # 2 MB total
HEX_NAME_ESCAPE_RE = re.compile(rb"#([0-9A-Fa-f]{2})")


@dataclass
class PdfInspectionResult:
    filename: str
    file_size: int
    eof_count: int
    has_signature_field: bool
    byterange_valid: bool
    incremental_update_after_sign: bool
    signature_details: Dict[str, object] = field(default_factory=dict)
    ocg_detected: bool = False
    ocg_tags_found: List[str] = field(default_factory=list)
    post_signature_diff_preview: str = ""
    dangerous_tags_found: List[str] = field(default_factory=list)
    matched_vaccines: List[str] = field(default_factory=list)
    verdict: str = "CLEAN"  # CLEAN | INFECTED
    reasons: List[str] = field(default_factory=list)


def _decode_pdf_hex_names(data: bytes) -> bytes:
    """
    Normalizes PDF Name hex escapes (ISO 32000-1 Section 7.3.5), e.g.:
    `/OpenActio#6e` -> `/OpenAction`, `/J#53` -> `/JS`, `/Java#53cript` -> `/JavaScript`.
    """
    return HEX_NAME_ESCAPE_RE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _extract_structural_pdf_bytes(raw_bytes: bytes) -> tuple[bytes, List[bytes]]:
    """
    Separates PDF dictionary/object structure from raw binary stream payloads so random
    compressed image/font bytes do not cause false positives, while decompressing
    `/FlateDecode` object streams (`/ObjStm`) so compressed exploit dictionaries are caught.
    """
    out_parts: List[bytes] = []
    decompressed_streams: List[bytes] = []
    total_decomp = 0
    pos = 0
    n = len(raw_bytes)

    stream_re = re.compile(rb"stream(?:\r\n|\n|\r)")
    endstream_re = re.compile(rb"endstream\b")

    while pos < n:
        m_start = stream_re.search(raw_bytes, pos)
        if not m_start:
            out_parts.append(raw_bytes[pos:])
            break

        header_slice = raw_bytes[pos : m_start.start()]
        out_parts.append(header_slice)
        out_parts.append(b"stream\n")

        stream_data_start = m_start.end()
        m_end = endstream_re.search(raw_bytes, stream_data_start)
        if not m_end:
            out_parts.append(raw_bytes[stream_data_start : min(n, stream_data_start + 4096)])
            break

        stream_body = raw_bytes[stream_data_start : m_end.start()].strip(b"\r\n")
        header_Context = _decode_pdf_hex_names(
            raw_bytes[max(0, m_start.start() - 512) : m_start.start()]
        )

        is_flate = bool(re.search(rb"/FlateDecode\b|/Fl\b", header_Context))
        is_objstm = bool(re.search(rb"/ObjStm\b", header_Context))
        is_binary_media = bool(
            re.search(rb"/Subtype\s*/(?:Image|Form)\b|/FontFile[23]?\b", header_Context)
        )

        if (is_objstm or (is_flate and not is_binary_media)) and total_decomp < MAX_TOTAL_DECOMPRESSED_BYTES:
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    dobj = zlib.decompressobj(wbits)
                    decomp = dobj.decompress(stream_body, MAX_DECOMPRESSED_STREAM_BYTES)
                    if decomp:
                        decompressed_streams.append(decomp)
                        total_decomp += len(decomp)
                    break
                except Exception:
                    continue
        elif not is_flate and not is_binary_media and len(stream_body) <= 65536:
            # Small uncompressed stream: keep printable ASCII lines, skip high-entropy binary
            out_parts.append(stream_body)

        out_parts.append(b"\nendstream")
        pos = m_end.end()

    return b"".join(out_parts), decompressed_streams


def _has_suspicious_uri(scan_bytes: bytes) -> bool:
    """
    Returns True only if a `/URI` action points to a dangerous scheme (javascript:, file:,
    data:, mhtml:, ms-msdt:), a raw IPv4 address, or a direct executable/script payload.
    Standard HTTPS links (e.g. https://bssn.go.id) are not flagged as malware.
    """
    for m in re.finditer(rb"/URI\s*\(([^)]{1,512})\)", scan_bytes):
        uri = m.group(1).strip().lower()
        if uri.startswith((b"javascript:", b"file:", b"data:", b"vbscript:", b"mhtml:", b"ms-msdt:")):
            return True
        if re.search(rb"^https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", uri):
            return True
        if re.search(rb"\.(?:exe|dll|scr|bat|cmd|ps1|vbs|hta|jar|msi|apk|zip|iso)(?:[?#]|$)", uri):
            return True
    return False


def inspect_pdf_bytes(
    raw_bytes: bytes,
    filename: str,
    active_vaccine_patterns: List[dict] | None = None,
) -> PdfInspectionResult:
    """
    Inspeksi deterministik struktur biner PDF:
    1. Menghitung jumlah %%EOF (indikator incremental update).
    2. Mem-parsing seluruh kamus tanda tangan (/Type /Sig, /SubFilter, /Contents) dan
       mengecek semua /ByteRange apakah menutup hingga akhir file (Shadow Attack / CVE-2026-91814).
    3. Men-decode obfuskasi nama hex PDF (/J#53 -> /JS, /OpenActio#6e -> /OpenAction)
       dan mendekompresi /ObjStm (/FlateDecode) secara aman.
    4. Memisahkan stream biner gambar/font dari struktur objek agar bebas False Positive.
    5. Mendeteksi Optional Content Groups (/OCG) pada dokumen bertanda tangan (CVE-2025-59802).
    6. Mencocokkan terhadap aturan Vaksin (YARA-style signatures) yang aktif.
    """
    file_size = len(raw_bytes)
    eof_matches = list(re.finditer(rb"%%EOF\s*", raw_bytes))
    eof_count = len(eof_matches)

    structural_bytes, decompressed_streams = _extract_structural_pdf_bytes(raw_bytes)
    decoded_structural = _decode_pdf_hex_names(structural_bytes)
    decoded_streams = b"\n".join(_decode_pdf_hex_names(s) for s in decompressed_streams)
    scan_corpus = decoded_structural + b"\n" + decoded_streams

    # Strip comment lines when checking whether /Type /Sig and /Contents are genuine objects
    uncommented_structural = re.sub(rb"%[^\r\n]*", b"", decoded_structural)
    has_real_type_sig = bool(re.search(rb"/Type\s*/Sig\b", uncommented_structural))
    has_real_contents = bool(re.search(rb"/Contents\s*<[0-9A-Fa-f\s]{8,}>", uncommented_structural))

    has_type_sig = bool(re.search(rb"/Type\s*/Sig\b", decoded_structural))
    subfilter_match = re.search(rb"/SubFilter\s*(/[A-Za-z0-9._-]+)", decoded_structural)
    subfilter = subfilter_match.group(1).decode("ascii", errors="ignore") if subfilter_match else None
    has_contents = bool(re.search(rb"/Contents\s*<", decoded_structural) or b"/Contents" in decoded_structural)

    br_matches = re.findall(
        rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", decoded_structural
    )
    has_sig = bool(br_matches) or has_type_sig
    byterange_valid = True
    incremental_after_sign = False
    post_signature_diff_preview = ""
    reasons: List[str] = []

    parsed_byterange = None
    if br_matches:
        # Check if /ByteRange was only injected inside a PDF comment (`% /ByteRange ...`) without a real signature object
        uncommented_br = re.findall(
            rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", uncommented_structural
        )
        if not uncommented_br and not (has_type_sig and has_contents):
            byterange_valid = False
            reasons.append(
                "Pemalsuan Klaim TTE: /ByteRange hanya ditemukan di dalam baris komentar PDF tanpa kamus kriptografi /Type /Sig yang sah."
            )

        # Validate ALL /ByteRange entries in the document (prevents dual-ByteRange shadow attack bypass)
        for br_tuple in br_matches:
            start1, len1, start2, len2 = [int(x) for x in br_tuple]
            parsed_byterange = [start1, len1, start2, len2]
            signed_end = start2 + len2
            if start1 != 0 or len1 <= 0 or start2 < (start1 + len1) or len2 <= 0 or signed_end > file_size:
                byterange_valid = False
                reasons.append(
                    f"Struktur /ByteRange tidak valid atau korup: [{start1} {len1} {start2} {len2}] untuk ukuran file {file_size} byte."
                )
            elif signed_end < file_size - 16:  # toleransi whitespace EOF kecil
                byterange_valid = False
                incremental_after_sign = True
                trailing_bytes = raw_bytes[signed_end:]
                preview_raw = trailing_bytes.decode("latin-1", errors="replace").strip()
                post_signature_diff_preview = preview_raw[:400] + (
                    "..." if len(preview_raw) > 400 else ""
                )
                reasons.append(
                    f"Shadow Attack / Incremental Update pasca-TTE terdeteksi: "
                    f"ByteRange berhenti di byte {signed_end} dari total {file_size} byte."
                )
    elif eof_count > 1:
        incremental_after_sign = True
        reasons.append(f"Terdapat {eof_count} revisi %%EOF (incremental update mencurigakan).")

    signature_details: Dict[str, object] = {
        "has_type_sig": has_type_sig,
        "subfilter": subfilter,
        "has_contents": has_contents,
        "byterange": parsed_byterange,
    }

    # Deteksi OCG (Optional Content Groups) ala CVE-2025-59802
    ocg_tags_found: List[str] = []
    for tag in OCG_PDF_TAGS:
        if re.search(rb"(?<![A-Za-z0-9_])" + re.escape(tag) + rb"(?![A-Za-z0-9_])", scan_corpus):
            ocg_tags_found.append(tag.decode("ascii"))
    ocg_detected = len(ocg_tags_found) > 0

    # Cek tag aktif berbahaya pada struktur objek & hasil dekompresi /ObjStm
    found_tags: List[str] = []
    for tag in DANGEROUS_PDF_TAGS:
        if re.search(rb"(?<![A-Za-z0-9_])" + re.escape(tag) + rb"(?![A-Za-z0-9_])", scan_corpus):
            tag_str = tag.decode("ascii")
            if tag_str in ("/EmbeddedFiles", "/EmbeddedFile"):
                tag_str = "/EmbeddedFile"
            if tag_str not in found_tags:
                found_tags.append(tag_str)

    if _has_suspicious_uri(scan_corpus) and "/URI" not in found_tags:
        found_tags.append("/URI")

    # OCG pada dokumen bertanda tangan (atau bersama indikator berbahaya) adalah serangan CVE-2025-59802
    ocg_is_malicious = ocg_detected and (has_sig or bool(found_tags) or not byterange_valid)
    if ocg_is_malicious:
        reasons.append(
            f"Deteksi OCG / Hidden Layer (CVE-2025-59802): {', '.join(ocg_tags_found)}"
        )

    if found_tags:
        reasons.append(f"Objek aktif berbahaya ditemukan: {', '.join(found_tags)}")

    # Cek terhadap Vaksin YARA aktif (hanya yang enabled, case-insensitive)
    matched_vaccines: List[str] = []
    if active_vaccine_patterns:
        lower_raw = raw_bytes.lower()
        lower_scan = scan_corpus.lower()
        for vac in active_vaccine_patterns:
            if not vac.get("enabled", True):
                continue
            pat_str = (vac.get("pattern") or "").strip()
            if not pat_str:
                continue
            pattern = pat_str.encode("utf-8", errors="ignore").lower()
            if pattern in lower_raw or pattern in lower_scan:
                matched_vaccines.append(vac["rule_name"])
                reasons.append(f"Diblokir oleh Vaksin Aktif: {vac['rule_name']}")

    verdict = (
        "INFECTED"
        if (not byterange_valid or found_tags or ocg_is_malicious or matched_vaccines)
        else "CLEAN"
    )

    return PdfInspectionResult(
        filename=filename,
        file_size=file_size,
        eof_count=eof_count,
        has_signature_field=has_sig,
        byterange_valid=byterange_valid,
        incremental_update_after_sign=incremental_after_sign,
        signature_details=signature_details,
        ocg_detected=ocg_detected,
        ocg_tags_found=ocg_tags_found,
        post_signature_diff_preview=post_signature_diff_preview,
        dangerous_tags_found=found_tags,
        matched_vaccines=matched_vaccines,
        verdict=verdict,
        reasons=reasons,
    )
