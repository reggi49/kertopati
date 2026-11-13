import re
from dataclasses import dataclass, field
from typing import Dict, List


DANGEROUS_PDF_TAGS = [
    b"/JS",
    b"/JavaScript",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/URI",
]

OCG_PDF_TAGS = [
    b"/OCProperties",
    b"/OCGs",
    b"/OCG",
]


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


def inspect_pdf_bytes(
    raw_bytes: bytes,
    filename: str,
    active_vaccine_patterns: List[dict] | None = None,
) -> PdfInspectionResult:
    """
    Inspeksi deterministik struktur biner PDF:
    1. Menghitung jumlah %%EOF (indikator incremental update).
    2. Mem-parsing kamus tanda tangan (/Type /Sig, /SubFilter, /Contents) dan
       mengecek /ByteRange apakah menutup hingga akhir file (Shadow Attack / CVE-2026-91814).
    3. Mengekstrak cuplikan objek pasca-tanda tangan jika ada byte di luar /ByteRange.
    4. Mendeteksi Optional Content Groups (/OCG, /OCGs, /OCProperties) untuk
       mencegah Signature Spoofing / hidden layer ala CVE-2025-59802.
    5. Memindai objek aktif berbahaya (/JS, /OpenAction, /Launch, dll).
    6. Mencocokkan terhadap aturan Vaksin (YARA-style signatures) yang aktif.
    """
    file_size = len(raw_bytes)
    eof_matches = list(re.finditer(rb"%%EOF\s*", raw_bytes))
    eof_count = len(eof_matches)

    has_type_sig = bool(re.search(rb"/Type\s*/Sig\b", raw_bytes))
    subfilter_match = re.search(rb"/SubFilter\s*(/[A-Za-z0-9._-]+)", raw_bytes)
    subfilter = subfilter_match.group(1).decode("ascii", errors="ignore") if subfilter_match else None
    has_contents = bool(re.search(rb"/Contents\s*<", raw_bytes) or b"/Contents" in raw_bytes)

    has_sig = b"/ByteRange" in raw_bytes or b"/Sig" in raw_bytes or has_type_sig
    byterange_valid = True
    incremental_after_sign = False
    post_signature_diff_preview = ""
    reasons: List[str] = []

    br_matches = re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", raw_bytes)
    parsed_byterange = None
    if br_matches:
        start1, len1, start2, len2 = [int(x) for x in br_matches[-1]]
        parsed_byterange = [start1, len1, start2, len2]
        signed_end = start2 + len2
        if signed_end < file_size - 16:  # toleransi whitespace EOF kecil
            byterange_valid = False
            incremental_after_sign = True
            trailing_bytes = raw_bytes[signed_end:]
            preview_raw = trailing_bytes.decode("latin-1", errors="replace").strip()
            post_signature_diff_preview = preview_raw[:400] + ("..." if len(preview_raw) > 400 else "")
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
        if re.search(rb"(?<!\w)" + re.escape(tag) + rb"\b", raw_bytes):
            ocg_tags_found.append(tag.decode("ascii"))
    ocg_detected = len(ocg_tags_found) > 0
    if ocg_detected:
        reasons.append(
            f"Deteksi OCG / Hidden Layer (CVE-2025-59802): {', '.join(ocg_tags_found)}"
        )

    # Cek tag aktif berbahaya
    found_tags: List[str] = []
    for tag in DANGEROUS_PDF_TAGS:
        if tag in raw_bytes:
            tag_str = tag.decode("ascii")
            found_tags.append(tag_str)

    if found_tags:
        reasons.append(f"Objek aktif berbahaya ditemukan: {', '.join(found_tags)}")

    # Cek terhadap Vaksin YARA aktif (hanya yang enabled)
    matched_vaccines: List[str] = []
    if active_vaccine_patterns:
        for vac in active_vaccine_patterns:
            if not vac.get("enabled", True):
                continue
            pattern = vac["pattern"].encode("utf-8")
            if pattern in raw_bytes:
                matched_vaccines.append(vac["rule_name"])
                reasons.append(f"Diblokir oleh Vaksin Aktif: {vac['rule_name']}")

    verdict = (
        "INFECTED"
        if (not byterange_valid or found_tags or ocg_detected or matched_vaccines)
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
