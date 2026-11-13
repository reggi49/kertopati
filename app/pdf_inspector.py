import re
from dataclasses import dataclass, field
from typing import List


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


@dataclass
class PdfInspectionResult:
    filename: str
    file_size: int
    eof_count: int
    has_signature_field: bool
    byterange_valid: bool
    incremental_update_after_sign: bool
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
    2. Mengecek /ByteRange tanda tangan digital (simulasi BSrE PAdES) apakah
       menutup hingga akhir file (mencegah Shadow Attack / CVE-2026-91814).
    3. Memindai objek aktif berbahaya (/JS, /OpenAction, /Launch, dll).
    4. Mencocokkan terhadap aturan Vaksin (YARA-style signatures) yang aktif.
    """
    file_size = len(raw_bytes)
    eof_matches = list(re.finditer(rb"%%EOF\s*", raw_bytes))
    eof_count = len(eof_matches)

    has_sig = b"/ByteRange" in raw_bytes or b"/Sig" in raw_bytes
    byterange_valid = True
    incremental_after_sign = False
    reasons: List[str] = []

    # Cek apakah /ByteRange mencakup sampai akhir file
    br_matches = re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", raw_bytes)
    if br_matches:
        # Ambil ByteRange terakhir
        start1, len1, start2, len2 = [int(x) for x in br_matches[-1]]
        signed_end = start2 + len2
        if signed_end < file_size - 16:  # toleransi whitespace EOF kecil
            byterange_valid = False
            incremental_after_sign = True
            reasons.append(
                f"Shadow Attack / Incremental Update pasca-TTE terdeteksi: "
                f"ByteRange berhenti di byte {signed_end} dari total {file_size} byte."
            )
    elif eof_count > 1:
        incremental_after_sign = True
        reasons.append(f"Terdapat {eof_count} revisi %%EOF (incremental update mencurigakan).")

    # Cek tag aktif berbahaya
    found_tags: List[str] = []
    for tag in DANGEROUS_PDF_TAGS:
        if tag in raw_bytes:
            tag_str = tag.decode("ascii")
            found_tags.append(tag_str)

    if found_tags:
        reasons.append(f"Objek aktif berbahaya ditemukan: {', '.join(found_tags)}")

    # Cek terhadap Vaksin YARA aktif
    matched_vaccines: List[str] = []
    if active_vaccine_patterns:
        for vac in active_vaccine_patterns:
            pattern = vac["pattern"].encode("utf-8")
            if pattern in raw_bytes:
                matched_vaccines.append(vac["rule_name"])
                reasons.append(f"Diblokir oleh Vaksin Aktif: {vac['rule_name']}")

    verdict = "INFECTED" if (not byterange_valid or found_tags or matched_vaccines) else "CLEAN"

    return PdfInspectionResult(
        filename=filename,
        file_size=file_size,
        eof_count=eof_count,
        has_signature_field=has_sig,
        byterange_valid=byterange_valid,
        incremental_update_after_sign=incremental_after_sign,
        dangerous_tags_found=found_tags,
        matched_vaccines=matched_vaccines,
        verdict=verdict,
        reasons=reasons,
    )
