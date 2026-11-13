import hashlib
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from pypdf import PdfReader, PdfWriter
from pypdf.errors import PdfReadError
from pypdf.generic import NameObject


RISKY_ROOT_KEYS = ("/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch")
RISKY_PAGE_KEYS = ("/AA", "/OpenAction", "/JS", "/JavaScript", "/Launch")


def _open_pdf_reader(raw_bytes: bytes) -> PdfReader:
    """Membuka PDF dengan pypdf, dengan fallback jika ada komentar sebelum %%EOF."""
    try:
        return PdfReader(io.BytesIO(raw_bytes))
    except PdfReadError:
        cleaned = re.sub(rb"(?:\r?\n%[^\r\n]*)+(?=\r?\n%%EOF\s*$)", b"", raw_bytes)
        return PdfReader(io.BytesIO(cleaned))


@dataclass
class CDRSanitizationResult:
    original_filename: str
    sanitized_filename: str
    original_sha256: str
    sanitized_sha256: str
    page_count: int
    removed_elements: List[str] = field(default_factory=list)
    sanitized_bytes: bytes = b""


def sanitize_pdf_bytes(
    raw_bytes: bytes,
    filename: str,
    output_dir: Path | None = None,
) -> CDRSanitizationResult:
    """
    Content Disarm & Reconstruction (CDR) menggunakan pypdf:
    Merekonstruksi PDF menjadi dokumen baru yang steril dengan menyalin halaman
    secara bersih, menghapus objek aksi berisiko (/OpenAction, /AA, /JavaScript,
    /JS, /Launch) serta membersihkan metadata asal.
    """
    original_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    reader = _open_pdf_reader(raw_bytes)
    writer = PdfWriter()

    removed: List[str] = []

    if reader.metadata:
        removed.append("OriginalMetadata")

    root_obj = reader.trailer.get("/Root")
    if root_obj is not None:
        root_resolved = root_obj.get_object()
        for key in RISKY_ROOT_KEYS:
            if key in root_resolved:
                removed.append(f"Root{key}")

    for page_idx, page in enumerate(reader.pages):
        for key in RISKY_PAGE_KEYS:
            if key in page:
                del page[NameObject(key)]
                tag_label = f"Page{page_idx + 1}{key}"
                if tag_label not in removed:
                    removed.append(tag_label)

        # Bersihkan anotasi tautan/aksi berbahaya jika ada
        if "/Annots" in page:
            annots = page["/Annots"].get_object()
            clean_annots = []
            for annot_ref in annots:
                annot = annot_ref.get_object()
                action = annot.get("/A")
                if action is not None:
                    action_obj = action.get_object()
                    subtype = str(action_obj.get("/S", ""))
                    if subtype in ("/JavaScript", "/Launch", "/URI"):
                        removed.append(f"Annot{subtype}")
                        continue
                clean_annots.append(annot_ref)
            if len(clean_annots) != len(annots):
                if clean_annots:
                    page[NameObject("/Annots")] = clean_annots
                else:
                    del page[NameObject("/Annots")]

        writer.add_page(page)

    # Pastikan root writer tidak mewarisi /OpenAction, /AA, atau /Names/JavaScript
    writer_root = writer._root_object
    for key in RISKY_ROOT_KEYS:
        if key in writer_root:
            del writer_root[NameObject(key)]

    # Ganti metadata dengan metadata steril SandiSeal CDR
    writer.add_metadata(
        {
            "/Producer": "SandiSeal CDR Sanitizer (Zero-Trust)",
            "/Creator": "SandiSeal Content Disarm & Reconstruction",
        }
    )

    out_buf = io.BytesIO()
    writer.write(out_buf)
    sanitized_bytes = out_buf.getvalue()
    sanitized_sha256 = hashlib.sha256(sanitized_bytes).hexdigest()

    safe_stem = Path(filename).name
    if not safe_stem.lower().endswith(".pdf"):
        safe_stem = f"{safe_stem}.pdf"
    sanitized_filename = f"sanitized_{safe_stem}"

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / sanitized_filename
        out_path.write_bytes(sanitized_bytes)

    return CDRSanitizationResult(
        original_filename=filename,
        sanitized_filename=sanitized_filename,
        original_sha256=original_sha256,
        sanitized_sha256=sanitized_sha256,
        page_count=len(reader.pages),
        removed_elements=removed,
        sanitized_bytes=sanitized_bytes,
    )
