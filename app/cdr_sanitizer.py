import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from PIL import Image
from pypdf import PdfReader, PdfWriter
from pypdf.errors import PdfReadError
from pypdf.generic import NameObject


RISKY_ROOT_KEYS = ("/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch", "/OCProperties")
RISKY_PAGE_KEYS = ("/AA", "/OpenAction", "/JS", "/JavaScript", "/Launch", "/OCProperties", "/OCGs", "/OCG")


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


def sanitize_image_bytes(
    raw_bytes: bytes,
    filename: str,
    output_dir: Path | None = None,
) -> CDRSanitizationResult:
    """
    CDR untuk gambar JPEG/PNG menggunakan Pillow:
    Membuka piksel gambar, membuang seluruh metadata EXIF/ICC/tEXt,
    dan menyimpan ulang ke buffer baru sehingga trailing bytes/polyglot ikut terbuang.
    """
    original_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    removed: List[str] = []

    with Image.open(io.BytesIO(raw_bytes)) as img:
        fmt = (img.format or "").upper()
        if fmt not in ("JPEG", "PNG"):
            fmt = "PNG" if Path(filename).suffix.lower() == ".png" else "JPEG"

        if img.info:
            removed.append("ImageMetadata(EXIF/ICC/tEXt)")

        target_mode = img.mode
        if fmt == "JPEG" and target_mode not in ("RGB", "L"):
            target_mode = "RGB"

        converted = img.convert(target_mode) if img.mode != target_mode else img
        clean_img = Image.new(converted.mode, converted.size)
        clean_img.paste(converted)

        out_buf = io.BytesIO()
        if fmt == "JPEG":
            clean_img.save(out_buf, format="JPEG", quality=92)
        else:
            clean_img.save(out_buf, format="PNG")

    sanitized_bytes = out_buf.getvalue()
    sanitized_sha256 = hashlib.sha256(sanitized_bytes).hexdigest()

    safe_stem = Path(filename).name
    sanitized_filename = f"sanitized_{safe_stem}"

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / sanitized_filename).write_bytes(sanitized_bytes)

    return CDRSanitizationResult(
        original_filename=filename,
        sanitized_filename=sanitized_filename,
        original_sha256=original_sha256,
        sanitized_sha256=sanitized_sha256,
        page_count=1,
        removed_elements=removed,
        sanitized_bytes=sanitized_bytes,
    )


def sanitize_office_bytes(
    raw_bytes: bytes,
    filename: str,
    output_dir: Path | None = None,
) -> CDRSanitizationResult:
    """
    CDR untuk dokumen Office DOCX/XLSX menggunakan zipfile:
    Merekonstruksi arsip ZIP baru tanpa vbaProject.bin, file executable/script,
    referensi macro, dan relasi TargetMode="External".
    """
    original_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    removed: List[str] = []
    bad_exts = (".exe", ".bat", ".ps1", ".js", ".vbs", ".cmd", ".scr", ".hta")

    out_buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zin, zipfile.ZipFile(
        out_buf, "w", compression=zipfile.ZIP_DEFLATED
    ) as zout:
        for item in zin.infolist():
            lower_name = item.filename.lower()
            if lower_name.endswith("vbaproject.bin"):
                removed.append(item.filename)
                continue
            if lower_name.endswith(bad_exts):
                removed.append(item.filename)
                continue

            data = zin.read(item.filename)
            if lower_name.endswith(".rels"):
                cleaned_data, n_ext = re.subn(
                    rb'<Relationship\b[^>]*TargetMode\s*=\s*["\']External["\'][^>]*/>',
                    b"",
                    data,
                    flags=re.IGNORECASE,
                )
                cleaned_data, n_vba = re.subn(
                    rb'<Relationship\b[^>]*vbaProject[^>]*/>',
                    b"",
                    cleaned_data,
                    flags=re.IGNORECASE,
                )
                if n_ext:
                    removed.append(f"ExternalRels({item.filename})")
                if n_vba:
                    removed.append(f"VbaRels({item.filename})")
                data = cleaned_data
            elif lower_name == "[content_types].xml":
                cleaned_data, n_ct = re.subn(
                    rb'<Override\b[^>]*vbaProject[^>]*/>',
                    b"",
                    data,
                    flags=re.IGNORECASE,
                )
                if n_ct:
                    removed.append("ContentTypesVbaOverride")
                data = cleaned_data

            zout.writestr(item.filename, data)

    sanitized_bytes = out_buf.getvalue()
    sanitized_sha256 = hashlib.sha256(sanitized_bytes).hexdigest()

    safe_stem = Path(filename).name
    sanitized_filename = f"sanitized_{safe_stem}"

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / sanitized_filename).write_bytes(sanitized_bytes)

    return CDRSanitizationResult(
        original_filename=filename,
        sanitized_filename=sanitized_filename,
        original_sha256=original_sha256,
        sanitized_sha256=sanitized_sha256,
        page_count=1,
        removed_elements=removed,
        sanitized_bytes=sanitized_bytes,
    )


def sanitize_document_bytes(
    raw_bytes: bytes,
    filename: str,
    file_format: str,
    output_dir: Path | None = None,
) -> CDRSanitizationResult:
    """Dispatcher CDR untuk PDF, Gambar (JPEG/PNG), dan Office (DOCX/XLSX)."""
    fmt = file_format.upper()
    if fmt == "PDF":
        return sanitize_pdf_bytes(raw_bytes, filename, output_dir=output_dir)
    if fmt in ("JPEG", "PNG"):
        return sanitize_image_bytes(raw_bytes, filename, output_dir=output_dir)
    return sanitize_office_bytes(raw_bytes, filename, output_dir=output_dir)
