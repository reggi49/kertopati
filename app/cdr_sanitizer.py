import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Set

from PIL import Image
from pypdf import PdfReader, PdfWriter
from pypdf.errors import PdfReadError
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject

from app.multi_inspector import EXECUTABLE_EXTENSIONS, MAX_ZIP_ENTRIES, MAX_ZIP_UNCOMPRESSED_BYTES

# Anti-Decompression Bomb limit for Pillow
Image.MAX_IMAGE_PIXELS = 50_000_000

RISKY_ROOT_KEYS = (
    "/OpenAction",
    "/AA",
    "/JavaScript",
    "/JS",
    "/Launch",
    "/OCProperties",
    "/OCGs",
    "/OCG",
    "/Names",
    "/AcroForm",
    "/EmbeddedFiles",
    "/EmbeddedFile",
    "/RichMedia",
    "/XFA",
    "/URI",
)
RISKY_PAGE_KEYS = (
    "/AA",
    "/OpenAction",
    "/JS",
    "/JavaScript",
    "/Launch",
    "/OCProperties",
    "/OCGs",
    "/OCG",
    "/EmbeddedFiles",
    "/EmbeddedFile",
    "/EF",
    "/FS",
    "/RichMedia",
    "/XFA",
    "/SubmitForm",
    "/ImportData",
    "/GoToR",
    "/GoToE",
    "/URI",
)
DANGEROUS_ANNOT_SUBTYPES = {
    "/FileAttachment",
    "/RichMedia",
    "/3D",
    "/Movie",
    "/Sound",
    "/Screen",
    "/TrapNet",
}


def _open_pdf_reader(raw_bytes: bytes) -> PdfReader:
    """Membuka PDF dengan pypdf, dengan fallback jika ada komentar sebelum %%EOF."""
    try:
        return PdfReader(io.BytesIO(raw_bytes), strict=False)
    except PdfReadError:
        cleaned = re.sub(rb"(?:\r?\n%[^\r\n]*)+(?=\r?\n%%EOF\s*$)", b"", raw_bytes)
        return PdfReader(io.BytesIO(cleaned), strict=False)


def _scrub_pdf_dict_recursive(
    obj: Any,
    removed: List[str],
    visited: Set[int],
    prefix: str = "Obj",
) -> None:
    try:
        if isinstance(obj, IndirectObject):
            obj = obj.get_object()
    except Exception:
        return

    obj_id = id(obj)
    if obj_id in visited:
        return
    visited.add(obj_id)

    if isinstance(obj, DictionaryObject):
        for key in list(obj.keys()):
            key_str = str(key)
            if key_str in RISKY_PAGE_KEYS or key_str == "/A":
                del obj[key]
                label = f"{prefix}{key_str}"
                if label not in removed:
                    removed.append(label)
                continue
            if key_str == "/Parent":
                continue
            _scrub_pdf_dict_recursive(obj[key], removed, visited, prefix)
    elif isinstance(obj, (ArrayObject, list)):
        for item in list(obj):
            _scrub_pdf_dict_recursive(item, removed, visited, prefix)


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
    /JS, /Launch, /EmbeddedFile, /FileAttachment, /RichMedia, /OCG) serta
    membersihkan metadata asal secara rekursif.
    """
    original_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    reader = _open_pdf_reader(raw_bytes)
    writer = PdfWriter()

    removed: List[str] = []

    if reader.metadata:
        removed.append("OriginalMetadata")

    root_obj = reader.trailer.get("/Root")
    if root_obj is not None:
        try:
            root_resolved = root_obj.get_object() if hasattr(root_obj, "get_object") else root_obj
            for key in RISKY_ROOT_KEYS:
                if key in root_resolved:
                    removed.append(f"Root{key}")
        except Exception:
            pass

    for page_idx, page in enumerate(reader.pages):
        for key in RISKY_PAGE_KEYS:
            if key in page:
                del page[NameObject(key)]
                tag_label = f"Page{page_idx + 1}{key}"
                if tag_label not in removed:
                    removed.append(tag_label)

        # Bersihkan anotasi tautan/aksi/attachment berbahaya jika ada
        if "/Annots" in page:
            try:
                annots = page["/Annots"].get_object()
                clean_annots = ArrayObject()
                for annot_ref in annots:
                    annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    if not isinstance(annot, DictionaryObject):
                        continue
                    annot_subtype = str(annot.get("/Subtype", ""))
                    if (
                        annot_subtype in DANGEROUS_ANNOT_SUBTYPES
                        or "/EF" in annot
                        or "/FS" in annot
                    ):
                        removed.append(f"Annot{annot_subtype or '/FileAttachment'}")
                        continue

                    action = annot.get("/A")
                    if action is not None:
                        action_obj = action.get_object() if hasattr(action, "get_object") else action
                        subtype = str(action_obj.get("/S", "")) if isinstance(action_obj, dict) else ""
                        if subtype in ("/JavaScript", "/Launch", "/URI", "/GoToR", "/GoToE", "/SubmitForm", "/ImportData"):
                            removed.append(f"Annot{subtype}")
                            continue
                        del annot[NameObject("/A")]
                        removed.append("Annot/A")

                    # Scrub /AA, /JS, /JavaScript, /Launch, /EF, /FS inside remaining annotations (e.g. /Widget)
                    _scrub_pdf_dict_recursive(
                        annot, removed, set(), prefix=f"Page{page_idx + 1}Annot"
                    )
                    clean_annots.append(annot)

                if clean_annots:
                    page[NameObject("/Annots")] = clean_annots
                else:
                    del page[NameObject("/Annots")]
            except Exception:
                del page[NameObject("/Annots")]
                removed.append(f"Page{page_idx + 1}/Annots")

        _scrub_pdf_dict_recursive(page, removed, set(), prefix=f"Page{page_idx + 1}")
        writer.add_page(page)

    # Pastikan root writer tidak mewarisi /OpenAction, /AA, /Names, /AcroForm, atau /OCProperties
    writer_root = writer._root_object
    for key in RISKY_ROOT_KEYS:
        if key in writer_root:
            del writer_root[NameObject(key)]
    _scrub_pdf_dict_recursive(writer_root, removed, set(), prefix="Root")

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
        out_dir_path = Path(output_dir)
        out_dir_path.mkdir(parents=True, exist_ok=True)
        out_path = out_dir_path / sanitized_filename
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
    Membuka piksel gambar, membuang seluruh metadata EXIF/ICC/tEXt/chunk privat,
    dan menyimpan ulang ke buffer baru sehingga trailing bytes/polyglot ikut terbuang.
    """
    original_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    removed: List[str] = []

    with Image.open(io.BytesIO(raw_bytes)) as img:
        img.load()
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
        out_dir_path = Path(output_dir)
        out_dir_path.mkdir(parents=True, exist_ok=True)
        (out_dir_path / sanitized_filename).write_bytes(sanitized_bytes)

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
    Merekonstruksi arsip ZIP baru tanpa vbaProject.bin, OLE objects, ActiveX,
    Excel 4.0 XLM macrosheets, file executable/script (.dll, .jar, .lnk, .exe, dll),
    DDE / DDEAUTO field codes, dan relasi TargetMode="External" (baik self-closing maupun berpasangan).
    """
    original_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    removed: List[str] = []

    out_buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zin, zipfile.ZipFile(
        out_buf, "w", compression=zipfile.ZIP_DEFLATED
    ) as zout:
        infolist = zin.infolist()
        if len(infolist) > MAX_ZIP_ENTRIES:
            raise ValueError(f"Arsip melampaui batas aman entri ZIP ({MAX_ZIP_ENTRIES}).")
        total_uncompressed = sum(max(i.file_size, 0) for i in infolist)
        if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
            raise ValueError("Ukuran dekompresi arsip melebihi batas aman 100 MB.")

        for item in infolist:
            norm_name = item.filename.replace("\\", "/")
            lower_name = norm_name.lower()

            if ".." in norm_name.split("/") or norm_name.startswith("/"):
                removed.append(f"PathTraversal({item.filename})")
                continue

            if (
                lower_name.endswith("vbaproject.bin")
                or "vbaproject" in lower_name
                or "vbadata" in lower_name
                or "oleobject" in lower_name
                or "/embeddings/" in lower_name
                or lower_name.startswith("embeddings/")
                or "activex" in lower_name
                or "macrosheets/" in lower_name
                or "dialogsheets/" in lower_name
                or "customui/" in lower_name
                or lower_name.endswith(".bin")
                or lower_name.endswith(EXECUTABLE_EXTENSIONS)
            ):
                removed.append(item.filename)
                continue

            data = zin.read(item.filename)
            if lower_name.endswith(".rels"):
                # Strip both self-closing <Relationship .../> and paired <Relationship ...>...</Relationship>
                cleaned_data, n_ext1 = re.subn(
                    rb'<Relationship\b[^>]*?(?:TargetMode\s*=\s*["\']External["\']|mhtml:|ms-msdt:)[^>]*?/>',
                    b"",
                    data,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                cleaned_data, n_ext2 = re.subn(
                    rb'<Relationship\b[^>]*?(?:TargetMode\s*=\s*["\']External["\']|mhtml:|ms-msdt:)[^>]*?>.*?</Relationship>',
                    b"",
                    cleaned_data,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                cleaned_data, n_vba1 = re.subn(
                    rb"<Relationship\b[^>]*?(?:vbaProject|activeX|oleObject|embeddings)[^>]*?/>",
                    b"",
                    cleaned_data,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                cleaned_data, n_vba2 = re.subn(
                    rb"<Relationship\b[^>]*?(?:vbaProject|activeX|oleObject|embeddings)[^>]*?>.*?</Relationship>",
                    b"",
                    cleaned_data,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                if n_ext1 + n_ext2 > 0:
                    removed.append(f"ExternalRels({item.filename})")
                if n_vba1 + n_vba2 > 0:
                    removed.append(f"VbaRels({item.filename})")
                data = cleaned_data
            elif lower_name == "[content_types].xml":
                cleaned_data, n_ct = re.subn(
                    rb"<Override\b[^>]*?(?:vbaProject|activeX|oleObject|macrosheet)[^>]*?/>",
                    b"",
                    data,
                    flags=re.IGNORECASE,
                )
                if n_ct:
                    removed.append("ContentTypesVbaOverride")
                data = cleaned_data
            elif lower_name.endswith(".xml"):
                cleaned_data, n_dde1 = re.subn(
                    rb"<w:fldSimple\b[^>]*?\bDDE(?:AUTO)?\b[^>]*?>.*?</w:fldSimple>",
                    b"",
                    data,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                cleaned_data, n_dde2 = re.subn(
                    rb"\bDDEAUTO\b",
                    b"DISABLED_FIELD",
                    cleaned_data,
                    flags=re.IGNORECASE,
                )
                cleaned_data, n_dde3 = re.subn(
                    rb"<(?:w:instrText|instrText)\b[^>]*?>[^<]*?\bDDE\b[^<]*?</(?:w:instrText|instrText)>",
                    b"<w:instrText></w:instrText>",
                    cleaned_data,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                if n_dde1 + n_dde2 + n_dde3 > 0:
                    removed.append(f"DDEField({item.filename})")
                data = cleaned_data

            zout.writestr(norm_name, data)

    sanitized_bytes = out_buf.getvalue()
    sanitized_sha256 = hashlib.sha256(sanitized_bytes).hexdigest()

    safe_stem = Path(filename).name
    sanitized_filename = f"sanitized_{safe_stem}"

    if output_dir is not None:
        out_dir_path = Path(output_dir)
        out_dir_path.mkdir(parents=True, exist_ok=True)
        (out_dir_path / sanitized_filename).write_bytes(sanitized_bytes)

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
