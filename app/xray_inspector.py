import io
import re
import zipfile
from pathlib import Path
from typing import Dict, List

from app.multi_inspector import (
    EXECUTABLE_EXTENSIONS,
    _find_jpeg_eoi_end,
    _find_png_iend_end,
    detect_magic_format,
)


def _to_hex_preview(data: bytes, max_bytes: int = 96) -> str:
    chunk = data[:max_bytes]
    return " ".join(f"{b:02X}" for b in chunk) + (" ..." if len(data) > max_bytes else "")


def _to_ascii_preview(data: bytes, max_chars: int = 500) -> str:
    text = data[: max_chars + 100].decode("latin-1", errors="replace")
    printable = "".join(ch if (32 <= ord(ch) <= 126 or ch in "\n\r\t") else "." for ch in text)
    return printable[:max_chars] + ("..." if len(printable) > max_chars else "")


def build_xray_report(raw_bytes: bytes, filename: str, file_format: str | None = None) -> Dict[str, object]:
    """
    Inspektor Forensik X-Ray File: membedah struktur byte sah vs sisipan berbahaya
    untuk PDF, JPEG/PNG, dan DOCX/XLSX.
    """
    ext = Path(filename).suffix.lower()
    detected_magic = detect_magic_format(raw_bytes)
    fmt = (file_format or "").upper()
    if not fmt or fmt == "UNKNOWN":
        if detected_magic == "OOXML":
            fmt = "XLSX" if ext == ".xlsx" else "DOCX"
        else:
            fmt = detected_magic

    total_size = len(raw_bytes)
    report: Dict[str, object] = {
        "filename": filename,
        "file_format": fmt,
        "total_size_bytes": total_size,
    }

    if fmt == "PDF" and detected_magic == "PDF":
        br_matches = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", raw_bytes))
        split_at = None
        split_reason = ""
        if br_matches:
            last = br_matches[-1]
            signed_end = int(last.group(3)) + int(last.group(4))
            if signed_end < total_size - 16:
                split_at = signed_end
                split_reason = "Byte di luar cakupan /ByteRange BSrE (Shadow Attack / Incremental Update)"

        if split_at is None:
            danger_match = re.search(
                rb"(?:%[^\r\n]*\r?\n)?\d+\s+\d+\s+obj[^\n]*?(?:/OpenAction|/JavaScript|/JS|/OCProperties|/OCG|/Launch)",
                raw_bytes,
                re.DOTALL,
            )
            if danger_match:
                split_at = danger_match.start()
                split_reason = "Objek aktif/OCG berbahaya terdeteksi di dalam struktur PDF"

        if split_at is not None and 0 <= split_at < total_size:
            clean_part = raw_bytes[:split_at]
            inj_part = raw_bytes[split_at:]
        else:
            clean_part = raw_bytes
            inj_part = b""

        report["xray_type"] = "PDF_REGIONS"
        report["clean_region"] = {
            "start_byte": 0,
            "end_byte": len(clean_part),
            "size_bytes": len(clean_part),
            "preview_ascii": _to_ascii_preview(clean_part, max_chars=360),
        }
        report["injected_region"] = {
            "start_byte": len(clean_part),
            "end_byte": total_size,
            "size_bytes": len(inj_part),
            "reason": split_reason or "Tidak ada trailing update di luar /ByteRange",
            "preview_ascii": _to_ascii_preview(inj_part, max_chars=450) if inj_part else "",
            "preview_hex": _to_hex_preview(inj_part) if inj_part else "",
        }
        return report

    if fmt in ("JPEG", "PNG") and detected_magic in ("JPEG", "PNG"):
        end_offset = _find_jpeg_eoi_end(raw_bytes) if detected_magic == "JPEG" else _find_png_iend_end(raw_bytes)
        if end_offset is None or end_offset > total_size:
            end_offset = total_size
        valid_part = raw_bytes[:end_offset]
        trailing = raw_bytes[end_offset:]
        marker = "FF D9 (JPEG EOI)" if detected_magic == "JPEG" else "IEND + CRC (PNG)"

        report["xray_type"] = "IMAGE_POLYGLOT"
        report["valid_image_bytes"] = {
            "start_byte": 0,
            "end_byte": end_offset,
            "size_bytes": len(valid_part),
            "marker": marker,
            "preview_hex": _to_hex_preview(valid_part, max_bytes=32),
        }
        report["trailing_payload_hex_ascii"] = {
            "start_byte": end_offset,
            "end_byte": total_size,
            "size_bytes": len(trailing),
            "preview_hex": _to_hex_preview(trailing) if trailing else "",
            "preview_ascii": _to_ascii_preview(trailing, max_chars=400) if trailing else "",
        }
        return report

    if fmt in ("DOCX", "XLSX", "OOXML") and detected_magic == "OOXML":
        entries: List[dict] = []
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
                for info in zf.infolist():
                    lower_name = info.filename.lower()
                    suspicious = False
                    reason = "Komponen OOXML standar"
                    if lower_name.endswith("vbaproject.bin"):
                        suspicious = True
                        reason = "Macro VBA berbahaya (vbaProject.bin)"
                    elif lower_name.endswith(EXECUTABLE_EXTENSIONS):
                        suspicious = True
                        reason = f"Skrip/executable tersembunyi ({Path(info.filename).suffix})"
                    elif lower_name.endswith(".rels"):
                        rels_bytes = zf.read(info.filename)
                        if re.search(rb'TargetMode\s*=\s*["\']External["\']', rels_bytes, re.IGNORECASE):
                            suspicious = True
                            reason = 'Relasi eksternal berbahaya (TargetMode="External")'
                    entries.append(
                        {
                            "filename": info.filename,
                            "size_bytes": info.file_size,
                            "suspicious": suspicious,
                            "reason": reason,
                        }
                    )
        except zipfile.BadZipFile:
            entries.append(
                {
                    "filename": filename,
                    "size_bytes": total_size,
                    "suspicious": True,
                    "reason": "Arsip OOXML rusak / invalid ZIP",
                }
            )
        report["xray_type"] = "OOXML_ARCHIVE"
        report["zip_entries"] = entries
        return report

    # Fallback untuk file palsu / magic bytes mismatch
    report["xray_type"] = "RAW_SPOOFED"
    report["clean_region"] = {
        "start_byte": 0,
        "end_byte": 0,
        "size_bytes": 0,
        "preview_ascii": "",
    }
    report["injected_region"] = {
        "start_byte": 0,
        "end_byte": total_size,
        "size_bytes": total_size,
        "reason": f"Magic bytes ({detected_magic}) tidak cocok dengan ekstensi file ({ext or 'none'})",
        "preview_ascii": _to_ascii_preview(raw_bytes, max_chars=400),
        "preview_hex": _to_hex_preview(raw_bytes),
    }
    return report
