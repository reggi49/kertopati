import io
from pathlib import Path
from typing import Tuple

from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader, PdfWriter


def _load_font(size: int, bold: bool = False) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    """Memuat font sistem macOS/Linux secara aman dengan fallback ke font default Pillow."""
    candidates = (
        [
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/Library/Fonts/Arial Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
        if bold
        else [
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    )
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size=size)
            except OSError:
                continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def render_surat_dinas_image(
    size: Tuple[int, int] = (800, 1131),
    classification: str = "TERBATAS - SIMULASI",
    subject: str = "Laporan Kesiapan Infrastruktur Jaringan & Persandian Satuan",
) -> Image.Image:
    """Menggambar halaman A4 Surat Dinas Simulasi TNI AD yang realistis dengan Pillow."""
    width, height = size
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    font_kop_top = _load_font(14, bold=True)
    font_kop_main = _load_font(17, bold=True)
    font_kop_sub = _load_font(12, bold=False)
    font_title = _load_font(14, bold=True)
    font_body = _load_font(13, bold=False)
    font_body_bold = _load_font(13, bold=True)
    font_small = _load_font(11, bold=False)
    font_small_bold = _load_font(11, bold=True)

    ink = (22, 28, 36)
    muted = (82, 92, 106)
    army_green = (29, 68, 43)
    gold = (182, 142, 48)
    border_gray = (198, 206, 216)

    # Bingkai dokumen tipis
    draw.rectangle([28, 24, width - 28, height - 24], outline=(224, 229, 235), width=1)

    # Label klasifikasi atas & bawah
    draw.rectangle([width - 215, 36, width - 45, 60], outline=army_green, width=1)
    draw.text((width - 203, 42), classification, fill=army_green, font=font_small_bold)
    draw.text((width // 2 - 70, height - 46), classification, fill=muted, font=font_small_bold)

    # Lambang perisai satuan sederhana di kiri kop surat
    shield = [(62, 54), (112, 54), (112, 95), (87, 118), (62, 95)]
    draw.polygon(shield, fill=army_green, outline=gold, width=2)
    draw.polygon([(87, 65), (93, 81), (103, 81), (95, 89), (98, 101), (87, 94), (76, 101), (79, 89), (71, 81), (81, 81)], fill=gold)

    # Kop Surat
    draw.text((135, 50), "TENTARA NASIONAL INDONESIA ANGKATAN DARAT", fill=ink, font=font_kop_top)
    draw.text((135, 70), "KOMANDO DAERAH MILITER III/SILIWANGI - KODIM 0606/KOTA BOGOR", fill=army_green, font=font_kop_main)
    draw.text((135, 95), "Jl. Jenderal Sudirman No. 33, Kota Bogor, Jawa Barat 16121", fill=muted, font=font_kop_sub)

    # Garis pemisah kop surat ganda
    draw.line([(48, 128), (width - 48, 128)], fill=ink, width=3)
    draw.line([(48, 133), (width - 48, 133)], fill=ink, width=1)

    # Judul Dokumen & Tempat Tanggal
    draw.text((width - 220, 150), "Bogor, 13 November 2026", fill=ink, font=font_body)
    draw.text((48, 180), "SURAT DINAS", fill=ink, font=font_title)

    # Blok Metadata Surat
    meta_rows = [
        ("Nomor", ": B / 214 / XI / 2026"),
        ("Klasifikasi", f": {classification}"),
        ("Lampiran", ": 1 (Satu) Berkas Rekapitulasi Perangkat"),
        ("Perihal", f": {subject}"),
    ]
    y = 212
    for label, val in meta_rows:
        draw.text((48, y), label, fill=ink, font=font_body_bold)
        draw.text((145, y), val, fill=ink, font=font_body)
        y += 24

    draw.line([(160, 306), (width - 48, 306)], fill=border_gray, width=1)

    # Alamat Tujuan
    y = 326
    draw.text((48, y), "Kepada", fill=ink, font=font_body_bold)
    draw.text((48, y + 22), "Yth. Panglima Kodam III/Siliwangi", fill=ink, font=font_body)
    draw.text((48, y + 44), "u.p. Komandan Korem 061/Suryakencana & Pusat Sandi Siber", fill=ink, font=font_body)
    draw.text((48, y + 66), "di Tempat", fill=ink, font=font_body)

    # Isi Paragraf Resmi
    paragraphs = [
        "1. Dasar: Program Kerja Bidang Pengamanan Informasi dan Persandian Satuan Kodim 0606/Kota Bogor Tahun Anggaran 2026 serta Prosedur Tetap Pertukaran Dokumen Zero-Trust.",
        "2. Sehubungan dengan dasar tersebut di atas, bersama ini kami laporkan kondisi terkini kesiapan infrastruktur jaringan, gerbang pertukaran dokumen elektronik, serta modul persandian satuan dalam keadaan baik dan beroperasi normal.",
        "3. Seluruh pengiriman naskah dinas elektronik telah melalui verifikasi integritas sertifikat elektronik dan pencatatan rantai kustodi untuk menjamin keaslian data antar satuan.",
    ]
    y = 430
    for para in paragraphs:
        # Bungkus teks per ~88 karakter agar rapi dalam margin A4
        words = para.split()
        line = ""
        for w in words:
            candidate = f"{line} {w}".strip()
            if len(candidate) > 88:
                draw.text((48, y), line, fill=ink, font=font_body)
                y += 21
                line = w
            else:
                line = candidate
        if line:
            draw.text((48, y), line, fill=ink, font=font_body)
            y += 28

    # Tabel Kecil Status Perangkat Satuan
    y += 8
    draw.text((48, y), "4. Rincian Status Kesiapan Perangkat Satuan:", fill=ink, font=font_body_bold)
    y += 28

    col_x = [48, 90, 315, 485, 600, width - 48]
    headers = ["No", "Nama Perangkat", "Lokasi Penempatan", "Status", "Keterangan"]
    rows = [
        ["1", "Gateway Kertopati-01", "Posko Utama Kodim", "SIAP / AKTIF", "Audit Harian Normal"],
        ["2", "Terminal E-Office Sandi", "Staf Ops & Persandian", "SIAP / AKTIF", "Sertifikat Valid"],
        ["3", "Server Arsip Terbatas", "Ruang Server Kodim", "SIAP / AKTIF", "Cadangan Terenkripsi"],
        ["4", "Radio Data Taktis", "Sektor A - Kota Bogor", "SIAP / AKTIF", "Uji Hubung Berhasil"],
    ]

    row_h = 30
    # Header Tabel
    draw.rectangle([col_x[0], y, col_x[-1], y + row_h], fill=(235, 242, 238), outline=army_green, width=1)
    for idx, title in enumerate(headers):
        draw.text((col_x[idx] + 8, y + 8), title, fill=army_green, font=font_small_bold)
        if idx > 0:
            draw.line([(col_x[idx], y), (col_x[idx], y + row_h)], fill=army_green, width=1)

    y += row_h
    for r_idx, row in enumerate(rows):
        bg = (255, 255, 255) if r_idx % 2 == 0 else (248, 250, 252)
        draw.rectangle([col_x[0], y, col_x[-1], y + row_h], fill=bg, outline=border_gray, width=1)
        for idx, cell in enumerate(row):
            color = army_green if idx == 3 else ink
            font_use = font_small_bold if idx == 3 else font_small
            draw.text((col_x[idx] + 8, y + 8), cell, fill=color, font=font_use)
            if idx > 0:
                draw.line([(col_x[idx], y), (col_x[idx], y + row_h)], fill=border_gray, width=1)
        y += row_h

    # Paragraf Penutup
    y += 22
    closing = "5. Demikian laporan kesiapan infrastruktur ini kami sampaikan sebagai bahan evaluasi dan pengawasan pimpinan. Atas perhatian serta arahannya kami ucapkan terima kasih."
    words = closing.split()
    line = ""
    for w in words:
        candidate = f"{line} {w}".strip()
        if len(candidate) > 88:
            draw.text((48, y), line, fill=ink, font=font_body)
            y += 21
            line = w
        else:
            line = candidate
    if line:
        draw.text((48, y), line, fill=ink, font=font_body)

    # Kotak Stempel Elektronik TTE BSrE di kanan bawah
    box_left, box_top, box_right, box_bottom = 415, 895, width - 48, 1035
    draw.rectangle([box_left, box_top, box_right, box_bottom], fill=(242, 250, 245), outline=army_green, width=2)
    draw.rectangle([box_left + 12, box_top + 14, box_left + 58, box_top + 60], fill=army_green, outline=gold, width=2)
    draw.text((box_left + 21, box_top + 29), "TTE", fill=(255, 255, 255), font=font_small_bold)

    draw.text((box_left + 70, box_top + 14), "[TTE TERVERIFIKASI BSrE BSSN]", fill=army_green, font=font_small_bold)
    draw.text((box_left + 70, box_top + 38), "Ditandatangani secara elektronik oleh:", fill=muted, font=font_small)
    draw.text((box_left + 70, box_top + 58), "Dansat Kodim 0606", fill=ink, font=font_body_bold)
    draw.text((box_left + 14, box_top + 88), "Komandan Kodim 0606/Kota Bogor", fill=ink, font=font_small_bold)
    draw.text((box_left + 14, box_top + 108), "ID Sertifikat: BSRE-SIM-0606-2026 | Dokumen Asli", fill=muted, font=font_small)

    return img


def build_clean_pdf_bytes() -> bytes:
    """Menghasilkan byte PDF Surat Dinas resmi dengan halaman terender + simulasi /ByteRange BSrE."""
    img = render_surat_dinas_image()
    img_pdf_buf = io.BytesIO()
    img.convert("RGB").save(img_pdf_buf, format="PDF", resolution=100.0)
    img_pdf_buf.seek(0)

    reader = PdfReader(img_pdf_buf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    writer.add_metadata(
        {
            "/Title": "Surat Dinas Simulasi TNI AD - Kodim 0606",
            "/Author": "Dansat Kodim 0606/Kota Bogor",
            "/Subject": "Laporan Kesiapan Infrastruktur Jaringan & Persandian Satuan",
        }
    )

    buf = io.BytesIO()
    writer.write(buf)
    raw = buf.getvalue().rstrip(b"%%EOF\r\n")

    # Simulasi kamus tanda tangan elektronik BSrE dengan /ByteRange yang valid hingga akhir file
    prefix = (
        raw
        + b"\n% BSrE-TTE-SIMULATION /Type /Sig /SubFilter /adbe.pkcs7.detached "
        + b"/Contents <3082010a020101> /ByteRange [0 100 120 "
    )
    placeholder_len = 8
    total_target = len(prefix) + placeholder_len
    val = total_target - 120
    candidate = prefix + f"{val}]\n%%EOF\n".encode("ascii")
    actual_val = len(candidate) - 120
    while actual_val != val:
        val = actual_val
        candidate = prefix + f"{val}]\n%%EOF\n".encode("ascii")
        actual_val = len(candidate) - 120

    return candidate


def build_clean_signed_pdf(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(build_clean_pdf_bytes())


if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "demo_samples" / "surat_dinas_bsre_bersih.pdf"
    build_clean_signed_pdf(target)
    print(f"Generated clean signed PDF: {target} ({target.stat().st_size} bytes)")
