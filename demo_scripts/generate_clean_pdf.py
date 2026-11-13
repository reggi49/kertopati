from pathlib import Path
from pypdf import PdfWriter


def build_clean_signed_pdf(output_path: Path) -> None:
    """
    Membuat surat dinas PDF bersih dengan simulasi metadata tanda tangan BSrE
    yang /ByteRange-nya mencakup seluruh isi file hingga akhir (tanpa script berbahaya).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    writer.add_metadata(
        {
            "/Title": "Surat Perintah Operasi Siber - Kodim 0606",
            "/Author": "Komandan Kodim 0606 (BSrE TTE Verified)",
            "/Subject": "Distribusi Dokumen Berjenjang Kodim -> Korem -> Pusat",
        }
    )

    temp_bytes_path = output_path.with_suffix(".tmp.pdf")
    with open(temp_bytes_path, "wb") as f:
        writer.write(f)

    raw = temp_bytes_path.read_bytes()
    temp_bytes_path.unlink()

    # Sisipkan marker simulasi /ByteRange BSrE yang valid (mencakup sampai akhir file)
    sig_comment = b"\n% BSrE-TTE-SIMULATION /Sig /ByteRange [0 100 120 "
    total_estimated = len(raw) + len(sig_comment) + 16
    remainder = total_estimated - 120
    footer = sig_comment + f"{remainder}] \n%%EOF\n".encode("ascii")

    # Pastikan panjang exact sesuai ByteRange
    final_bytes = raw.rstrip(b"%%EOF\r\n") + footer
    # Hitung ulang agar start2 + len2 == len(final_bytes)
    prefix = raw.rstrip(b"%%EOF\r\n") + b"\n% BSrE-TTE-SIMULATION /Sig /ByteRange [0 100 120 "
    suffix_template = b"%d]\n%%%%EOF\n"
    # Iterasi 2 kali untuk menstabilkan panjang angka
    est_len = len(prefix) + 12
    for _ in range(3):
        val = est_len - 120
        candidate = prefix + f"{val}]\n%%EOF\n".encode("ascii")
        est_len = len(candidate)

    output_path.write_bytes(candidate)
    print(f"[OK] PDF bersih dibuat: {output_path} ({len(candidate)} bytes)")


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "demo_samples" / "surat_dinas_bsre_bersih.pdf"
    build_clean_signed_pdf(out)
