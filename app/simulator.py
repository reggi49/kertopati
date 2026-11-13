import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

from demo_scripts.generate_clean_pdf import build_clean_pdf_bytes
from demo_scripts.generate_multiformat_demos import build_macro_docx_bytes, build_polyglot_jpeg_bytes


CVE_CATALOG: Dict[str, dict] = {
    "CVE-2026-91814": {
        "title": "PDF Shadow Attack / Incremental Update Bypass (BSrE TTE)",
        "filename": "sim_cve_2026_91814_shadow.pdf",
        "description": "Menyisipkan objek berbahaya setelah /ByteRange tanda tangan BSrE sehingga indikator tanda tangan terlihat sah di viewer konvensional.",
    },
    "CVE-2026-6361": {
        "title": "PDFium RCE / Embedded /OpenAction + /JavaScript",
        "filename": "sim_cve_2026_6361_pdfium_rce.pdf",
        "description": "Mengeksekusi skrip otomatis /OpenAction + /JavaScript saat dokumen dibuka oleh operator.",
    },
    "CVE-2025-59802": {
        "title": "PDF OCG Hidden Content Spoofing",
        "filename": "sim_cve_2025_59802_ocg_spoof.pdf",
        "description": "Menyembunyikan instruksi palsu menggunakan Optional Content Groups (/OCProperties /OCG) di balik dokumen bertanda tangan.",
    },
    "JPEG-POLYGLOT": {
        "title": "JPEG Polyglot (Trailing ZIP + PowerShell -enc)",
        "filename": "sim_jpeg_polyglot_lapangan.jpg",
        "description": "Gambar laporan lapangan valid yang disisipi arsip ZIP dan perintah powershell -enc setelah marker EOI FF D9.",
    },
    "DOCX-MACRO": {
        "title": "DOCX Macro (vbaProject.bin) + External Template Injection",
        "filename": "sim_docx_macro_anggaran.docx",
        "description": "Dokumen Word yang membawa macro VBA berbahaya dan relasi eksternal TargetMode=\"External\".",
    },
}


def build_cve_sample(cve_id: str, demo_samples_dir: Path | None = None) -> Tuple[str, bytes, dict]:
    """Menghasilkan sampel inert untuk 5 skenario serangan CVE/multi-format."""
    if cve_id not in CVE_CATALOG:
        raise ValueError(f"Skenario CVE tidak dikenal: {cve_id}")

    meta = CVE_CATALOG[cve_id]
    filename = meta["filename"]

    if cve_id == "CVE-2026-91814":
        if demo_samples_dir and (demo_samples_dir / "surat_dinas_bsre_terinfeksi.pdf").exists():
            return filename, (demo_samples_dir / "surat_dinas_bsre_terinfeksi.pdf").read_bytes(), meta
        signed_pdf = build_clean_pdf_bytes()
        evil_tail = (
            b"\n% --- SHADOW INCREMENTAL UPDATE (CVE-2026-91814) ---\n"
            b"99 0 obj << /Type /Action /S /JavaScript /OpenAction true "
            b"/JS (app.alert('SHADOW_CVE_2026_91814: WScript.Shell -> http://c2-attacker.local/beacon')) >> endobj\n%%EOF\n"
        )
        return filename, signed_pdf + evil_tail, meta

    if cve_id == "CVE-2026-6361":
        base = build_clean_pdf_bytes().rstrip(b"%%EOF\r\n")
        payload = (
            b"\n98 0 obj << /Type /Catalog /OpenAction << /S /JavaScript "
            b"/JS (eval('WScript.Shell CVE_2026_6361_PDFIUM_EXPLOIT http://c2-pdfium.local/stage2')) >> >> endobj\n%%EOF\n"
        )
        return filename, base + payload, meta

    if cve_id == "CVE-2025-59802":
        base = build_clean_pdf_bytes().rstrip(b"%%EOF\r\n")
        ocg_payload = (
            b"\n% BSrE-TTE /Type /Sig /SubFilter /adbe.pkcs7.detached /Contents <ABCD>\n"
            b"77 0 obj << /OCProperties << /OCGs [78 0 R] >> /OCG << /Name (HiddenCommandLayer_CVE_2025_59802) >> >> endobj\n%%EOF\n"
        )
        return filename, base + ocg_payload, meta

    if cve_id == "JPEG-POLYGLOT":
        if demo_samples_dir and (demo_samples_dir / "laporan_lapangan_polyglot.jpg").exists():
            return filename, (demo_samples_dir / "laporan_lapangan_polyglot.jpg").read_bytes(), meta
        return filename, build_polyglot_jpeg_bytes(), meta

    # DOCX-MACRO
    if demo_samples_dir and (demo_samples_dir / "rekap_anggaran_macro.docx").exists():
        return filename, (demo_samples_dir / "rekap_anggaran_macro.docx").read_bytes(), meta

    return filename, build_macro_docx_bytes(), meta


def build_without_kertopati_response(
    cve_id: str,
    filename: str,
    raw_bytes: bytes,
    meta: dict,
    attacker_ip: str,
    user_agent: str,
) -> dict:
    """Respons simulasi ketika server satuan TIDAK dilindungi oleh Kertopati."""
    payload_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "cve_id": cve_id,
        "cve_title": meta["title"],
        "protection_mode": "WITHOUT_KERTOPATI",
        "server_status": "COMPROMISED / TAKEN OVER",
        "attacker_view": {
            "status": "SHELL_OPENED",
            "message": f"Payload {cve_id} berhasil dieksekusi di server target tanpa hambatan!",
            "terminal_logs": [
                f"[*] Mengunggah {filename} ({len(raw_bytes)} bytes) ke E-Office konvensional...",
                "[+] Pemeriksaan ekstensi & TTE standar: LOLOS (bypassed)",
                f"[+] Triggering exploit {cve_id} -> Reverse shell terbuka dari {attacker_ip}",
                "root@server-satuan-target:~# id",
                "uid=0(root) gid=0(root) groups=0(root)",
                "root@server-satuan-target:~# cat /etc/rahasia/rencana_operasi_satuan.txt",
                "[CRITICAL LEAK] DOKUMEN RAHASIA TERBACA: KOORDINAT_DISLOKASI_PASUKAN_2026.ENC",
                "[!] Server satuan berhasil diambil alih sepenuhnya (FULL TAKEOVER).",
            ],
        },
        "soc_view": {
            "verdict": "COMPROMISED",
            "server_status": "COMPROMISED / TAKEN OVER",
            "message": "TIDAK ADA VISIBILITAS! Server konvensional gagal mendeteksi manipulasi struktur file dan telah dikuasai penyerang.",
            "forensic_telemetry": {
                "attacker_ip": attacker_ip,
                "user_agent": user_agent,
                "timestamp": ts,
                "payload_sha256": payload_sha256,
                "honeypot_commands": [],
            },
            "immunized_units": {
                "Kodim 0606": "COMPROMISED",
                "Korem 061": "VULNERABLE",
                "Kodam III": "VULNERABLE",
                "Mabesad": "AT_RISK",
            },
        },
    }


def build_honeypot_attacker_view(
    cve_id: str,
    filename: str,
    sandbox_result: dict | None = None,
) -> dict:
    """Respons Plasebo Honeypot nyata dari container/sandbox terisolasi saat Mode Dengan Kertopati aktif."""
    sbx = sandbox_result or {}
    backend = sbx.get("execution_backend", "Isolated Sandbox")
    cid = sbx.get("container_id", "-")
    exit_code = sbx.get("exit_code", 0)
    duration_ms = sbx.get("duration_ms", 0)
    real_stdout = (sbx.get("stdout") or "").splitlines()
    flags = " ".join(sbx.get("isolation_flags") or [])

    terminal_logs = [
        f"[*] Mengunggah {filename} ke target...",
        "[+] HTTP 200 OK — Dokumen diterima di antrean (Plasebo Aktif).",
        f"[*] Payload dialihkan ke eksekusi terisolasi: {backend}",
        f"[*] Container/Sandbox ID: {cid} | Exit: {exit_code} ({duration_ms} ms)",
        f"[*] Isolation Flags: {flags}",
        "--- REAL SANDBOX STDOUT (/decoy_satuan) ---",
        *(real_stdout if real_stdout else ["(tidak ada output stdout)"]),
        "--- END SANDBOX STDOUT ---",
        "[!] Pelaku hanya mengakses /decoy_satuan umpan tanpa akses jaringan & data asli satuan.",
    ]

    return {
        "status": "200 OK (PLASEBO HONEYPOT)",
        "message": f"Dokumen {filename} dialihkan ke sandbox terisolasi ({cid}).",
        "execution_backend": backend,
        "container_id": cid,
        "terminal_logs": terminal_logs,
    }
