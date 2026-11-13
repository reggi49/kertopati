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
from app.cdr_sanitizer import sanitize_pdf_bytes
from app.ledger import ChainOfCustodyLedger
from app.pdf_inspector import inspect_pdf_bytes
from app.sandbox_vaccine import SandboxVaccineEngine
from generate_clean_pdf import build_clean_signed_pdf
from generate_evil_pdf import build_infected_shadow_pdf


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

    return TestClient(app_main.app), test_ledger, test_sandbox, sanitized_dir


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
