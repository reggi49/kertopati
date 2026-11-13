from pathlib import Path
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.cdr_sanitizer import sanitize_pdf_bytes
from app.ledger import ChainOfCustodyLedger
from app.pdf_inspector import inspect_pdf_bytes
from app.sandbox_vaccine import SandboxVaccineEngine

app = FastAPI(title="SandiSeal — Zero-Trust Document & BSrE Integrity Shield")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SANITIZED_DIR = DATA_DIR / "sanitized"
SANITIZED_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

ledger = ChainOfCustodyLedger(db_path=str(DATA_DIR / "ledger.db"))
sandbox_engine = SandboxVaccineEngine(base_dir=str(DATA_DIR))


def _process_document(
    raw_bytes: bytes,
    filename: str,
    source_unit: str,
    target_unit: str,
) -> dict:
    active_vaccines = sandbox_engine.get_active_vaccines()
    inspection = inspect_pdf_bytes(raw_bytes, filename, active_vaccine_patterns=active_vaccines)

    if inspection.verdict == "CLEAN":
        cdr_result = sanitize_pdf_bytes(
            raw_bytes=raw_bytes,
            filename=filename,
            output_dir=SANITIZED_DIR,
        )
        block = ledger.append_block(
            filename=filename,
            raw_bytes=raw_bytes,
            source_unit=source_unit,
            target_unit=target_unit,
            bsre_status="BSrE ByteRange Utuh",
            verdict="CLEAN -> Diteruskan ke Pusat",
        )
        return {
            "sender_view": {
                "status": "200 OK",
                "message": f"Dokumen {filename} berhasil dikirim dari {source_unit} ke {target_unit}.",
            },
            "soc_view": {
                "verdict": "CLEAN",
                "details": inspection.__dict__,
                "cdr": {
                    "sanitized_filename": cdr_result.sanitized_filename,
                    "sanitized_sha256": cdr_result.sanitized_sha256,
                    "page_count": cdr_result.page_count,
                    "removed_elements": cdr_result.removed_elements,
                    "download_url": f"/api/download/sanitized/{cdr_result.sanitized_filename}",
                },
                "ledger_block": block,
            },
        }

    # Jalur INFECTED: Stealth Auto-Sandbox (Plasebo) + Vaksin YARA
    ledger.append_block(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=source_unit,
        target_unit=target_unit,
        bsre_status="ANOMALI / SHADOW UPDATE" if not inspection.byterange_valid else "SIGNED MALWARE",
        verdict="DIVERTED TO AUTO-SANDBOX",
    )
    sandbox_event = sandbox_engine.detonate_and_vaccinate(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=source_unit,
        inspection_reasons=inspection.reasons,
        dangerous_tags=inspection.dangerous_tags_found,
    )
    return {
        # Pelaku / pengirim tetap melihat respons normal (Plasebo)
        "sender_view": {
            "status": "200 OK",
            "message": f"Dokumen {filename} berhasil dikirim dari {source_unit} ke {target_unit}.",
        },
        "soc_view": {
            "verdict": "INFECTED_SANDBOXED",
            "details": inspection.__dict__,
            "sandbox_event": sandbox_event,
        },
    }


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "blocks": ledger.list_blocks(),
            "sandbox_events": sandbox_engine.get_sandbox_events(),
            "vaccines": sandbox_engine.get_active_vaccines(),
            "ledger_verification": ledger.verify_chain(),
        },
    )


@app.post("/api/upload")
async def upload_pdf(
    file: UploadFile = File(...),
    source_unit: str = Form("Kodim 0606/Kota Bogor"),
    target_unit: str = Form("Korem 061/Suryakencana -> PUSSIBERAD"),
):
    raw_bytes = await file.read()
    result = _process_document(raw_bytes, file.filename or "dokumen.pdf", source_unit, target_unit)
    return JSONResponse(result)


@app.post("/api/demo/reset")
async def reset_demo_data():
    ledger.reset()
    sandbox_engine.reset()
    if SANITIZED_DIR.exists():
        for f in SANITIZED_DIR.iterdir():
            if f.is_file():
                f.unlink()
    return JSONResponse(
        {
            "status": "ok",
            "message": "Data demo (ledger, sandbox, vaksin, dan hasil sanitasi CDR) berhasil dibersihkan.",
        }
    )


@app.post("/api/demo/{scenario}")
async def run_demo_scenario(scenario: str):
    demo_dir = BASE_DIR / "demo_samples"
    if scenario == "clean":
        target = demo_dir / "surat_dinas_bsre_bersih.pdf"
    elif scenario == "infected":
        target = demo_dir / "surat_dinas_bsre_terinfeksi.pdf"
    else:
        return JSONResponse({"error": "Skenario tidak dikenal"}, status_code=400)

    if not target.exists():
        return JSONResponse(
            {"error": f"File demo {target.name} belum dibuat. Jalankan script di demo_scripts/ terlebih dahulu."},
            status_code=404,
        )

    raw_bytes = target.read_bytes()
    result = _process_document(
        raw_bytes,
        target.name,
        "Kodim 0606/Kota Bogor",
        "Korem 061/Suryakencana -> Pusat",
    )
    return JSONResponse(result)


@app.get("/api/download/sanitized/{filename}")
async def download_sanitized_pdf(filename: str):
    safe_name = Path(filename).name
    target = (SANITIZED_DIR / safe_name).resolve()
    if not str(target).startswith(str(SANITIZED_DIR.resolve())) or not target.exists():
        return JSONResponse({"error": "File hasil sanitasi tidak ditemukan."}, status_code=404)
    return FileResponse(
        path=str(target),
        media_type="application/pdf",
        filename=safe_name,
    )


@app.get("/api/ledger/verify")
async def verify_ledger():
    return JSONResponse(ledger.verify_chain())


@app.get("/api/state")
async def get_state():
    return JSONResponse(
        {
            "blocks": ledger.list_blocks(),
            "sandbox_events": sandbox_engine.get_sandbox_events(),
            "vaccines": sandbox_engine.get_active_vaccines(),
            "ledger_verification": ledger.verify_chain(),
        }
    )
