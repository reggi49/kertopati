import hashlib
import json
import re
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.ai_analyst import analyze_threat_and_synthesize_vaccine, pre_triage_extract
from app.cdr_sanitizer import sanitize_document_bytes, sanitize_pdf_bytes
from app.ledger import ChainOfCustodyLedger
from app.multi_inspector import inspect_file_bytes
from app.real_sandbox import (
    close_sandbox_session,
    create_sandbox_session,
    exec_sandbox_command,
    execute_in_isolated_sandbox,
    get_sandbox_session,
)
from app.sandbox_vaccine import SandboxVaccineEngine
from app.simulator import (
    CVE_CATALOG,
    build_cve_sample,
    build_honeypot_attacker_view,
    build_without_kertopati_response,
)
from app.xray_inspector import build_xray_report

app = FastAPI(title="Kertopati — Zero-Trust Information Exchange Gateway")


class SandboxReviewRequest(BaseModel):
    decision: str
    note: str = ""


class SimulateRequest(BaseModel):
    cve_id: str
    protection_mode: str = "WITH_KERTOPATI"
    attacker_ip: str = "185.220.101.47"
    user_agent: str = "Mozilla/5.0 (RedTeam-Sim/2026)"


class SandboxExecRequest(BaseModel):
    command: str


class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    agent_name: str = "Kertopati AI Agent"
    hostname: str = "unknown-host"
    status: str = "ACTIVE"
    files_audited: int = 0
    clean_count: int = 0
    infected_count: int = 0
    vaccines_generated: int = 0
    last_mitre_techniques: List[str] = []
    last_file: str = ""
    timestamp: str = ""


class WebhookRegisterRequest(BaseModel):
    name: str
    url: str
    events: List[str] = ["INFECTED_SANDBOXED", "SIMULATE_INTERCEPTED", "LEDGER_TAMPERED"]

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SANITIZED_DIR = DATA_DIR / "sanitized"
SANITIZED_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

MEDIA_TYPES = {
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

ledger = ChainOfCustodyLedger(db_path=str(DATA_DIR / "ledger.db"))
sandbox_engine = SandboxVaccineEngine(base_dir=str(DATA_DIR))


def _sanitize_filename(filename: str | None) -> str:
    base = Path(filename or "dokumen.pdf").name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._")
    return cleaned or "dokumen.pdf"


def _runtime_dir() -> Path:
    return Path(sandbox_engine.quarantine_dir).parent


def _read_agent_status() -> dict:
    status_path = _runtime_dir() / "agent_status.json"
    default = {
        "status": "STANDBY",
        "agent_id": "belum-terhubung",
        "agent_name": "Kertopati AI Agent",
        "hostname": "-",
        "total_files_audited": 0,
        "total_clean": 0,
        "total_infected": 0,
        "vaccines_generated": 0,
        "last_mitre_techniques": [],
        "last_file": "",
        "last_heartbeat": "",
    }
    if not status_path.exists():
        return default
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
        last_hb = data.get("last_heartbeat")
        if last_hb:
            dt = datetime.fromisoformat(last_hb)
            age_sec = (datetime.now(timezone.utc) - dt).total_seconds()
            data["status"] = "ACTIVE" if age_sec <= 120 else "STANDBY"
        return {**default, **data}
    except Exception:
        return default


def _save_agent_status(hb: AgentHeartbeatRequest) -> dict:
    current = _read_agent_status()
    now_iso = hb.timestamp or datetime.now(timezone.utc).isoformat()
    updated = {
        "status": "ACTIVE",
        "agent_id": hb.agent_id,
        "agent_name": hb.agent_name or "Kertopati AI Agent",
        "hostname": hb.hostname,
        "total_files_audited": current.get("total_files_audited", 0) + max(hb.files_audited, 0),
        "total_clean": current.get("total_clean", 0) + max(hb.clean_count, 0),
        "total_infected": current.get("total_infected", 0) + max(hb.infected_count, 0),
        "vaccines_generated": current.get("vaccines_generated", 0) + max(hb.vaccines_generated, 0),
        "last_mitre_techniques": hb.last_mitre_techniques or current.get("last_mitre_techniques", []),
        "last_file": hb.last_file or current.get("last_file", ""),
        "last_heartbeat": now_iso,
    }
    status_path = _runtime_dir() / "agent_status.json"
    status_path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
    return updated


def _read_webhooks() -> List[dict]:
    path = _runtime_dir() / "webhooks.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _read_webhook_events() -> List[dict]:
    path = _runtime_dir() / "webhook_events.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _dispatch_webhook_alert(event_type: str, payload: dict) -> None:
    webhooks = _read_webhooks()
    events = _read_webhook_events()
    deliveries: List[dict] = []
    for wh in webhooks:
        if event_type not in (wh.get("events") or [event_type]):
            continue
        delivery_status = "QUEUED_AIRGAPPED"
        url = wh.get("url", "")
        if url.startswith(("http://", "https://")) and "example.local" not in url:
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps({"event": event_type, "payload": payload}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    delivery_status = f"DELIVERED ({resp.status})"
            except Exception:
                delivery_status = "QUEUED_OFFLINE"
        deliveries.append({"webhook": wh.get("name"), "url": url, "status": delivery_status})

    events.insert(
        0,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "deliveries": deliveries,
        },
    )
    (_runtime_dir() / "webhook_events.json").write_text(json.dumps(events[:50], indent=2), encoding="utf-8")


def _process_document(
    raw_bytes: bytes,
    filename: str,
    source_unit: str,
    target_unit: str,
) -> dict:
    active_vaccines = sandbox_engine.get_enabled_vaccines()
    inspection = inspect_file_bytes(raw_bytes, filename, active_vaccine_patterns=active_vaccines)

    if inspection.verdict == "CLEAN":
        cdr_result = sanitize_document_bytes(
            raw_bytes=raw_bytes,
            filename=filename,
            file_format=inspection.file_format,
            output_dir=SANITIZED_DIR,
        )
        integrity_label = (
            "BSrE ByteRange Utuh"
            if inspection.file_format == "PDF"
            else f"{inspection.file_format} Steril (CDR)"
        )
        block = ledger.append_block(
            filename=filename,
            raw_bytes=raw_bytes,
            source_unit=source_unit,
            target_unit=target_unit,
            bsre_status=integrity_label,
            verdict="CLEAN -> Diteruskan ke Pusat",
            file_format=inspection.file_format,
        )
        return {
            "sender_view": {
                "status": "200 OK",
                "message": f"Dokumen {filename} berhasil dikirim dari {source_unit} ke {target_unit}.",
            },
            "soc_view": {
                "verdict": "CLEAN",
                "details": inspection.details,
                "cdr": {
                    "sanitized_filename": cdr_result.sanitized_filename,
                    "sanitized_sha256": cdr_result.sanitized_sha256,
                    "original_size_bytes": len(raw_bytes),
                    "sanitized_size_bytes": len(cdr_result.sanitized_bytes),
                    "page_count": cdr_result.page_count,
                    "removed_elements": cdr_result.removed_elements,
                    "stripped_elements": (
                        ", ".join(cdr_result.removed_elements)
                        if cdr_result.removed_elements
                        else "Metadata & struktur diverifikasi steril"
                    ),
                    "download_url": f"/api/download/sanitized/{cdr_result.sanitized_filename}",
                },
                "ledger_block": block,
            },
        }

    # Jalur INFECTED: Stealth Auto-Sandbox (Plasebo) + Vaksin YARA
    if not inspection.magic_bytes_valid:
        bsre_status = "FAKE FILE / MAGIC BYTES MISMATCH"
    elif inspection.file_format == "PDF":
        bsre_status = (
            "ANOMALI / SHADOW UPDATE"
            if not inspection.details.get("byterange_valid", True)
            else "SIGNED MALWARE / OCG"
        )
    else:
        bsre_status = f"{inspection.file_format} POLYGLOT / MACRO TERDETEKSI"

    ledger.append_block(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=source_unit,
        target_unit=target_unit,
        bsre_status=bsre_status,
        verdict="DIVERTED TO AUTO-SANDBOX",
        file_format=inspection.file_format,
    )
    sandbox_event = sandbox_engine.detonate_and_vaccinate(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=source_unit,
        inspection_reasons=inspection.reasons,
        dangerous_tags=inspection.dangerous_tags_found,
        file_format=inspection.file_format,
    )
    _dispatch_webhook_alert(
        "INFECTED_SANDBOXED",
        {
            "filename": filename,
            "source_unit": source_unit,
            "file_format": inspection.file_format,
            "generated_vaccine": sandbox_event.get("generated_vaccine"),
            "reasons": inspection.reasons,
        },
    )
    return {
        # Pelaku / pengirim tetap melihat respons normal (Plasebo)
        "sender_view": {
            "status": "200 OK",
            "message": f"Dokumen {filename} berhasil dikirim dari {source_unit} ke {target_unit}.",
        },
        "soc_view": {
            "verdict": "INFECTED_SANDBOXED",
            "details": inspection.details,
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
            "agent_status": _read_agent_status(),
            "cve_catalog": CVE_CATALOG,
        },
    )


@app.post("/api/upload")
async def upload_pdf(
    file: UploadFile = File(...),
    source_unit: str = Form("Kodim 0606/Kota Bogor"),
    target_unit: str = Form("Korem 061/Suryakencana -> PUSSIBERAD"),
):
    safe_filename = _sanitize_filename(file.filename)
    raw_bytes = await file.read()

    if len(raw_bytes) > MAX_UPLOAD_SIZE_BYTES:
        return JSONResponse(
            {"error": "Ukuran file melebihi batas maksimal 10 MB."},
            status_code=413,
        )

    result = _process_document(raw_bytes, safe_filename, source_unit, target_unit)
    return JSONResponse(result)


@app.post("/api/demo/reset")
async def reset_demo_data():
    ledger.reset()
    sandbox_engine.reset()
    for fname in ("agent_status.json", "webhook_events.json"):
        p = _runtime_dir() / fname
        if p.exists():
            p.unlink()
    if SANITIZED_DIR.exists():
        for f in SANITIZED_DIR.iterdir():
            if f.is_file():
                f.unlink()
    # Also clean up active range investigations and sandbox sessions on reset
    for inv in list(_RANGE_INVESTIGATIONS.values()):
        if inv.get("sandbox_session_id"):
            close_sandbox_session(inv["sandbox_session_id"])
    _RANGE_INVESTIGATIONS.clear()
    return JSONResponse(
        {
            "status": "ok",
            "message": "Data demo (ledger, sandbox, vaksin, dan hasil sanitasi CDR) berhasil dibersihkan.",
        }
    )


@app.post("/api/demo/multihop")
async def run_multihop_demo():
    demo_file = BASE_DIR / "demo_samples" / "surat_dinas_bsre_bersih.pdf"
    if not demo_file.exists():
        return JSONResponse(
            {"error": "File demo surat_dinas_bsre_bersih.pdf belum dibuat."},
            status_code=404,
        )

    raw_bytes = demo_file.read_bytes()
    cdr_result = sanitize_pdf_bytes(
        raw_bytes=raw_bytes,
        filename=demo_file.name,
        output_dir=SANITIZED_DIR,
    )

    hop1 = ledger.append_block(
        filename=demo_file.name,
        raw_bytes=raw_bytes,
        source_unit="Kodim 0606/Kota Bogor",
        target_unit="Korem 061/Suryakencana",
        bsre_status="BSrE ByteRange Utuh",
        verdict="CLEAN -> Diteruskan ke Korem",
        file_format="PDF",
    )
    hop2 = ledger.append_block(
        filename=cdr_result.sanitized_filename,
        raw_bytes=cdr_result.sanitized_bytes,
        source_unit="Korem 061/Suryakencana",
        target_unit="PUSSIBERAD Pusat",
        bsre_status="BSrE ByteRange Utuh (CDR Steril)",
        verdict="CLEAN -> Diteruskan ke Pusat",
        file_format="PDF",
    )
    hop3 = ledger.append_block(
        filename=cdr_result.sanitized_filename,
        raw_bytes=cdr_result.sanitized_bytes,
        source_unit="PUSSIBERAD Pusat",
        target_unit="Arsip Komando Pusat",
        bsre_status="BSrE Terverifikasi Pusat",
        verdict="CLEAN -> Diterima & Diverifikasi Pusat",
        file_format="PDF",
    )

    return JSONResponse(
        {
            "sender_view": {
                "status": "200 OK",
                "message": f"Dokumen {demo_file.name} selesai dikirim berjenjang (3-Hop: Kodim -> Korem -> Pusat).",
            },
            "soc_view": {
                "verdict": "CLEAN",
                "multihop_blocks": [hop1, hop2, hop3],
                "cdr": {
                    "sanitized_filename": cdr_result.sanitized_filename,
                    "sanitized_sha256": cdr_result.sanitized_sha256,
                    "original_size_bytes": len(raw_bytes),
                    "sanitized_size_bytes": len(cdr_result.sanitized_bytes),
                    "page_count": cdr_result.page_count,
                    "removed_elements": cdr_result.removed_elements,
                    "stripped_elements": (
                        ", ".join(cdr_result.removed_elements)
                        if cdr_result.removed_elements
                        else "Metadata & struktur diverifikasi steril"
                    ),
                    "download_url": f"/api/download/sanitized/{cdr_result.sanitized_filename}",
                },
                "ledger_verification": ledger.verify_chain(),
            },
        }
    )


@app.post("/api/demo/tamper")
async def run_tamper_demo():
    tamper_res = ledger.simulate_tamper()
    if "error" in tamper_res:
        return JSONResponse(tamper_res, status_code=400)
    return JSONResponse(
        {
            "sender_view": {
                "status": "ALERT",
                "message": "Simulasi manipulasi paksa pada database ledger di Korem dijalankan.",
            },
            "soc_view": {
                "verdict": "TAMPERED",
                **tamper_res,
            },
        }
    )


@app.post("/api/demo/{scenario}")
async def run_demo_scenario(scenario: str):
    demo_dir = BASE_DIR / "demo_samples"
    scenario_map = {
        "clean": "surat_dinas_bsre_bersih.pdf",
        "infected": "surat_dinas_bsre_terinfeksi.pdf",
        "jpeg_polyglot": "laporan_lapangan_polyglot.jpg",
        "docx_macro": "rekap_anggaran_macro.docx",
    }
    if scenario not in scenario_map:
        return JSONResponse({"error": "Skenario tidak dikenal"}, status_code=400)

    target = demo_dir / scenario_map[scenario]
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
    media_type = MEDIA_TYPES.get(target.suffix.lower(), "application/octet-stream")
    return FileResponse(
        path=str(target),
        media_type=media_type,
        filename=safe_name,
    )


@app.get("/api/ledger/verify")
async def verify_ledger():
    return JSONResponse(ledger.verify_chain())


@app.post("/api/sandbox/{sha256_prefix}/review")
async def review_sandbox_event(sha256_prefix: str, payload: SandboxReviewRequest):
    event = sandbox_engine.get_event_by_prefix(sha256_prefix)
    if event is None:
        return JSONResponse({"error": "Event sandbox tidak ditemukan."}, status_code=404)

    q_name = event.get("quarantine_file") or f"{sha256_prefix}_{Path(event['filename']).name}"
    q_path = sandbox_engine.quarantine_dir / q_name
    raw_bytes = q_path.read_bytes() if q_path.exists() else event["filename"].encode("utf-8")
    fmt = event.get("file_format", "PDF")

    if payload.decision == "CONFIRMED_COMPROMISED":
        note = payload.note or "Dikonfirmasi oleh SOC: Perangkat satuan asal terindikasi kompromi. Vaksin YARA tetap aktif."
        updated = sandbox_engine.update_event_hitl(
            sha256_prefix=sha256_prefix,
            hitl_status="PERANGKAT_TERINFEKSI",
            hitl_note=note,
        )
        block = ledger.append_block(
            filename=event["filename"],
            raw_bytes=raw_bytes,
            source_unit=event["source_unit"],
            target_unit="SOC PUSSIBERAD (HITL)",
            bsre_status="HITL: PERANGKAT TERINFEKSI",
            verdict="PERANGKAT_TERINFEKSI -> Isolasi Satuan",
            file_format=fmt,
        )
        return JSONResponse({"status": "ok", "event": updated, "ledger_block": block})

    if payload.decision == "HUMAN_ERROR_RELEASE_CDR":
        if fmt == "UNKNOWN":
            return JSONResponse(
                {"error": "File dengan format tidak dikenal/palsu tidak dapat disterilkan via CDR."},
                status_code=400,
            )
        try:
            cdr_res = sanitize_document_bytes(
                raw_bytes=raw_bytes,
                filename=event["filename"],
                file_format=fmt,
                output_dir=SANITIZED_DIR,
            )
        except Exception as exc:
            return JSONResponse(
                {"error": f"Gagal melakukan CDR pada file karantina: {exc}"},
                status_code=400,
            )

        dl_url = f"/api/download/sanitized/{cdr_res.sanitized_filename}"
        note = payload.note or "Kelalaian pengguna: File disterilkan via CDR dan dirilis untuk diteruskan."
        updated = sandbox_engine.update_event_hitl(
            sha256_prefix=sha256_prefix,
            hitl_status="KELALAIAN_PENGGUNA",
            hitl_note=note,
            sanitized_download_url=dl_url,
        )
        block = ledger.append_block(
            filename=cdr_res.sanitized_filename,
            raw_bytes=cdr_res.sanitized_bytes,
            source_unit=event["source_unit"],
            target_unit="PUSSIBERAD Pusat (HITL CDR Release)",
            bsre_status="HITL: CDR STERIL DIRILIS",
            verdict="CLEAN -> Rilis Versi CDR (Kelalaian User)",
            file_format=fmt,
        )
        return JSONResponse(
            {
                "status": "ok",
                "event": updated,
                "ledger_block": block,
                "cdr": {
                    "sanitized_filename": cdr_res.sanitized_filename,
                    "original_size_bytes": len(raw_bytes),
                    "sanitized_size_bytes": len(cdr_res.sanitized_bytes),
                    "removed_elements": cdr_res.removed_elements,
                    "download_url": dl_url,
                },
            }
        )

    return JSONResponse({"error": "Keputusan HITL tidak valid."}, status_code=400)


@app.patch("/api/vaccines/{rule_name}/toggle")
async def toggle_vaccine(rule_name: str):
    updated = sandbox_engine.toggle_vaccine(rule_name)
    if updated is None:
        return JSONResponse({"error": f"Vaksin {rule_name} tidak ditemukan."}, status_code=404)
    return JSONResponse({"status": "ok", "vaccine": updated})


@app.get("/api/vaccines/export")
async def export_vaccines():
    bundle = sandbox_engine.export_vaccines()
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": 'attachment; filename="sandiseal_vaccines_bundle.json"'},
    )


@app.post("/api/vaccines/import")
async def import_vaccines(request: Request):
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            return JSONResponse({"error": "File bundle tidak ditemukan."}, status_code=400)
        raw = await upload.read()
        bundle = json.loads(raw.decode("utf-8"))
    else:
        bundle = await request.json()

    try:
        res = sandbox_engine.import_vaccines(bundle)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    return JSONResponse({"status": "ok", **res})


_RANGE_INVESTIGATIONS: Dict[str, dict] = {}


@app.post("/api/range/start")
async def range_start_investigation(payload: SimulateRequest, request: Request):
    """Tahap 1: Mengirim & mengekstrak telemetri awal artifak serangan tanpa auto-selesai."""
    demo_dir = BASE_DIR / "demo_samples"
    try:
        filename, raw_bytes, meta = build_cve_sample(payload.cve_id, demo_samples_dir=demo_dir)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    if payload.protection_mode not in ("WITH_KERTOPATI", "WITHOUT_KERTOPATI"):
        return JSONResponse({"error": "protection_mode harus WITHOUT_KERTOPATI atau WITH_KERTOPATI"}, status_code=400)

    inv_id = uuid.uuid4().hex[:10]
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    attacker_ip = payload.attacker_ip or (request.client.host if request.client else "185.220.101.47")
    user_agent = payload.user_agent or request.headers.get("user-agent", "RedTeam-Sim/2026")
    header_hex = " ".join(f"{b:02X}" for b in raw_bytes[:32])
    header_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:32])

    inv = {
        "inv_id": inv_id,
        "cve_id": payload.cve_id,
        "cve_title": meta["title"],
        "cve_description": meta["description"],
        "protection_mode": payload.protection_mode,
        "filename": filename,
        "raw_bytes": raw_bytes,
        "sha256": sha256,
        "sha256_prefix": sha256[:12],
        "size_bytes": len(raw_bytes),
        "attacker_ip": attacker_ip,
        "user_agent": user_agent,
        "current_step": 1,
        "sandbox_session_id": None,
        "inspection": None,
        "ai_result": None,
    }
    _RANGE_INVESTIGATIONS[inv_id] = inv

    return JSONResponse(
        {
            "inv_id": inv_id,
            "current_step": 1,
            "cve_id": payload.cve_id,
            "cve_title": meta["title"],
            "cve_description": meta["description"],
            "protection_mode": payload.protection_mode,
            "artifact": {
                "filename": filename,
                "size_bytes": len(raw_bytes),
                "sha256": sha256,
                "sha256_prefix": sha256[:12],
                "header_hex": header_hex,
                "header_ascii": header_ascii,
                "attacker_ip": attacker_ip,
                "user_agent": user_agent,
            },
            "next_step": "audit",
        }
    )


@app.post("/api/range/start-upload")
async def range_start_upload_investigation(
    request: Request,
    file: UploadFile = File(...),
    protection_mode: str = Form("WITH_KERTOPATI"),
):
    """Tahap 1 (Upload Custom): Mengirim dokumen nyata ke misi Cyber Range mulai dari pengiriman file."""
    if protection_mode not in ("WITH_KERTOPATI", "WITHOUT_KERTOPATI"):
        return JSONResponse({"error": "protection_mode harus WITHOUT_KERTOPATI atau WITH_KERTOPATI"}, status_code=400)

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_SIZE_BYTES:
        return JSONResponse({"error": "Ukuran file melebihi batas maksimal 10 MB."}, status_code=413)

    filename = Path(file.filename or "dokumen_uji.bin").name
    inv_id = uuid.uuid4().hex[:10]
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    attacker_ip = request.client.host if request.client else "185.220.101.47"
    user_agent = request.headers.get("user-agent", "Operator-Web-Uploader/2026")
    header_hex = " ".join(f"{b:02X}" for b in raw_bytes[:32])
    header_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:32])

    inv = {
        "inv_id": inv_id,
        "cve_id": "CUSTOM-UPLOAD",
        "cve_title": f"Dokumen Unggahan Operator ({filename})",
        "cve_description": "Inspeksi dokumen nyata unggahan pengguna melalui alur Gateway -> Audit/CDR -> Live Docker Container.",
        "protection_mode": protection_mode,
        "filename": filename,
        "raw_bytes": raw_bytes,
        "sha256": sha256,
        "sha256_prefix": sha256[:12],
        "size_bytes": len(raw_bytes),
        "attacker_ip": attacker_ip,
        "user_agent": user_agent,
        "current_step": 1,
        "sandbox_session_id": None,
        "inspection": None,
        "ai_result": None,
    }
    _RANGE_INVESTIGATIONS[inv_id] = inv

    return JSONResponse(
        {
            "inv_id": inv_id,
            "current_step": 1,
            "cve_id": "CUSTOM-UPLOAD",
            "cve_title": inv["cve_title"],
            "cve_description": inv["cve_description"],
            "protection_mode": protection_mode,
            "artifact": {
                "filename": filename,
                "size_bytes": len(raw_bytes),
                "sha256": sha256,
                "sha256_prefix": sha256[:12],
                "header_hex": header_hex,
                "header_ascii": header_ascii,
                "attacker_ip": attacker_ip,
                "user_agent": user_agent,
            },
            "next_step": "audit",
        }
    )


@app.post("/api/range/{inv_id}/step/audit")
async def range_step_audit(inv_id: str):
    """Tahap 2: Audit Struktural, Magic Bytes, /ByteRange, OCG, Macro & CDR nyata."""
    inv = _RANGE_INVESTIGATIONS.get(inv_id)
    if not inv:
        return JSONResponse({"error": "Sesi investigasi tidak ditemukan."}, status_code=404)

    raw_bytes: bytes = inv["raw_bytes"]
    filename: str = inv["filename"]

    if inv["protection_mode"] == "WITHOUT_KERTOPATI":
        resp = build_without_kertopati_response(
            cve_id=inv["cve_id"] if inv["cve_id"] in ("CVE-2026-91814", "CVE-2026-6361", "CVE-2025-59802", "JPEG-POLYGLOT", "DOCX-MACRO") else "CVE-2026-91814",
            filename=filename,
            raw_bytes=raw_bytes,
            meta={"title": inv["cve_title"]},
            attacker_ip=inv["attacker_ip"],
            user_agent=inv["user_agent"],
        )
        if inv.get("sandbox_session_id"):
            close_sandbox_session(inv["sandbox_session_id"])
        vuln_sbx = create_sandbox_session(
            raw_bytes=raw_bytes,
            filename=filename,
            cve_id=inv["cve_id"],
            mode="vulnerable",
        )
        inv["sandbox_session_id"] = vuln_sbx["session_id"]
        inv["current_step"] = 2
        return JSONResponse(
            {
                "inv_id": inv_id,
                "current_step": 2,
                "failed_at_step": 2,
                "vulnerable_terminal_ready": True,
                "sandbox_session": vuln_sbx,
                **resp,
            }
        )

    inspection = inspect_file_bytes(
        raw_bytes,
        filename,
        active_vaccine_patterns=sandbox_engine.get_enabled_vaccines(),
    )
    inv["inspection"] = inspection
    inv["current_step"] = 2

    return JSONResponse(
        {
            "inv_id": inv_id,
            "current_step": 2,
            "protection_mode": "WITH_KERTOPATI",
            "audit": {
                "verdict": inspection.verdict,
                "file_format": inspection.file_format,
                "magic_bytes_valid": inspection.magic_bytes_valid,
                "dangerous_tags_found": inspection.dangerous_tags_found,
                "reasons": inspection.reasons,
                "details": inspection.details,
                "cdr_action": (
                    "DITAHAN — Dialihkan senyap ke Sandbox Terisolasi (Plasebo) sebelum dikirim ke tujuan"
                    if inspection.verdict != "CLEAN"
                    else "AMAN — Disanitasi CDR sebelum dikirim"
                ),
            },
            "next_step": "sandbox",
        }
    )


@app.post("/api/range/{inv_id}/step/sandbox")
async def range_step_sandbox(inv_id: str):
    """Tahap 3: Memulai container/sandbox terisolasi nyata dan membuka terminal interaktif."""
    inv = _RANGE_INVESTIGATIONS.get(inv_id)
    if not inv:
        return JSONResponse({"error": "Sesi investigasi tidak ditemukan."}, status_code=404)

    raw_bytes: bytes = inv["raw_bytes"]
    filename: str = inv["filename"]
    sha_prefix: str = inv["sha256_prefix"]

    # Simpan artefak ke direktori karantina agar tombol Bedah X-Ray langsung berfungsi di Tahap 3
    q_path = sandbox_engine.quarantine_dir / f"{sha_prefix}_{Path(filename).name}"
    q_path.write_bytes(raw_bytes)

    if inv.get("sandbox_session_id"):
        close_sandbox_session(inv["sandbox_session_id"])

    sbx_session = create_sandbox_session(
        raw_bytes=raw_bytes,
        filename=filename,
        cve_id=inv["cve_id"],
    )
    inv["sandbox_session_id"] = sbx_session["session_id"]
    inv["current_step"] = 3

    return JSONResponse(
        {
            "inv_id": inv_id,
            "current_step": 3,
            "sha256_prefix": sha_prefix,
            "xray_url": f"/api/xray/{sha_prefix}",
            "attacker_view": {
                "status": "200 OK (PLASEBO HONEYPOT AKTIF)",
                "message": f"Pelaku melihat antrean normal sementara sesi diarahkan ke {sbx_session['execution_backend']}.",
            },
            "sandbox_session": sbx_session,
            "next_step": "ai_analyze",
        }
    )


@app.post("/api/range/{inv_id}/sandbox/exec")
async def range_sandbox_exec(inv_id: str, payload: SandboxExecRequest):
    """Eksekusi perintah Linux stateful (cd, ls, pwd, dll.) di dalam container/sandbox sesi investigasi aktif."""
    inv = _RANGE_INVESTIGATIONS.get(inv_id)
    if not inv or not inv.get("sandbox_session_id"):
        return JSONResponse({"error": "Belum ada sesi container/sandbox aktif untuk investigasi ini."}, status_code=404)

    try:
        res = exec_sandbox_command(inv["sandbox_session_id"], payload.command)
        session = get_sandbox_session(inv["sandbox_session_id"])
    except (KeyError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    return JSONResponse(
        {
            "inv_id": inv_id,
            "result": res,
            "command_history": session["command_history"],
            "container_id": session["container_id"],
            "container_name": session.get("container_name"),
            "execution_backend": session["execution_backend"],
            "cwd": session.get("cwd", "/decoy_satuan"),
            "prompt_user": session.get("prompt_user", "nobody"),
            "mode": session.get("mode", "plasebo"),
            "docker_proof": session.get("docker_proof", {}),
        }
    )


@app.get("/api/range/{inv_id}/sandbox/status")
async def range_sandbox_status(inv_id: str):
    """Mengembalikan telemetri `docker inspect` nyata dari container aktif untuk verifikasi anti-hardcode."""
    inv = _RANGE_INVESTIGATIONS.get(inv_id)
    if not inv or not inv.get("sandbox_session_id"):
        return JSONResponse({"error": "Belum ada sesi container/sandbox aktif untuk investigasi ini."}, status_code=404)

    try:
        session = get_sandbox_session(inv["sandbox_session_id"], refresh_docker_proof=True)
    except KeyError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

    return JSONResponse(
        {
            "inv_id": inv_id,
            "active": session["active"],
            "mode": session.get("mode", "plasebo"),
            "execution_backend": session["execution_backend"],
            "container_id": session["container_id"],
            "container_name": session.get("container_name"),
            "cwd": session.get("cwd"),
            "prompt_user": session.get("prompt_user"),
            "isolation_flags": session["isolation_flags"],
            "docker_proof": session.get("docker_proof", {}),
            "decoy_files": session.get("decoy_files", []),
        }
    )


@app.post("/api/range/{inv_id}/step/ai-analyze")
async def range_step_ai_analyze(inv_id: str):
    """Tahap 4: Menjalankan 3-Tahap Kertopati AI Threat Analyst secara nyata (Pre-Triage, AI+MITRE+YARA/Sigma, ABLE Validation)."""
    inv = _RANGE_INVESTIGATIONS.get(inv_id)
    if not inv:
        return JSONResponse({"error": "Sesi investigasi tidak ditemukan."}, status_code=404)

    raw_bytes: bytes = inv["raw_bytes"]
    filename: str = inv["filename"]
    inspection = inv.get("inspection") or inspect_file_bytes(raw_bytes, filename)
    inv["inspection"] = inspection

    # Tahap 1 AI Analyst: Pre-Triage & Deobfuscation + Anti-Prompt-Injection
    stage1_pre_triage = pre_triage_extract(raw_bytes, inspection.dangerous_tags_found)

    # Siapkan baseline sampel bersih dari demo_samples untuk ABLE Self-Validation Gate
    clean_baselines: List[bytes] = []
    demo_dir = BASE_DIR / "demo_samples"
    if demo_dir.exists():
        for sample_path in demo_dir.iterdir():
            if sample_path.is_file() and "bersih" in sample_path.name.lower():
                clean_baselines.append(sample_path.read_bytes())

    # Tahap 2 & 3 AI Analyst: MITRE ATT&CK, YARA + Sigma, dan ABLE Gate nyata
    synthesis = analyze_threat_and_synthesize_vaccine(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=f"Simulasi RedTeam ({inv['cve_id']})",
        file_format=inspection.file_format,
        inspection_reasons=inspection.reasons,
        dangerous_tags=inspection.dangerous_tags_found,
        clean_baselines=clean_baselines,
    )
    inv["ai_result"] = synthesis
    inv["current_step"] = 4

    honeypot_cmds: List[str] = []
    if inv.get("sandbox_session_id"):
        try:
            sess = get_sandbox_session(inv["sandbox_session_id"])
            honeypot_cmds = [c["command"] for c in sess.get("command_history", [])]
        except KeyError:
            pass

    ai = synthesis["ai_analysis"]
    return JSONResponse(
        {
            "inv_id": inv_id,
            "current_step": 4,
            "stage1_pre_triage": stage1_pre_triage,
            "stage2_ai_synthesis": {
                "analysis_mode": ai.get("analysis_mode"),
                "severity": ai.get("severity"),
                "mitre_attack": ai.get("mitre_attack", []),
                "commander_brief": ai.get("commander_brief", ""),
                "rule_name": synthesis["rule_name"],
                "primary_ioc": synthesis["primary_ioc"],
                "yara_rule": synthesis["yara_rule"],
                "sigma_network_rule": ai.get("sigma_network_rule", ""),
            },
            "stage3_able_validation": {
                "validation_status": ai.get("validation_status"),
                "recall_test": ai.get("recall_test"),
                "false_positive_test": ai.get("false_positive_test"),
                "clean_baselines_tested": len(clean_baselines),
            },
            "honeypot_commands_captured": honeypot_cmds,
            "next_step": "immunize",
        }
    )


@app.post("/api/range/{inv_id}/step/immunize")
async def range_step_immunize(inv_id: str):
    """Tahap 5: Menutup container sandbox, mencatat Ledger SHA-256, menerbitkan vaksin aktif, & verifikasi re-attack nyata."""
    inv = _RANGE_INVESTIGATIONS.get(inv_id)
    if not inv:
        return JSONResponse({"error": "Sesi investigasi tidak ditemukan."}, status_code=404)

    raw_bytes: bytes = inv["raw_bytes"]
    filename: str = inv["filename"]
    inspection = inv.get("inspection") or inspect_file_bytes(raw_bytes, filename)

    honeypot_cmds: List[str] = []
    sandbox_meta: dict = {}
    if inv.get("sandbox_session_id"):
        try:
            sess = get_sandbox_session(inv["sandbox_session_id"])
            honeypot_cmds = [c["command"] for c in sess.get("command_history", [])]
            sandbox_meta = {
                "container_id": sess["container_id"],
                "execution_backend": sess["execution_backend"],
                "isolation_flags": sess["isolation_flags"],
            }
        except KeyError:
            pass
        close_sandbox_session(inv["sandbox_session_id"])
        inv["sandbox_session_id"] = None

    ledger_block = ledger.append_block(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=f"Simulasi RedTeam ({inv['cve_id']})",
        target_unit="Korem 061/Suryakencana -> PUSSIBERAD",
        bsre_status=f"DIVERTED ({inv['cve_id']})",
        verdict="DIVERTED TO AUTO-SANDBOX",
        file_format=inspection.file_format,
    )
    sandbox_event = sandbox_engine.detonate_and_vaccinate(
        filename=filename,
        raw_bytes=raw_bytes,
        source_unit=f"Simulasi RedTeam ({inv['cve_id']})",
        inspection_reasons=inspection.reasons,
        dangerous_tags=inspection.dangerous_tags_found,
        file_format=inspection.file_format,
    )

    # Update metrik Kertopati AI Agent secara nyata
    ai_info = sandbox_event.get("ai_analysis") or {}
    _save_agent_status(
        AgentHeartbeatRequest(
            agent_id="kertopati-ai-agent-soc",
            agent_name="Kertopati AI Agent",
            hostname="gateway-korem-061",
            status="ACTIVE",
            files_audited=1,
            clean_count=0,
            infected_count=1,
            vaccines_generated=1,
            last_mitre_techniques=list(ai_info.get("mitre_attack") or []),
            last_file=filename,
        )
    )

    immunized_units = {
        "Kodim 0606": "IMMUNIZED",
        "Korem 061": "IMMUNIZED",
        "Kodam III": "IMMUNIZED",
        "Mabesad": "IMMUNIZED",
    }
    _dispatch_webhook_alert(
        "SIMULATE_INTERCEPTED",
        {
            "cve_id": inv["cve_id"],
            "attacker_ip": inv["attacker_ip"],
            "sha256_prefix": inv["sha256_prefix"],
            "sandbox_meta": sandbox_meta,
            "honeypot_commands": honeypot_cmds,
            "immunized_units": immunized_units,
        },
    )

    # Verifikasi empiris nyata: kirim ulang byte yang sama melewati Policy Engine bervaksin
    retest = inspect_file_bytes(
        raw_bytes,
        filename,
        active_vaccine_patterns=sandbox_engine.get_enabled_vaccines(),
    )
    matched_vaccines = retest.details.get("matched_vaccines", [])
    inv["current_step"] = 5

    return JSONResponse(
        {
            "inv_id": inv_id,
            "current_step": 5,
            "server_status": "SANDBOXED_IMMUNIZED",
            "ledger_block": ledger_block,
            "sandbox_event": sandbox_event,
            "sandbox_meta": sandbox_meta,
            "honeypot_commands_captured": honeypot_cmds,
            "immunized_units": immunized_units,
            "immunity_verification": {
                "retest_verdict": retest.verdict,
                "blocked_by_vaccine": len(matched_vaccines) > 0,
                "matched_vaccines": matched_vaccines,
                "reasons": retest.reasons,
            },
        }
    )


@app.post("/api/simulate")
async def simulate_attack(payload: SimulateRequest, request: Request):
    demo_dir = BASE_DIR / "demo_samples"
    try:
        filename, raw_bytes, meta = build_cve_sample(payload.cve_id, demo_samples_dir=demo_dir)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    attacker_ip = payload.attacker_ip or (request.client.host if request.client else "185.220.101.47")
    user_agent = payload.user_agent or request.headers.get("user-agent", "RedTeam-Sim/2026")

    if payload.protection_mode == "WITHOUT_KERTOPATI":
        return JSONResponse(
            build_without_kertopati_response(
                cve_id=payload.cve_id,
                filename=filename,
                raw_bytes=raw_bytes,
                meta=meta,
                attacker_ip=attacker_ip,
                user_agent=user_agent,
            )
        )

    if payload.protection_mode != "WITH_KERTOPATI":
        return JSONResponse({"error": "protection_mode harus WITHOUT_KERTOPATI atau WITH_KERTOPATI"}, status_code=400)

    # WITH_KERTOPATI: Inspeksi nyata + Eksekusi Sandbox Terisolasi Nyata + AI Agent + Ledger + Webhook
    sandbox_exec = execute_in_isolated_sandbox(
        raw_bytes=raw_bytes,
        filename=filename,
        cve_id=payload.cve_id,
    )
    processed = _process_document(
        raw_bytes=raw_bytes,
        filename=filename,
        source_unit=f"Simulasi RedTeam ({payload.cve_id})",
        target_unit="Korem 061/Suryakencana -> PUSSIBERAD",
    )
    payload_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    forensic_telemetry = {
        "attacker_ip": attacker_ip,
        "user_agent": user_agent,
        "timestamp": ts,
        "payload_sha256": payload_sha256,
        "sha256_prefix": payload_sha256[:12],
        "execution_backend": sandbox_exec["execution_backend"],
        "container_id": sandbox_exec["container_id"],
        "isolation_flags": sandbox_exec["isolation_flags"],
        "exit_code": sandbox_exec["exit_code"],
        "duration_ms": sandbox_exec["duration_ms"],
        "sandbox_stdout": sandbox_exec["stdout"],
        "sandbox_stderr": sandbox_exec["stderr"],
        "honeypot_commands": sandbox_exec["executed_commands"],
    }
    immunized_units = {
        "Kodim 0606": "IMMUNIZED",
        "Korem 061": "IMMUNIZED",
        "Kodam III": "IMMUNIZED",
        "Mabesad": "IMMUNIZED",
    }
    _dispatch_webhook_alert(
        "SIMULATE_INTERCEPTED",
        {
            "cve_id": payload.cve_id,
            "attacker_ip": attacker_ip,
            "sha256_prefix": payload_sha256[:12],
            "container_id": sandbox_exec["container_id"],
            "execution_backend": sandbox_exec["execution_backend"],
            "immunized_units": immunized_units,
        },
    )

    soc_view = processed.get("soc_view", {})
    soc_view["server_status"] = "SANDBOXED_IMMUNIZED"
    soc_view["forensic_telemetry"] = forensic_telemetry
    soc_view["sandbox_execution"] = sandbox_exec
    soc_view["immunized_units"] = immunized_units

    sb_event = soc_view.get("sandbox_event") or {}
    ai_info = sb_event.get("ai_analysis") or {}
    _save_agent_status(
        AgentHeartbeatRequest(
            agent_id="kertopati-ai-agent-soc",
            agent_name="Kertopati AI Agent",
            hostname="gateway-korem-061",
            status="ACTIVE",
            files_audited=1,
            clean_count=0,
            infected_count=1,
            vaccines_generated=1 if sb_event.get("generated_vaccine") else 0,
            last_mitre_techniques=list(ai_info.get("mitre_attack") or []),
            last_file=filename,
        )
    )

    return JSONResponse(
        {
            "cve_id": payload.cve_id,
            "cve_title": meta["title"],
            "protection_mode": "WITH_KERTOPATI",
            "server_status": "SANDBOXED_IMMUNIZED",
            "sandbox_execution": sandbox_exec,
            "sender_view": processed.get("sender_view"),
            "attacker_view": build_honeypot_attacker_view(
                payload.cve_id,
                filename,
                sandbox_result=sandbox_exec,
            ),
            "soc_view": soc_view,
        }
    )


@app.get("/api/xray/{sha256_prefix}")
async def xray_quarantined_file(sha256_prefix: str):
    event = sandbox_engine.get_event_by_prefix(sha256_prefix)
    q_path = None
    filename = ""
    file_format = None

    if event is not None:
        q_name = event.get("quarantine_file") or f"{sha256_prefix}_{Path(event['filename']).name}"
        candidate = sandbox_engine.quarantine_dir / q_name
        if candidate.exists():
            q_path = candidate
            filename = event["filename"]
            file_format = event.get("file_format")

    if q_path is None:
        for p in sandbox_engine.quarantine_dir.iterdir():
            if p.is_file() and p.name.startswith(sha256_prefix):
                q_path = p
                filename = p.name.split("_", 1)[1] if "_" in p.name else p.name
                break

    if q_path is None or not q_path.exists():
        return JSONResponse({"error": f"Sampel karantina {sha256_prefix} tidak ditemukan."}, status_code=404)

    report = build_xray_report(q_path.read_bytes(), filename=filename, file_format=file_format)
    report["sha256_prefix"] = sha256_prefix
    return JSONResponse(report)


@app.post("/api/agent/heartbeat")
async def agent_heartbeat(payload: AgentHeartbeatRequest):
    updated = _save_agent_status(payload)
    return JSONResponse({"status": "ok", "agent": updated})


@app.get("/api/agent/status")
async def get_agent_status():
    return JSONResponse(_read_agent_status())


@app.post("/api/webhooks/register")
async def register_webhook(payload: WebhookRegisterRequest):
    webhooks = _read_webhooks()
    entry = {
        "name": payload.name,
        "url": payload.url,
        "events": payload.events,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    webhooks = [w for w in webhooks if w.get("url") != payload.url]
    webhooks.append(entry)
    (_runtime_dir() / "webhooks.json").write_text(json.dumps(webhooks, indent=2), encoding="utf-8")
    return JSONResponse({"status": "ok", "webhook": entry, "total_webhooks": len(webhooks)})


@app.get("/api/webhooks/events")
async def get_webhook_events():
    return JSONResponse(
        {
            "webhooks": _read_webhooks(),
            "events": _read_webhook_events(),
        }
    )


@app.get("/api/state")
async def get_state():
    return JSONResponse(
        {
            "blocks": ledger.list_blocks(),
            "sandbox_events": sandbox_engine.get_sandbox_events(),
            "vaccines": sandbox_engine.get_active_vaccines(),
            "ledger_verification": ledger.verify_chain(),
            "agent_status": _read_agent_status(),
        }
    )
