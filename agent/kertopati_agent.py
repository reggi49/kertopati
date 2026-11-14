import argparse
import json
import mimetypes
import re
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.ai_analyst import analyze_threat_and_synthesize_vaccine


DEFAULT_AGENT_DIR = Path(__file__).resolve().parent


def _encode_multipart(
    fields: Dict[str, str],
    file_field: str,
    filename: str,
    file_bytes: bytes,
) -> tuple[bytes, str]:
    boundary = f"----KertopatiAgentBoundary{uuid.uuid4().hex}"
    parts: List[bytes] = []
    for k, v in fields.items():
        parts.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                f"{v}\r\n"
            ).encode("utf-8")
        )
    safe_filename = re.sub(r'["\r\n\\]', "_", filename)
    ctype = mimetypes.guess_type(safe_filename)[0] or "application/octet-stream"
    parts.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; filename="{safe_filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n"
        ).encode("utf-8")
        + file_bytes
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _http_post_multipart(
    url: str,
    fields: Dict[str, str],
    filename: str,
    file_bytes: bytes,
    timeout: float = 10.0,
) -> dict:
    body, content_type = _encode_multipart(fields, "file", filename, file_bytes)
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": content_type},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_json(url: str, payload: dict, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_agent_cycle(
    server_url: str = "http://127.0.0.1:8000",
    watch_dir: Path | None = None,
    clean_dir: Path | None = None,
    quarantine_dir: Path | None = None,
    source_unit: str = "E-Office Kertopati AI Agent",
    target_unit: str = "Korem 061/Suryakencana -> PUSSIBERAD",
    agent_id: str | None = None,
    upload_fn: Callable[[str, Dict[str, str], str, bytes], dict] | None = None,
    heartbeat_fn: Callable[[str, dict], dict] | None = None,
) -> dict:
    """
    Menjalankan 1 siklus Kertopati AI Agent:
    - Memindai watch_dir untuk file baru
    - Mengirim setiap file ke POST /api/upload
    - Memicu pipeline AI Threat Analyst (deobfuscation, MITRE ATT&CK, YARA + Sigma) untuk file berbahaya
    - Memindahkan file CLEAN ke clean_dir dan INFECTED ke quarantine_dir
    - Mengirim metrik AI Agent ke POST /api/agent/heartbeat
    """
    watch_path = Path(watch_dir or (DEFAULT_AGENT_DIR / "watch_inbox"))
    clean_path = Path(clean_dir or (DEFAULT_AGENT_DIR / "clean_outbox"))
    quarantine_path = Path(quarantine_dir or (DEFAULT_AGENT_DIR / "quarantine_local"))

    watch_path.mkdir(parents=True, exist_ok=True)
    clean_path.mkdir(parents=True, exist_ok=True)
    quarantine_path.mkdir(parents=True, exist_ok=True)

    uploader = upload_fn or _http_post_multipart
    heartbeater = heartbeat_fn or _http_post_json
    base_url = server_url.rstrip("/")

    files_audited = 0
    clean_count = 0
    infected_count = 0
    vaccines_generated = 0
    last_mitre_techniques: List[str] = []
    last_file = ""
    results: List[dict] = []

    for item in sorted(watch_path.iterdir()):
        if not item.is_file() or item.name.startswith("."):
            continue
        try:
            raw_bytes = item.read_bytes()
            resp = uploader(
                f"{base_url}/api/upload",
                {"source_unit": source_unit, "target_unit": target_unit},
                item.name,
                raw_bytes,
            )
            soc_view = resp.get("soc_view") or {}
            verdict = soc_view.get("verdict", "INFECTED_SANDBOXED")
            files_audited += 1
            last_file = item.name

            if verdict == "CLEAN":
                cdr_info = soc_view.get("cdr") or {}
                dl_url = cdr_info.get("download_url")
                wrote_cdr = False
                if dl_url and upload_fn is None:
                    try:
                        full_dl = dl_url if dl_url.startswith("http") else f"{base_url}{dl_url}"
                        with urllib.request.urlopen(full_dl, timeout=10.0) as dl_resp:
                            sanitized_bytes = dl_resp.read()
                        if sanitized_bytes:
                            (clean_path / item.name).write_bytes(sanitized_bytes)
                            item.unlink(missing_ok=True)
                            wrote_cdr = True
                    except Exception:
                        wrote_cdr = False
                if not wrote_cdr:
                    shutil.move(str(item), str(clean_path / item.name))
                clean_count += 1
                results.append({"filename": item.name, "verdict": verdict})
            else:
                shutil.move(str(item), str(quarantine_path / item.name))
                infected_count += 1
                sb_event = soc_view.get("sandbox_event") or {}
                ai_info = sb_event.get("ai_analysis")
                if not ai_info:
                    # Pastikan pipeline ai_analyst.py dipicu jika belum tersedia dari respons
                    details = soc_view.get("details") or {}
                    synthesis = analyze_threat_and_synthesize_vaccine(
                        filename=item.name,
                        raw_bytes=raw_bytes,
                        source_unit=source_unit,
                        file_format=str(details.get("file_format") or "UNKNOWN"),
                        inspection_reasons=list(sb_event.get("reasons") or details.get("reasons") or ["Malicious artifact detected"]),
                        dangerous_tags=list(details.get("dangerous_tags_found") or details.get("dangerous_tags") or []),
                    )
                    ai_info = synthesis.get("ai_analysis") or {}
                    vaccine_rule = synthesis.get("rule_name", "")
                else:
                    vaccine_rule = sb_event.get("generated_vaccine", "")

                if vaccine_rule or ai_info:
                    vaccines_generated += 1
                mitre_list = list(ai_info.get("mitre_attack") or [])
                if mitre_list:
                    last_mitre_techniques = mitre_list
                results.append(
                    {
                        "filename": item.name,
                        "verdict": verdict,
                        "vaccine_rule": vaccine_rule,
                        "mitre_attack": mitre_list,
                    }
                )
        except Exception as exc:
            results.append({"filename": item.name, "verdict": "ERROR", "error": str(exc)})

    hb_payload = {
        "agent_id": agent_id or f"kertopati-ai-agent-{socket.gethostname()}",
        "agent_name": "Kertopati AI Agent",
        "hostname": socket.gethostname(),
        "status": "ACTIVE",
        "files_audited": files_audited,
        "clean_count": clean_count,
        "infected_count": infected_count,
        "vaccines_generated": vaccines_generated,
        "last_mitre_techniques": last_mitre_techniques,
        "last_file": last_file,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        hb_resp = heartbeater(f"{base_url}/api/agent/heartbeat", hb_payload)
    except Exception as exc:
        hb_resp = {"error": str(exc)}

    return {
        "processed": results,
        "files_audited": files_audited,
        "clean_count": clean_count,
        "infected_count": infected_count,
        "vaccines_generated": vaccines_generated,
        "last_mitre_techniques": last_mitre_techniques,
        "heartbeat": hb_payload,
        "heartbeat_response": hb_resp,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Kertopati AI Agent (24/7 Autonomous Defense)")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000", help="URL server gateway Kertopati")
    parser.add_argument("--watch-dir", default=str(DEFAULT_AGENT_DIR / "watch_inbox"), help="Folder pantau masuk")
    parser.add_argument("--clean-dir", default=str(DEFAULT_AGENT_DIR / "clean_outbox"), help="Folder tujuan file bersih")
    parser.add_argument("--quarantine-dir", default=str(DEFAULT_AGENT_DIR / "quarantine_local"), help="Folder karantina lokal")
    parser.add_argument("--source-unit", default="E-Office Kodim 0606 (Kertopati AI Agent)")
    parser.add_argument("--target-unit", default="Korem 061/Suryakencana -> PUSSIBERAD")
    parser.add_argument("--interval", type=float, default=3.0, help="Interval polling daemon (detik)")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--once", action="store_true", help="Jalankan 1 siklus lalu berhenti")
    mode_group.add_argument("--daemon", action="store_true", help="Jalankan terus-menerus 24/7")
    args = parser.parse_args()

    run_once = args.once or not args.daemon
    if run_once:
        summary = run_agent_cycle(
            server_url=args.server_url,
            watch_dir=Path(args.watch_dir),
            clean_dir=Path(args.clean_dir),
            quarantine_dir=Path(args.quarantine_dir),
            source_unit=args.source_unit,
            target_unit=args.target_unit,
        )
        print(json.dumps(summary, indent=2))
        return

    print(f"[Kertopati AI Agent] Memantau {args.watch_dir} -> {args.server_url} (interval {args.interval}s)")
    while True:
        try:
            summary = run_agent_cycle(
                server_url=args.server_url,
                watch_dir=Path(args.watch_dir),
                clean_dir=Path(args.clean_dir),
                quarantine_dir=Path(args.quarantine_dir),
                source_unit=args.source_unit,
                target_unit=args.target_unit,
            )
            if summary["files_audited"] > 0:
                print(
                    f"[Kertopati AI Agent] Diaudit: {summary['files_audited']} file "
                    f"(Bersih={summary['clean_count']}, Terinfeksi={summary['infected_count']}, "
                    f"Vaksin AI={summary['vaccines_generated']})"
                )
        except Exception as exc:
            print(f"[Kertopati AI Agent] Peringatan koneksi: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
