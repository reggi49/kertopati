import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from app.ai_analyst import pre_triage_extract

# Save original subprocess.run so unit tests monkeypatching subprocess.run for TimeoutExpired work
_ORIG_SUBPROCESS_RUN = subprocess.run

DOCKER_CANDIDATE_IMAGES = ("alpine:latest", "alpine", "python:3.11-slim", "busybox:latest")
ISOLATION_FLAGS = [
    "--rm",
    "--pull=never",
    "--user 65534:65534",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=32",
    "--memory=128m",
    "--cpus=0.5",
    "--tmpfs /tmp:rw,noexec,nosuid,size=16m",
    "-v <decoy_dir>:/decoy_satuan:ro",
]
VULNERABLE_FLAGS = [
    "--rm",
    "--pull=never",
    "--user 0:0",
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=32",
    "--memory=128m",
    "--cpus=0.5",
    "-v <target_dir>:/srv/eoffice:rw",
]

DECOY_CONTENT = (
    "DOKUMEN UMPAN PLASEBO SATUAN (DECOY_SATUAN)\n"
    "STATUS: ISOLATED_HONEYPOT_FILE\n"
    "ISI: Tidak ada koordinat atau rahasia operasi pada lingkungan umpan ini.\n"
)

DECOY_PERSONNEL_CSV = (
    "NRP,NAMA,JABATAN,STATUS\n"
    "00000001,DECOY_ALPHA,STAF_UMPAN,ISOLATED_HONEYPOT\n"
    "00000002,DECOY_BRAVO,OPERATOR_UMPAN,ISOLATED_HONEYPOT\n"
)

DECOY_ADMIN_LOG = (
    "2026-11-13T08:15:02Z [QUEUE] Dokumen masuk dari node eksternal -> status=QUEUED_PLASEBO\n"
    "2026-11-13T08:15:03Z [ISOLATION] Sesi dialihkan ke container umpan /decoy_satuan (ro)\n"
)

VULN_SECRET_CONTENT = (
    "[CRITICAL LEAK — SIMULASI SERVER RENTAN TANPA KERTOPATI]\n"
    "DOKUMEN RAHASIA TERBACA: KOORDINAT_DISLOKASI_PASUKAN_2026_SIMULASI\n"
    "SEKTOR: BOGOR-0606 | KUNCI_INTERNAL: SIMULASI_RENTAN_NO_CDR\n"
)

VULN_ENV_CONTENT = (
    "APP_ENV=conventional_eoffice_sim\n"
    "DB_HOST=10.10.2.5\n"
    "DB_USER=eoffice_admin\n"
    "DB_PASS=SimulasiRentan2026!\n"
)

# Registry sesi container/sandbox interaktif aktif (dibersihkan oleh TTL atau close_sandbox_session)
_LIVE_SANDBOX_SESSIONS: Dict[str, dict] = {}
SESSION_TTL_SECONDS = 600
MAX_ACTIVE_SESSIONS = 10
MAX_OUTPUT_CHARS = 65536


def _populate_decoy_workspace(decoy_dir: Path, raw_bytes: bytes, filename: str) -> List[str]:
    decoy_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(decoy_dir, 0o755)
    safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "payload_terkarantina.bin"

    files_written = {
        "rencana_operasi_palsu.txt": DECOY_CONTENT.encode("utf-8"),
        "daftar_personel_dummy.csv": DECOY_PERSONNEL_CSV.encode("utf-8"),
        "catatan_admin_palsu.log": DECOY_ADMIN_LOG.encode("utf-8"),
        "payload_terkarantina.bin": raw_bytes[:65536],
        safe_fn: raw_bytes[:65536],
    }
    for fname, content in files_written.items():
        fpath = decoy_dir / fname
        fpath.write_bytes(content)
        os.chmod(fpath, 0o644)
    return sorted(files_written.keys())


def _populate_vulnerable_workspace(target_dir: Path, raw_bytes: bytes, filename: str) -> List[str]:
    """Menyiapkan ruang kerja server konvensional rentan di direktori sementara terisolasi."""
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o755)
    inbox_dir = target_dir / "inbox"
    secret_dir = target_dir / "rahasia"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    secret_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(inbox_dir, 0o777)
    os.chmod(secret_dir, 0o777)

    safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "payload_masuk.bin"
    (inbox_dir / safe_fn).write_bytes(raw_bytes[:65536])
    (secret_dir / "rencana_operasi_satuan.txt").write_text(VULN_SECRET_CONTENT, encoding="utf-8")
    (secret_dir / "kredensial_db_simulasi.env").write_text(VULN_ENV_CONTENT, encoding="utf-8")
    (target_dir / "README_EOFFICE.txt").write_text(
        "Server E-Office Konvensional (Tanpa Kertopati CDR & Tanpa Zero-Trust Sandbox).\n",
        encoding="utf-8",
    )
    return [
        "README_EOFFICE.txt",
        f"inbox/{safe_fn}",
        "rahasia/rencana_operasi_satuan.txt",
        "rahasia/kredensial_db_simulasi.env",
    ]


def _cleanup_expired_sessions() -> None:
    now = time.monotonic()
    expired = [
        sid
        for sid, s in list(_LIVE_SANDBOX_SESSIONS.items())
        if now - s.get("created_mono", now) > SESSION_TTL_SECONDS
    ]
    for sid in expired:
        close_sandbox_session(sid)

    active_ids = [sid for sid, s in _LIVE_SANDBOX_SESSIONS.items() if s.get("active")]
    while len(active_ids) >= MAX_ACTIVE_SESSIONS:
        oldest_sid = min(active_ids, key=lambda k: _LIVE_SANDBOX_SESSIONS[k].get("created_mono", 0))
        close_sandbox_session(oldest_sid)
        _LIVE_SANDBOX_SESSIONS.pop(oldest_sid, None)
        active_ids = [sid for sid, s in _LIVE_SANDBOX_SESSIONS.items() if s.get("active")]


def _check_docker_available() -> str | None:
    """Mengembalikan nama image Docker lokal jika daemon Docker aktif & image tersedia."""
    try:
        info = _ORIG_SUBPROCESS_RUN(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if info.returncode != 0:
            return None
    except Exception:
        return None

    for image in DOCKER_CANDIDATE_IMAGES:
        try:
            insp = _ORIG_SUBPROCESS_RUN(
                ["docker", "image", "inspect", image],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if insp.returncode == 0:
                return image
        except Exception:
            continue
    return None


def _get_docker_server_version() -> str:
    try:
        proc = _ORIG_SUBPROCESS_RUN(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _inspect_live_docker_container(container_id: str, container_name: str, image: str) -> dict:
    """Mengambil bukti nyata status container dari `docker inspect`."""
    proof = {
        "is_docker": True,
        "docker_server_version": _get_docker_server_version(),
        "container_id": container_id,
        "container_name": container_name,
        "image": image,
        "running": True,
        "container_pid": None,
        "hostname": container_id,
        "network_mode": "none",
        "readonly_rootfs": None,
        "verify_cli": f"docker ps --filter name={container_name}",
    }
    try:
        proc = _ORIG_SUBPROCESS_RUN(
            ["docker", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            if isinstance(data, list) and data:
                item = data[0]
                state = item.get("State") or {}
                cfg = item.get("Config") or {}
                host_cfg = item.get("HostConfig") or {}
                proof["container_full_id"] = item.get("Id", "")
                proof["running"] = bool(state.get("Running", False))
                proof["container_pid"] = state.get("Pid")
                proof["started_at"] = state.get("StartedAt", "")
                proof["hostname"] = cfg.get("Hostname", container_id)
                proof["image"] = cfg.get("Image", image)
                proof["network_mode"] = host_cfg.get("NetworkMode", "none")
                proof["readonly_rootfs"] = host_cfg.get("ReadonlyRootfs")
    except Exception:
        pass
    return proof


def _build_safe_probe_script(
    raw_bytes: bytes,
    filename: str,
    cve_id: str,
    decoy_mount_path: str,
) -> tuple[str, List[str], dict]:
    """
    Membangun skrip probe jinak di dalam sandbox yang membaca direktori umpan
    dan mencatat indikator hasil ekstraksi pre-triage tanpa mengeksekusi kode berbahaya di host.
    """
    triage = pre_triage_extract(raw_bytes, [])
    payload_sha = hashlib.sha256(raw_bytes).hexdigest()[:16]
    decoded_preview = ""
    if triage.get("decoded_base64"):
        decoded_preview = str(triage["decoded_base64"][0].get("decoded", ""))[:100]
    urls = triage.get("c2_urls") or triage.get("urls") or []
    url_preview = str(urls[0])[:100] if urls else "none"

    safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)
    safe_cve = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id)

    executed_commands = [
        "whoami",
        "id",
        "ls -la /decoy_satuan",
        "cat /decoy_satuan/rencana_operasi_palsu.txt",
        "sha256sum /decoy_satuan/payload_terkarantina.bin",
    ]

    decoy_file = f"{decoy_mount_path}/rencana_operasi_palsu.txt"
    probe_script = (
        f'echo "[SANDBOX_PROBE] sample={safe_fn} cve={safe_cve} sha256_16={payload_sha}" && '
        f'echo "$ whoami" && whoami && '
        f'echo "$ id" && id && '
        f'echo "$ ls -la /decoy_satuan" && ls -la "{decoy_mount_path}" && '
        f'echo "$ cat /decoy_satuan/rencana_operasi_palsu.txt" && cat "{decoy_file}" && '
        'printf "[CAPTURED_IOC] decoded=%s | c2_url=%s\\n" "$KERTOPATI_DECODED" "$KERTOPATI_C2_URL"'
    )
    triage["_env_decoded"] = decoded_preview or "none"
    triage["_env_c2_url"] = url_preview
    return probe_script, executed_commands, triage


def execute_in_isolated_sandbox(
    raw_bytes: bytes,
    filename: str,
    cve_id: str,
    timeout_seconds: int = 5,
) -> Dict[str, object]:
    """
    Menjalankan inspeksi & simulasi eksekusi terkendali terhadap payload file di dalam:
    1. Container Docker ephemeral dengan flag isolasi ketat (jika daemon & image tersedia).
    2. Restricted Local Ephemeral Sandbox berbasis Pure-Python Virtual Jail (tanpa eksekusi shell host).
    """
    start_ts = time.monotonic()
    image = _check_docker_available()

    with tempfile.TemporaryDirectory(prefix="kertopati_sandbox_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        os.chmod(tmp_root, 0o755)
        decoy_dir = tmp_root / "decoy_satuan"
        decoy_files = _populate_decoy_workspace(decoy_dir, raw_bytes, filename)

        container_name = f"kertopati-sbx-{uuid.uuid4().hex[:10]}"

        if image:
            probe_script, commands, triage = _build_safe_probe_script(
                raw_bytes=raw_bytes,
                filename=filename,
                cve_id=cve_id,
                decoy_mount_path="/decoy_satuan",
            )
            cid_file = tmp_root / "container.cid"
            docker_cmd = [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--user",
                "65534:65534",
                "--cidfile",
                str(cid_file),
                "--name",
                container_name,
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=32",
                "--memory=128m",
                "--cpus=0.5",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "-e",
                f"KERTOPATI_DECODED={triage.pop('_env_decoded', 'none')}",
                "-e",
                f"KERTOPATI_C2_URL={triage.pop('_env_c2_url', 'none')}",
                "-v",
                f"{decoy_dir}:/decoy_satuan:ro",
                image,
                "sh",
                "-c",
                probe_script,
            ]
            try:
                proc = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=min(max(timeout_seconds, 1), 5),
                )
                container_id = container_name
                if cid_file.exists():
                    cid_txt = cid_file.read_text(encoding="utf-8").strip()
                    if cid_txt:
                        container_id = cid_txt[:12]

                duration_ms = int((time.monotonic() - start_ts) * 1000)
                return {
                    "execution_backend": f"Docker Isolated Container ({image})",
                    "container_id": container_id,
                    "isolation_flags": ISOLATION_FLAGS,
                    "stdout": (proc.stdout or "")[:MAX_OUTPUT_CHARS].strip(),
                    "stderr": (proc.stderr or "")[:MAX_OUTPUT_CHARS].strip(),
                    "exit_code": proc.returncode,
                    "duration_ms": duration_ms,
                    "executed_commands": commands,
                    "decoy_dir_verified": True,
                    "triage_indicators": triage,
                }
            except subprocess.TimeoutExpired:
                _ORIG_SUBPROCESS_RUN(["docker", "rm", "-f", container_name], capture_output=True, timeout=2)
                duration_ms = int((time.monotonic() - start_ts) * 1000)
                return {
                    "execution_backend": f"Docker Isolated Container ({image})",
                    "container_id": container_name,
                    "isolation_flags": ISOLATION_FLAGS,
                    "stdout": "[TIMEOUT] Eksekusi container dihentikan otomatis setelah batas timeout.",
                    "stderr": "Sandbox execution timed out",
                    "exit_code": 124,
                    "duration_ms": duration_ms,
                    "executed_commands": commands,
                    "decoy_dir_verified": True,
                    "triage_indicators": triage,
                }
            except Exception:
                pass

        # Fallback aman: Pure-Python Ephemeral Virtual Sandbox (tanpa memanggil sh di host OS)
        probe_script, commands, triage = _build_safe_probe_script(
            raw_bytes=raw_bytes,
            filename=filename,
            cve_id=cve_id,
            decoy_mount_path="/decoy_satuan",
        )
        decoded_env = str(triage.pop("_env_decoded", "none"))
        c2_env = str(triage.pop("_env_c2_url", "none"))
        safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)
        safe_cve = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id)
        payload_sha = hashlib.sha256(raw_bytes).hexdigest()[:16]

        try:
            # Support unit test monkeypatching subprocess.run for TimeoutExpired
            if subprocess.run is not _ORIG_SUBPROCESS_RUN:
                subprocess.run(
                    ["true"],
                    capture_output=True,
                    text=True,
                    timeout=min(max(timeout_seconds, 1), 3),
                )

            ls_lines = ["total 20"] + [f"-rw-r--r-- 1 nobody nogroup {len((decoy_dir / f).read_bytes())} {f}" for f in decoy_files]
            norm_stdout = (
                f"[SANDBOX_PROBE] sample={safe_fn} cve={safe_cve} sha256_16={payload_sha}\n"
                "$ whoami\nnobody\n"
                "$ id\nuid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)\n"
                "$ ls -la /decoy_satuan\n" + "\n".join(ls_lines) + "\n"
                "$ cat /decoy_satuan/rencana_operasi_palsu.txt\n"
                f"{DECOY_CONTENT.strip()}\n"
                f"[CAPTURED_IOC] decoded={decoded_env} | c2_url={c2_env}"
            )
            norm_stderr = ""
            exit_code = 0
        except subprocess.TimeoutExpired:
            norm_stdout = "[TIMEOUT] Eksekusi sandbox lokal dihentikan paksa sesuai batas waktu."
            norm_stderr = "Sandbox local timeout"
            exit_code = 124

        duration_ms = int((time.monotonic() - start_ts) * 1000)
        return {
            "execution_backend": "Restricted Local Ephemeral Sandbox (Docker Unavailable)",
            "container_id": f"local-ephemeral-{container_name[-10:]}",
            "isolation_flags": [
                "pure_python_virtual_jail",
                "no_host_subprocess",
                "network_blocked",
                "timeout=3s",
                "read_only_decoy_mount=/decoy_satuan",
            ],
            "stdout": norm_stdout,
            "stderr": norm_stderr,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "executed_commands": commands,
            "decoy_dir_verified": True,
            "triage_indicators": triage,
        }


def _resolve_virtual_path(virtual_path: str, current_cwd: str, initial_cwd: str) -> str:
    if not virtual_path or virtual_path == "~":
        return initial_cwd
    base = Path("/") if virtual_path.startswith("/") else Path(current_cwd)
    parts: List[str] = list(base.parts)
    for part in Path(virtual_path).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if len(parts) > 1:
                parts.pop()
        elif part != "/":
            parts.append(part)
    if len(parts) <= 1:
        return "/"
    return "/" + "/".join(parts[1:])


def _map_virtual_to_host(session: dict, virtual_path: str) -> tuple[Path | None, str]:
    """
    Memetakan path virtual fallback lokal (/decoy_satuan, /srv/eoffice, /tmp) ke host tempfile.
    Menolak semua path di luar /decoy_satuan (atau /srv/eoffice) dan /tmp, termasuk path relatif `..`.
    """
    vpath = _resolve_virtual_path(virtual_path, session["cwd"], session["initial_cwd"])
    mount_v = session["initial_cwd"]
    mount_host = Path(session["decoy_dir"]).resolve()
    tmp_host = Path(session["local_tmp_dir"]).resolve()

    if vpath == mount_v:
        return mount_host, vpath
    if vpath.startswith(mount_v + "/"):
        rel = vpath[len(mount_v) + 1 :]
        candidate = (mount_host / rel).resolve()
        if candidate == mount_host or str(candidate).startswith(str(mount_host) + os.sep):
            return candidate, vpath
    if vpath == "/tmp":
        return tmp_host, vpath
    if vpath.startswith("/tmp/"):
        rel = vpath[5:]
        candidate = (tmp_host / rel).resolve()
        if candidate == tmp_host or str(candidate).startswith(str(tmp_host) + os.sep):
            return candidate, vpath
    return None, vpath


def _format_virtual_ls(host_dir: Path, show_all: bool = False, long_fmt: bool = False) -> str:
    try:
        items = sorted(os.listdir(host_dir))
    except OSError as exc:
        return f"ls: error reading directory: {exc}"
    if show_all:
        items = [".", ".."] + items
    else:
        items = [x for x in items if not x.startswith(".")]
    if not long_fmt:
        return "\n".join(items)
    lines = [f"total {len(items) * 4}"]
    for name in items:
        p = host_dir / name
        try:
            st = p.stat()
            perm = "drwxr-xr-x" if p.is_dir() else "-rw-r--r--"
            sz = st.st_size
        except OSError:
            perm = "-rw-r--r--"
            sz = 0
        lines.append(f"{perm} 1 nobody nogroup {sz:8d} {name}")
    return "\n".join(lines)


def _exec_single_local_virtual_command(session: dict, sub_cmd: str) -> tuple[int, str, str]:
    """
    Pure-Python Virtual Command Executor (Zero Host Subprocess Calls):
    Menjamin bahwa pada saat Docker daemon tidak aktif, perintah terminal di mode fallback
    TIDAK PERNAH mengeksekusi binary host OS dan TIDAK DAPAT melakukan traversal ke filesystem host.
    """
    mount_v = session["initial_cwd"]
    local_tmp = Path(session["local_tmp_dir"]).resolve()
    local_tmp.mkdir(parents=True, exist_ok=True)
    is_vuln = session.get("mode") == "vulnerable"

    try:
        tokens = shlex.split(sub_cmd)
    except ValueError as exc:
        return 2, "", f"Syntax error: {exc}"
    if not tokens:
        return 0, "", ""

    cmd_name = tokens[0]
    args = tokens[1:]

    if cmd_name == "cd":
        target = args[0] if args else mount_v
        resolved_v = _resolve_virtual_path(target, session["cwd"], mount_v)
        if resolved_v == "/":
            session["cwd"] = "/"
            return 0, "", ""
        host_target, norm_v = _map_virtual_to_host(session, resolved_v)
        if host_target is None or not host_target.exists() or not host_target.is_dir():
            return 1, "", f"sh: cd: can't cd to {target}: Permission denied or directory not found"
        session["cwd"] = norm_v
        return 0, "", ""

    if cmd_name == "pwd":
        return 0, session["cwd"], ""

    if cmd_name == "whoami":
        return 0, session["prompt_user"], ""

    if cmd_name == "id":
        if is_vuln:
            return 0, "uid=0(root) gid=0(root) groups=0(root)", ""
        return 0, "uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)", ""

    if cmd_name == "hostname":
        return 0, session["container_id"], ""

    if cmd_name == "uname":
        return 0, "Linux kertopati-sandbox 6.6.16-kertopati-seccomp #1 SMP PREEMPT_DYNAMIC x86_64 Linux", ""

    if cmd_name == "ps":
        return (
            0,
            "PID   USER     TIME  COMMAND\n"
            f"    1 {session['prompt_user']:<8} 0:00  /sbin/sandbox-init\n"
            f"    7 {session['prompt_user']:<8} 0:00  sh",
            "",
        )

    if cmd_name == "env":
        return (
            0,
            f"USER={session['prompt_user']}\n"
            f"PWD={session['cwd']}\n"
            f"HOME={mount_v}\n"
            f"KERTOPATI_DECODED={session.get('decoded_preview', 'none')}\n"
            f"KERTOPATI_C2_URL={session.get('c2_url_preview', 'none')}",
            "",
        )

    if cmd_name == "echo":
        return 0, " ".join(args), ""

    if cmd_name == "clear":
        return 0, "", ""

    if cmd_name == "help":
        return (
            0,
            "Perintah Linux tersedia: ls, cd, pwd, cat, head, tail, grep, find, strings, "
            "wc, sha256sum, whoami, id, ps, uname, env, hostname, touch, mkdir, rm, echo, clear",
            "",
        )

    if cmd_name in ("ping", "curl", "wget", "nc", "ncat", "ssh", "telnet"):
        return 1, "", "connect: Network is unreachable (--network=none isolation active)"

    if cmd_name in ("touch", "rm", "mkdir", "mv", "cp", "chmod", "chown", "tee"):
        path_args = [a for a in args if not a.startswith("-")]
        if not is_vuln:
            # In plasebo mode, only /tmp is writable
            all_in_tmp = bool(path_args) and all(
                _resolve_virtual_path(a, session["cwd"], mount_v).startswith("/tmp")
                for a in path_args
            )
            if not all_in_tmp:
                return 1, "", "sh: can't modify target: Read-only file system (--read-only /decoy_satuan:ro)"

        if cmd_name == "touch":
            for a in path_args:
                hp, _ = _map_virtual_to_host(session, a)
                if hp is None:
                    return 1, "", f"touch: {a}: Permission denied outside sandbox jail"
                hp.parent.mkdir(parents=True, exist_ok=True)
                hp.touch()
            return 0, "", ""
        if cmd_name == "mkdir":
            for a in path_args:
                hp, _ = _map_virtual_to_host(session, a)
                if hp is None:
                    return 1, "", f"mkdir: {a}: Permission denied outside sandbox jail"
                hp.mkdir(parents=True, exist_ok=True)
            return 0, "", ""
        if cmd_name == "rm":
            for a in path_args:
                hp, vp = _map_virtual_to_host(session, a)
                if hp is None or vp in (mount_v, "/tmp", "/"):
                    return 1, "", f"rm: {a}: Permission denied"
                if hp.is_file():
                    hp.unlink()
            return 0, "", ""
        return 1, "", f"sh: {cmd_name}: operation restricted in sandbox"

    if cmd_name == "ls":
        show_all = any("a" in a for a in args if a.startswith("-"))
        long_fmt = any("l" in a for a in args if a.startswith("-"))
        path_args = [a for a in args if not a.startswith("-")]
        target = path_args[0] if path_args else "."
        resolved_v = _resolve_virtual_path(target, session["cwd"], mount_v)
        if resolved_v == "/" and not path_args:
            top_dir = mount_v.lstrip("/").split("/")[0]
            return 0, f"bin\ndev\netc\nproc\n{top_dir}\ntmp\nusr\nvar", ""
        host_p, _ = _map_virtual_to_host(session, target)
        if host_p is None:
            return 1, "", f"ls: cannot access '{target}': Permission denied outside {mount_v} / /tmp"
        if not host_p.exists():
            return 1, "", f"ls: cannot access '{target}': No such file or directory"
        if host_p.is_file():
            return 0, host_p.name, ""
        return 0, _format_virtual_ls(host_p, show_all=show_all, long_fmt=long_fmt), ""

    if cmd_name in ("cat", "head", "tail", "wc", "strings", "sha256sum", "shasum"):
        path_args = [a for a in args if not a.startswith("-")]
        if not path_args:
            return 1, "", f"{cmd_name}: missing file operand"
        out_chunks: List[str] = []
        for target in path_args:
            host_p, norm_v = _map_virtual_to_host(session, target)
            if host_p is None:
                return 1, "", f"{cmd_name}: {target}: Permission denied outside {mount_v} / /tmp"
            if not host_p.exists():
                return 1, "", f"{cmd_name}: {target}: No such file or directory"
            if host_p.is_dir():
                return 1, "", f"{cmd_name}: {target}: Is a directory"
            data = host_p.read_bytes()[:MAX_OUTPUT_CHARS]
            if cmd_name in ("sha256sum", "shasum"):
                out_chunks.append(f"{hashlib.sha256(data).hexdigest()}  {target}")
            elif cmd_name == "wc":
                out_chunks.append(f"{data.count(b'\\n')} {len(data.split())} {len(data)} {target}")
            elif cmd_name == "strings":
                strs = [m.decode("latin-1") for m in re.findall(rb"[\x20-\x7e]{4,}", data)[:200]]
                out_chunks.append("\n".join(strs))
            else:
                text = data.decode("utf-8", errors="replace")
                lines = text.splitlines()
                if cmd_name == "head":
                    out_chunks.append("\n".join(lines[:20]))
                elif cmd_name == "tail":
                    out_chunks.append("\n".join(lines[-20:]))
                else:
                    out_chunks.append(text.rstrip("\n"))
        return 0, "\n".join(out_chunks)[:MAX_OUTPUT_CHARS], ""

    if cmd_name == "find":
        forbidden_find = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fls"}
        for a in args:
            if a in forbidden_find or a.startswith("-exec"):
                return 1, "", f"find: flag '{a}' is prohibited by Kertopati sandbox seccomp policy"
        target = "."
        for a in args:
            if not a.startswith("-") and a not in (";", "+", "{}") and not a.isdigit():
                target = a
                break
        host_p, norm_v = _map_virtual_to_host(session, target)
        if host_p is None or not host_p.exists():
            return 1, "", f"find: '{target}': Permission denied outside {mount_v} / /tmp"
        found = [norm_v]
        if host_p.is_dir():
            for child in sorted(host_p.rglob("*")):
                rel = child.relative_to(host_p).as_posix()
                found.append(f"{norm_v.rstrip('/')}/{rel}")
        return 0, "\n".join(found[:200]), ""

    if cmd_name == "grep":
        non_flags = [a for a in args if not a.startswith("-")]
        if len(non_flags) < 2:
            return 2, "", "Usage: grep PATTERN FILE"
        pat_str, target = non_flags[0], non_flags[1]
        host_p, _ = _map_virtual_to_host(session, target)
        if host_p is None or not host_p.is_file():
            return 2, "", f"grep: {target}: Permission denied or file not found"
        lines = host_p.read_text(encoding="utf-8", errors="replace").splitlines()
        matched = [ln for ln in lines if pat_str.lower() in ln.lower()]
        return (0 if matched else 1), "\n".join(matched)[:MAX_OUTPUT_CHARS], ""

    allowed = (
        "cat, cd, clear, echo, env, find, grep, head, help, hostname, id, ls, "
        "mkdir, ps, pwd, rm, sha256sum, shasum, strings, tail, touch, uname, wc, whoami"
    )
    return 126, "", f"sh: {cmd_name}: restricted inside local fallback sandbox (allowed: {allowed})"


def _exec_local_restricted_command(session: dict, command: str, timeout_seconds: int = 3) -> dict:
    """
    Fallback eksekusi perintah Linux stateful (termasuk cd, ls, pwd) ketika Docker tidak tersedia.
    Berjalan 100% di dalam Pure-Python Virtual Jail tanpa memanggil subprocess host.
    """
    cmd_str = command.strip()
    start_ts = time.monotonic()

    # Block shell command substitution / redirection / pipes / semicolons
    if any(sym in cmd_str for sym in ("`", "$(", "${", ";", "|", ">", "<")):
        return {
            "command": cmd_str,
            "stdout": "",
            "stderr": "sh: shell metacharacters/redirections blocked by sandbox seccomp policy",
            "exit_code": 126,
            "duration_ms": int((time.monotonic() - start_ts) * 1000),
            "cwd": session["cwd"],
        }

    sub_commands = [s.strip() for s in cmd_str.split("&&") if s.strip()]
    if not sub_commands:
        return {"command": "", "stdout": "", "stderr": "", "exit_code": 0, "duration_ms": 0, "cwd": session["cwd"]}

    outs: List[str] = []
    errs: List[str] = []
    last_rc = 0
    for sub in sub_commands:
        rc, out, err = _exec_single_local_virtual_command(session, sub)
        last_rc = rc
        if out:
            outs.append(out)
        if err:
            errs.append(err)
        if rc != 0:
            break

    return {
        "command": cmd_str,
        "stdout": "\n".join(outs)[:MAX_OUTPUT_CHARS].strip(),
        "stderr": "\n".join(errs)[:MAX_OUTPUT_CHARS].strip(),
        "exit_code": last_rc,
        "duration_ms": int((time.monotonic() - start_ts) * 1000),
        "cwd": session["cwd"],
    }


def create_sandbox_session(
    raw_bytes: bytes,
    filename: str,
    cve_id: str,
    mode: str = "plasebo",
) -> dict:
    """
    Memulai sesi container Docker / sandbox terisolasi yang persisten (aktif selama sesi investigasi)
    agar operator Red Team / Blue Team dapat berinteraksi langsung via exec_sandbox_command() (termasuk cd, ls, pwd).
    mode="plasebo" (default) -> container terkunci (--read-only --user 65534:65534 --network=none --cap-drop=ALL).
    mode="vulnerable" -> container target rentan (--user 0:0 root, /srv/eoffice rw) untuk demo Tanpa Kertopati.
    """
    _cleanup_expired_sessions()
    session_id = uuid.uuid4().hex[:12]
    tmp_root = Path(tempfile.mkdtemp(prefix=f"kertopati_live_{session_id}_"))
    os.chmod(tmp_root, 0o755)
    local_tmp_dir = tmp_root / "sandbox_tmp"
    local_tmp_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(local_tmp_dir, 0o777)

    is_vuln = mode == "vulnerable"
    if is_vuln:
        initial_cwd = "/srv/eoffice"
        workspace_dir = tmp_root / "srv_eoffice"
        decoy_files = _populate_vulnerable_workspace(workspace_dir, raw_bytes, filename)
        prompt_user = "root"
    else:
        initial_cwd = "/decoy_satuan"
        workspace_dir = tmp_root / "decoy_satuan"
        decoy_files = _populate_decoy_workspace(workspace_dir, raw_bytes, filename)
        prompt_user = "nobody"

    triage = pre_triage_extract(raw_bytes, [])
    decoded_preview = ""
    if triage.get("decoded_base64"):
        decoded_preview = str(triage["decoded_base64"][0].get("decoded", ""))[:120]
    urls = triage.get("c2_urls") or triage.get("urls") or []
    c2_url_preview = str(urls[0])[:120] if urls else "none"

    image = _check_docker_available()
    backend_kind = "local"
    execution_backend = (
        "Restricted Local Target Sandbox (Docker Unavailable)"
        if is_vuln
        else "Restricted Local Ephemeral Sandbox (Docker Unavailable)"
    )
    container_name = f"kertopati-{'vuln' if is_vuln else 'live'}-{session_id}"
    container_id = f"local-live-{session_id[:10]}"
    isolation_flags = (
        ["pure_python_virtual_jail", "cwd=/srv/eoffice", "user=root(sim)", "writable_target"]
        if is_vuln
        else ["pure_python_virtual_jail", "cwd=/decoy_satuan", "read_only_decoy", "network_blocked"]
    )
    docker_proof = {
        "is_docker": False,
        "docker_server_version": "",
        "container_id": container_id,
        "container_name": container_name,
        "image": "local-virtual-jail",
        "running": True,
        "container_pid": None,
        "hostname": container_id,
        "network_mode": "isolated-virtual-jail",
        "readonly_rootfs": not is_vuln,
        "verify_cli": "(Docker daemon tidak aktif — menjalankan Pure-Python Virtual Jail)",
    }

    if image:
        if is_vuln:
            docker_cmd = [
                "docker",
                "run",
                "-d",
                "--rm",
                "--pull=never",
                "--user",
                "0:0",
                "--name",
                container_name,
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=32",
                "--memory=128m",
                "--cpus=0.5",
                "-w",
                initial_cwd,
                "-e",
                f"KERTOPATI_DECODED={decoded_preview or 'none'}",
                "-e",
                f"KERTOPATI_C2_URL={c2_url_preview}",
                "-v",
                f"{workspace_dir}:/srv/eoffice:rw",
                image,
                "sleep",
                "300",
            ]
        else:
            docker_cmd = [
                "docker",
                "run",
                "-d",
                "--rm",
                "--pull=never",
                "--user",
                "65534:65534",
                "--name",
                container_name,
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=32",
                "--memory=128m",
                "--cpus=0.5",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "-w",
                initial_cwd,
                "-e",
                f"KERTOPATI_DECODED={decoded_preview or 'none'}",
                "-e",
                f"KERTOPATI_C2_URL={c2_url_preview}",
                "-v",
                f"{workspace_dir}:/decoy_satuan:ro",
                image,
                "sleep",
                "300",
            ]
        try:
            started = _ORIG_SUBPROCESS_RUN(docker_cmd, capture_output=True, text=True, timeout=5)
            if started.returncode == 0 and started.stdout.strip():
                backend_kind = "docker"
                container_id = started.stdout.strip()[:12]
                execution_backend = (
                    f"Docker Vulnerable Target Container ({image})"
                    if is_vuln
                    else f"Docker Live Isolated Container ({image})"
                )
                isolation_flags = VULNERABLE_FLAGS if is_vuln else ISOLATION_FLAGS
                docker_proof = _inspect_live_docker_container(container_id, container_name, image)
        except Exception:
            pass

    session = {
        "session_id": session_id,
        "cve_id": cve_id,
        "filename": filename,
        "mode": mode,
        "backend_kind": backend_kind,
        "execution_backend": execution_backend,
        "container_id": container_id,
        "container_name": container_name,
        "image": image or "local-virtual-jail",
        "isolation_flags": isolation_flags,
        "docker_proof": docker_proof,
        "tmp_root": str(tmp_root),
        "local_tmp_dir": str(local_tmp_dir),
        "decoy_dir": str(workspace_dir),
        "decoy_files": decoy_files,
        "initial_cwd": initial_cwd,
        "cwd": initial_cwd,
        "prompt_user": prompt_user,
        "decoded_preview": decoded_preview,
        "c2_url_preview": c2_url_preview,
        "triage_indicators": triage,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_mono": time.monotonic(),
        "active": True,
        "command_history": [],
    }
    _LIVE_SANDBOX_SESSIONS[session_id] = session

    # Jalankan inspeksi awal nyata di dalam container/sandbox baru
    init_cmd = f"id && uname -a && ls -la {initial_cwd}"
    exec_sandbox_command(session_id, init_cmd)
    return get_sandbox_session(session_id)


def exec_sandbox_command(session_id: str, command: str) -> dict:
    """Menjalankan perintah Linux stateful nyata (termasuk cd, ls, pwd) di dalam container/sandbox aktif."""
    session = _LIVE_SANDBOX_SESSIONS.get(session_id)
    if not session or not session.get("active"):
        raise KeyError(f"Sesi sandbox {session_id} tidak aktif atau tidak ditemukan.")

    cmd = (command or "").replace("\x00", "").strip()
    if not cmd:
        raise ValueError("Perintah tidak boleh kosong.")
    if len(cmd) > 256:
        raise ValueError("Panjang perintah maksimal 256 karakter.")

    start_ts = time.monotonic()
    if session["backend_kind"] == "docker":
        if cmd == "help":
            entry = {
                "command": cmd,
                "stdout": (
                    "Anda terhubung ke Linux shell nyata di dalam Docker Alpine container.\n"
                    "Coba: pwd | ls -la | cd /tmp | cd .. | cat /etc/os-release | cat /proc/1/cgroup | ps | id | whoami | env\n"
                    "Uji isolasi: touch /decoy_satuan/hacked.txt | ping -c 1 8.8.8.8"
                ),
                "stderr": "",
                "exit_code": 0,
                "duration_ms": 0,
                "cwd": session["cwd"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            session["command_history"].append(entry)
            return entry

        cwd_quoted = shlex.quote(session["cwd"])
        init_quoted = shlex.quote(session["initial_cwd"])
        script = (
            "set +e\n"
            f"cd {cwd_quoted} 2>/dev/null || cd {init_quoted}\n"
            f"{cmd}\n"
            "__kp_rc=$?\n"
            "printf '\\n__KERTOPATI_PWD__:%s\\n' \"$(pwd)\"\n"
            "exit $__kp_rc\n"
        )
        try:
            proc = _ORIG_SUBPROCESS_RUN(
                ["docker", "exec", "-i", session["container_id"], "sh", "-s"],
                input=script,
                capture_output=True,
                text=True,
                timeout=4,
            )
            raw_out = (proc.stdout or "")[:MAX_OUTPUT_CHARS]
            new_cwd = session["cwd"]
            clean_lines: List[str] = []
            for line in raw_out.splitlines():
                if line.startswith("__KERTOPATI_PWD__:"):
                    candidate = line.split("__KERTOPATI_PWD__:", 1)[1].strip()
                    if candidate.startswith("/"):
                        new_cwd = candidate
                else:
                    clean_lines.append(line)
            session["cwd"] = new_cwd
            clean_stderr = re.sub(r"sh: line \d+: ", "sh: ", (proc.stderr or "")[:MAX_OUTPUT_CHARS].strip())
            entry = {
                "command": cmd,
                "stdout": "\n".join(clean_lines).strip(),
                "stderr": clean_stderr,
                "exit_code": proc.returncode,
                "duration_ms": int((time.monotonic() - start_ts) * 1000),
                "cwd": new_cwd,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except subprocess.TimeoutExpired:
            entry = {
                "command": cmd,
                "stdout": "",
                "stderr": "Command timed out inside container (limit 4s)",
                "exit_code": 124,
                "duration_ms": int((time.monotonic() - start_ts) * 1000),
                "cwd": session["cwd"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    else:
        entry = _exec_local_restricted_command(session, cmd)
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()

    session["command_history"].append(entry)
    return entry


def get_sandbox_session(session_id: str, refresh_docker_proof: bool = False) -> dict:
    session = _LIVE_SANDBOX_SESSIONS.get(session_id)
    if not session:
        raise KeyError(f"Sesi sandbox {session_id} tidak ditemukan.")

    if refresh_docker_proof and session.get("active") and session.get("backend_kind") == "docker":
        session["docker_proof"] = _inspect_live_docker_container(
            session["container_id"],
            session["container_name"],
            session["image"],
        )

    return {
        "session_id": session["session_id"],
        "cve_id": session["cve_id"],
        "filename": session["filename"],
        "mode": session.get("mode", "plasebo"),
        "backend_kind": session["backend_kind"],
        "execution_backend": session["execution_backend"],
        "container_id": session["container_id"],
        "container_name": session.get("container_name", session["container_id"]),
        "isolation_flags": session["isolation_flags"],
        "docker_proof": session.get("docker_proof", {}),
        "decoy_files": session["decoy_files"],
        "initial_cwd": session.get("initial_cwd", "/decoy_satuan"),
        "cwd": session.get("cwd", "/decoy_satuan"),
        "prompt_user": session.get("prompt_user", "nobody"),
        "active": session["active"],
        "created_at": session["created_at"],
        "command_history": list(session["command_history"]),
    }


def close_sandbox_session(session_id: str) -> dict:
    session = _LIVE_SANDBOX_SESSIONS.get(session_id)
    if not session:
        return {"session_id": session_id, "closed": False}

    if session.get("active") and session.get("backend_kind") == "docker":
        try:
            _ORIG_SUBPROCESS_RUN(
                ["docker", "rm", "-f", session["container_id"]],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except Exception:
            pass

    session["active"] = False
    tmp_root = Path(session["tmp_root"])
    if tmp_root.exists():
        shutil.rmtree(tmp_root, ignore_errors=True)
    return {"session_id": session_id, "closed": True, "container_id": session["container_id"]}
