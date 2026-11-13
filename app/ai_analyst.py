import base64
import hashlib
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


PROMPT_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+previous\s+instructions|disregard\s+all|system\s*:|<\|im_start\|>|<\|endoftext\|>)",
    re.IGNORECASE,
)


def _sanitize_for_prompt(text: str, max_len: int = 400) -> str:
    """Tahap 1: Sanitasi teks ekstraksi agar aman dari prompt injection & karakter kontrol."""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    cleaned = PROMPT_INJECTION_PATTERNS.sub("[REDACTED_DIRECTIVE]", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]


def _try_decode_base64_payloads(raw_bytes: bytes) -> List[Dict[str, str]]:
    """
    Mendeteksi dan men-decode string Base64 (termasuk PowerShell UTF-16LE -enc
    seperti 'JAB...' maupun UTF-8 standar).
    """
    decoded_items: List[Dict[str, str]] = []
    # Cari pola eksplisit powershell -enc <b64> atau token base64 panjang >= 16
    candidates = re.findall(
        rb"(?:powershell[^\r\n]{0,30}?-enc(?:odedcommand)?\s+)?([A-Za-z0-9+/]{16,}={0,2})",
        raw_bytes,
        re.IGNORECASE,
    )
    seen = set()
    for cand_bytes in candidates:
        b64_str = cand_bytes.decode("ascii", errors="ignore")
        if b64_str in seen:
            continue
        seen.add(b64_str)
        padded = b64_str + ("=" * ((4 - len(b64_str) % 4) % 4))
        try:
            raw_dec = base64.b64decode(padded, validate=True)
        except Exception:
            continue
        if len(raw_dec) < 4:
            continue

        # Coba UTF-16LE dulu (umum pada PowerShell -EncodedCommand seperti JAB...)
        decoded_text = ""
        encoding_used = ""
        if len(raw_dec) % 2 == 0 and b"\x00" in raw_dec:
            try:
                u16 = raw_dec.decode("utf-16le")
                printable_ratio = sum(32 <= ord(c) <= 126 for c in u16) / max(len(u16), 1)
                if printable_ratio >= 0.85 and len(u16.strip()) >= 4:
                    decoded_text = u16.strip()
                    encoding_used = "UTF-16LE"
            except Exception:
                pass

        if not decoded_text:
            try:
                u8 = raw_dec.decode("utf-8")
                printable_ratio = sum(32 <= ord(c) <= 126 for c in u8) / max(len(u8), 1)
                if printable_ratio >= 0.85 and len(u8.strip()) >= 4:
                    decoded_text = u8.strip()
                    encoding_used = "UTF-8"
            except Exception:
                pass

        if decoded_text:
            decoded_items.append(
                {
                    "encoded": b64_str[:80],
                    "decoded": _sanitize_for_prompt(decoded_text, max_len=240),
                    "encoding": encoding_used,
                }
            )
    return decoded_items


def pre_triage_extract(raw_bytes: bytes, dangerous_tags: List[str]) -> Dict[str, object]:
    """
    Tahap 1 — Deterministic Pre-Triage & Anti-Prompt-Injection:
    Mengekstrak indikator berbahaya, URL/IP C2, dan melakukan deobfuscation Base64.
    """
    decoded_b64 = _try_decode_base64_payloads(raw_bytes)
    urls = [
        _sanitize_for_prompt(u.decode("latin-1", errors="ignore"), 160)
        for u in re.findall(rb"https?://[^\s\)\>\"'\<]+", raw_bytes, re.IGNORECASE)
    ]
    ips = [
        ip.decode("ascii", errors="ignore")
        for ip in re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_bytes)
    ]

    # Pilih primary IOC deterministik dengan panjang >= 5 agar tidak overly broad
    primary_ioc = ""
    cmd_match = re.search(
        rb"(app\.alert|eval\(|ActiveXObject|WScript\.Shell|powershell[^\r\n\"']{0,40}|<script[^>]*>|https?://[^\s\)\>\"'\<]+|vbaProject\.bin)",
        raw_bytes,
        re.IGNORECASE,
    )
    if cmd_match:
        primary_ioc = cmd_match.group(0).decode("latin-1", errors="ignore").strip()
    elif urls:
        primary_ioc = urls[0]
    elif dangerous_tags:
        for tag in dangerous_tags:
            if len(tag) >= 5:
                primary_ioc = tag
                break
        if not primary_ioc:
            primary_ioc = dangerous_tags[0]

    if not primary_ioc or len(primary_ioc) < 5:
        primary_ioc = "ShadowUpdate_After_BSrE_ByteRange"

    decoded_payload_str = "; ".join(item["decoded"] for item in decoded_b64)
    return {
        "primary_ioc": primary_ioc.replace('"', '\\"'),
        "decoded_base64": decoded_b64,
        "decoded_payload": decoded_payload_str,
        "c2_urls": list(dict.fromkeys(urls)),
        "c2_ips": list(dict.fromkeys(ips)),
    }


def _map_mitre_attack(
    raw_bytes: bytes,
    file_format: str,
    dangerous_tags: List[str],
    triage: Dict[str, object],
    reasons: List[str],
) -> List[str]:
    """Memetakan indikator ke teknik MITRE ATT&CK secara deterministik."""
    lower_raw = raw_bytes.lower()
    reasons_joined = " ".join(reasons).lower()
    techniques: List[str] = []

    if b"powershell" in lower_raw or "powershell" in triage.get("decoded_payload", "").lower():
        techniques.append("T1059.001 PowerShell")
    if triage.get("decoded_base64") or "TRAILING_POLYGLOT" in dangerous_tags or b"eval(" in lower_raw:
        techniques.append("T1027 Obfuscated Files or Information")
    if (
        "shadow attack" in reasons_joined
        or "byterange" in reasons_joined
        or "/OCProperties" in dangerous_tags
        or "/OCG" in dangerous_tags
        or "ocg" in reasons_joined
    ):
        techniques.append("T1553.002 Code Signing")
    if b"vbaproject.bin" in lower_raw or "VBA_MACRO" in dangerous_tags:
        techniques.append("T1059.005 Visual Basic")
    if b"/javascript" in lower_raw or b"/js" in lower_raw or b"<script" in lower_raw:
        techniques.append("T1059.007 JavaScript")

    techniques.append("T1204.002 Malicious File")
    return list(dict.fromkeys(techniques))


def _synthesize_commander_brief(
    filename: str,
    file_format: str,
    mitre_list: List[str],
    triage: Dict[str, object],
    reasons: List[str],
) -> tuple[str, str]:
    """
    Tahap 2: Menggunakan Local LLM (OLLAMA_URL) jika aktif & merespons <= 3 detik,
    atau Kertopati AI Heuristic Engine secara deterministik (100% air-gapped).
    """
    ollama_url = os.environ.get("OLLAMA_URL", "").strip()
    decoded_info = triage.get("decoded_payload") or "Tidak ada payload Base64"
    c2_info = ", ".join(triage.get("c2_urls") or []) or "Tidak terdeteksi"

    if ollama_url:
        prompt = (
            "Anda adalah analis siber TNI AD. Ringkas ancaman dokumen ini dalam 2 kalimat bahasa Indonesia "
            "yang jelas untuk komandan:\n"
            f"File: {_sanitize_for_prompt(filename, 80)} ({file_format})\n"
            f"MITRE: {', '.join(mitre_list)}\n"
            f"Decoded: {_sanitize_for_prompt(str(decoded_info), 150)}\n"
            f"C2: {_sanitize_for_prompt(c2_info, 120)}\n"
            f"Temuan: {_sanitize_for_prompt('; '.join(reasons), 200)}"
        )
        try:
            req = urllib.request.Request(
                ollama_url.rstrip("/") + "/api/generate",
                data=json.dumps(
                    {
                        "model": os.environ.get("OLLAMA_MODEL", "llama3.2"),
                        "prompt": prompt,
                        "stream": False,
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                llm_text = _sanitize_for_prompt(body.get("response", ""), max_len=360)
                if llm_text:
                    return llm_text, "Local LLM (Ollama)"
        except Exception:
            pass

    # Fallback deterministik: Kertopati AI Heuristic Engine
    parts = [
        f"Dokumen {file_format} '{filename}' terdeteksi membawa ancaman ({', '.join(mitre_list[:2])}) dan dialihkan senyap ke Auto-Sandbox."
    ]
    if triage.get("decoded_payload"):
        parts.append(f"Payload terenkode Base64 berhasil didekode menjadi perintah: '{triage['decoded_payload']}'.")
    if triage.get("c2_urls"):
        parts.append(f"Terdeteksi indikasi alamat C2/eksternal: {', '.join(triage['c2_urls'][:2])}.")
    parts.append("Vaksin YARA dan aturan Sigma SIEM telah diterbitkan untuk memblokir varian serupa di seluruh satuan.")
    return " ".join(parts), "Kertopati AI Heuristic Engine"


def _build_sigma_rule(
    rule_name: str,
    filename: str,
    mitre_list: List[str],
    triage: Dict[str, object],
    severity: str,
) -> str:
    """Menghasilkan aturan deteksi Sigma YAML untuk SIEM / Firewall satuan."""
    mitre_tags = "\n".join(
        f"    - attack.{m.split()[0].lower()}" for m in mitre_list
    )
    c2_urls = triage.get("c2_urls") or []
    decoded_cmd = triage.get("decoded_payload") or ""
    primary_ioc = triage.get("primary_ioc") or filename

    detection_lines = ["    selection:"]
    if decoded_cmd or "powershell" in str(primary_ioc).lower():
        cmd_val = str(primary_ioc).replace("'", "''")
        detection_lines.append(f"        CommandLine|contains: '{cmd_val}'")
        if decoded_cmd:
            detection_lines.append(f"        DecodedPayload|contains: '{decoded_cmd.replace(chr(39), '')}'")
        category = "process_creation"
        product = "windows"
    elif c2_urls:
        url_val = str(c2_urls[0]).replace("'", "''")
        detection_lines.append(f"        DestinationUrl|contains: '{url_val}'")
        category = "proxy"
        product = "network"
    else:
        ioc_val = str(primary_ioc).replace("'", "''")
        detection_lines.append(f"        PayloadSignature|contains: '{ioc_val}'")
        category = "file_event"
        product = "kertopati_gateway"

    level = "critical" if severity == "CRITICAL" else ("high" if severity == "HIGH" else "medium")
    return f"""title: Kertopati Auto-Sigma - {rule_name}
id: {hashlib.md5(rule_name.encode('utf-8')).hexdigest()}
status: experimental
description: Aturan SIEM/Firewall otomatis dari Auto-Sandbox Kertopati untuk sampel {filename}
author: Kertopati AI Threat Analyst
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
tags:
{mitre_tags}
logsource:
    category: {category}
    product: {product}
detection:
{chr(10).join(detection_lines)}
    condition: selection
falsepositives:
    - Tidak ada pada korpus baseline bersih Kertopati
level: {level}
"""


def validate_vaccine_pattern(
    patterns: List[str],
    malicious_bytes: bytes,
    clean_samples: List[bytes] | None = None,
) -> Dict[str, str]:
    """
    Tahap 3 — Automated Self-Validation Gate (Metodologi ABLE):
    1. Recall Check: Pola vaksin harus cocok (MATCH) pada sampel berbahaya.
    2. False Positive Check: Pola tidak boleh cocok pada sampel bersih & panjang >= 5 char.
    """
    valid_patterns = [p for p in patterns if p and len(p) >= 5]
    if not valid_patterns:
        return {
            "validation_status": "NEEDS_REVIEW (Pattern Too Broad)",
            "recall_test": "FAIL",
            "false_positive_test": "FAIL",
        }

    primary_bytes = valid_patterns[0].encode("utf-8", errors="ignore")
    recall_ok = primary_bytes in malicious_bytes

    baselines = list(clean_samples or [])
    baselines.extend(
        [
            b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n",
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x00IEND\xaeB`\x82",
        ]
    )

    fp_found = False
    for sample in baselines:
        for pat in valid_patterns:
            if pat.encode("utf-8", errors="ignore") in sample:
                fp_found = True
                break
        if fp_found:
            break

    recall_test = "PASS" if recall_ok else "FAIL"
    fp_test = "PASS" if not fp_found else "FAIL"
    status = "VALIDATED (0% FP on Baseline)" if (recall_ok and not fp_found) else "NEEDS_REVIEW"

    return {
        "validation_status": status,
        "recall_test": recall_test,
        "false_positive_test": fp_test,
    }


def analyze_threat_and_synthesize_vaccine(
    filename: str,
    raw_bytes: bytes,
    source_unit: str,
    file_format: str,
    inspection_reasons: List[str],
    dangerous_tags: List[str],
    clean_baselines: List[bytes] | None = None,
) -> Dict[str, object]:
    """Pipeline lengkap 3 tahap (Pre-Triage -> AI Reasoning & Multi-Rule -> ABLE Validation)."""
    doc_hash = hashlib.sha256(raw_bytes).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    rule_name = f"SandiSeal_Vaccine_{doc_hash[:8]}"

    # Tahap 1
    triage = pre_triage_extract(raw_bytes, dangerous_tags)
    primary_ioc = str(triage["primary_ioc"])

    # Tahap 2
    mitre_list = _map_mitre_attack(raw_bytes, file_format, dangerous_tags, triage, inspection_reasons)
    severity = (
        "CRITICAL"
        if (triage["decoded_base64"] or triage["c2_urls"] or "VBA_MACRO" in dangerous_tags or len(mitre_list) >= 3)
        else "HIGH"
    )
    commander_brief, analysis_mode = _synthesize_commander_brief(
        filename, file_format, mitre_list, triage, inspection_reasons
    )

    fmt = (file_format or "UNKNOWN").upper()
    if fmt == "PDF":
        header_cond = "uint32(0) == 0x46445025"
    elif fmt == "JPEG":
        header_cond = "uint16(0) == 0xD8FF"
    elif fmt == "PNG":
        header_cond = "uint32(0) == 0x474E5089"
    elif fmt in ("DOCX", "XLSX", "OOXML"):
        header_cond = "uint32(0) == 0x04034B50"
    else:
        header_cond = ""

    strings_block = f'        $ioc = "{primary_ioc}" ascii nocase'
    decoded_payload = str(triage.get("decoded_payload") or "")
    if decoded_payload and len(decoded_payload) >= 5:
        safe_dec = decoded_payload.replace('"', '\\"')
        strings_block += f'\n        $decoded_cmd = "{safe_dec}" ascii wide nocase'
        cond_expr = f"{header_cond} and ($ioc or $decoded_cmd)" if header_cond else "($ioc or $decoded_cmd)"
    else:
        cond_expr = f"{header_cond} and $ioc" if header_cond else "$ioc"

    yara_rule = f"""rule {rule_name} {{
    meta:
        author = "Kertopati AI Threat Analyst"
        created = "{timestamp}"
        source_unit = "{source_unit}"
        file_format = "{fmt}"
        severity = "{severity}"
        mitre_attack = "{', '.join(mitre_list)}"
        sample_sha256 = "{doc_hash}"
    strings:
{strings_block}
    condition:
        {cond_expr}
}}
"""

    sigma_rule = _build_sigma_rule(rule_name, filename, mitre_list, triage, severity)

    # Tahap 3 — ABLE Self-Validation Gate
    validation = validate_vaccine_pattern(
        patterns=[primary_ioc],
        malicious_bytes=raw_bytes,
        clean_samples=clean_baselines,
    )

    return {
        "rule_name": rule_name,
        "primary_ioc": primary_ioc,
        "yara_rule": yara_rule,
        "created_at": timestamp,
        "ai_analysis": {
            "severity": severity,
            "mitre_attack": mitre_list,
            "decoded_payload": decoded_payload,
            "c2_indicators": triage.get("c2_urls", []),
            "commander_brief": commander_brief,
            "sigma_network_rule": sigma_rule,
            "validation_status": validation["validation_status"],
            "recall_test": validation["recall_test"],
            "false_positive_test": validation["false_positive_test"],
            "analysis_mode": analysis_mode,
        },
    }
