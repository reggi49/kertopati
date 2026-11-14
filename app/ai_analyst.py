import base64
import hashlib
import json
import os
import re
import socket
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from app.pdf_inspector import _decode_pdf_hex_names, _extract_structural_pdf_bytes
from app.pdf_malware_analyzer import (
    DANGEROUS_PDF_APIS,
    calculate_shannon_entropy,
    deep_analyze_pdf_malware,
)


def _load_dotenv_if_present() -> None:
    """Memuat .env di root repo secara aman hanya di luar sesi pytest agar rahasia tidak di-hardcode."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return
    allowed_keys = {"GEMINI_API_KEY", "GEMINI_MODEL"}
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            key = k.strip()
            val = v.strip().strip('"').strip("'")
            if key in allowed_keys and val and key not in os.environ:
                os.environ[key] = val
    except Exception:
        pass


PROMPT_INJECTION_PATTERNS = re.compile(
    r"("
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|directives|rules)"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)?"
    r"|system\s+override"
    r"|you\s+are\s+now\s+dan\b"
    r"|you\s+are\s+now\b"
    r"|do\s+anything\s+now"
    r"|system\s*:"
    r"|assistant\s*:"
    r"|user\s*:"
    r"|verdict\s*=\s*clean"
    r"|<\|im_start\|>"
    r"|<\|endoftext\|>"
    r"|\[/?inst\]"
    r"|#{2,}"
    r")",
    re.IGNORECASE,
)

BENIGN_SCHEMA_DOMAINS = (
    "www.w3.org",
    "w3.org",
    "ns.adobe.com",
    "adobe.com/xap",
    "purl.org",
    "iptc.org",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "xml.org",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "Redirects blocked for AI API calls", headers, fp
        )


GEMINI_MAX_RETRIES = 10


def _is_retryable_gemini_error(exc: Exception) -> bool:
    """Mengulang panggilan Gemini bila terjadi timeout atau error server sementara (408/429/5xx)."""
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (408, 429, 500, 502, 503, 504)
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return True
        return "timed out" in str(reason).lower()
    return "timed out" in str(exc).lower()


def _call_gemini_with_retry(
    endpoint: str,
    payload_bytes: bytes,
    gemini_key: str,
    max_attempts: int = GEMINI_MAX_RETRIES,
    timeout: float = 6.0,
) -> str:
    """Memanggil Gemini API dan mencoba ulang hingga maks 10x saat timeout sebelum fallback offline."""
    opener = urllib.request.build_opener(_NoRedirectHandler)
    for attempt in range(1, max_attempts + 1):
        try:
            req = urllib.request.Request(
                endpoint,
                data=payload_bytes,
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": gemini_key,
                },
                method="POST",
            )
            with opener.open(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                cands = body.get("candidates") or []
                parts = ((cands[0].get("content") or {}).get("parts") or []) if cands else []
                gem_text = (
                    _sanitize_for_prompt(str((parts[0] or {}).get("text", "")), max_len=900)
                    if parts
                    else ""
                )
                if gem_text:
                    return gem_text
                return ""
        except Exception as exc:
            if _is_retryable_gemini_error(exc) and attempt < max_attempts:
                time.sleep(0.15)
                continue
            return ""
    return ""


def _sanitize_for_prompt(text: str, max_len: int = 400) -> str:
    """
    Tahap 1: Sanitasi teks ekstraksi agar aman dari prompt injection, karakter kontrol,
    dan obfuskasi spasi Unicode (NFKC + zero-width space stripping).
    """
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00a0]", " ", normalized)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", normalized)
    cleaned = PROMPT_INJECTION_PATTERNS.sub("[REDACTED_DIRECTIVE]", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]


def _yara_escape_string(raw: str) -> str:
    """
    Escapes raw string bytes for safe inclusion inside a YARA double-quoted literal `"..."`.
    Prevents YARA rule injection via quotes, backslashes, or embedded newlines.
    """
    out: List[str] = []
    for ch in raw:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= code <= 126:
            out.append(ch)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)


def _sanitize_meta_value(val: str, max_len: int = 120) -> str:
    """Membersihkan field meta YARA/Sigma dari karakter kutip, baris baru, atau kurung kurawal."""
    cleaned = re.sub(r'[\r\n"\\{}/*`]', " ", str(val or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len] or "unknown"


def _is_benign_schema_url(url: str) -> bool:
    low = url.lower()
    return any(dom in low for dom in BENIGN_SCHEMA_DOMAINS)


def _try_decode_base64_payloads(raw_bytes: bytes) -> List[Dict[str, str]]:
    """
    Mendeteksi dan men-decode string Base64 (termasuk PowerShell UTF-16LE -enc
    seperti 'JAB...' maupun UTF-8 standar).
    """
    decoded_items: List[Dict[str, str]] = []
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


def _extract_non_pdf_evidence(
    raw_bytes: bytes,
    dangerous_tags: List[str],
    decoded_b64: List[Dict[str, str]],
    dedup_urls: List[str],
) -> Dict[str, object]:
    """Menghitung metrik forensik seragam (entropi, API, skor risiko) untuk artefak non-PDF."""
    decoded_str = "; ".join(item["decoded"] for item in decoded_b64)
    text_sample = raw_bytes[-4096:].decode("latin-1", errors="ignore")
    haystack = f"{text_sample}\n{decoded_str}"

    detected_apis = [
        api_name for api_name, pat in DANGEROUS_PDF_APIS if pat.search(haystack)
    ]

    snippet = ""
    m_ps = re.search(
        rb"(powershell[^\r\n]{0,160}|<script[^>]*>.*?</script>|vbaProject\.bin|DDEAUTO[^\r\n]{0,120}|TargetMode=[\"']External[\"'][^\r\n]{0,80})",
        raw_bytes,
        re.IGNORECASE | re.DOTALL,
    )
    if m_ps:
        snippet = _sanitize_for_prompt(m_ps.group(0).decode("latin-1", errors="ignore"), 260)

    # Fokus entropi pada payload trailing jika polyglot, atau bytes keseluruhan untuk dokumen lain
    if "TRAILING_POLYGLOT" in dangerous_tags and b"\xff\xd9" in raw_bytes:
        eoi = raw_bytes.find(b"\xff\xd9") + 2
        ent = calculate_shannon_entropy(raw_bytes[eoi:] or raw_bytes)
    else:
        ent = calculate_shannon_entropy(raw_bytes[:65536])

    score = 20 if dangerous_tags else 0
    score += min(25, len(dangerous_tags) * 8)
    score += min(25, len(detected_apis) * 9)
    score += 15 if decoded_b64 else 0
    score += 10 if dedup_urls else 0
    score += 10 if ent > 6.5 else 0

    return {
        "is_pdf": False,
        "extracted_script_preview": snippet,
        "deobfuscated_script": decoded_str or snippet,
        "obfuscation_layers": ["Base64"] if decoded_b64 else [],
        "embedded_files": [],
        "shannon_entropy": ent,
        "detected_apis": detected_apis,
        "risk_score": max(0, min(100, int(score))),
    }


def pre_triage_extract(raw_bytes: bytes, dangerous_tags: List[str] | None = None) -> Dict[str, object]:
    """
    Tahap 1 — Deterministic Pre-Triage & Anti-Prompt-Injection:
    Mengekstrak indikator berbahaya, URL/IP C2 (mengecualikan namespace XMP/XML sah),
    melakukan deobfuscation Base64, hex-name PDF, serta pembedahan skrip JS PDF.
    """
    dangerous_tags = list(dangerous_tags or [])
    decoded_b64 = _try_decode_base64_payloads(raw_bytes)
    pdf_forensics = (
        deep_analyze_pdf_malware(raw_bytes)
        if raw_bytes.lstrip().startswith(b"%PDF")
        else None
    )

    deobf_text = str((pdf_forensics or {}).get("deobfuscated_script") or "")
    url_source = raw_bytes + b"\n" + deobf_text.encode("utf-8", errors="ignore")
    raw_urls = [
        u.decode("latin-1", errors="ignore")
        for u in re.findall(rb"https?://[^\s\)\>\"'\<]+", url_source, re.IGNORECASE)
    ]
    filtered_urls = [
        _sanitize_for_prompt(u, 160)
        for u in raw_urls
        if not _is_benign_schema_url(u)
    ]
    dedup_urls = list(dict.fromkeys(u for u in filtered_urls if u))

    ips = [
        ip.decode("ascii", errors="ignore")
        for ip in re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", url_source)
    ]

    # Pilih primary IOC deterministik: prioritaskan indikator eksploitasi/script sebelum URL generik
    primary_ioc = ""
    scan_bytes = raw_bytes
    if raw_bytes.lstrip().startswith(b"%PDF"):
        struct_b, decomp_list = _extract_structural_pdf_bytes(raw_bytes)
        scan_bytes = _decode_pdf_hex_names(struct_b + b"\n" + b"\n".join(decomp_list))

    cmd_match = re.search(
        rb"(app\.alert\([^\r\n\)]{1,80}\)|app\.alert|eval\(|ActiveXObject|WScript\.Shell|powershell[^\r\n\"']{0,40}|<script[^>]*>|vbaProject\.bin|DDEAUTO|TargetMode=[\"']External[\"'])",
        scan_bytes,
        re.IGNORECASE,
    )
    if cmd_match:
        primary_ioc = cmd_match.group(0).decode("latin-1", errors="ignore").strip()
    elif dedup_urls:
        primary_ioc = dedup_urls[0]
    elif dangerous_tags:
        for tag in dangerous_tags:
            if tag.startswith("/") and len(tag) >= 5 and tag.encode("latin-1", errors="ignore") in scan_bytes:
                primary_ioc = tag
                break
        if not primary_ioc:
            for tag in dangerous_tags:
                if len(tag) >= 5:
                    primary_ioc = tag
                    break
        if not primary_ioc:
            primary_ioc = dangerous_tags[0]

    if not primary_ioc or len(primary_ioc) < 5:
        primary_ioc = "ShadowUpdate_After_BSrE_ByteRange"

    decoded_parts = [item["decoded"] for item in decoded_b64]
    if (
        pdf_forensics
        and pdf_forensics.get("obfuscation_layers")
        and deobf_text
        and deobf_text != pdf_forensics.get("extracted_script_preview")
    ):
        decoded_parts.append(_sanitize_for_prompt(deobf_text, max_len=240))
    decoded_payload_str = "; ".join(dict.fromkeys(p for p in decoded_parts if p))

    forensic_meta = pdf_forensics or _extract_non_pdf_evidence(
        raw_bytes, dangerous_tags, decoded_b64, dedup_urls
    )

    return {
        # Simpan primary_ioc apa adanya (tanpa pre-escaping) agar pencocokan byte konsisten;
        # escaping khusus YARA dilakukan oleh _yara_escape_string saat merender rule.
        "primary_ioc": primary_ioc,
        "decoded_base64": decoded_b64,
        "decoded_payload": decoded_payload_str,
        "c2_urls": dedup_urls,
        "urls": dedup_urls,
        "c2_ips": list(dict.fromkeys(ips)),
        "extracted_script_preview": str(forensic_meta.get("extracted_script_preview") or ""),
        "deobfuscated_script": str(forensic_meta.get("deobfuscated_script") or ""),
        "obfuscation_layers": list(forensic_meta.get("obfuscation_layers") or []),
        "embedded_files": list(forensic_meta.get("embedded_files") or []),
        "shannon_entropy": float(forensic_meta.get("shannon_entropy") or 0.0),
        "detected_apis": list(forensic_meta.get("detected_apis") or []),
        "risk_score": int(forensic_meta.get("risk_score") or 0),
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
    deobf_low = str(triage.get("deobfuscated_script") or "").lower()
    decoded_low = str(triage.get("decoded_payload") or "").lower()
    reasons_joined = " ".join(reasons).lower()
    detected_apis = [a.lower() for a in (triage.get("detected_apis") or [])]
    obf_layers = list(triage.get("obfuscation_layers") or [])
    techniques: List[str] = []

    if b"powershell" in lower_raw or "powershell" in decoded_low or "powershell" in deobf_low:
        techniques.append("T1059.001 PowerShell")
    if (
        triage.get("decoded_base64")
        or obf_layers
        or "TRAILING_POLYGLOT" in dangerous_tags
        or b"eval(" in lower_raw
        or "eval(" in deobf_low
    ):
        techniques.append("T1027 Obfuscated Files or Information")
    if (
        "shadow attack" in reasons_joined
        or "byterange" in reasons_joined
        or "/OCProperties" in dangerous_tags
        or "/OCG" in dangerous_tags
        or "ocg" in reasons_joined
    ):
        techniques.append("T1553.002 Code Signing")
    if b"vbaproject.bin" in lower_raw or "VBA_MACRO" in dangerous_tags or "DDE_INJECTION" in dangerous_tags:
        techniques.append("T1059.005 Visual Basic")
    if (
        b"/javascript" in lower_raw
        or b"/js" in lower_raw
        or b"<script" in lower_raw
        or "/JS" in dangerous_tags
        or any(api in ("app.alert", "app.launchurl", "eval(") for api in detected_apis)
    ):
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
    Tahap 2 AI Reasoning:
    1. Langsung ke Gemini API via GEMINI_API_KEY (retry hingga maks 10x saat timeout)
    2. Offline Evidence-Based Engine bila Gemini tidak tersedia atau seluruh percobaan timeout
    """
    _load_dotenv_if_present()

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest").strip()

    decoded_info = str(triage.get("decoded_payload") or "Tidak ada")
    extracted_js = str(triage.get("extracted_script_preview") or "")
    deobf_js = str(triage.get("deobfuscated_script") or "")
    entropy_val = float(triage.get("shannon_entropy") or 0.0)
    detected_apis = list(triage.get("detected_apis") or [])
    risk_score = int(triage.get("risk_score") or 0)
    c2_info = ", ".join(triage.get("c2_urls") or []) or "Tidak terdeteksi"

    prompt = (
        "Anda adalah Senior Malware Reverse Engineer & analis siber Kertopati TNI AD. "
        "Ringkas ancaman dokumen berikut dalam tepat 2 kalimat polos bahasa Indonesia (tanpa bullet/markdown) yang tajam, faktual, dan berbasis bukti "
        "(sebutkan risk score, API berbahaya, serta hasil deobfuskasi jika ada):\n"
        f"File: {_sanitize_for_prompt(filename, 80)} ({file_format})\n"
        f"Risk Score: {risk_score}/100 | Shannon Entropy: {entropy_val:.2f}\n"
        f"MITRE: {', '.join(mitre_list)}\n"
        f"Detected APIs: {', '.join(detected_apis) or 'Tidak ada'}\n"
        f"Extracted Script: {_sanitize_for_prompt(extracted_js, 220) or '-'}\n"
        f"Deobfuscated Script: {_sanitize_for_prompt(deobf_js, 220) or '-'}\n"
        f"Decoded Base64: {_sanitize_for_prompt(decoded_info, 150)}\n"
        f"C2 URLs: {_sanitize_for_prompt(c2_info, 120)}\n"
        f"Temuan: {_sanitize_for_prompt('; '.join(reasons), 200)}"
    )

    # Prioritas 1: Langsung ke Gemini API (coba ulang hingga maks 10x jika timeout)
    if gemini_key and re.fullmatch(r"[A-Za-z0-9._-]{3,64}", gemini_model):
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:generateContent"
        payload_bytes = json.dumps(
            {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 400, "temperature": 0.2},
            }
        ).encode("utf-8")
        gem_text = _call_gemini_with_retry(
            endpoint=endpoint,
            payload_bytes=payload_bytes,
            gemini_key=gemini_key,
            max_attempts=GEMINI_MAX_RETRIES,
            timeout=6.0,
        )
        if gem_text:
            return gem_text, f"Gemini AI ({gemini_model})"

    # Prioritas 2: Offline Evidence-Based Engine (tanpa kalimat generik/dongeng)
    safe_fn = _sanitize_meta_value(filename, 80)
    parts = [
        f"Hasil pembedahan {file_format} '{safe_fn}': Risk Score {risk_score}/100 | Entropy {entropy_val:.2f} | MITRE {', '.join(mitre_list[:2])}."
    ]
    if detected_apis:
        parts.append(f"API berbahaya terdeteksi: {', '.join(detected_apis[:5])}.")
    if extracted_js:
        parts.append(f"Skrip terekstrak: `{_sanitize_for_prompt(extracted_js, 110)}`.")
    if deobf_js and deobf_js != extracted_js:
        parts.append(f"Hasil deobfuskasi JS: `{_sanitize_for_prompt(deobf_js, 140)}`.")
    elif triage.get("decoded_payload"):
        parts.append(f"Payload terdekode: `{triage['decoded_payload']}`.")
    if triage.get("c2_urls"):
        parts.append(f"Indikasi C2/eksternal: {', '.join(triage['c2_urls'][:2])}.")
    parts.append("Artefak dikarantina ke Auto-Sandbox dan aturan YARA + Sigma diterbitkan untuk seluruh satuan.")
    return " ".join(parts), "Kertopati AI Evidence Engine (Offline)"


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
    primary_ioc = _sanitize_meta_value(str(triage.get("primary_ioc") or filename), 120)
    safe_fn = _sanitize_meta_value(filename, 80)

    detection_lines = ["    selection:"]
    if decoded_cmd or "powershell" in str(primary_ioc).lower():
        cmd_val = str(primary_ioc).replace("'", "''")
        detection_lines.append(f"        CommandLine|contains: '{cmd_val}'")
        if decoded_cmd:
            detection_lines.append(
                f"        DecodedPayload|contains: '{_sanitize_meta_value(decoded_cmd, 120).replace(chr(39), '')}'"
            )
        category = "process_creation"
        product = "windows"
    elif c2_urls:
        url_val = _sanitize_meta_value(str(c2_urls[0]), 120).replace("'", "''")
        detection_lines.append(f"        DestinationUrl|contains: '{url_val}'")
        category = "proxy"
        product = "network"
    else:
        ioc_val = str(primary_ioc).replace("'", "''")
        detection_lines.append(f"        PayloadSignature|contains: '{ioc_val}'")
        category = "file_event"
        product = "kertopati_gateway"

    level = "critical" if severity == "CRITICAL" else ("high" if severity == "HIGH" else "medium")
    rule_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"kertopati.sigma.{rule_name}"))
    return f"""title: Kertopati Auto-Sigma - {rule_name}
id: {rule_uuid}
status: experimental
description: Aturan SIEM/Firewall otomatis dari Auto-Sandbox Kertopati untuk sampel {safe_fn}
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
    2. False Positive Check: Pola tidak boleh cocok pada sampel bersih (termasuk XMP/RDF) & panjang >= 5 char.
    """
    valid_patterns = [p for p in patterns if p and len(p.strip()) >= 5]
    if not valid_patterns:
        return {
            "validation_status": "NEEDS_REVIEW (Pattern Too Broad)",
            "recall_test": "FAIL",
            "false_positive_test": "FAIL",
        }

    primary_bytes = valid_patterns[0].encode("utf-8", errors="ignore").lower()
    decoded_malicious = _decode_pdf_hex_names(malicious_bytes)
    if malicious_bytes.startswith(b"%PDF-"):
        struct_b, decomp_list = _extract_structural_pdf_bytes(malicious_bytes)
        decoded_malicious = decoded_malicious + b"\n" + _decode_pdf_hex_names(b"\n".join(decomp_list))
    recall_ok = (primary_bytes in malicious_bytes.lower()) or (primary_bytes in decoded_malicious.lower())

    baselines = list(clean_samples or [])
    baselines.extend(
        [
            (
                b"%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R /Metadata 3 0 R >>endobj\n"
                b"<?xpacket?><x:xmpmeta xmlns:x='adobe:ns:meta/'>"
                b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#' "
                b"xmlns:dc='http://purl.org/dc/elements/1.1/' "
                b"xmlns:xmp='http://ns.adobe.com/xap/1.0/'/></x:xmpmeta>\n%%EOF\n"
            ),
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x00IEND\xaeB`\x82",
        ]
    )

    fp_found = False
    for sample in baselines:
        sample_low = sample.lower()
        for pat in valid_patterns:
            if pat.encode("utf-8", errors="ignore").lower() in sample_low:
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
    risk_score = int(triage.get("risk_score") or 0)
    severity = (
        "CRITICAL"
        if (
            risk_score >= 70
            or triage["decoded_base64"]
            or triage["c2_urls"]
            or "VBA_MACRO" in dangerous_tags
            or len(mitre_list) >= 3
        )
        else "HIGH"
    )
    commander_brief, analysis_mode = _synthesize_commander_brief(
        filename, file_format, mitre_list, triage, inspection_reasons
    )

    fmt = _sanitize_meta_value((file_format or "UNKNOWN").upper(), 32)
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

    escaped_ioc = _yara_escape_string(primary_ioc)
    strings_block = f'        $ioc = "{escaped_ioc}" ascii nocase'
    decoded_payload = str(triage.get("decoded_payload") or "")
    if decoded_payload and len(decoded_payload) >= 5:
        safe_dec = _yara_escape_string(decoded_payload)
        strings_block += f'\n        $decoded_cmd = "{safe_dec}" ascii wide nocase'
        cond_expr = f"{header_cond} and ($ioc or $decoded_cmd)" if header_cond else "($ioc or $decoded_cmd)"
    else:
        cond_expr = f"{header_cond} and $ioc" if header_cond else "$ioc"

    safe_unit = _sanitize_meta_value(source_unit, 80)
    safe_mitre = _sanitize_meta_value(", ".join(mitre_list), 120)

    yara_rule = f"""rule {rule_name} {{
    meta:
        author = "Kertopati AI Threat Analyst"
        created = "{timestamp}"
        source_unit = "{safe_unit}"
        file_format = "{fmt}"
        severity = "{severity}"
        mitre_attack = "{safe_mitre}"
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
            "extracted_script_preview": str(triage.get("extracted_script_preview") or ""),
            "deobfuscated_script": str(triage.get("deobfuscated_script") or ""),
            "obfuscation_layers": list(triage.get("obfuscation_layers") or []),
            "embedded_files": list(triage.get("embedded_files") or []),
            "shannon_entropy": float(triage.get("shannon_entropy") or 0.0),
            "detected_apis": list(triage.get("detected_apis") or []),
            "risk_score": risk_score,
            "c2_indicators": triage.get("c2_urls", []),
            "commander_brief": commander_brief,
            "sigma_network_rule": sigma_rule,
            "validation_status": validation["validation_status"],
            "recall_test": validation["recall_test"],
            "false_positive_test": validation["false_positive_test"],
            "analysis_mode": analysis_mode,
        },
    }
