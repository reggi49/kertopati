import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.ai_analyst import (
    _sanitize_meta_value,
    _yara_escape_string,
    analyze_threat_and_synthesize_vaccine,
    validate_vaccine_pattern,
)

RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")

FORBIDDEN_OVERBROAD_PATTERNS = {
    "%pdf",
    "%pdf-",
    "%pdf-1.",
    "obj",
    "endobj",
    "stream",
    "endstream",
    "xref",
    "trailer",
    "startxref",
    "%%eof",
    "/type",
    "/page",
    "/pages",
    "/catalog",
    "/font",
    "/filter",
    "/flatedecode",
    "/byterange",
    "/contents",
    "jfif",
    "ihdr",
    "idat",
    "iend",
    "pk\x03\x04",
    "xml",
    "xmlns",
    "http://",
    "https://",
}


class SandboxVaccineEngine:
    """
    Stealth Auto-Sandbox (Plasebo) & Generator Aturan YARA ("Vaksin"):
    - Mengkarantina dokumen berbahaya tanpa memberi tahu pelaku.
    - Mengekstrak indikator berbahaya (script/payload/tag).
    - Menghasilkan file aturan YARA (.yar) otomatis untuk seluruh satuan.
    """

    def __init__(self, base_dir: str = "data"):
        self.quarantine_dir = Path(base_dir) / "sandbox_quarantine"
        self.vaccine_dir = Path(base_dir) / "vaccines"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.vaccine_dir.mkdir(parents=True, exist_ok=True)
        self.rules_index_path = self.vaccine_dir / "active_vaccines.json"
        self.events_path = self.quarantine_dir / "sandbox_events.json"

        if not self.rules_index_path.exists():
            self.rules_index_path.write_text("[]", encoding="utf-8")
        if not self.events_path.exists():
            self.events_path.write_text("[]", encoding="utf-8")

    def get_active_vaccines(self) -> List[dict]:
        vaccines = json.loads(self.rules_index_path.read_text(encoding="utf-8"))
        for v in vaccines:
            if "enabled" not in v:
                v["enabled"] = True
        return vaccines

    def get_enabled_vaccines(self) -> List[dict]:
        return [v for v in self.get_active_vaccines() if v.get("enabled", True)]

    def get_sandbox_events(self) -> List[dict]:
        return json.loads(self.events_path.read_text(encoding="utf-8"))

    def detonate_and_vaccinate(
        self,
        filename: str,
        raw_bytes: bytes,
        source_unit: str,
        inspection_reasons: List[str],
        dangerous_tags: List[str],
        file_format: str = "PDF",
    ) -> dict:
        doc_hash = hashlib.sha256(raw_bytes).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Simpan salinan terisolasi ke Sandbox Quarantine
        safe_fn = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "sample.bin"
        quarantine_file = self.quarantine_dir / f"{doc_hash[:12]}_{safe_fn}"
        quarantine_file.write_bytes(raw_bytes)

        # 2. Siapkan baseline sampel bersih untuk ABLE Self-Validation Gate
        clean_baselines: List[bytes] = []
        demo_dir = Path(__file__).resolve().parent.parent / "demo_samples"
        if demo_dir.exists():
            for sample_path in demo_dir.iterdir():
                if sample_path.is_file() and "bersih" in sample_path.name.lower():
                    clean_baselines.append(sample_path.read_bytes())

        # 3. Jalankan Pipeline 3-Tahap AI Threat Analyst & Multi-Layer Vaccine
        fmt = (file_format or "UNKNOWN").upper()
        synthesis = analyze_threat_and_synthesize_vaccine(
            filename=filename,
            raw_bytes=raw_bytes,
            source_unit=source_unit,
            file_format=fmt,
            inspection_reasons=inspection_reasons,
            dangerous_tags=dangerous_tags,
            clean_baselines=clean_baselines,
        )
        extracted_ioc = str(synthesis["primary_ioc"])
        rule_name = str(synthesis["rule_name"])
        yara_content = str(synthesis["yara_rule"])
        ai_analysis = synthesis["ai_analysis"]
        validation_status = str(ai_analysis.get("validation_status", ""))
        is_validated = validation_status.startswith("VALIDATED")

        yara_path = self.vaccine_dir / f"{rule_name}.yar"
        yara_path.write_text(yara_content, encoding="utf-8")

        # 4. Daftarkan vaksin ke Policy Engine (hanya aktif otomatis jika lulus Self-Validation Gate)
        vaccines = self.get_active_vaccines()
        if not any(v["pattern"] == extracted_ioc for v in vaccines):
            vaccines.insert(
                0,
                {
                    "rule_name": rule_name,
                    "pattern": extracted_ioc,
                    "file_format": fmt,
                    "enabled": is_validated,
                    "created_at": timestamp,
                    "yara_file": str(yara_path.name),
                    "yara_preview": yara_content,
                    "ai_analysis": ai_analysis,
                },
            )
            self.rules_index_path.write_text(json.dumps(vaccines, indent=2), encoding="utf-8")

        # 5. Catat event Sandbox
        events = self.get_sandbox_events()
        sha256_prefix = doc_hash[:12]
        event = {
            "timestamp": timestamp,
            "filename": filename,
            "file_format": fmt,
            "source_unit": source_unit,
            "sha256": doc_hash[:16] + "...",
            "sha256_prefix": sha256_prefix,
            "quarantine_file": quarantine_file.name,
            "reasons": inspection_reasons,
            "extracted_ioc": extracted_ioc,
            "generated_vaccine": rule_name,
            "ai_analysis": ai_analysis,
            "hitl_status": "PENDING_REVIEW",
            "hitl_note": "",
            "hitl_sanitized_download_url": "",
            "placebo_response": "200 OK - Dokumen diterima di antrean (Pelaku tidak sadar dialihkan)",
        }
        events.insert(0, event)
        self.events_path.write_text(json.dumps(events[:30], indent=2), encoding="utf-8")

        return event

    def get_event_by_prefix(self, sha256_prefix: str) -> dict | None:
        """Mencari event sandbox berdasarkan prefix SHA-256."""
        for ev in self.get_sandbox_events():
            if ev.get("sha256_prefix") == sha256_prefix or ev.get("sha256", "").startswith(sha256_prefix):
                return ev
        return None

    def update_event_hitl(
        self,
        sha256_prefix: str,
        hitl_status: str,
        hitl_note: str,
        sanitized_download_url: str = "",
    ) -> dict | None:
        """Memperbarui status Human-in-the-Loop (HITL) pada event sandbox."""
        events = self.get_sandbox_events()
        updated = None
        for ev in events:
            if ev.get("sha256_prefix") == sha256_prefix or ev.get("sha256", "").startswith(sha256_prefix):
                ev["hitl_status"] = hitl_status
                ev["hitl_note"] = hitl_note
                if sanitized_download_url:
                    ev["hitl_sanitized_download_url"] = sanitized_download_url
                updated = ev
                break
        if updated is not None:
            self.events_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
        return updated

    def reset(self) -> None:
        """Membersihkan seluruh sampel karantina, event sandbox, dan aturan vaksin."""
        for p in self.quarantine_dir.iterdir():
            if p.is_file():
                p.unlink()
        for p in self.vaccine_dir.iterdir():
            if p.is_file():
                p.unlink()
        self.rules_index_path.write_text("[]", encoding="utf-8")
        self.events_path.write_text("[]", encoding="utf-8")

    def toggle_vaccine(self, rule_name: str) -> dict | None:
        """Mengaktifkan atau menonaktifkan aturan vaksin berdasarkan rule_name."""
        vaccines = self.get_active_vaccines()
        updated = None
        for v in vaccines:
            if v["rule_name"] == rule_name:
                v["enabled"] = not v.get("enabled", True)
                updated = v
                break
        if updated is not None:
            self.rules_index_path.write_text(json.dumps(vaccines, indent=2), encoding="utf-8")
        return updated

    def export_vaccines(self) -> dict:
        """Mengekspor seluruh vaksin aktif (enabled == True) sebagai bundle sinkronisasi offline."""
        enabled = self.get_enabled_vaccines()
        return {
            "bundle_version": "1.0",
            "source": "SandiSeal-Pusat",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(enabled),
            "vaccines": enabled,
        }

    def import_vaccines(self, bundle: dict | list) -> dict:
        """
        Mengimpor bundle vaksin dari Pusat ke node Kodim/Korem secara offline.
        Memvalidasi nama rule (anti-XSS/injeksi) dan menguji setiap pattern dengan
        Self-Validation Gate agar pola terlalu umum (mis. '%PDF') ditolak otomatis.
        """
        incoming = bundle.get("vaccines", []) if isinstance(bundle, dict) else bundle
        if not isinstance(incoming, list):
            raise ValueError("Format bundle vaksin tidak valid.")

        clean_baselines: List[bytes] = []
        demo_dir = Path(__file__).resolve().parent.parent / "demo_samples"
        if demo_dir.exists():
            for sample_path in demo_dir.iterdir():
                if sample_path.is_file() and "bersih" in sample_path.name.lower():
                    clean_baselines.append(sample_path.read_bytes())

        vaccines = self.get_active_vaccines()
        existing_names = {v["rule_name"] for v in vaccines}
        existing_patterns = {v["pattern"] for v in vaccines}
        imported_count = 0
        rejected_count = 0

        for item in incoming:
            if not isinstance(item, dict):
                rejected_count += 1
                continue
            rule_name = str(item.get("rule_name") or "").strip()
            pattern = str(item.get("pattern") or "").strip()
            if not rule_name or not pattern:
                rejected_count += 1
                continue
            if not RULE_NAME_RE.match(rule_name):
                rejected_count += 1
                continue
            if len(pattern) < 5 or pattern.lower() in FORBIDDEN_OVERBROAD_PATTERNS:
                rejected_count += 1
                continue

            gate = validate_vaccine_pattern(
                patterns=[pattern],
                malicious_bytes=pattern.encode("utf-8", errors="ignore"),
                clean_samples=clean_baselines,
            )
            if gate["false_positive_test"] != "PASS" or gate["recall_test"] != "PASS":
                rejected_count += 1
                continue

            if rule_name in existing_names or pattern in existing_patterns:
                continue

            escaped_pat = _yara_escape_string(pattern)
            safe_fmt = _sanitize_meta_value(item.get("file_format", "UNKNOWN"), 32)
            yara_preview = (
                f"rule {rule_name} {{\n"
                f"    meta:\n"
                f'        author = "Kertopati AI Threat Analyst"\n'
                f'        file_format = "{safe_fmt}"\n'
                f'        validation_status = "VALIDATED (0% FP on Baseline)"\n'
                f"    strings:\n"
                f'        $ioc = "{escaped_pat}" ascii nocase\n'
                f"    condition:\n"
                f"        uint32(0) == 0x46445025 and $ioc\n"
                f"}}\n"
            )
            yara_file = f"{rule_name}.yar"
            (self.vaccine_dir / yara_file).write_text(yara_preview, encoding="utf-8")

            vaccines.insert(
                0,
                {
                    "rule_name": rule_name,
                    "pattern": pattern,
                    "file_format": safe_fmt,
                    "enabled": bool(item.get("enabled", True)),
                    "created_at": item.get("created_at") or datetime.now(timezone.utc).isoformat(),
                    "yara_file": yara_file,
                    "yara_preview": yara_preview,
                    "ai_analysis": item.get("ai_analysis") or {},
                },
            )
            existing_names.add(rule_name)
            existing_patterns.add(pattern)
            imported_count += 1

        self.rules_index_path.write_text(json.dumps(vaccines, indent=2), encoding="utf-8")
        return {
            "imported_count": imported_count,
            "rejected_count": rejected_count,
            "total_vaccines": len(vaccines),
        }
