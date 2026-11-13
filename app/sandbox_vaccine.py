import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List


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
        return json.loads(self.rules_index_path.read_text(encoding="utf-8"))

    def get_sandbox_events(self) -> List[dict]:
        return json.loads(self.events_path.read_text(encoding="utf-8"))

    def detonate_and_vaccinate(
        self,
        filename: str,
        raw_bytes: bytes,
        source_unit: str,
        inspection_reasons: List[str],
        dangerous_tags: List[str],
    ) -> dict:
        doc_hash = hashlib.sha256(raw_bytes).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Simpan salinan terisolasi ke Sandbox Quarantine
        quarantine_file = self.quarantine_dir / f"{doc_hash[:12]}_{Path(filename).name}"
        quarantine_file.write_bytes(raw_bytes)

        # 2. Ekstrak fragmen string berbahaya dari payload PDF (simulasi analisis sandbox)
        extracted_ioc = "ShadowUpdate_After_BSrE_ByteRange"
        js_snippet = re.search(rb"(app\.alert|eval\(|ActiveXObject|WScript\.Shell|http[s]?://[^\s\)\>]+)", raw_bytes)
        if js_snippet:
            extracted_ioc = js_snippet.group(0).decode("latin-1", errors="ignore")
        elif dangerous_tags:
            extracted_ioc = dangerous_tags[0]

        # 3. Generate Aturan YARA ("Vaksin")
        rule_name = f"SandiSeal_Vaccine_{doc_hash[:8]}"
        yara_content = f"""rule {rule_name} {{
    meta:
        author = "SandiSeal Auto-Sandbox"
        created = "{timestamp}"
        source_unit = "{source_unit}"
        sample_sha256 = "{doc_hash}"
        description = "Auto-generated vaccine from stealth sandbox detonation"
    strings:
        $ioc = "{extracted_ioc}" ascii nocase
    condition:
        uint32(0) == 0x46445025 and $ioc
}}
"""
        yara_path = self.vaccine_dir / f"{rule_name}.yar"
        yara_path.write_text(yara_content, encoding="utf-8")

        # 4. Daftarkan vaksin aktif ke Policy Engine
        vaccines = self.get_active_vaccines()
        if not any(v["pattern"] == extracted_ioc for v in vaccines):
            vaccines.insert(
                0,
                {
                    "rule_name": rule_name,
                    "pattern": extracted_ioc,
                    "created_at": timestamp,
                    "yara_file": str(yara_path.name),
                    "yara_preview": yara_content,
                },
            )
            self.rules_index_path.write_text(json.dumps(vaccines, indent=2), encoding="utf-8")

        # 5. Catat event Sandbox
        events = self.get_sandbox_events()
        event = {
            "timestamp": timestamp,
            "filename": filename,
            "source_unit": source_unit,
            "sha256": doc_hash[:16] + "...",
            "reasons": inspection_reasons,
            "extracted_ioc": extracted_ioc,
            "generated_vaccine": rule_name,
            "placebo_response": "200 OK - Dokumen diterima di antrean (Pelaku tidak sadar dialihkan)",
        }
        events.insert(0, event)
        self.events_path.write_text(json.dumps(events[:30], indent=2), encoding="utf-8")

        return event

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
