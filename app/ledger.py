import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List


class ChainOfCustodyLedger:
    """
    Append-only SHA-256 Ledger untuk mencatat rantai perpindahan dokumen
    berjenjang (Kodim -> Korem -> Pusat) secara tamper-evident.
    """

    def __init__(self, db_path: str = "data/ledger.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS custody_blocks (
                    block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    doc_sha256 TEXT NOT NULL,
                    source_unit TEXT NOT NULL,
                    target_unit TEXT NOT NULL,
                    bsre_status TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _get_last_hash(self, conn: sqlite3.Connection) -> str:
        cur = conn.execute(
            "SELECT block_hash FROM custody_blocks ORDER BY block_index DESC LIMIT 1"
        )
        row = cur.fetchone()
        return row[0] if row else "0" * 64

    def append_block(
        self,
        filename: str,
        raw_bytes: bytes,
        source_unit: str,
        target_unit: str,
        bsre_status: str,
        verdict: str,
    ) -> dict:
        doc_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            prev_hash = self._get_last_hash(conn)
            payload = json.dumps(
                {
                    "timestamp": timestamp,
                    "filename": filename,
                    "doc_sha256": doc_sha256,
                    "source_unit": source_unit,
                    "target_unit": target_unit,
                    "bsre_status": bsre_status,
                    "verdict": verdict,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
            )
            block_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            conn.execute(
                """
                INSERT INTO custody_blocks
                (timestamp, filename, doc_sha256, source_unit, target_unit, bsre_status, verdict, prev_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    filename,
                    doc_sha256,
                    source_unit,
                    target_unit,
                    bsre_status,
                    verdict,
                    prev_hash,
                    block_hash,
                ),
            )
            conn.commit()

        return {
            "timestamp": timestamp,
            "filename": filename,
            "doc_sha256": doc_sha256,
            "source_unit": source_unit,
            "target_unit": target_unit,
            "bsre_status": bsre_status,
            "verdict": verdict,
            "prev_hash": prev_hash[:16] + "...",
            "block_hash": block_hash[:16] + "...",
        }

    def list_blocks(self) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM custody_blocks ORDER BY block_index DESC LIMIT 50"
            ).fetchall()
            return [dict(r) for r in rows]

    def verify_chain(self) -> dict:
        """
        Menghitung ulang seluruh prev_hash dan block_hash dari blok pertama
        hingga terakhir untuk membuktikan rantai Kodim -> Korem -> Pusat
        belum pernah dimodifikasi (tamper-evident).
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM custody_blocks ORDER BY block_index ASC"
            ).fetchall()

        expected_prev_hash = "0" * 64
        tampered_blocks: List[dict] = []

        for row in rows:
            block = dict(row)
            block_idx = block["block_index"]
            reasons: List[str] = []

            if block["prev_hash"] != expected_prev_hash:
                reasons.append("prev_hash tidak cocok dengan block_hash sebelumnya")

            payload = json.dumps(
                {
                    "timestamp": block["timestamp"],
                    "filename": block["filename"],
                    "doc_sha256": block["doc_sha256"],
                    "source_unit": block["source_unit"],
                    "target_unit": block["target_unit"],
                    "bsre_status": block["bsre_status"],
                    "verdict": block["verdict"],
                    "prev_hash": block["prev_hash"],
                },
                sort_keys=True,
            )
            recomputed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if block["block_hash"] != recomputed_hash:
                reasons.append("block_hash tidak cocok dengan isi blok (indikasi manipulasi data)")

            if reasons:
                tampered_blocks.append(
                    {
                        "block_index": block_idx,
                        "filename": block["filename"],
                        "reasons": reasons,
                    }
                )

            expected_prev_hash = block["block_hash"]

        is_valid = len(tampered_blocks) == 0
        return {
            "valid": is_valid,
            "status": "VERIFIED" if is_valid else "TAMPERED",
            "total_blocks": len(rows),
            "tampered_blocks": tampered_blocks,
        }

    def reset(self) -> None:
        """Membersihkan seluruh isi ledger untuk keperluan reset demo."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM custody_blocks")
            conn.execute("DELETE FROM sqlite_sequence WHERE name = 'custody_blocks'")
            conn.commit()
