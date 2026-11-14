import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class ChainOfCustodyLedger:
    """
    Append-only HMAC-SHA256 Ledger dengan Signed Head Checkpoint untuk mencatat
    rantai perpindahan dokumen berjenjang (Kodim -> Korem -> Pusat) secara
    tamper-evident (tahan terhadap modifikasi baris, penghapusan blok/truncation,
    maupun percobaan re-hash seluruh tabel tanpa kunci kriptografi).
    """

    def __init__(self, db_path: str = "data/ledger.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = str(db_path)
        self.key_path = f"{self.db_path}.key"
        self.head_path = f"{self.db_path}.head.json"
        self._secret_key = self._load_or_create_key()
        self._init_db()

    def _load_or_create_key(self) -> bytes:
        env_key = os.environ.get("KERTOPATI_LEDGER_KEY", "").strip()
        if env_key:
            return env_key.encode("utf-8")
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, "rb") as f:
                    data = f.read().strip()
                    if len(data) >= 32:
                        return data
            except OSError:
                pass
        key = secrets.token_hex(32).encode("ascii")
        try:
            with open(self.key_path, "wb") as f:
                f.write(key)
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def _compute_block_hmac(self, payload_dict: Dict[str, Any]) -> str:
        payload = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        return hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()

    def _write_head_checkpoint(self, block_count: int, last_index: int, head_hash: str) -> None:
        sig_input = f"{block_count}:{last_index}:{head_hash}".encode("utf-8")
        head_hmac = hmac.new(self._secret_key, sig_input, hashlib.sha256).hexdigest()
        data = {
            "block_count": block_count,
            "last_index": last_index,
            "head_hash": head_hash,
            "head_hmac": head_hmac,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            with open(self.head_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.chmod(self.head_path, 0o600)
        except OSError:
            pass

    def _read_head_checkpoint(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.head_path):
            return None
        try:
            with open(self.head_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"corrupt": True}

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS custody_blocks (
                    block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_format TEXT NOT NULL DEFAULT 'PDF',
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
            cols = [r[1] for r in conn.execute("PRAGMA table_info(custody_blocks)").fetchall()]
            if "file_format" not in cols:
                conn.execute("ALTER TABLE custody_blocks ADD COLUMN file_format TEXT NOT NULL DEFAULT 'PDF'")
            conn.commit()
            if not os.path.exists(self.head_path):
                rows = conn.execute(
                    "SELECT block_index, block_hash FROM custody_blocks ORDER BY block_index ASC"
                ).fetchall()
                if rows:
                    self._write_head_checkpoint(len(rows), int(rows[-1][0]), str(rows[-1][1]))
                else:
                    self._write_head_checkpoint(0, 0, "0" * 64)

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
        file_format: str = "PDF",
    ) -> dict:
        doc_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            prev_hash = self._get_last_hash(conn)
            block_hash = self._compute_block_hmac(
                {
                    "timestamp": timestamp,
                    "filename": filename,
                    "file_format": file_format,
                    "doc_sha256": doc_sha256,
                    "source_unit": source_unit,
                    "target_unit": target_unit,
                    "bsre_status": bsre_status,
                    "verdict": verdict,
                    "prev_hash": prev_hash,
                }
            )
            cur = conn.execute(
                """
                INSERT INTO custody_blocks
                (timestamp, filename, file_format, doc_sha256, source_unit, target_unit, bsre_status, verdict, prev_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    filename,
                    file_format,
                    doc_sha256,
                    source_unit,
                    target_unit,
                    bsre_status,
                    verdict,
                    prev_hash,
                    block_hash,
                ),
            )
            last_id = int(cur.lastrowid or 0)
            cnt_row = conn.execute("SELECT COUNT(*) FROM custody_blocks").fetchone()
            total_cnt = int(cnt_row[0]) if cnt_row else 1
            conn.commit()

        self._write_head_checkpoint(total_cnt, last_id, block_hash)

        return {
            "block_index": last_id,
            "timestamp": timestamp,
            "filename": filename,
            "file_format": file_format,
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
        Menghitung ulang seluruh prev_hash dan HMAC-SHA256 block_hash dari blok pertama
        hingga terakhir, serta memverifikasi Signed Head Checkpoint untuk mendeteksi
        modifikasi isi, penghapusan blok terakhir (truncation), atau re-hash ilegal.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM custody_blocks ORDER BY block_index ASC"
            ).fetchall()

        expected_prev_hash = "0" * 64
        tampered_blocks: List[dict] = []

        for expected_idx, row in enumerate(rows, start=1):
            block = dict(row)
            block_idx = block["block_index"]
            reasons: List[str] = []

            if block_idx != expected_idx:
                reasons.append(f"urutan block_index terputus (diharapkan #{expected_idx}, ditemukan #{block_idx})")

            if block["prev_hash"] != expected_prev_hash:
                reasons.append("prev_hash tidak cocok dengan block_hash sebelumnya")

            recomputed_hash = self._compute_block_hmac(
                {
                    "timestamp": block["timestamp"],
                    "filename": block["filename"],
                    "file_format": block.get("file_format", "PDF"),
                    "doc_sha256": block["doc_sha256"],
                    "source_unit": block["source_unit"],
                    "target_unit": block["target_unit"],
                    "bsre_status": block["bsre_status"],
                    "verdict": block["verdict"],
                    "prev_hash": block["prev_hash"],
                }
            )

            if not hmac.compare_digest(str(block["block_hash"]), recomputed_hash):
                reasons.append("block_hash tidak cocok dengan isi blok (indikasi manipulasi data / kunci HMAC tidak sah)")

            if reasons:
                tampered_blocks.append(
                    {
                        "block_index": block_idx,
                        "filename": block["filename"],
                        "reasons": reasons,
                    }
                )

            expected_prev_hash = block["block_hash"]

        head = self._read_head_checkpoint()
        if head is not None:
            if head.get("corrupt"):
                tampered_blocks.append(
                    {
                        "block_index": len(rows) + 1,
                        "filename": "LEDGER_HEAD_SEAL",
                        "reasons": ["File segel kepala ledger rusak atau dimodifikasi"],
                    }
                )
            else:
                exp_cnt = int(head.get("block_count", 0))
                exp_last = int(head.get("last_index", 0))
                exp_hash = str(head.get("head_hash", "0" * 64))
                stored_hmac = str(head.get("head_hmac", ""))
                sig_input = f"{exp_cnt}:{exp_last}:{exp_hash}".encode("utf-8")
                calc_hmac = hmac.new(self._secret_key, sig_input, hashlib.sha256).hexdigest()

                if not hmac.compare_digest(stored_hmac, calc_hmac):
                    tampered_blocks.append(
                        {
                            "block_index": exp_last or 1,
                            "filename": "LEDGER_HEAD_SEAL",
                            "reasons": ["Segel HMAC kepala ledger tidak valid"],
                        }
                    )
                elif len(rows) != exp_cnt:
                    tampered_blocks.append(
                        {
                            "block_index": exp_last or (len(rows) + 1),
                            "filename": "CHAIN_TRUNCATION",
                            "reasons": [
                                f"Penghapusan blok (Truncation Attack) terdeteksi: jumlah blok {len(rows)} != segel {exp_cnt}"
                            ],
                        }
                    )
                elif rows and not hmac.compare_digest(str(rows[-1]["block_hash"]), exp_hash):
                    last_b_idx = int(rows[-1]["block_index"])
                    if not any(tb["block_index"] == last_b_idx for tb in tampered_blocks):
                        tampered_blocks.append(
                            {
                                "block_index": last_b_idx,
                                "filename": str(rows[-1]["filename"]),
                                "reasons": ["Hash blok terakhir tidak cocok dengan segel kepala ledger"],
                            }
                        )

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
        self._write_head_checkpoint(0, 0, "0" * 64)

    def simulate_tamper(self, block_index: int | None = None) -> dict:
        """
        Mensimulasikan manipulasi manual 1 field pada blok ledger (untuk demo uji tamper)
        tanpa mengubah block_hash, sehingga verify_chain() mendeteksi kerusakan rantai.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if block_index is not None:
                row = conn.execute(
                    "SELECT * FROM custody_blocks WHERE block_index = ?",
                    (block_index,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM custody_blocks WHERE block_index = 2"
                ).fetchone()
                if row is None:
                    row = conn.execute(
                        "SELECT * FROM custody_blocks ORDER BY block_index DESC LIMIT 1"
                    ).fetchone()

            if row is None:
                return {"error": "Belum ada blok di ledger untuk disimulasikan tamper."}

            target_idx = row["block_index"]
            original_verdict = row["verdict"]
            tampered_verdict = (
                original_verdict + " [PAYLOAD_SISIPAN_TAMPERED]"
                if "[PAYLOAD_SISIPAN_TAMPERED]" not in original_verdict
                else original_verdict + "!"
            )
            conn.execute(
                "UPDATE custody_blocks SET verdict = ? WHERE block_index = ?",
                (tampered_verdict, target_idx),
            )
            conn.commit()

        verification = self.verify_chain()
        return {
            "tampered_block_index": target_idx,
            "original_verdict": original_verdict,
            "tampered_verdict": tampered_verdict,
            "verification": verification,
        }
