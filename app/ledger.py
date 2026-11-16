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

    @staticmethod
    def _block_payload_dict(block: Dict[str, Any]) -> Dict[str, Any]:
        return {
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

    EDITABLE_FIELDS = ("verdict", "filename", "source_unit", "target_unit", "bsre_status", "doc_sha256")

    def _sanitize_updates(self, updates: Optional[Dict[str, Any]]) -> Dict[str, str]:
        if not updates:
            return {}
        clean: Dict[str, str] = {}
        for k, v in updates.items():
            if k in self.EDITABLE_FIELDS and v is not None:
                clean[k] = str(v).strip()[:500]
        return clean

    def inspect_blocks(self) -> dict:
        """
        Mengembalikan bedah kriptografi lengkap tiap blok: canonical JSON payload,
        stored block_hash, recomputed HMAC-SHA256, plain SHA-256, serta status Head Checkpoint.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM custody_blocks ORDER BY block_index ASC"
            ).fetchall()

        expected_prev_hash = "0" * 64
        detailed_blocks: List[dict] = []

        for expected_idx, row in enumerate(rows, start=1):
            block = dict(row)
            block_idx = int(block["block_index"])
            payload_dict = self._block_payload_dict(block)
            canonical_json = json.dumps(payload_dict, sort_keys=True)
            recomputed_hmac = hmac.new(
                self._secret_key, canonical_json.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            plain_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

            index_valid = block_idx == expected_idx
            prev_link_valid = block["prev_hash"] == expected_prev_hash
            hmac_valid = hmac.compare_digest(str(block["block_hash"]), recomputed_hmac)
            plain_sha_matched_stored = hmac.compare_digest(str(block["block_hash"]), plain_sha256)

            reasons: List[str] = []
            if not index_valid:
                reasons.append(f"urutan block_index terputus (diharapkan #{expected_idx}, ditemukan #{block_idx})")
            if not prev_link_valid:
                reasons.append("prev_hash tidak cocok dengan block_hash sebelumnya")
            if not hmac_valid:
                if plain_sha_matched_stored:
                    reasons.append("block_hash memakai SHA-256 polos tanpa kunci HMAC server (indikasi Naive Re-Hash Attack)")
                else:
                    reasons.append("block_hash tidak cocok dengan HMAC-SHA256 isi blok (data telah dimodifikasi)")

            detailed_blocks.append(
                {
                    **block,
                    "canonical_json": canonical_json,
                    "recomputed_hmac": recomputed_hmac,
                    "plain_sha256": plain_sha256,
                    "expected_prev_hash": expected_prev_hash,
                    "index_valid": index_valid,
                    "prev_link_valid": prev_link_valid,
                    "hmac_valid": hmac_valid,
                    "plain_sha_matched_stored": plain_sha_matched_stored,
                    "block_valid": len(reasons) == 0,
                    "reasons": reasons,
                }
            )
            expected_prev_hash = str(block["block_hash"])

        head = self._read_head_checkpoint()
        head_info: Dict[str, Any] = {"present": head is not None}
        if head is not None and not head.get("corrupt"):
            exp_cnt = int(head.get("block_count", 0))
            exp_last = int(head.get("last_index", 0))
            exp_hash = str(head.get("head_hash", "0" * 64))
            stored_hmac = str(head.get("head_hmac", ""))
            sig_input = f"{exp_cnt}:{exp_last}:{exp_hash}".encode("utf-8")
            calc_hmac = hmac.new(self._secret_key, sig_input, hashlib.sha256).hexdigest()
            head_info.update(
                {
                    "corrupt": False,
                    "block_count": exp_cnt,
                    "actual_count": len(rows),
                    "last_index": exp_last,
                    "head_hash": exp_hash,
                    "head_hmac": stored_hmac,
                    "updated_at": head.get("updated_at"),
                    "head_hmac_valid": hmac.compare_digest(stored_hmac, calc_hmac),
                    "count_matches": len(rows) == exp_cnt,
                    "head_hash_matches": (not rows and exp_hash == "0" * 64)
                    or (bool(rows) and hmac.compare_digest(str(rows[-1]["block_hash"]), exp_hash)),
                }
            )
        elif head is not None:
            head_info.update({"corrupt": True, "head_hmac_valid": False, "count_matches": False, "head_hash_matches": False})

        verification = self.verify_chain()
        return {
            "blocks": list(reversed(detailed_blocks)),
            "head_checkpoint": head_info,
            "verification": verification,
        }

    def attack_edit_block(
        self,
        block_index: Optional[int] = None,
        updates: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """Serangan Level 1: Mengubah kolom blok langsung di SQLite tanpa mengubah hash."""
        clean_updates = self._sanitize_updates(updates)
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
                ).fetchone() or conn.execute(
                    "SELECT * FROM custody_blocks ORDER BY block_index DESC LIMIT 1"
                ).fetchone()

            if row is None:
                return {"error": "Belum ada blok di ledger untuk dimanipulasi."}

            target_idx = int(row["block_index"])
            if not clean_updates:
                orig_v = str(row["verdict"])
                clean_updates = {
                    "verdict": (
                        orig_v + " [PAYLOAD_SISIPAN_TAMPERED]"
                        if "[PAYLOAD_SISIPAN_TAMPERED]" not in orig_v
                        else orig_v + "!"
                    )
                }

            before = {k: row[k] for k in clean_updates}
            set_clause = ", ".join(f"{col} = ?" for col in clean_updates)
            params = list(clean_updates.values()) + [target_idx]
            conn.execute(
                f"UPDATE custody_blocks SET {set_clause} WHERE block_index = ?",
                params,
            )
            conn.commit()

        mutation_ops = [
            f"MUTATE BLOCK #{target_idx} :: {col}: {before[col]!r} -> {val!r}"
            for col, val in clean_updates.items()
        ]
        verification = self.verify_chain()
        return {
            "attack_type": "edit_field",
            "target_block_index": target_idx,
            "before": before,
            "after": clean_updates,
            "mutation_ops": mutation_ops,
            "verification": verification,
        }

    def attack_rehash_cascade(
        self,
        block_index: Optional[int] = None,
        updates: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """
        Serangan Level 2 (Naive Re-Hash Cascade): Penyerang mengubah isi blok lalu menghitung
        ulang SHA-256 polos dari blok target hingga blok terakhir agar prev_hash terlihat nyambung,
        namun tetap terdeteksi karena verifier memakai HMAC-SHA256 + Signed Head Checkpoint.
        """
        clean_updates = self._sanitize_updates(updates)
        mutation_ops: List[str] = []

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM custody_blocks ORDER BY block_index ASC").fetchall()
            ]
            if not rows:
                return {"error": "Belum ada blok di ledger untuk diserang."}

            if block_index is None:
                target_pos = 1 if len(rows) >= 2 else len(rows) - 1
            else:
                matches = [i for i, r in enumerate(rows) if int(r["block_index"]) == int(block_index)]
                if not matches:
                    return {"error": f"Blok #{block_index} tidak ditemukan di ledger."}
                target_pos = matches[0]

            target_row = rows[target_pos]
            target_idx = int(target_row["block_index"])
            if not clean_updates or all(str(target_row[k]) == v for k, v in clean_updates.items()):
                orig_v = str(target_row["verdict"])
                clean_updates["verdict"] = (
                    orig_v + " [FORGED_CLEAN_BYPASS]"
                    if "[FORGED_CLEAN_BYPASS]" not in orig_v
                    else orig_v + "!"
                )

            before = {k: target_row[k] for k in clean_updates}
            for k, v in clean_updates.items():
                target_row[k] = v
                mutation_ops.append(f"MUTATE BLOCK #{target_idx} :: {k}: {before[k]!r} -> {v!r}")

            prev_h = rows[target_pos - 1]["block_hash"] if target_pos > 0 else "0" * 64
            for pos in range(target_pos, len(rows)):
                cur_row = rows[pos]
                cur_idx = int(cur_row["block_index"])
                cur_row["prev_hash"] = prev_h
                forged_payload = json.dumps(self._block_payload_dict(cur_row), sort_keys=True).encode("utf-8")
                forged_sha256 = hashlib.sha256(forged_payload).hexdigest()
                cur_row["block_hash"] = forged_sha256

                conn.execute(
                    """
                    UPDATE custody_blocks
                    SET filename = ?, source_unit = ?, target_unit = ?, bsre_status = ?,
                        verdict = ?, doc_sha256 = ?, prev_hash = ?, block_hash = ?
                    WHERE block_index = ?
                    """,
                    (
                        cur_row["filename"],
                        cur_row["source_unit"],
                        cur_row["target_unit"],
                        cur_row["bsre_status"],
                        cur_row["verdict"],
                        cur_row["doc_sha256"],
                        cur_row["prev_hash"],
                        cur_row["block_hash"],
                        cur_idx,
                    ),
                )
                mutation_ops.append(
                    f"REHASH_PLAIN_SHA256 BLOCK #{cur_idx} :: prev={str(prev_h)[:12]}... -> sha256={forged_sha256[:12]}... (tanpa kunci HMAC)"
                )
                prev_h = forged_sha256

            conn.commit()

        verification = self.verify_chain()
        return {
            "attack_type": "rehash_cascade",
            "target_block_index": target_idx,
            "rehashed_blocks_count": len(rows) - target_pos,
            "before": before,
            "after": clean_updates,
            "mutation_ops": mutation_ops,
            "verification": verification,
        }

    def attack_truncate_last(self) -> dict:
        """
        Serangan Level 3 (Truncation Attack): Menghapus blok terakhir dari penyimpanan tanpa
        memperbarui Signed Head Checkpoint, membuktikan deteksi penghapusan riwayat ekor rantai.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            last_row = conn.execute(
                "SELECT * FROM custody_blocks ORDER BY block_index DESC LIMIT 1"
            ).fetchone()
            if last_row is None:
                return {"error": "Belum ada blok di ledger untuk dihapus."}

            deleted_block = dict(last_row)
            target_idx = int(deleted_block["block_index"])
            conn.execute("DELETE FROM custody_blocks WHERE block_index = ?", (target_idx,))
            conn.commit()

        mutation_op = f"TRUNCATE_TAIL BLOCK #{target_idx} ({deleted_block.get('source_unit')}): hapus blok terakhir tanpa segel ulang Head Checkpoint"
        verification = self.verify_chain()
        return {
            "attack_type": "truncate_last",
            "deleted_block_index": target_idx,
            "deleted_unit": deleted_block.get("source_unit"),
            "deleted_filename": deleted_block.get("filename"),
            "mutation_ops": [mutation_op],
            "verification": verification,
        }

    def verify_document_against_block(
        self,
        raw_bytes: bytes,
        block_index: Optional[int] = None,
    ) -> dict:
        """
        Memverifikasi integritas isi byte dokumen (off-chain) dengan menghitung SHA-256
        aktual file lalu mencocokkannya terhadap doc_sha256 di blok ledger sekaligus
        memeriksa integritas rantai HMAC & Signed Head Checkpoint.
        """
        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        file_size = len(raw_bytes)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM custody_blocks ORDER BY block_index DESC").fetchall()
            ]

        if not rows:
            return {"error": "Belum ada blok di ledger untuk dibandingkan dengan dokumen."}

        matching_blocks = [
            {
                "block_index": int(r["block_index"]),
                "filename": r["filename"],
                "source_unit": r["source_unit"],
                "target_unit": r["target_unit"],
            }
            for r in rows
            if hmac.compare_digest(str(r["doc_sha256"]), file_sha256)
        ]

        if block_index is not None:
            matches = [r for r in rows if int(r["block_index"]) == int(block_index)]
            if not matches:
                return {"error": f"Blok #{block_index} tidak ditemukan di ledger."}
            target = matches[0]
        else:
            target = (
                next((r for r in rows if hmac.compare_digest(str(r["doc_sha256"]), file_sha256)), None)
                or rows[0]
            )

        expected_sha = str(target["doc_sha256"])
        doc_match = hmac.compare_digest(expected_sha, file_sha256)
        chain_verification = self.verify_chain()
        chain_valid = bool(chain_verification.get("valid"))

        if doc_match and chain_valid:
            verdict = "AUTHENTIC_VERIFIED"
        elif not doc_match and chain_valid:
            verdict = "DOCUMENT_TAMPERED"
        elif doc_match and not chain_valid:
            verdict = "LEDGER_SPOOFED_TAMPERED"
        else:
            verdict = "DOCUMENT_AND_LEDGER_TAMPERED"

        return {
            "verdict": verdict,
            "authentic": doc_match and chain_valid,
            "doc_sha256_match": doc_match,
            "chain_valid": chain_valid,
            "file_sha256": file_sha256,
            "file_size": file_size,
            "block_index": int(target["block_index"]),
            "block_filename": target["filename"],
            "source_unit": target["source_unit"],
            "target_unit": target["target_unit"],
            "expected_doc_sha256": expected_sha,
            "matching_blocks": matching_blocks,
            "chain_verification": chain_verification,
        }
