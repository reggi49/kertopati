# SandiSeal MVP — Zero-Trust Document & BSrE Integrity Shield

Purwarupa sistem pertahanan dokumen berjenjang (**Kodim → Korem → Pusat**) untuk **Kartika Cyber Hackathon 2026** (Kategori 02: *Defensive Shield*).

## Fitur Utama
1. **Audit Deterministik PDF & `/ByteRange` BSrE (`app/pdf_inspector.py`)**: Mendeteksi objek aktif berbahaya (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`) dan anomali *incremental update* pasca-penandatanganan (*Shadow Attack* ala CVE-2026-91814).
2. **Immutable SHA-256 Chain of Custody (`app/ledger.py`)**: Mencatat rantai perpindahan dokumen antar-satuan secara *append-only* dalam penyimpanan lokal (*on-premise/air-gapped ready*).
3. **Stealth Auto-Sandbox & Generator Vaksin YARA (`app/sandbox_vaccine.py`)**: Mengalihkan dokumen mencurigakan secara senyap (*plasebo*) ke *sandbox* isolasi, membedah *payload*, dan otomatis menerbitkan aturan YARA (`.yar`) baru untuk memblokir varian serangan serupa di seluruh satuan.

## Cara Menjalankan di Mac / Linux
```bash
# 1. Buat virtual environment & install dependensi
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Buat 2 file PDF demo (bersih vs terinfeksi)
python3 demo_scripts/generate_clean_pdf.py
python3 demo_scripts/generate_evil_pdf.py

# 3. Jalankan server FastAPI
uvicorn app.main:app --reload --port 8000
```
Buka browser ke `http://localhost:8000` untuk mencoba dashboard dan skenario demo 1-klik.
