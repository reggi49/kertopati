# SandiSeal — Dokumen Desain

Turunan dari PRD SandiSeal (versi 1.0). Dokumen ini menjelaskan struktur aplikasi, UI/UX, dan tech stack. Rujukan ke kebutuhan memakai ID PRD (FR-01 dst). Semua pilihan teknologi berstatus usulan sampai dikonfirmasi pada fase desain.

---

## 1. Prinsip desain

1. **Deterministik, bukan menebak.** Keputusan audit selalu berasal dari aturan yang bisa dijelaskan dan diulang. Input sama menghasilkan keputusan sama.
2. **Offline dulu.** Tidak ada CDN, font eksternal, telemetri, atau panggilan keluar. Semua aset dan dependensi ada di paket rilis.
3. **Asli tidak pernah diubah.** Berkas asli disimpan terkunci. Hasil CDR selalu berupa dokumen turunan berlabel.
4. **Plasebo hanya untuk pengirim eksternal.** Pihak internal yang berwenang selalu melihat status sebenarnya. Ledger mencatat kebenaran.
5. **Operator tidak perlu paham PDF.** Antarmuka memakai bahasa kerja persuratan. Istilah teknis hanya muncul di panel rincian untuk analis.
6. **Aman secara bawaan.** Parser dan sandbox adalah target serangan, jadi dijalankan terpisah, tanpa hak istimewa, dengan batas sumber daya.

---

## 2. Struktur aplikasi

### 2.1 Komponen logis

```
                    +----------------------------+
 Pengirim --------> |  Gateway (FastAPI)         |
 (Kodim/Korem)      |  REST, proxy/webhook, UI   |
                    +-------------+--------------+
                                  |
                        antrian (SQLite WAL)
                                  |
                    +-------------v--------------+
                    |  Worker audit              |  proses terpisah,
                    |  parser + audit + CDR      |  tanpa hak istimewa
                    +------+------+--------------+
                           |      |
                 Lolos/Sanitasi   Berbahaya
                           |      |
                           |   +--v-----------+     +-------------------+
                           |   | Runner sandbox|---> | Generator vaksin  |
                           |   | (kontainer,   |     | YARA + gerbang FP |
                           |   |  tanpa jaringan)|   +---------+---------+
                           |   +--------------+               |
                           v                                  v
                    +-------------+                 +----------------------+
                    |  Ledger     | <---- semua --- |  Rule store bertanda |
                    |  hash-chain |     peristiwa   |  tangan (Pusat/node) |
                    +-------------+                 +----------------------+
```

### 2.2 Struktur repositori

```
sandiseal/
├── compose.yaml                 # orkestrasi satu node
├── Dockerfile                   # multi-stage, pengguna non-root
├── pyproject.toml
├── README.md
├── design.md                    # dokumen ini
├── docs/
│   ├── PRD.md
│   ├── install.md               # panduan instalasi offline
│   ├── runbook-operator.md
│   ├── panduan-analis.md
│   └── api.md
├── src/sandiseal/
│   ├── main.py                  # titik masuk FastAPI
│   ├── config.py                # konfigurasi dari satu berkas + env
│   ├── api/                     # router REST (documents, ledger, rules, auth, health)
│   ├── core/                    # model domain, status, kode alasan, kebijakan keputusan
│   ├── queue/                   # antrian pekerjaan berbasis SQLite
│   ├── audit/                   # parser, byterange, incremental, objek aktif, OCG
│   ├── cdr/                     # rekonstruksi PDF dari daftar objek diizinkan
│   ├── sandbox/                 # runner kontainer, ekstraksi payload, indikator
│   ├── vaccine/                 # generator YARA, gerbang false positive, penandatanganan
│   ├── ledger/                  # hash-chain, verifikasi, ekspor bukti kustodi
│   ├── auth/                    # login, RBAC, TOTP
│   ├── storage/                 # penyimpanan terenkripsi (asli, turunan, hasil sandbox)
│   ├── notify/                  # syslog dan email internal
│   └── ui/
│       ├── templates/           # Jinja2
│       ├── static/              # CSS, JS kecil, ikon, font (lokal)
│       └── i18n/id.yaml         # teks antarmuka Bahasa Indonesia
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/                     # tiga skenario demo
│   ├── fuzz/
│   └── corpus/                  # korpus A–F (lihat PRD bagian 10)
└── deploy/
    ├── build-offline-bundle.sh  # membuat arsip rilis
    ├── install.sh               # instalasi + pemeriksaan awal
    ├── preflight.sh             # cek CPU, RAM, port, jam, isolasi jaringan sandbox
    ├── config.kodim.yaml
    ├── config.korem.yaml
    └── config.pusat.yaml
```

### 2.3 Layanan dalam Docker Compose (satu node)

| Layanan | Peran | Hak akses |
| --- | --- | --- |
| `gateway` | API, UI, proxy/webhook, otentikasi | Baca/tulis DB dan penyimpanan; tidak membuka berkas PDF |
| `auditor` | Worker audit dan CDR; membuka dan mem-parse PDF | Baca berkas asli, tulis hasil; tanpa jaringan; tanpa capability |
| `sandbox-runner` | Menjalankan kontainer analisis sekali pakai | Hanya berkomunikasi dengan runtime kontainer lewat soket terbatas |
| `vaccine` | Membuat, menguji, menandatangani, dan memuat aturan | Akses ke rule store dan korpus bersih |
| `ledger` (modul di gateway atau proses terpisah) | Satu-satunya penulis ke tabel ledger | Tabel append-only |

Jaringan: satu jaringan internal untuk gateway, auditor, vaccine. Sandbox memakai jaringan `none`. Hanya `gateway` yang membuka port (API dan UI).

### 2.4 Status dokumen (mesin status)

```
DITERIMA -> DIAUDIT -+-> LOLOS ----------------------> DITERUSKAN
                     |
                     +-> DISANITASI (turunan dibuat) -> DITERUSKAN
                     |
                     +-> BERBAHAYA -> DI_SANDBOX -> DIANALISIS -> (aturan kandidat)
                                         |
                                         +-> DITAHAN (menunggu tinjauan analis)
```

Setiap transisi menulis satu entri ledger (FR-12). Dokumen dengan status `BERBAHAYA` tidak pernah mencapai `DITERUSKAN` (FR-15).

### 2.5 Dua kanal, dua tampilan status

| Kanal | Pemakai | Yang dilihat saat dokumen berbahaya |
| --- | --- | --- |
| **Kanal pengirim eksternal** (API penerimaan, proxy) | Sistem atau pihak yang mengirim dokumen | Tanda terima netral yang sama dengan kasus normal. Tidak ada sinyal deteksi |
| **Konsol internal** (UI web, peran operator, admin, analis, auditor) | Personel berwenang | Status sebenarnya, kode alasan, dan jejak kustodi sesuai hak peran |

---

## 3. Tech stack

### 3.1 Ringkasan

| Lapisan | Pilihan | Alasan |
| --- | --- | --- |
| Bahasa | Python 3.12 | Sesuai dokumen sumber; ekosistem PDF dan YARA matang |
| Web/API | FastAPI + Uvicorn | Ditetapkan di dokumen sumber; skema OpenAPI otomatis |
| Validasi | Pydantic v2 | Kontrak API dan konfigurasi yang ketat |
| UI | Jinja2 + HTMX + CSS sendiri (tanpa framework build) | Ringan, mudah diaudit, tanpa rantai Node.js, berjalan offline |
| Parser PDF | pikepdf (qpdf) untuk struktur objek | Akses ke objek, xref, dan stream tanpa mengeksekusi |
| Tanda tangan | pyHanko (hanya struktur `/Sig`, `/ByteRange`, `/DocMDP`) | Membaca struktur tanda tangan; verifikasi sertifikat penuh ditunda ke 2.0 |
| CDR | Rekonstruksi dari daftar objek diizinkan (pikepdf); mode ketat opsional: rasterisasi halaman lalu susun ulang | Dua tingkat sanitasi sesuai kebijakan satuan |
| Aturan | yara-python | Standar de facto; format aturan portabel |
| Ledger | SQLite (WAL) + SHA-256 berantai + tanda tangan Ed25519 per node | Tanpa server basis data tambahan; siap offline |
| Antrian | Tabel antrian di SQLite | Menghindari Redis/Rabbit; cukup untuk beban per node |
| Kripto | `cryptography` (AES-256-GCM, Ed25519) | Pustaka teruji; enkripsi simpanan dan tanda tangan aturan |
| Otentikasi | Argon2id (kata sandi), TOTP (`pyotp`), sesi cookie `HttpOnly` | MFA yang bekerja tanpa jaringan |
| Sandbox | Kontainer sekali pakai: `--network none`, root read-only, seccomp, cgroup, batas waktu | Isolasi tanpa jaringan; lihat 3.3 |
| Log | `structlog` JSON + syslog | Mudah dikirim ke pengumpul log internal |
| Orkestrasi | Docker Compose | Satu perintah; ditetapkan di dokumen sumber |

Catatan lisensi: pustaka berlisensi AGPL (misalnya PyMuPDF) tidak dipakai kecuali ada persetujuan hukum. Seluruh dependensi dicatat di SBOM.

### 3.2 Pengembangan dan kualitas

| Kebutuhan | Alat |
| --- | --- |
| Uji unit dan integrasi | pytest, pytest-asyncio, httpx |
| Uji berbasis properti | Hypothesis (aturan audit dan rantai ledger) |
| Fuzzing parser | Atheris atau libFuzzer, minimal 24 jam sebelum rilis |
| Lint dan tipe | ruff, mypy (strict untuk `core`, `audit`, `ledger`) |
| Keamanan kode | bandit, pip-audit (saat build, bukan di node) |
| Uji E2E | Playwright terhadap UI (tiga skenario demo) |
| SBOM dan tanda tangan rilis | syft saat build; arsip rilis ditandatangani Ed25519 |

### 3.3 Catatan keputusan teknis

- **Sandbox dan soket kontainer.** Memberikan akses soket Docker ke layanan mana pun setara akses root. Rancangan: hanya `sandbox-runner` (proses kecil, kode terbatas) yang boleh menyentuh runtime, memakai Podman rootless bila tersedia. Keputusan akhir bergantung pada kebijakan server satuan (PRD bagian 13).
- **Parser sebagai target.** `auditor` berjalan sebagai proses anak per dokumen dengan batas memori dan waktu, sehingga kegagalan satu dokumen tidak mematikan layanan.
- **SQLite per node.** Cukup untuk beban target PRD. Bila sinkronisasi lintas satuan (fase 1.2) membutuhkan basis data bersama, migrasi ke PostgreSQL dipertimbangkan saat itu.
- **HTMX, bukan SPA.** Mengurangi permukaan serangan dan dependensi. Interaksi yang dibutuhkan (polling status, filter tabel, dialog konfirmasi) sudah tercakup.

---

## 4. Model data (sketsa)

```sql
documents(
  id TEXT PRIMARY KEY, sha256_asal TEXT NOT NULL, ukuran INTEGER,
  unit_asal TEXT, unit_tujuan TEXT, status TEXT NOT NULL,
  keputusan TEXT, diterima_pada TEXT, diperbarui_pada TEXT,
  path_asli TEXT, path_turunan TEXT, sha256_turunan TEXT
);

findings(
  id INTEGER PRIMARY KEY, document_id TEXT REFERENCES documents(id),
  kode_alasan TEXT, objek TEXT, tingkat TEXT,   -- info | ringan | berbahaya
  rincian TEXT
);

ledger(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
  jenis TEXT NOT NULL, document_id TEXT,
  unit_asal TEXT, unit_tujuan TEXT,
  keputusan TEXT, versi_aturan TEXT,
  waktu TEXT NOT NULL, tanda_tangan_node TEXT
);
-- entry_hash = SHA-256(prev_hash || data entri kanonik)
-- Tidak ada UPDATE/DELETE: dijaga trigger dan hak akses

rules(
  id TEXT PRIMARY KEY, versi INTEGER, isi TEXT, status TEXT, -- kandidat | aktif | ditarik
  penandatangan TEXT, tanda_tangan TEXT, hasil_uji_fp TEXT, dibuat_pada TEXT
);

users(id TEXT PRIMARY KEY, nama TEXT, peran TEXT, hash_sandi TEXT,
      rahasia_totp TEXT, aktif INTEGER);
```

Kode alasan (contoh): `ACT_JS`, `ACT_OPENACTION`, `ACT_LAUNCH`, `ACT_EMBEDDED`, `SIG_BYTES_OUTSIDE_RANGE`, `SIG_INCREMENTAL_CONTENT`, `SIG_INCREMENTAL_ALLOWED`, `OCG_HIDDEN_CONTENT`, `PARSE_MALFORMED`.

---

## 5. Antarmuka API (ringkas)

| Metode dan jalur | Fungsi | Peran |
| --- | --- | --- |
| `POST /v1/documents` | Unggah PDF; kembalikan id dan tanda terima | operator, sistem |
| `GET /v1/documents/{id}` | Status, keputusan, temuan | sesuai hak peran |
| `GET /v1/documents/{id}/custody` | Jejak kustodi dan bukti ledger | operator, analis, auditor |
| `GET /v1/ledger/verify` | Verifikasi rantai hash | admin, analis, auditor |
| `GET /v1/rules` | Daftar aturan dan versinya | analis, admin |
| `POST /v1/rules/{id}/approve` | Setujui aturan kandidat | analis |
| `POST /v1/rules/import` | Impor paket aturan bertanda tangan | admin |
| `GET /v1/health` | Kesehatan layanan | admin, pemantau |

Respons untuk kanal pengirim eksternal memakai bentuk yang sama untuk semua keputusan. Detail keputusan hanya tersedia lewat konsol internal.

---

## 6. UI/UX

### 6.1 Pengguna dan tujuan

| Peran | Tujuan utama | Layar utama |
| --- | --- | --- |
| Operator persuratan | Mengirim dokumen dan tahu aman atau tidak, tanpa istilah teknis | Beranda, Unggah, Daftar dokumen |
| Admin sistem | Menjaga node sehat dan terbarui | Kesehatan, Pengguna, Pembaruan, Cadangan |
| Analis keamanan siber | Meninjau dokumen ditahan dan menyetujui aturan | Karantina, Detail dokumen, Aturan vaksin |
| Auditor / pimpinan | Memastikan rantai kustodi utuh | Ledger, Laporan ringkas (hanya baca) |

### 6.2 Arsitektur informasi (peta situs)

```
Masuk (kata sandi + TOTP)
└── Beranda
    ├── Dokumen
    │   ├── Unggah dokumen
    │   ├── Daftar dokumen (filter: status, unit, tanggal)
    │   └── Detail dokumen
    │       ├── Ringkasan keputusan
    │       ├── Temuan (rincian teknis, untuk analis)
    │       └── Jejak kustodi
    ├── Karantina                      (analis, admin)
    │   └── Detail sandbox: payload, indikator, aturan kandidat
    ├── Aturan vaksin                  (analis, admin)
    ├── Ledger                         (auditor, analis, admin)
    │   └── Verifikasi rantai, ekspor bukti
    └── Administrasi                   (admin)
        ├── Pengguna dan peran
        ├── Kesehatan node
        ├── Pembaruan dan impor aturan
        └── Cadangan
```

Menu hanya menampilkan item yang boleh dibuka oleh peran pengguna. Item di luar hak tidak ditampilkan (bukan hanya dinonaktifkan).

### 6.3 Alur utama

**Operator mengirim dokumen**

1. Beranda → tombol besar **Unggah dokumen**.
2. Pilih berkas PDF (seret dan lepas atau pilih berkas), isi unit tujuan.
3. Tekan **Kirim**. Muncul layar proses dengan tahap: *Diterima → Diperiksa → Hasil*.
4. Hasil tampil dalam bahasa kerja: **Aman dan terkirim**, **Terkirim setelah dibersihkan** (dokumen turunan), atau **Ditahan untuk pemeriksaan**.

**Analis meninjau dokumen ditahan**

1. Karantina → pilih dokumen → lihat temuan per objek dan kode alasan.
2. Lihat indikator hasil sandbox dan aturan kandidat beserta hasil uji false positive.
3. **Setujui aturan** atau **Tolak**, dan catat alasan. Tindakan masuk ledger.

**Auditor memeriksa kustodi**

1. Ledger → **Verifikasi rantai** → hasil: *Utuh* atau *Terputus di entri #N*.
2. Detail dokumen → **Ekspor bukti kustodi** (PDF dan JSON).

### 6.4 Wireframe

Masuk:

```
+------------------------------------------+
|              SandiSeal                   |
|   Pemeriksa dokumen jalur komando        |
|                                          |
|   Nama pengguna  [____________________]  |
|   Kata sandi     [____________________]  |
|   Kode TOTP      [______]                |
|                                          |
|   [ Masuk ]                              |
|   Node: Kodim 0000   Aturan v12          |
+------------------------------------------+
```

Beranda (operator):

```
+----------------------------------------------------------+
| SandiSeal   Dokumen  Karantina  Ledger        [Nama v]   |
+----------------------------------------------------------+
|  [ + Unggah dokumen ]                                    |
|                                                          |
|  Hari ini                                                |
|  +-----------+ +-----------+ +-----------+ +-----------+ |
|  |  Terkirim | | Dibersih- | |  Ditahan  | |  Diproses | |
|  |    42     | |  kan  3   | |     1     | |     2     | |
|  +-----------+ +-----------+ +-----------+ +-----------+ |
|                                                          |
|  Dokumen terbaru                                         |
|  Nama berkas        Tujuan     Status          Waktu     |
|  surat_041.pdf      Korem      (v) Terkirim    13:02     |
|  nota_dinas.pdf     Pusat      (!) Ditahan     12:58     |
+----------------------------------------------------------+
```

Detail dokumen (analis):

```
+----------------------------------------------------------+
| < Daftar dokumen        nota_dinas.pdf        [ Ditahan ] |
+----------------------------------------------------------+
| Keputusan: BERBAHAYA                                     |
| Alasan   : Objek aktif pada tanda tangan valid           |
|                                                          |
| [ Ringkasan ] [ Temuan ] [ Sandbox ] [ Kustodi ]         |
|                                                          |
| Temuan                                                   |
|  Kode              Objek            Tingkat              |
|  ACT_OPENACTION    /OpenAction      Berbahaya            |
|  ACT_JS            /JavaScript      Berbahaya            |
|  SIG_INCREMENTAL.. rev. setelah TTE Berbahaya            |
|                                                          |
| Aturan kandidat: SS-2026-0042   Uji FP: lulus (0/1000)   |
| [ Setujui aturan ]  [ Tolak ]                            |
+----------------------------------------------------------+
```

Jejak kustodi:

```
 #    Waktu      Peristiwa            Asal -> Tujuan     Hash (8 awal)
 118  12:57:41   Diterima             Kodim -> Korem     9f3a21c0
 119  12:57:43   Diaudit: Berbahaya   -                  4be07d11
 120  12:57:44   Dialihkan sandbox    -                  c2a9e8f3
 121  12:58:10   Aturan kandidat      -                  7d10ab54
                                       Rantai: utuh (v)
```

### 6.5 Sistem status dan warna

Warna tidak pernah menjadi satu-satunya penanda. Setiap status punya ikon dan teks.

| Status (tampilan operator) | Istilah internal | Warna | Ikon |
| --- | --- | --- | --- |
| Terkirim | LOLOS / DITERUSKAN | Hijau | Centang |
| Terkirim setelah dibersihkan | DISANITASI | Kuning | Tanda perisai |
| Ditahan | BERBAHAYA / DITAHAN | Merah | Tanda seru |
| Diproses | DIAUDIT | Abu-abu | Jam |
| Rantai utuh / terputus | Verifikasi ledger | Hijau / Merah | Rantai |

### 6.6 Design tokens

| Token | Nilai usulan | Pemakaian |
| --- | --- | --- |
| `--font` | Font sistem (tanpa unduhan); cadangan sans-serif | Semua teks |
| `--fs-base` | 16 px | Teks isi |
| `--fs-sm` / `--fs-lg` / `--fs-xl` | 14 / 18 / 24 px | Keterangan, subjudul, judul |
| `--space` | Kelipatan 4 px | Jarak |
| `--radius` | 8 px | Kartu, tombol |
| `--c-bg` / `--c-surface` | Terang dan tinggi kontras; mode gelap tersedia | Latar |
| `--c-ok` / `--c-warn` / `--c-bad` | Hijau / kuning / merah dengan rasio kontras ≥ 4,5:1 | Status |
| `--c-accent` | Biru tua | Aksi utama |

Mode gelap disediakan untuk ruang operasi dengan cahaya rendah. Seluruh warna diambil dari token sehingga tema dapat diganti satu berkas.

### 6.7 Komponen

- **Tombol aksi utama** besar untuk Unggah; satu aksi utama per layar.
- **Kartu ringkasan** angka harian dengan tautan ke daftar yang terfilter.
- **Tabel** dengan penyortiran, filter status, dan paginasi; baris dapat dibuka dengan keyboard.
- **Lencana status** (ikon + teks + warna).
- **Garis waktu tahap** untuk proses dokumen: Diterima → Diperiksa → Hasil.
- **Panel temuan** yang bisa dilipat; istilah teknis hanya untuk peran analis.
- **Dialog konfirmasi** untuk tindakan yang tidak bisa dibatalkan (setujui aturan, tarik aturan, hapus pengguna).
- **Banner sistem** untuk peringatan node (rantai terputus, aturan kedaluwarsa, disk hampir penuh).

### 6.8 Teks antarmuka (Bahasa Indonesia)

- Kalimat pendek dan aktif. Contoh: "Dokumen ditahan untuk pemeriksaan. Analis akan menghubungi Anda." Bukan "Terdeteksi anomali struktur objek PDF".
- Pesan galat menyebut apa yang terjadi dan apa langkah berikutnya. Contoh: "Berkas melebihi 50 MB. Kecilkan berkas lalu coba lagi."
- Semua teks ada di `ui/i18n/id.yaml` supaya mudah direvisi tanpa mengubah kode.
- Operator tidak melihat nama objek PDF atau kode alasan; analis melihatnya di tab Temuan.

### 6.9 Keadaan khusus

| Keadaan | Perilaku |
| --- | --- |
| Daftar kosong | Pesan ramah dan tombol Unggah |
| Berkas bukan PDF atau rusak | Ditolak dengan pesan jelas; peristiwa tetap dicatat |
| Pemrosesan lambat | Garis waktu tahap tetap tampil; polling status tiap beberapa detik |
| Layanan audit mati | Banner merah; dokumen tetap di antrian dan dilanjutkan saat layanan pulih |
| Rantai ledger terputus | Banner merah di semua layar untuk admin, analis, auditor; alarm ke syslog |
| Aturan kedaluwarsa | Banner kuning dengan tanggal aturan terakhir |
| Sesi habis | Kembali ke layar masuk, berkas yang belum terkirim tidak hilang bila memungkinkan |

### 6.10 Aksesibilitas dan keterpakaian

- Navigasi penuh dengan keyboard; fokus terlihat jelas.
- Kontras teks minimal 4,5:1; status tidak bergantung pada warna saja.
- Label formulir terkait ke input; pembaca layar membaca status lewat teks, bukan ikon.
- Target sentuh minimal 44 px; antarmuka berfungsi pada layar 1366×768 dan tablet.
- Tanpa animasi yang berkedip; animasi kecil menghormati preferensi "kurangi gerak".

---

## 7. Keamanan implementasi (ringkas)

- Unggahan divalidasi: tipe (magic bytes), ukuran, jumlah halaman; nama berkas disanitasi dan tidak dipakai sebagai jalur.
- Berkas asli dan turunan dienkripsi saat disimpan (AES-256-GCM); kunci dari berkas kunci node, bukan di repositori.
- Header keamanan HTTP (CSP ketat tanpa sumber eksternal, `X-Content-Type-Options`, `Frame-Options`), cookie `HttpOnly`, `Secure`, `SameSite=Strict`, token CSRF pada aksi yang mengubah data.
- Pembatasan percobaan masuk; log setiap percobaan gagal.
- Pratinjau PDF di UI tidak memakai penampil bawaan yang menjalankan skrip; analis melihat rincian teks, bukan merender dokumen berbahaya.
- Paket aturan dan pembaruan hanya diterima bila tanda tangan Ed25519 valid terhadap kunci publik Pusat yang tertanam.

---

## 8. Build dan rilis

1. Build image multi-stage dengan dependensi dibekukan (`pip` dengan hash terkunci) dan roda dependensi disalin lokal.
2. `build-offline-bundle.sh` menghasilkan satu arsip: image Docker, `compose.yaml`, konfigurasi contoh, dokumen, SBOM, checksum, tanda tangan.
3. `install.sh` memeriksa tanda tangan arsip, menjalankan `preflight.sh` (CPU, RAM, disk, port, jam sistem, isolasi jaringan sandbox), memuat image, dan menyalakan layanan.
4. Pembaruan dan rollback dengan satu perintah; versi sebelumnya disimpan satu tingkat.

---

## 9. Keputusan yang masih terbuka

| Topik | Pilihan | Dampak |
| --- | --- | --- |
| Runtime sandbox | Podman rootless vs Docker dengan runner terbatas | Keamanan isolasi dan kebijakan server satuan |
| Mode CDR bawaan | Rekonstruksi objek vs rasterisasi | Keutuhan tampilan vs jaminan sanitasi |
| Tingkat otomatisasi vaksin | Aktif otomatis vs butuh persetujuan analis | Kecepatan vs risiko false positive massal |
| UI | HTMX server-rendered vs SPA | Kesederhanaan vs interaktivitas |
| Basis data lintas satuan (fase 1.2) | SQLite sinkron vs PostgreSQL | Skala dan kerumitan operasi |
| Penyimpanan kunci | Berkas terproteksi vs modul perangkat keras | Tingkat perlindungan kunci Pusat |
