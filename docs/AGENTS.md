# AGENTS.md — Pedoman Agent untuk SandiSeal

Baca file ini sebelum mengubah apa pun. Tujuannya: agent tahu apa yang dibangun, di mana keputusannya tertulis, apa yang boleh dan tidak boleh dilakukan, dan kapan harus bertanya.

---

## 1. Apa yang dibangun

SandiSeal adalah gateway on-premise untuk jalur dokumen Kodim → Korem → Pusat TNI AD. Setiap PDF diaudit secara deterministik, disanitasi (CDR) atau dialihkan ke sandbox senyap, dicatat di ledger hash-chain, dan polanya diubah menjadi aturan YARA (vaksin) yang dibagikan ke semua node.

Targetnya: **versi 1.0 siap dipakai**, berjalan 100% offline pada satu server (4 vCPU, 8 GB RAM) lewat Docker Compose.

Ini alat **pertahanan**. Semua pekerjaan di repo ini bertujuan mendeteksi, menahan, dan menganalisis dokumen berbahaya, bukan membuatnya.

---

## 2. Sumber kebenaran

| Dokumen | Isi | Prioritas |
| --- | --- | --- |
| `docs/PRD.md` (PRD SandiSeal) | Apa yang harus ada: FR-01 sampai FR-27, target, kriteria penerimaan | Tertinggi untuk perilaku produk |
| `design.md` | Struktur aplikasi, tech stack, model data, API, UI/UX | Tertinggi untuk cara membangun |
| `AGENTS.md` (file ini) | Aturan kerja agent | Tertinggi untuk proses |

Bila dua dokumen bertentangan, hentikan dan tanyakan. Jangan memilih sendiri diam-diam. Jangan mengubah PRD atau `design.md` tanpa diminta; usulkan perubahan di deskripsi PR.

Rujuk kebutuhan dengan ID (misalnya "FR-06") di commit, komentar kode, dan nama uji.

---

## 3. Aturan emas

1. **Deterministik.** Input sama harus menghasilkan keputusan dan kode alasan sama. Tidak ada heuristik acak, model ML, atau ketergantungan pada waktu dan lokasi dalam logika audit.
2. **Offline.** Tidak ada panggilan jaringan keluar saat runtime, tidak ada CDN, font eksternal, atau telemetri. Bila sebuah fitur butuh internet, rancangannya salah.
3. **Berkas asli tidak pernah diubah.** CDR menghasilkan dokumen turunan berlabel dengan hash sendiri yang tertaut ke hash asal.
4. **Ledger append-only.** Tidak ada UPDATE atau DELETE pada tabel ledger, dan tidak ada kode yang menulis ledger selain modul `ledger`.
5. **Jangan jalankan isi PDF.** Parser membaca struktur, tidak mengeksekusi skrip, tidak membuka tautan, tidak merender dokumen yang belum dinyatakan aman.
6. **Plasebo hanya untuk pengirim eksternal.** Konsol internal dan ledger selalu menampilkan status sebenarnya. Jangan pernah menyesatkan pengguna internal atau menulis data palsu ke ledger.
7. **Gagal dengan aman.** Bila ragu, dokumen ditahan, bukan diteruskan. Parser gagal, batas waktu, atau struktur rusak berarti keputusan Berbahaya atau ditolak.
8. **Setiap keputusan bisa dijelaskan.** Semua temuan membawa kode alasan yang tercatat dan diuji.

---

## 4. Struktur repositori dan batas modul

```
src/sandiseal/
  api/ core/ queue/ audit/ cdr/ sandbox/ vaccine/ ledger/ auth/ storage/ notify/ ui/
tests/  unit/ integration/ e2e/ fuzz/ corpus/
deploy/ docs/
```

Aturan ketergantungan antarmodul:

- `core` (model, status, kode alasan, kebijakan keputusan) tidak mengimpor modul lain.
- `audit` dan `cdr` hanya bergantung pada `core`. Keduanya berjalan di proses `auditor` terpisah.
- `ledger` hanya dapat ditulis lewat fungsi publiknya; modul lain tidak boleh menyentuh tabelnya langsung.
- `sandbox` tidak pernah berbagi kredensial, volume, atau jaringan dengan layanan produksi.
- `ui` tidak berisi logika keputusan; ia hanya menampilkan hasil dari `api`.

Jangan membuat modul, layanan, atau dependensi baru di luar `design.md` tanpa persetujuan.

---

## 5. Urutan pembangunan versi 1.0

Kerjakan berurutan; tiap langkah selesai bersama ujinya. Jangan melompat.

1. Kerangka gateway, antrian, dan ledger berantai hash (FR-01 sampai FR-03, FR-12, FR-13).
2. Mesin audit: struktur PDF, /ByteRange, incremental update, objek aktif, OCG, keputusan dan kode alasan (FR-04 sampai FR-09).
3. CDR dan kebijakan dokumen turunan (FR-10, FR-11).
4. Sandbox terisolasi, pengalihan senyap, ekstraksi payload (FR-15 sampai FR-17).
5. Generator vaksin, gerbang false positive, distribusi bertanda tangan (FR-18 sampai FR-21).
6. Dashboard, RBAC dengan MFA, mode proxy untuk E-Office (FR-22 sampai FR-25).
7. Pengujian penerimaan, fuzzing, paket instalasi offline, dokumentasi.

Prioritas: P0 wajib, P1 bila waktu cukup, P2 ditunda ke 2.0. Jangan mengerjakan P2 sebelum semua P0 selesai.

---

## 6. Perintah standar

Sediakan target berikut di `Makefile`. Jalankan sebelum menyatakan pekerjaan selesai.

| Perintah | Fungsi |
| --- | --- |
| `make setup` | Pasang dependensi dari cache lokal (tanpa internet) |
| `make lint` | ruff dan mypy (strict untuk `core`, `audit`, `ledger`) |
| `make test` | Uji unit dan integrasi |
| `make test-corpus` | Uji korpus A sampai F dan laporan false positive |
| `make fuzz` | Fuzzing parser (durasi dapat diatur) |
| `make e2e` | Tiga skenario demo (Playwright) |
| `make bundle` | Bangun arsip rilis offline |
| `make verify-ledger` | Uji perusakan dan verifikasi rantai |

Bila lingkungan tidak punya jaringan untuk memasang paket, jangan mencoba memasang. Kerjakan dengan yang ada, laporkan paket yang tidak dipakai, dan minta pengguna menyesuaikan pengaturan jaringan.

---

## 7. Konvensi kode

- Python 3.12, tipe eksplisit di semua fungsi publik, Pydantic v2 untuk kontrak API dan konfigurasi.
- Fungsi audit bersifat murni bila mungkin: menerima byte atau objek, mengembalikan temuan, tanpa efek samping.
- Kode alasan memakai konstanta di `core` (misalnya `ACT_JS`, `SIG_BYTES_OUTSIDE_RANGE`). Jangan menulis string kode alasan di tempat lain.
- Teks antarmuka hanya di `ui/i18n/id.yaml`, Bahasa Indonesia, bahasa kerja persuratan. Jangan menulis teks UI langsung di templat atau kode.
- Nama berkas dari pengguna tidak pernah dipakai sebagai jalur berkas.
- Log terstruktur JSON. Jangan mencatat isi dokumen, kata sandi, atau rahasia TOTP.
- Komentar menjelaskan **mengapa**, bukan **apa**. Rujuk ID kebutuhan bila relevan.
- Kunci, token, dan rahasia tidak pernah masuk repositori.

---

## 8. Aturan keamanan yang tidak boleh dilanggar

1. **Tidak ada eksploit nyata di repo.** Sampel uji berbahaya adalah berkas inert buatan sendiri: payload hanya menulis log atau tidak berbahaya sama sekali. Jangan menulis, menyalin, atau menyimpan kode eksploit fungsional, shellcode, atau malware, walaupun untuk uji. Bila sebuah uji tampak membutuhkannya, hentikan dan tanyakan.
2. **Tidak ada eksekusi isi dokumen di luar sandbox.** Sandbox: tanpa jaringan, sistem berkas read-only, batas CPU, memori, waktu, tanpa kredensial produksi.
3. **Parser berjalan di proses terpisah tanpa hak istimewa** dengan batas memori dan waktu.
4. **Paket aturan dan pembaruan hanya diterima bila tanda tangan valid.** Kunci penandatangan hanya ada di Pusat, tidak di node Kodim.
5. **Tidak ada akses soket Docker ke layanan selain `sandbox-runner`.**
6. **Dependensi dibekukan dengan hash.** Jangan menambah dependensi tanpa persetujuan; catat lisensinya. Hindari lisensi AGPL.
7. **Jangan melemahkan pemeriksaan agar uji lulus.** Bila sebuah uji gagal, perbaiki penyebabnya, bukan ambang atau aturannya.

---

## 9. Pengujian dan definisi selesai

Sebuah tugas selesai hanya bila semua ini benar:

- [ ] Perilaku sesuai kebutuhan PRD yang dirujuk, termasuk kasus gagal.
- [ ] Uji unit dan integrasi baru ditulis dan lulus; tidak ada uji yang dinonaktifkan.
- [ ] `make lint` dan `make test` bersih.
- [ ] Untuk perubahan audit atau CDR: `make test-corpus` dijalankan dan false positive tidak naik.
- [ ] Untuk perubahan ledger: uji perusakan (ubah, hapus, sisip entri) terdeteksi.
- [ ] Tidak ada panggilan jaringan keluar yang baru.
- [ ] Dokumentasi terkait diperbarui (`docs/`, `design.md` bila rancangan berubah dan sudah disetujui).
- [ ] Keputusan yang diambil dan hal yang belum pasti ditulis di deskripsi PR.

Target PRD yang harus tetap terjaga: deteksi objek aktif dan shadow attack 100% pada korpus uji, false positive 0,5% atau kurang pada PDF bersih, persentil ke-95 waktu proses 5 detik atau kurang untuk PDF sampai 10 halaman, serta setiap perusakan ledger terdeteksi.

---

## 10. Kapan bertanya, kapan memutuskan sendiri

**Putuskan sendiri dan catat** bila: pilihan bersifat teknis dan reversibel, sudah punya default di `design.md`, atau hanya memengaruhi implementasi internal satu modul.

**Berhenti dan tanyakan** bila:

- PRD dan `design.md` bertentangan, atau kebutuhan ambigu.
- Perubahan menyentuh kebijakan dokumen bertanda tangan, perilaku plasebo, atau cara aturan vaksin diaktifkan.
- Butuh dependensi, layanan, atau port baru.
- Perubahan tidak dapat dibatalkan (migrasi data, penghapusan, format ledger).
- Sebuah uji tampak menuntut sampel berbahaya sungguhan.
- Pertanyaan terbuka di PRD bagian 13 menjadi penghalang (misalnya format selain PDF, spesifikasi server satuan, titik integrasi E-Office).

Saat bertanya: sebut konteks, dua atau tiga pilihan, dampak masing-masing, dan rekomendasi Anda. Satu pertanyaan fokus lebih baik daripada daftar panjang.

Bila bekerja tanpa pengawasan: ambil pembacaan paling masuk akal, tulis di awal hasil kerja pembacaan mana yang dipakai, dan lanjutkan. Untuk keputusan yang tidak bisa dibatalkan, selesaikan persiapan lalu berhenti.

---

## 11. Alur kerja per tugas

1. Baca bagian PRD dan `design.md` yang relevan. Catat ID kebutuhan.
2. Tulis uji terlebih dahulu atau bersamaan, termasuk kasus gagal.
3. Implementasikan perubahan sekecil yang memenuhi kebutuhan. Hindari refaktor yang tidak diminta.
4. Jalankan perintah di bagian 6 yang relevan.
5. Tulis ringkasan: apa yang berubah, kebutuhan yang dipenuhi, uji yang dijalankan, keputusan, dan hal yang belum pasti.

Commit kecil dan fokus, format: `modul: ringkasan singkat (FR-xx)`. Contoh: `audit: deteksi incremental update pasca-TTE (FR-06)`.

---

## 12. Yang tidak boleh dilakukan

- Menambah fitur di luar PRD (misalnya format Office, verifikasi sertifikat BSrE penuh) sebelum P0 selesai.
- Mengubah ambang, daftar objek aktif, atau aturan audit hanya agar korpus lulus.
- Menyimpan atau mencatat isi dokumen pengguna di log.
- Menulis data ke ledger dari luar modul `ledger`.
- Mengirim apa pun ke layanan eksternal, termasuk saat debugging.
- Menyatakan "selesai" tanpa menjalankan uji.
- Menghapus uji yang gagal atau menandainya dilewati tanpa alasan tertulis dan persetujuan.

---

## 13. Glosarium singkat

| Istilah | Arti |
| --- | --- |
| TTE | Tanda Tangan Elektronik tersertifikasi BSrE BSSN |
| CDR | Content Disarm and Reconstruction: membangun ulang dokumen dari objek yang diizinkan |
| /ByteRange | Rentang byte yang dicakup tanda tangan PDF |
| Incremental update | Revisi PDF yang ditambahkan di akhir berkas; dapat dipakai untuk shadow attack |
| Shadow attack | Perubahan isi tampilan PDF bertanda tangan tanpa merusak indikator tanda tangan |
| Plasebo | Pengalihan senyap dokumen berbahaya; pengirim eksternal tidak diberi sinyal deteksi |
| Vaksin | Aturan YARA otomatis dari hasil analisis sandbox, dibagikan ke semua node |
| Ledger | Catatan kustodi append-only dengan hash berantai SHA-256 |
| Node | Satu instalasi SandiSeal di satu satuan (Kodim, Korem, atau Pusat) |
