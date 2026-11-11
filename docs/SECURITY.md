# Model ancaman dan batasan keamanan

Dokumen ini menyatakan apa yang SentinelGraph AI **lindungi**, apa yang **tidak**, dan
sisa risiko yang harus diterima operator.

---

## 1. Asumsi lingkungan

SentinelGraph dijalankan di lingkungan **tertutup**:

- Server dijalankan pada workstation analis atau host lab, bukan internet terbuka.
- Data yang diimpor berasal dari lingkungan sendiri atau data sintetis.
- Pengguna yang bisa menjangkau port aplikasi dianggap terpercaya.

**Bila salah satu asumsi ini tidak berlaku, bagian 4 wajib dibaca sebelum deploy.**

## 2. Permukaan serangan yang diperhitungkan

| Permukaan | Ancaman | Mitigasi |
|---|---|---|
| Unggahan artifact | Payload raksasa, JSON dalam, field asing | Batas ukuran, validasi bentuk per record, hanya informasi yang diterima |
| Output LLM | Halusinasi, sitasi karangan, instruksi tersembunyi | Validasi skema + verifikasi setiap ID event + penandaan hipotesis |
| Konfigurasi provider | SSRF ke metadata cloud / layanan internal | Blokade alamat privat & link-local; pengecualian hanya untuk provider lokal |
| Penyimpanan kunci API | Kunci bocor dari database | Enkripsi Fernet; tanpa `SG_MASTER_KEY` kunci tidak disimpan |
| Pesan error | Kebocoran kunci di log | `redact_secrets` sebelum persist |
| Konten yang dirender | XSS lewat nama host/file | React meng-escape; laporan HTML meng-escape semua nilai dinamis |

## 3. Yang TIDAK dilindungi

Dinyatakan terbuka, bukan disembunyikan:

1. **Tidak ada autentikasi maupun otorisasi.** Siapa pun yang bisa melakukan HTTP ke
   port aplikasi bisa membaca seluruh insiden dan mengubah status insiden.
2. **Tidak ada TLS.** Trafik HTTP polos. Bila diakses lewat jaringan, isi insiden
   dapat disadap.
3. **Tidak ada enkripsi at-rest untuk tabel event.** Hanya kunci provider yang
   dienkripsi.
4. **Tidak ada rate limiting** pada endpoint API.
5. **Tidak ada perlindungan terhadap pengguna berbahaya** (mis. analis internal yang
   menghapus audit log).
6. **Tidak ada isolasi antar proyek** di luar filter `project_id` pada query.

## 4. Syarat deploy yang aman

Bila aplikasi dipakai di luar demo:

1. Jalankan di belakang reverse proxy dengan TLS.
2. Tambahkan autentikasi (paling tidak HTTP Basic + IP allowlist) di lapisan proxy.
3. Batasi bind ke `127.0.0.1` bila hanya untuk workstation lokal.
4. Set `SG_MASTER_KEY` dan simpan di secret manager, bukan di shell history.
5. Jangan arahkan konektor langsung ke internet.

## 5. Risiko sisa yang diterima

| Risiko | Tingkat | Alasan diterima |
|---|---|---|
| Ringkasan AI bisa menyesatkan | **Tinggi** | Teks bebas tidak bisa diverifikasi mesin. Mitigasi: penanda eksplisit, dan deteksi tidak bergantung pada AI. |
| Rule engine bisa false positive | Sedang | Wajar untuk deteksi berbasis rule. Mitigasi: narasi menyatakan ketidakpastian, bukan menyimpulkan kompromi. |
| Dataset demo tidak representatif | Sedang | Data sintetis. Kemampuan deteksi pada data nyata belum diukur. |
| Heuristik pengelompokan insiden | Rendah–sedang | Dapat memisahkan atau menggabungkan insiden secara keliru. Ditandai sebagai heuristik di laporan. |
| Timestamp `assumed` menyesatkan urutan | Rendah | Ditandai eksplisit dan ditempatkan dengan penanda. |

## 6. Sikap terhadap klaim

Produk ini sengaja **tidak** mengklaim:

- Mendeteksi zero-day.
- Menetapkan bahwa suatu host terkompromi.
- Menetapkan bahwa data keluar dari jaringan.
- Bahwa AI menghasilkan analisis yang benar.

Yang diklaim hanya:

- Event tercatat dan bisa diperiksa ulang.
- Rule yang dijalankan bersifat deterministik dan dapat direproduksi.
- Setiap klaim yang membawa sitasi telah diperiksa terhadap database.
- Ketidakpastian dinyatakan, bukan disembunyikan.

## 7. Pelaporan kerentanan

Ini adalah prototipe hackathon. Temuan keamanan sebaiknya dilaporkan sebagai issue
dengan langkah reproduksi; jangan diuji pada instance yang memuat data pihak lain.
