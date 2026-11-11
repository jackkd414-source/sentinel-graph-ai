# Proposal — SentinelGraph AI

**Kategori:** Defensive Shield (Penangkalan)
**Event:** Kartika Cyber Hackathon 2026
**Tagline:** From Signals to Story

---

## 1. Masalah

Tim blue team tidak kekurangan data. Mereka kekurangan **cerita yang bisa
dipertanggungjawabkan**.

Rata-rata SOC menerima puluhan hingga ratusan alert per hari. Setiap alert benar secara
individual, tetapi terpisah-pisah. Analis menghabiskan waktu memindahkan potongan dari
satu panel ke panel lain, lalu menyusun narasi secara manual di kepala — narasi yang
hilang begitu ia pindah shift.

Dua pendekatan yang ada sekarang sama-sama bermasalah:

**Pendekatan pertama: SIEM saja.** Memberi banyak alert, tetapi tidak merangkainya.
Analis tetap harus menyusun cerita sendiri, dan kesimpulannya tidak bisa direproduksi.

**Pendekatan kedua: menambahkan LLM untuk merangkum.** Terlihat modern, tetapi
memperkenalkan masalah baru yang lebih berbahaya: model bahasa menghasilkan teks yang
meyakinkan tanpa jaminan kebenaran. Ketika ringkasan AI menyatakan "terjadi eksfiltrasi
data", tidak ada cara bagi analis untuk tahu apakah itu kesimpulan dari bukti, atau
sekadar pola bahasa yang dihasilkan model.

Akibatnya, laporan insiden sering berisi klaim yang tidak bisa dipertahankan saat
dipertanyakan di ruang rapat atau proses audit.

## 2. Solusi

SentinelGraph AI memisahkan tiga lapis kebenaran secara eksplisit dan tidak
mencampurnya:

| Lapis | Sumber | Sifat |
|---|---|---|
| **Observed fact** | Event yang diimpor | Dapat diperiksa ulang; setiap klaim membawa ID event |
| **Derived finding** | Rule engine deterministik | Dapat direproduksi; logika rule ditampilkan |
| **AI hypothesis** | Model bahasa | Diperlakukan sebagai tersangka, bukan saksi |

Kontribusi utama bukan pada penggunaan AI, melainkan pada **mekanisme yang membuat AI
tidak bisa berbohong tanpa ketahuan**.

### Evidence guard

Sebelum model dipanggil, sistem mencatat daftar ID event yang dikirim. Setelah respons
diterima:

1. Skema output divalidasi secara ketat.
2. Setiap ID event yang dikutip diperiksa terhadap daftar tersebut.
3. ID yang tidak ada — termasuk nilai non-integer seperti `1.5` yang bisa diam-diam
   berubah menjadi `1` — dibuang.
4. Jumlah sitasi yang dibuang **dilaporkan ke pengguna**, tidak disembunyikan.
5. Setiap hipotesis diberi status: `supported`, `contested`, atau `unsupported`.

Hipotesis yang kehilangan seluruh buktinya tetap ditampilkan, tetapi ditandai
`no surviving evidence`. Pengguna melihat kebohongan model, bukan ringkasan yang
sudah dibersihkan sehingga tampak meyakinkan.

### Deteksi tidak bergantung pada AI

Seluruh kemampuan deteksi berjalan tanpa LLM dan tanpa jaringan. Enam rule deterministik
(R-001 sampai R-006) membaca tabel event dan menghasilkan alert yang setiap barisnya
membawa ID event sumber. Sistem tetap berfungsi penuh bila tidak ada provider AI
dikonfigurasi — dan menyatakan itu secara terbuka di antarmuka, bukan gagal diam-diam.

## 3. Kebaruan teknis

**a. Setiap relasi graf harus punya bukti atau dinyatakan sebagai turunan.**
Relasi berstatus `observed` wajib merujuk minimal satu event; relasi `inferred` wajib
menjelaskan metode penurunannya dan tidak mengklaim fakta langsung. Antarmuka
menampilkan perbedaan ini secara visual.

**b. Penanganan timestamp yang jujur.**
Timestamp tanpa zona tidak ditebak diam-diam. Sistem mencatat statusnya: `explicit`,
`assumed` (dengan zona yang dideklarasikan), atau `UNKNOWN`. Timestamp yang tidak bisa
diparse tetap disimpan dan ditandai, bukan dibuang — karena membuang bukti waktu adalah
bentuk ketidakjujuran tersendiri.

**c. Kegagalan yang terlihat.**
Exception pada rule dikumpulkan ke `engine_errors` dan ditampilkan, bukan ditelan.
Output AI yang tidak valid menghasilkan `validation_failed` dan **tidak ada satu pun
konten AI** yang masuk laporan; laporan menyatakan kegagalan itu secara eksplisit.

**d. Laporan yang menyatakan ketidakpastian.**
Laporan insiden memuat seksi khusus "Known impact vs. unestablished impact" yang
menyatakan apa yang **tidak** bisa dibuktikan:

> Confirmed compromise: NOT established by this evidence set.
> Confirmed data exfiltration: NOT established.

## 4. Bukti pengujian

Tiga skenario adversarial dijalankan terhadap provider palsu yang sengaja berbohong:

| Skenario | Input dari model | Hasil sistem |
|---|---|---|
| Campuran | 6 ID karangan + 1 ID asli | 6 dibuang & dilaporkan; hipotesis berbukti `evidence-linked`, sisanya `no surviving evidence` |
| Semua karangan | 3 ID palsu | Seluruhnya dibuang; satu-satunya hipotesis `unsupported` |
| JSON rusak | Bukan JSON | `validation_failed`; laporan menyatakan AI gagal, tanpa konten fiktif |

Selain itu:

- **136 test otomatis lulus** (pytest), mencakup ingest, deteksi, korelasi, AI, keamanan,
  dan API.
- **Verifikasi end-to-end**: `tools/verify.py` menjalankan 26 pemeriksaan terhadap API
  yang berjalan dan mengembalikan verdict berbasis exit code. Hasil: **26/26 PASS**.
- **Jalur jaringan provider diuji nyata**: permintaan ke `api.openai.com` menghasilkan
  HTTP 401 asli, dilaporkan sebagai `ok:false` dengan kategori `auth` — bukan pura-pura
  berhasil.

**Yang belum diuji dan dinyatakan terbuka:** tidak ada provider cloud yang diuji dengan
kredensial valid. Kualitas analisis model nyata belum diukur secara kuantitatif.

## 5. Kelayakan

**Stack:** Python 3.11 + FastAPI + SQLite (stdlib `sqlite3`, tanpa ORM) untuk backend;
React + TypeScript + Vite untuk frontend. Attack graph digambar dengan SVG tulisan tangan
— tanpa dependensi graf berat.

**Alasan pemilihan:**
- SQLite tanpa ORM: setiap query bisa dibaca langsung saat audit.
- SVG manual: kontrol penuh atas pembedaan visual observed vs inferred, sekaligus
  meminimalkan permukaan supply chain yang harus dipercaya.
- Tanpa dependensi AI wajib: sistem berjalan penuh tanpa koneksi internet.

**Jalur produksi:** kode sudah terstruktur dengan pemisahan modul yang jelas
(`ingest`, `detection`, `correlation`, `ai_analysis`, `reporting`, `api`). Yang perlu
ditambahkan untuk produksi sudah teridentifikasi dan didokumentasikan: autentikasi,
TLS di belakang reverse proxy, konektor SIEM, dan enkripsi at-rest.

## 6. Dampak

**Bagi analis:** waktu yang biasanya habis memindahkan potongan data bisa dipakai untuk
penalaran. Graf dan timeline sudah tersusun, dengan setiap elemen dapat ditelusuri.

**Bagi organisasi:** laporan insiden yang bisa dipertahankan saat dipersoalkan. Ketika
pimpinan bertanya "apakah data kita bocor?", jawabannya bukan tebakan model, melainkan
pernyataan berbasis bukti tentang apa yang terbukti dan apa yang tidak.

**Bagi ekosistem:** pendekatan evidence guard dapat diterapkan pada sistem apa pun yang
menggunakan LLM untuk analisis keamanan. Ini pola yang lebih penting daripada produknya
sendiri.

## 7. Batasan yang dinyatakan terbuka

1. Belum ada autentikasi maupun otorisasi pengguna.
2. Belum ada TLS; harus di belakang reverse proxy.
3. Tabel event belum dienkripsi at-rest (hanya kunci provider yang dienkripsi).
4. Rule R-006 (volume anomaly) bersifat ilustratif, belum dikalibrasi ke baseline nyata.
5. Belum ada konektor langsung ke SIEM/EDR; impor melalui unggahan file.
6. Pengelompokan insiden memakai heuristik host/akun, bukan model probabilistik.
7. Dataset demo bersifat sintetis; kemampuan deteksi pada data nyata belum diukur.

## 8. Kesesuaian dengan kriteria penilaian

| Kriteria | Bobot | Pemenuhan |
|---|---|---|
| Relevansi & manfaat | 25% | Menyasar masalah nyata SOC: merangkai alert menjadi cerita yang dapat dipertanggungjawabkan. Dampak langsung pada kualitas laporan insiden. |
| Inovasi teknis | 25% | Evidence guard yang membuang dan melaporkan sitasi karangan model; pemisahan eksplisit fakta/turunan/hipotesis pada setiap lapis, termasuk per relasi graf. |
| Fungsi prototipe | 25% | Berjalan penuh. 136 test lulus, 26/26 pemeriksaan end-to-end PASS, tiga skenario adversarial terbukti tertangani. |
| Kelayakan | 15% | Stack minimal, tanpa dependensi AI wajib, jalan tanpa internet. Jalur produksi sudah dipetakan. |
| Dokumentasi | 10% | README, arsitektur, model ancaman, panduan demo, dan skrip video — semuanya menyatakan batasan secara eksplisit. |
