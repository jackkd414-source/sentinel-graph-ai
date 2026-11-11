# Slide deck — SentinelGraph AI

**Format:** 10 slide. Satu ide per slide. Rasio 16:9.
**Waktu presentasi:** 10 menit (Babak 2 final), atau 3 menit bila dipangkas.
**Prinsip:** setiap slide punya satu kalimat yang harus diingat penonton.

---

## Slide 1 — Judul

```
SentinelGraph AI
From Signals to Story

Investigasi insiden yang bisa dipertanggungjawabkan

Kartika Cyber Hackathon 2026 — Defensive Shield
[Nama Tim] · [Anggota 1] · [Anggota 2]
```

**Catatan pembicara:** jangan mulai dengan menjelaskan fitur. Mulai dengan masalahnya
di slide berikutnya. Slide ini hanya 5 detik.

---

## Slide 2 — Masalahnya bukan data

**Judul:** Kita punya terlalu banyak alert, terlalu sedikit cerita

**Isi (3 poin, bukan paragraf):**

- Analis menerima puluhan alert per hari. Masing-masing benar. Semuanya terpisah.
- Cerita serangan disusun manual di kepala analis — dan hilang saat pindah shift.
- Laporan akhirnya berisi klaim yang tidak bisa dipertahankan saat dipersoalkan.

**Kalimat kunci:** *"Masalahnya bukan kekurangan data. Masalahnya tidak ada yang bisa
membuktikan bahwa cerita yang kita susun itu benar."*

---

## Slide 3 — Dua pendekatan yang gagal

**Judul:** SIEM terlalu mentah, LLM terlalu percaya diri

**Tabel:**

| | Masalah |
|---|---|
| SIEM saja | Memberi alert, tidak merangkai. Kesimpulan tidak bisa direproduksi. |
| LLM untuk merangkum | Menghasilkan teks meyakinkan tanpa jaminan benar. Tidak ada cara memeriksa. |

**Kalimat kunci:** *"LLM menjawab pertanyaan 'apa yang mungkin terjadi'. Kami butuh
jawaban atas 'apa yang bisa saya buktikan'."*

---

## Slide 4 — Solusi: tiga lapis yang tidak dicampur

**Judul:** Fakta, turunan, hipotesis — dipisahkan secara eksplisit

**Visual:** tiga kotak bertingkat

```
┌─────────────────────────────┐
│ AI HYPOTHESIS               │  diperlakukan sebagai tersangka
│ model bahasa, opsional      │
├─────────────────────────────┤
│ DERIVED FINDING             │  deterministik, dapat direproduksi
│ rule engine R-001..R-006    │
├─────────────────────────────┤
│ OBSERVED FACT               │  setiap klaim membawa ID event
│ event yang diimpor          │
└─────────────────────────────┘
```

**Kalimat kunci:** *"Setiap lapis punya aturan pembuktian sendiri. Tidak ada klaim yang
naik lapis tanpa bukti."*

---

## Slide 5 — Mekanisme inti: evidence guard

**Judul:** AI tidak bisa berbohong tanpa ketahuan

**Alur (5 langkah, ditampilkan sebagai pipeline horizontal):**

```
catat ID yang dikirim  →  kirim ke model  →  validasi skema
                                                      ↓
                              laporkan jumlah yang dibuang  ←  periksa setiap sitasi
                                                      ↓
                                    tandai: supported / contested / unsupported
```

**Poin pendukung:**

- ID karangan dibuang. Nilai non-integer seperti `1.5` ditolak — bukan diam-diam
  menjadi `1`.
- Jumlah sitasi yang dibuang **dilaporkan ke pengguna**, tidak dibersihkan diam-diam.
- Hipotesis tanpa bukti tetap tampil, bertanda `no surviving evidence`.

**Kalimat kunci:** *"Kami tidak membuat model jadi jujur. Kami membuat kebohongannya
terlihat."*

---

## Slide 6 — Bukti: model benar-benar mencoba berbohong

**Judul:** Diuji dengan model yang sengaja tidak jujur

**Tabel hasil:**

| Yang dikirim model | Yang dilakukan sistem |
|---|---|
| 6 ID karangan + 1 ID asli | 6 dibuang & dilaporkan; hipotesis berbukti tetap `evidence-linked` |
| 3 ID palsu seluruhnya | Semua dibuang; hipotesis bertanda `unsupported` |
| JSON rusak | `validation_failed`; tidak ada konten AI masuk laporan |

**Angka besar di layar:** `6 sitasi karangan dibuang` · `0 lolos validasi`

**Kalimat kunci:** *"Ini bukan simulasi di atas kertas. Ini output nyata dari sistem
yang berjalan."*

---

## Slide 7 — Produknya berjalan

**Judul:** Bukan mockup

**Screenshot:** dashboard + graf + panel node (tiga gambar berdampingan)

**Poin:**

- 136 test otomatis lulus
- 26/26 pemeriksaan end-to-end PASS (verdict berbasis exit code)
- 4 insiden, 60 node, 52 relasi graf — **setiap relasi membawa ID event sumbernya**
- Rule engine berjalan tanpa AI dan tanpa jaringan

**Kalimat kunci:** *"Cabut provider AI-nya, semua fitur deteksi, korelasi, graf, dan
laporan tetap berjalan."*

---

## Slide 8 — Yang membedakan: laporan yang jujur

**Judul:** Kami menyatakan apa yang tidak bisa dibuktikan

**Screenshot:** potongan laporan seksi 7

```
Confirmed compromise:        NOT established by this evidence set.
Confirmed data exfiltration: NOT established.
```

**Kalimat kunci:** *"Laporan yang berguna di ruang rapat adalah laporan yang berani
mengatakan 'saya belum bisa membuktikan ini'."*

---

## Slide 9 — Kelayakan

**Judul:** Ringan, auditabel, jalan tanpa internet

**Kiri — stack:**
- Python 3.11 + FastAPI
- SQLite tanpa ORM — setiap query bisa dibaca saat audit
- React + TypeScript + Vite
- Attack graph SVG tulisan tangan — tanpa dependensi berat

**Kanan — jalur produksi (sudah dipetakan):**
1. Autentikasi + RBAC
2. TLS di belakang reverse proxy
3. Konektor SIEM/EDR
4. Enkripsi at-rest

**Kalimat kunci:** *"Bukan prototipe yang harus ditulis ulang untuk dipakai."*

---

## Slide 10 — Penutup

**Judul:** Dari sinyal menjadi cerita

**Tiga kalimat, bukan lebih:**

> Deteksi deterministik yang bisa diaudit.
> Graf yang setiap garisnya berbukti.
> AI yang diperlakukan sebagai tersangka — bukan saksi.

**Penutup:** *"SentinelGraph AI."*

---

## Versi 3 menit (bila dipangkas)

| Slide | Waktu | Yang wajib ditampilkan |
|---|---|---|
| 1 | 0:00 | Judul |
| 2 | 0:15 | Masalah |
| 4 | 0:40 | Tiga lapis |
| 5 | 1:10 | Evidence guard |
| 6 | 1:45 | Hasil uji adversarial — **wajib** |
| 8 | 2:20 | "NOT established" |
| 10 | 2:50 | Penutup |

Slide 3, 7, dan 9 dilewati. Bila ditanya, jawab dari slide lengkap.

---

## Antisipasi pertanyaan juri

**"Ini cuma wrapper API OpenAI?"**
> "Tidak. Deteksi, korelasi, graf, dan laporan berjalan tanpa AI sama sekali. Cabut
> provider-nya, aplikasi tetap berfungsi penuh. AI hanya menafsirkan hasil yang sudah
> ada, dan hanya lewat gerbang validasi."

**"Bagaimana kalau modelnya pintar dan tidak berhalusinasi?"**
> "Justru itu intinya — kami tidak mengandalkan model untuk jujur. Kalau model jujur,
> semua hipotesis jadi evidence-linked. Kalau tidak, ketahuan dan dilaporkan. Yang
> penting bukan hasilnya, tapi bahwa hasilnya bisa diperiksa."

**"Sudah dicoba dengan provider nyata?"**
> "Jalur jaringannya iya — kami menguji ke api.openai.com dan mendapat 401 asli karena
> kredensial tidak valid. Yang belum: mengukur kualitas analisis dengan kredensial valid.
> Itu tercatat sebagai batasan di proposal."

**"Data demo asli?"**
> "Sintetis, dan kami sebut terus terang. Yang diuji adalah mekanisme, bukan akurasi
> deteksi pada data nyata."

**"Bagaimana kalau AI-nya dimatikan?"**
> "Semua fitur inti tetap jalan. Antarmuka menyatakan 'no AI provider configured',
> bukan gagal diam-diam."

**"Apa rencana setelah hackathon?"**
> "Tiga hal berurutan: autentikasi, konektor SIEM, lalu kalibrasi rule terhadap baseline
> nyata. Pola evidence guard-nya bisa dipakai di sistem lain — itu bagian yang paling
> layak dibawa keluar dari proyek ini."

---

## Catatan desain slide

- **Maksimal 30 kata per slide.** Bila lebih, potong.
- **Satu screenshot asli lebih baik daripada tiga diagram.**
- Jangan pakai animasi transisi. Fokus penonton harus ke isi.
- Nomor slide di kanan bawah, kecil.
- Konsisten: judul di kiri atas, satu warna aksen untuk penekanan.
