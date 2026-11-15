# Panduan demo, SentinelGraph AI

Durasi target: **3 menit** untuk presentasi, **10 menit** untuk sesi tanya jawab.
Semua langkah di bawah sudah diverifikasi berjalan pada build saat ini.

---

## Persiapan (sebelum panggung)

```bash
cd sentinelgraph-ai
export PYTHONPATH=backend
export SG_MASTER_KEY="$(./.venv/Scripts/python.exe -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
rm -f data/sentinelgraph.db*
./.venv/Scripts/python.exe -m sentinelgraph serve --port 8088
```

Buka `http://127.0.0.1:8088/` di browser. Pastikan Dashboard menampilkan **29 event,
10 alert, 4 insiden**. Bila kosong, klik **Load demo**.

**Opsional, siapkan provider AI.** Bila tidak ada kunci nyata, gunakan stub lokal agar
jalur AI tetap bisa didemokan:

```bash
# terminal terpisah
./.venv/Scripts/python.exe backend/tools/fake_provider.py --port 8099 --mode mixed
# lalu di UI: AI Providers → ollama → base URL http://127.0.0.1:8099 → model stub-model-1
```

Bila memakai stub, **katakan terus terang** bahwa itu stub dan tujuannya mendemonstrasikan
mekanisme pertahanan, bukan kualitas model.

---

## Alur demo

### 1. Dashboard (20 detik)

> "Ini bukan dashboard kosong. 29 event, 10 alert, 4 insiden, semuanya berasal dari
> tabel. Setiap angka bisa ditelusuri."

Tunjuk panel **Analysis Engine**: bila AI off, tertulis "No AI provider configured -
semua fitur deteksi, korelasi, graf, dan laporan berjalan tanpa AI."

### 2. Buka INC-0001 → Overview (30 detik)

> "Perhatikan kalimat ini: *'The IOC match is a fact; that the host is compromised is a
> hypothesis requiring corroboration.'* Produk ini tidak memberi tahu Anda bahwa Anda
> sudah diserang. Ia memberi tahu apa yang diamati dan apa yang masih harus dibuktikan."

Tunjuk kartu **Affected assets** dan **Accounts involved**.

### 3. Timeline (25 detik)

Buka tab **Timeline**. Sembilan event berurutan:

1. Email phishing masuk ke MAILGW-01
2. HTTP request ke domain phishing dari WS-FIN-07
3. Proses `powershell.exe` dipanggil `OUTLOOK.EXE`
4. DNS + koneksi ke 203.0.113.66 (C2)
5. Akses file sensitif (Finance & HR)
6. Transfer keluar 14,7 MB

> "Ini adalah 'story' dalam tagline, tapi setiap baris adalah event yang tersimpan,
> bukan narasi yang dibuat-buat."

### 4. Attack graph (35 detik)

Buka tab **Attack graph**. Graf radial: alert di inti, host di cincin luar.

> "Setiap garis di sini punya bukti. Klik node untuk melihat relasinya."

Klik satu node host. Pada panel relasi, tunjukkan:

```
evidence: #12, #13, #14
```

atau untuk relasi turunan:

```
derived relation, no single source event
```

> "Perbedaan ini penting. Kami tidak mencampur fakta dengan turunan."

### 5. AI analysis, momen kunci (60 detik)

Buka tab **AI analysis**, klik **Analyze with AI**.

Tunjuk hasilnya:

- Dua hipotesis muncul
- Satu berlabel **evidence-linked**, punya sitasi event nyata
- Satu berlabel **no surviving evidence**, sitasi dari model semuanya palsu
- Di bawah: "Evidence guard: 6 citation(s) ... were removed"

> "Model mencoba mengarang. Ia menyebut event 9999, 8888, 6666, yang tidak ada.
> Setiap sitasi diperiksa ke database. Yang tidak ada dibuang. Hipotesis yang kehilangan
> seluruh buktinya tetap ditampilkan, tapi ditandai jelas sebagai klaim tanpa bukti.
>
> Kami tidak menyembunyikannya, kami menunjukkannya. Itu inti dari produk ini."

Tunjuk disclaimer di bawah ringkasan: *"Summary is free-form model text and is not
verified against the event store."*

### 6. Report (25 detik)

Buka tab **Report**, klik **Download** (markdown). Buka seksi 7:

> **Confirmed compromise:** NOT established by this evidence set.
> **Confirmed data exfiltration:** NOT established.

> "Ini yang biasanya tidak dilakukan alat lain: laporan yang menyatakan apa yang
> **tidak** bisa dibuktikan."

---

## Pertanyaan yang kemungkinan muncul

**"Apakah ini benar-benar pakai AI?"**
> "Jalur AI-nya nyata, kami menguji ke api.openai.com dan mendapat 401 asli karena
> kuncinya tidak valid. Saat ini kami tidak punya kredensial valid, jadi demo memakai
> stub lokal. Yang terbukti adalah mekanisme pertahanannya, bukan kualitas modelnya."

**"Bagaimana kalau model-nya pintar dan tidak berhalusinasi?"**
> "Justru itu intinya, kami tidak mengandalkan model untuk jujur. Setiap sitasi
> diverifikasi. Kalau model jujur, semua hipotesis jadi evidence-linked. Kalau tidak,
> ketahuan."

**"Bisa dipakai untuk data nyata?"**
> "Mesin deteksinya ya. Tapi belum ada autentikasi, jadi harus di belakang proxy dengan
> TLS. Ini tercatat sebagai batasan di dokumentasi."

**"Apa bedanya dengan SIEM?"**
> "SIEM mengumpulkan dan memberi alert. Kami fokus pada lapisan setelah alert: merangkai
> menjadi cerita yang bisa dipertanggungjawabkan, dengan pemisahan eksplisit antara fakta,
> turunan, dan hipotesis AI."

---

## Bila ada yang gagal saat demo

| Gejala | Tindakan |
|---|---|
| Dashboard kosong | Klik **Load demo** |
| Graf bertumpuk | Muat ulang halaman (layout dihitung ulang) |
| AI analysis error | Buka **AI Providers** → **Test**; bila gagal, lanjutkan demo tanpa AI, semua fitur lain jalan |
| Halaman putih | Buka konsol browser; laporkan apa adanya, jangan mengklaim berhasil |

Jangan pernah mengklaim fitur berjalan bila belum terlihat berjalan.
