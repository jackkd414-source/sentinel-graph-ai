# Skrip video demo, SentinelGraph AI

Durasi target: **3 menit** (batas tipikal submission hackathon).
Format keluaran: 1920x1080, rekam layar penuh browser, narasi Bahasa Indonesia.

---

## Persiapan sebelum rekam

1. Tutup semua tab browser lain. Satu tab saja: `http://127.0.0.1:8088/`
2. Zoom browser 100%, lebar jendela minimal 1440px.
3. Pastikan server jalan, lalu muat ulang demo dari UI:
   - Klik **Load demo dataset** → pastikan Dashboard menampilkan **29 event, 10 alert, 4 insiden**.
   - Master key tidak perlu diset manual. Bila `SG_MASTER_KEY` kosong, kunci dibuat otomatis
     di `<data dir>/master.key` saat pertama dipakai.
4. Siapkan provider AI:
   - Lokal tanpa key (paling praktis untuk rekaman): jalankan Ollama, lalu di UI
     **AI Providers** tambahkan provider `ollama` dengan base URL `http://127.0.0.1:11434`.
     Hanya Ollama yang diizinkan memakai alamat loopback.
   - Atau pakai provider cloud dengan key Anda sendiri.
   - Di UI: **AI Providers** → pastikan status "Provider configured and ready."
   - Catatan: `fake_provider` di `backend/tests/test_ai.py` adalah fixture pytest, bukan
     skrip yang bisa dijalankan untuk demo. Tidak ada berkas `fake_provider.py`.
5. Rekam percobaan **dulu tanpa mikrofon**, tonton ulang, baru rekam dengan narasi.

---

## Shot list

### SHOT 1, Hook (0:00-0:15)

**Layar:** Dashboard.

**Narasi:**
> "Setiap hari tim keamanan menerima ratusan alert. Masalahnya bukan kekurangan data -
> masalahnya merangkai potongan itu menjadi cerita yang bisa dipertanggungjawabkan.
> Ini SentinelGraph AI: dari sinyal menjadi cerita."

**Aksi:** diam, biarkan dashboard terlihat. Sorot angka 29 / 10 / 4.

---

### SHOT 2, Bukan dashboard kosong (0:15-0:35)

**Layar:** Masih Dashboard, gulir pelan ke tabel insiden.

**Narasi:**
> "Dua puluh sembilan event, sepuluh alert, empat insiden. Semua angka ini berasal dari
> tabel database, bukan konstanta. Setiap baris bisa ditelusuri sampai event aslinya."

**Aksi:** klik baris **INC-0001**.

---

### SHOT 3, Pemisahan fakta vs hipotesis (0:35-1:05)

**Layar:** Tab **Overview**, INC-0001.

**Narasi:**
> "Perhatikan kalimat ini. IOC match adalah fakta. Bahwa host terkompromi adalah
> hipotesis yang butuh pembuktian. Kami tidak memberi tahu Anda bahwa Anda diserang -
> kami memberi tahu apa yang diamati, dan apa yang belum bisa dibuktikan."

**Aksi:** scroll pelan menuju kartu **Findings, why this fired**, tunjuk satu narasi R-004
yang berbunyi "Whether data left the network is NOT established".

---

### SHOT 4, Timeline (1:05-1:25)

**Layar:** Tab **Timeline**.

**Narasi:**
> "Sembilan event berurutan dalam sembilan menit: email phishing masuk, kredensial
> dipanen, PowerShell dipanggil Outlook, koneksi ke infrastruktur C2, akses file
> keuangan dan HR, lalu transfer keluar empat belas koma tujuh megabyte."

**Aksi:** scroll dari event teratas ke terbawah, berhenti di baris transfer.

---

### SHOT 5, Graf berbukti (1:25-1:50)

**Layar:** Tab **Attack graph**.

**Narasi:**
> "Inilah graf serangannya. Alert di inti, host di cincin luar, entitas perimeter di
> tepi. Tapi yang penting bukan gambarnya, melainkan bahwa setiap garis bisa dibuktikan."

**Aksi:** klik node **WS-FIN-07**. Panel kanan muncul. Sorot baris:
```
observed  evidence: #147, #148
```
lalu sorot baris inferred yang berbunyi:
```
INFERRED  derived relation, no single source event
```

**Narasi lanjutan:**
> "Relasi yang tercatat langsung membawa ID event sumbernya. Relasi yang kami turunkan
> diberi label berbeda dan dijelaskan cara penurunannya. Kami tidak mencampur keduanya."

---

### SHOT 6, Momen kunci: model berbohong (1:50-2:30)

**Layar:** Tab **AI analysis**.

**Narasi:**
> "Sekarang bagian yang paling sering dilewati produk lain. Saya jalankan analisis AI."

**Aksi:** klik **Analyze with AI**. Tunggu hasil.

**Narasi:**
> "Model mengembalikan dua hipotesis. Yang pertama bertanda evidence-linked, ia mengutip
> event yang benar-benar ada. Yang kedua bertanda no surviving evidence."

**Aksi:** sorot chip `no surviving evidence`, lalu sorot baris sitasi di bawah hipotesis:
```
supports: none    contradicts: none
```
Catatan: baris `Evidence guard: N citation(s) ... were removed` **tidak** ada di panel AI,
melainkan muncul di laporan yang diunduh (seksi 6). Sorot di SHOT 7.

**Narasi:**
> "Model tadi mengarang enam rujukan. ID yang disebutnya tidak ada di database.
> Setiap sitasi diperiksa. Yang tidak ada dibuang. Hipotesis yang kehilangan seluruh
> buktinya tetap ditampilkan, tapi ditandai jelas sebagai klaim tanpa dasar.
> Kami tidak menyembunyikannya. Justru itu buktinya bahwa sistem ini bisa dipercaya."

**Aksi:** sorot disclaimer di bawah ringkasan:
```
Summary is free-form model text and is not verified against the event store.
```

---

### SHOT 7, Laporan yang jujur (2:30-2:50)

**Layar:** Tab **Report** → klik **Download**.

**Narasi:**
> "Terakhir, laporannya. Ini yang biasanya tidak dilakukan alat lain."

**Aksi:** buka file markdown. Di seksi 6, sorot baris:
```
Evidence guard: 6 citation(s) produced by the model referenced events that do not
exist in this incident and were removed.
```
lalu scroll ke seksi 7.

**Narasi:**
> "Confirmed compromise: not established. Confirmed data exfiltration: not established.
> Laporan yang menyatakan apa yang tidak bisa dibuktikan, itu yang membuatnya bisa
> dipakai di ruang rapat, bukan hanya di dashboard."

---

### SHOT 8, Penutup (2:50-3:00)

**Layar:** kembali ke Dashboard.

**Narasi:**
> "SentinelGraph AI. Deteksi deterministik yang bisa diaudit, graf yang setiap garisnya
> berbukti, dan AI yang diperlakukan sebagai tersangka, bukan saksi.
> Dari sinyal menjadi cerita."

---

## Catatan produksi

**Yang harus diperlihatkan apa adanya (jangan dipotong):**
- Chip `no surviving evidence`, ini pembeda utama produk.
- Baris "evidence: #..." pada panel node.
- Seksi "NOT established" pada laporan.

**Yang harus disebutkan terus terang bila ditanya:**
- Provider yang dipakai saat rekaman adalah model lokal (Ollama), bukan model cloud.
  Tujuannya mendemonstrasikan mekanisme pertahanan, bukan kualitas model.
- Jalur jaringan nyata sudah diuji ke api.openai.com dan menghasilkan 401 asli,
  dilaporkan sebagai `ok:false` dengan `error_category: "auth"`.
- Jumlah dan ID sitasi karangan bergantung pada apa yang benar-benar dikembalikan model
  saat rekaman. Sebutkan jumlahnya, atau baca ID langsung dari layar. Jangan menyebut ID
  tertentu (misalnya 9999, 8888, 6666) kecuali memang muncul di rekaman Anda.

**Bila ada yang gagal saat rekaman:**
- Halaman putih → stop rekaman, cek konsol, ulangi. Jangan menyambung.
- AI error → tampilkan apa adanya di layar, lalu lanjutkan. Justru bagus: menunjukkan
  sistem tidak berpura-pura berhasil.

**Setelah rekaman:**
- Tonton ulang sekali penuh. Pastikan tidak ada notifikasi OS yang muncul.
- Pastikan wajah/nama pengguna di layar tidak terekspos (cek taskbar, tab lain).
- Ekspor 1080p, H.264, bitrate ~8 Mbps.
