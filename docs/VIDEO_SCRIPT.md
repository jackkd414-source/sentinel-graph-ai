# Skrip video demo, SentinelGraph AI

Durasi target: **3 menit**. Format 1920x1080, rekam layar penuh browser, narasi Bahasa Indonesia.

---

## Persiapan sebelum rekam

1. Tutup semua tab lain. Sisakan satu: `http://127.0.0.1:8088/`
2. Zoom browser 100%, lebar jendela minimal 1440px.
3. Pastikan server jalan, lalu muat ulang demo:
   - Klik **Load demo dataset**. Dashboard harus menampilkan **29 event, 10 alert, 4 insiden**.
   - Master key tidak perlu diset. Kalau `SG_MASTER_KEY` kosong, kuncinya dibuat otomatis
     di `<data dir>/master.key` saat pertama dipakai.
4. Siapkan provider AI:
   - Paling praktis: jalankan Ollama, lalu di **AI Providers** tambahkan provider `ollama`
     dengan base URL `http://127.0.0.1:11434`. Hanya Ollama yang boleh pakai alamat loopback.
   - Atau provider cloud dengan key Anda sendiri.
   - Statusnya harus "Provider configured and ready."
   - Catatan: `fake_provider` di `backend/tests/test_ai.py` itu fixture pytest, bukan skrip
     yang bisa dijalankan. Tidak ada berkas `fake_provider.py`.
5. Rekam percobaan dulu tanpa mikrofon. Tonton ulang, baru rekam dengan narasi.

---

## Shot list

### SHOT 1, Hook (0:00-0:15)

**Layar:** Dashboard.

**Narasi:**
> "Tim keamanan tiap hari kebanjiran alert. Datanya sudah ada, dan di situlah masalahnya:
> terlalu banyak, tersebar di banyak alat, dan tidak ada yang menyusunnya jadi satu cerita.
> Itu yang coba kami bereskan."

**Aksi:** diam. Biarkan dashboard terlihat. Sorot angka 29 / 10 / 4.

---

### SHOT 2, Bukan dashboard kosong (0:15-0:35)

**Layar:** Masih Dashboard. Gulir pelan ke tabel insiden.

**Narasi:**
> "Dua puluh sembilan event, sepuluh alert, empat insiden. Angka ini dibaca langsung dari
> database. Klik satu baris, Anda bisa menelusurinya sampai ke event aslinya."

**Aksi:** klik baris **INC-0001**.

---

### SHOT 3, Fakta vs hipotesis (0:35-1:05)

**Layar:** Tab **Overview**, INC-0001.

**Narasi:**
> "Lihat baris ini. IOC match itu fakta yang teramati. Kesimpulan bahwa host-nya
> terkompromi baru hipotesis, dan itu masih perlu dibuktikan. Produk ini berhenti di
> apa yang teramati, dan bilang terus terang kalau ada yang belum bisa dibuktikan."

**Aksi:** scroll pelan ke kartu **Findings, why this fired**. Tunjuk narasi R-004:
"Whether data left the network is NOT established".

---

### SHOT 4, Timeline (1:05-1:25)

**Layar:** Tab **Timeline**.

**Narasi:**
> "Sembilan event dalam sembilan menit. Email phishing masuk, kredensial dipakai, Outlook
> memanggil PowerShell, keluar koneksi ke infrastruktur C2, file keuangan dan HR diakses,
> lalu transfer keluar empat belas koma tujuh megabyte."

**Aksi:** scroll dari event teratas ke terbawah. Berhenti di baris transfer.

---

### SHOT 5, Graf berbukti (1:25-1:50)

**Layar:** Tab **Attack graph**.

**Narasi:**
> "Ini graf serangannya. Alert di tengah, host di sekelilingnya, entitas perimeter di luar.
> Setiap garis di sini bisa ditelusuri ke event asalnya."

**Aksi:** klik node **WS-FIN-07**. Panel kanan muncul. Sorot baris:
```
observed  evidence: #147, #148
```
lalu sorot baris inferred:
```
INFERRED  derived relation, no single source event
```

**Narasi lanjutan:**
> "Relasi yang benar-benar tercatat membawa ID event sumbernya. Kalau relasinya hasil
> turunan, labelnya beda dan cara menurunkannya dijelaskan. Dua-duanya tidak pernah
> dicampur."

---

### SHOT 6, Momen kunci: model berbohong (1:50-2:30)

**Layar:** Tab **AI analysis**.

**Narasi:**
> "Sekarang saya jalankan analisis AI-nya."

**Aksi:** klik **Analyze with AI**. Tunggu hasil.

**Narasi:**
> "Modelnya balik dengan dua hipotesis. Yang pertama evidence-linked, sitasinya event yang
> memang ada. Yang kedua ditandai no surviving evidence."

**Aksi:** sorot chip `no surviving evidence`, lalu baris sitasinya:
```
supports: none    contradicts: none
```
Catatan: baris `Evidence guard: N citation(s) ... were removed` **tidak** ada di panel AI.
Baris itu muncul di laporan (seksi 6). Sorot di SHOT 7.

**Narasi:**
> "Model tadi mengarang enam rujukan. ID yang disebutnya tidak ada di database. Sistem
> memeriksa tiap sitasi, membuang yang tidak ada, lalu tetap menampilkan hipotesisnya
> dengan tanda jelas bahwa klaimnya tidak punya dasar. Sebenarnya lebih gampang kalau
> hipotesis yang salah itu kami buang saja dan tidak ada yang tahu. Tapi karena
> ditampilkan dan dilabeli, Anda bisa menilai sendiri."

**Aksi:** sorot disclaimer di bawah ringkasan:
```
Summary is free-form model text and is not verified against the event store.
```

---

### SHOT 7, Laporan (2:30-2:50)

**Layar:** Tab **Report** → klik **Download**.

**Narasi:**
> "Terakhir, laporannya."

**Aksi:** buka file markdown. Di seksi 6, sorot baris:
```
Evidence guard: 6 citation(s) produced by the model referenced events that do not
exist in this incident and were removed.
```
lalu scroll ke seksi 7.

**Narasi:**
> "Confirmed compromise: not established. Confirmed data exfiltration: not established.
> Laporan ini menyebut hal yang tidak bisa dibuktikan. Laporan begini yang bisa dibawa
> ke rapat, bukan cuma dilihat sebentar di dashboard."

---

### SHOT 8, Penutup (2:50-3:00)

**Layar:** kembali ke Dashboard.

**Narasi:**
> "Deteksi yang bisa diaudit, graf yang tiap garisnya bisa ditelusuri, dan AI yang kami
> perlakukan sebagai tersangka, bukan saksi. Itu SentinelGraph AI."

---

## Catatan produksi

**Yang jangan dipotong:**
- Chip `no surviving evidence`. Ini pembeda utamanya.
- Baris "evidence: #..." di panel node.
- Seksi "NOT established" di laporan.

**Kalau ditanya, jawab terus terang:**
- Provider saat rekaman adalah model lokal (Ollama), bukan model cloud. Yang
  didemonstrasikan mekanisme pertahanannya, bukan kualitas modelnya.
- Jalur jaringan nyata sudah diuji ke api.openai.com dan dapat 401 asli, tercatat sebagai
  `ok:false` dengan `error_category: "auth"`.
- Jumlah dan ID sitasi karangan tergantung apa yang benar-benar dikembalikan model saat
  rekaman. Sebut jumlahnya, atau baca ID-nya dari layar. Jangan sebut ID tertentu
  (misalnya 9999, 8888, 6666) kalau tidak muncul di rekaman Anda.

**Kalau ada yang gagal saat rekaman:**
- Halaman putih: stop, cek konsol, ulangi. Jangan disambung.
- AI error: biarkan terlihat di layar, lalu lanjut. Justru bagus, menunjukkan sistemnya
  tidak berpura-pura berhasil.

**Setelah rekaman:**
- Tonton ulang sekali penuh. Pastikan tidak ada notifikasi OS yang muncul.
- Pastikan nama pengguna di layar tidak terekspos (cek taskbar dan tab lain).
- Ekspor 1080p, H.264, bitrate sekitar 8 Mbps.
