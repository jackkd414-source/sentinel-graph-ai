# Demo Guide, 3 menit untuk juri

Dataset: **sintetis** (25-29 event, 4 insiden). Tidak ada data mesin nyata.

## Persiapan (sebelum tampil)

```bash
scripts/setup.ps1                 # sekali saja
scripts/start.ps1                 # http://127.0.0.1:8088
```

Pastikan dashboard menampilkan angka non-nol. Klik **Load demo** bila kosong.

## Alur

1. **Dashboard**, 25 event, 10 alert, 4 insiden, 5 aset. Sebutkan: setiap angka
   berasal dari tabel SQLite, bukan konstanta.
2. **INC-0001 → Overview**, tunjukkan pemisahan tegas: "IOC match adalah fakta;
   host terkompromi adalah hipotesis". Panel bukti menyebut ID event sumber.
3. **Timeline**, 9 event berurutan: email phishing → proses → koneksi luar.
4. **Attack Graph**, tekan **⤢ Fit to view**. Graf otomatis terpusat dan seluruh node
   masuk frame. Sorot satu node: edge terkait menyala, label relasi muncul.
   - Toggle **Show inferred** → edge putus-putus (hipotesis) vs solid (observed).
   - Klik chip **RELATIONS** untuk menyembunyikan jenis edge tertentu.
   - Pilih **incident** di dropdown untuk memfilter graf ke host insiden itu.
   - Klik node → panel kanan menampilkan **EVIDENCE** (baris event asli).
5. **Detection Rules**, 6 rule deterministik; alert selalu membawa ID event.
6. **AI Analysis (opsional)**, bila provider aktif: tunjukkan hipotesis
   `evidence-linked` vs `no surviving evidence`, dan jumlah sitasi yang dibuang
   evidence guard. Bila tidak ada provider: nyatakan mode core-only tetap penuh.
7. **Report**, unduh markdown; buka seksi "Confirmed compromise: NOT established".

## Kalimat kunci

> "Sistem ini menolak mengklaim kompromi yang tidak bisa dibuktikan. Deteksi tidak
> bergantung pada AI, dan setiap temuan bisa ditelusuri ke baris event."

## Jangan dilakukan saat demo

- Jangan gunakan `--host 0.0.0.0` tanpa token (startup akan menolak, itu memang fitur).
- Jangan impor log mesin nyata di depan juri; pakai dataset sintetis.
