# Memasang Sysmon untuk SentinelGraph AI

## Mengapa Sysmon?

SentinelGraph berjalan tanpa Sysmon, tetapi **rule serius tidak akan pernah menyala**
pada log Windows biasa. Alasannya terukur, dari impor `security.json` (5000 event) dan
`firewall.json` (626 event) di mesin ini:

| Rule | Field yang dibutuhkan | Tersedia tanpa Sysmon? |
|---|---|---|
| R-002 rantai proses | `parent_process` | Hampir tidak, hanya 26 dari 5000, semuanya proses boot normal |
| R-003 koneksi ke IOC | `dst_ip` dari event koneksi | Tidak, event 5156/5157 = **0** |
| R-004 file → transfer | `file_path`, `bytes_out` | Tidak, event 4663/4656 = **0** |

Windows tidak mencatat ini secara default. Sysmon yang mengisinya.

## Pemasangan (satu klik)

1. Buka folder: `<SYSMON_DIR>`
2. **Klik dua kali** `PASANG-SYSMON.bat`
3. Klik **Yes** pada prompt UAC
4. Tunggu ± 60 detik (skrip mengekspor event Sysmon otomatis)

Skrip akan:
- memasang Sysmon dengan config ramping `sentinelgraph-sysmon.xml`
- memverifikasi service berjalan
- mengekspor 1 jam pertama ke `sysmon.json`

### PENTING: membaca log Sysmon butuh Administrator

Log `Microsoft-Windows-Sysmon/Operational` **hanya bisa dibaca Administrator**.
Tanpa hak itu, ekspor gagal dengan "Attempted to perform an unauthorized operation".

Karena itu, untuk ekspor berikutnya pakai launcher yang menaikkan hak sendiri:

```
Klik dua kali:  <PROJECT_ROOT>\tools\EKSPOR-SYSMON.bat
```

Klik **Yes** di UAC, dan `sysmon.json` akan dibuat. Log lengkapnya tersimpan di
`sysmon-export.log`.

Alternatif manual (PowerShell **as Administrator**):

```powershell
cd <PROJECT_ROOT>
.\tools\export-windows-logs.ps1 -Preset sysmon -Hours 24 -Out sysmon.json
```

## Impor ke SentinelGraph

Halaman **Import** → pilih `sysmon.json` → **Import**.

Setelah itu buka **Attack Graph** dan **Events**, node `process`, `user`, dan `ip` akan
muncul karena field-nya kini terisi.

## Ekspor berikutnya

Setelah Sysmon berjalan, ambil event kapan saja:

```powershell
cd <PROJECT_ROOT>
.\tools\export-windows-logs.ps1 -Preset sysmon -Hours 24 -Out sysmon.json
```

Jendela waktu lebih besar = peluang menangkap pola lebih tinggi:

```powershell
.\tools\export-windows-logs.ps1 -Preset sysmon -Hours 72 -Out sysmon-3hari.json
```

## Hasil nyata setelah dipasang

Sysmon v15.22 terpasang dan berjalan di mesin ini. Ekspor pertama (24 jam) menghasilkan
**4298 event**, dan impor ke SentinelGraph memberikan:

| Field | Terisi |
|---|---|
| `user_name` | 4295 |
| `process_name` | 4296 |
| `parent_process` | 1471 |
| `command_line` | 1474 |
| `dst_ip` | 855 |
| `file_path` | 318 |
| `domain` | 108 |

Attack graph melonjak dari **258 → 1890 node**. Bandingkan dengan log Security biasa yang
hanya menghasilkan 258 node dan 0 field proses.

Yang penting: **ini tidak otomatis menghasilkan alert banyak.** Deteksi butuh pola
serangan nyata. Pada mesin kerja yang tidak diserang, hasilnya tetap sedikit, itu benar,
bukan bug. Untuk menguji bahwa rule menyala, lihat bagian berikut.

## Membuktikan rule benar-benar menyala

Kalau ingin memastikan pipeline deteksi bekerja, jalankan:

```powershell
cd <PROJECT_ROOT>
.\.venv\Scripts\python.exe tools\verify_sysmon_format.py
```

Skrip ini menyuntikkan event bergaya Sysmon (rantai Word → PowerShell, koneksi ke IOC)
dan memverifikasi R-002 dan R-003 menyala. Hasil yang diharapkan: **6/6 PASS**.

## Config yang dipakai

`sentinelgraph-sysmon.xml` sengaja **ramping**, bukan config SOC penuh seperti
SwiftOnSecurity. Alasan: mesin ini laptop kerja dengan ~8 GB RAM. Config SOC penuh akan
membanjiri disk dan CPU.

Event yang diaktifkan dan alasannya:

| Event | Nama | Untuk rule |
|---|---|---|
| 1 | ProcessCreate | R-002 (`process_name`, `parent_process`, `command_line`) |
| 3 | NetworkConnect | R-003 (`dst_ip`, `dst_port`) |
| 11 | FileCreate | R-004 (`file_path`) |
| 22 | DNSEvent | R-003 (`domain`) |
| 23 | FileDelete | R-004 (`file_path`) |

Yang dikecualikan: loopback/mDNS (bukan ancaman, dan membanjiri log), proses rutin
Windows (RuntimeBroker, taskhostw, dll), dan proses renderer browser.

### Menyesuaikan config

Ubah `sentinelgraph-sysmon.xml`, lalu terapkan ulang:

```powershell
# PowerShell AS ADMINISTRATOR
cd <SYSMON_DIR>
.\Sysmon64.exe -c sentinelgraph-sysmon.xml
```

## Menghapus Sysmon

```powershell
# PowerShell AS ADMINISTRATOR
cd <SYSMON_DIR>
.\Sysmon64.exe -u
```

Sysmon akan hilang sepenuhnya; event yang sudah diekspor ke JSON tetap ada.

## Pemecahan masalah

| Gejala | Sebab | Solusi |
|---|---|---|
| Skrip bilang "Sysmon belum terpasang" | Belum dipasang | Jalankan `PASANG-SYSMON.bat` |
| `sysmon.json` hampir kosong | Tidak ada aktivitas selama jendela waktu | Perbesar `-Hours`, buka beberapa aplikasi lalu ekspor lagi |
| Impor berhasil tapi 0 alert | Data memang tidak memuat pola serangan | Lihat `docs/DATA_MANAGEMENT.md`, ini temuan, bukan bug |
| Service tidak jalan | Config ditolak | Cek `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5` |

## Catatan penting

- Sysmon **berjalan otomatis setelah reboot** (service `StartType: Automatic`).
- Ini alat monitoring yang sah dari Microsoft Sysinternals. Di lingkungan perusahaan,
  biasanya memang sudah dipasang oleh tim keamanan.
- Log Sysmon bisa membesar. Untuk laptop kerja, config ramping ini menekan itu, tapi
  tetap pantau ukuran file log bila dipakai berhari-hari.
