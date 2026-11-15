# Mengelola data: membersihkan impor & mengambil log Windows

Dokumen ini menjawab dua pertanyaan operasional:

1. Bagaimana membersihkan data yang sudah diimpor?
2. Bagaimana mendapatkan log Windows Security atau Firewall?

---

## 1. Membersihkan data yang diimpor

Tersedia di halaman **Evidence** (menu DATA → Evidence). Ada dua tingkat:

### a. Hapus satu impor (per-artifact)

Setiap baris di tabel artefak punya tombol **Delete**.

Yang terjadi saat diklik:
1. Artefak dihapus, dan **semua event yang berasal dari file itu ikut terhapus**.
2. Alerts, insiden, findings, dan graf **dibangun ulang** dari event yang tersisa.
3. Nomor event yang dihapus dilaporkan, misalnya: `Deleted "logs.csv", 4 event(s) removed, derived data rebuilt.`

Ini penting: menghapus artefak saja (tanpa menghapus event-nya) akan meninggalkan
event yatim yang tetap memicu alert. Jadi penghapusan selalu diikuti rebuild.

### b. Hapus semua data impor (reset penuh)

Panel **Clear all imported data** di bagian bawah halaman Evidence. Dua tombol:

| Tombol | Yang dihapus | Yang disimpan |
|---|---|---|
| **Clear data (keep IOCs)** | Semua event, alert, insiden, graf, artefak, findings, hasil analisis AI, riwayat status | 6 rule deteksi + indikator threat-intel (5 IOC) |
| **Clear data + IOCs** | Semua di atas **plus** indikator threat-intel | 6 rule deteksi |

Setelah salah satu tombol diklik, konfirmasi muncul lebih dulu karena tindakan ini
tidak bisa dibatalkan.

**Kapan pakai yang mana:**
- Salah impor satu file → pakai tombol **Delete** di baris file itu.
- Mau mulai bersih tanpa kehilangan konfigurasi → **Clear data (keep IOCs)**.
- Mau benar-benar kosong → **Clear data + IOCs**.
- Mau kembali ke data demo → klik **Load demo** di header (akan memuat ulang dari nol
  bila dipanggil dengan reset).

### Lewat API (bila perlu otomatisasi)

```bash
# Hapus satu artefak beserta event-nya + rebuild
curl -X DELETE http://127.0.0.1:8088/api/artifacts/<ID>

# Reset penuh, pertahankan IOC
curl -X POST "http://127.0.0.1:8088/api/data/reset?keep_iocs=true"

# Reset penuh termasuk IOC
curl -X POST "http://127.0.0.1:8088/api/data/reset?keep_iocs=false"
```

Daftar artefak beserta ID-nya:
```bash
curl -s http://127.0.0.1:8088/api/artifacts | \
  ./.venv/Scripts/python.exe -c "import json,sys;[print(a['id'],a['name']) for a in json.load(sys.stdin)['artifacts']]"
```

Semua tindakan tercatat di **Audit log** (`GET /api/audit`), jadi jejak penghapusan
tidak hilang.

### Catatan teknis

Reset lama (sebelum perbaikan) hanya menghapus 6 tabel dan meninggalkan baris yatim di
`alert_events`, `edge_events`, `findings`, `ai_runs`, dan `incident_status_history`.
Reset sekarang menghapus **12 tabel** dengan urutan anak-dulu, dan ada test regresi yang
memverifikasi tidak ada baris yatim tersisa
(`test_data_reset_leaves_no_orphan_link_rows`).

---

## 2. Mengambil log Windows Security / Firewall

SentinelGraph menerima format JSON. Skrip eksportir sudah tersedia:

```
tools\export-windows-logs.ps1
```

### Peringatan hak akses

Log **Security** dan **Firewall** **memerlukan PowerShell sebagai Administrator**.
Tanpa itu, `Get-WinEvent` menolak dengan `Attempted to perform an unauthorized operation`.
Ini batasan Windows, bukan batasan alat ini.

Log yang bisa dibaca tanpa admin: `Microsoft-Windows-PowerShell/Operational`,
`System`, dan log aplikasi.

### Contoh pemakaian

Buka PowerShell **sebagai Administrator** (klik kanan → Run as administrator),
lalu masuk ke folder proyek:

```powershell
cd <PROJECT_ROOT>

# Security log, 24 jam terakhir
.\tools\export-windows-logs.ps1 -Preset security -Hours 24 -Out security.json

# Firewall log, 72 jam terakhir
.\tools\export-windows-logs.ps1 -Preset firewall -Hours 72 -Out firewall.json

# Semua log penting sekaligus (butuh admin)
.\tools\export-windows-logs.ps1 -Preset all -Hours 6 -Out bundle.json

# Tanpa admin - ini yang bisa langsung dicoba sekarang
.\tools\export-windows-logs.ps1 -Preset powershell -Hours 24 -Out ps.json
```

Bila eksekusi skrip diblokir policy, jalankan dengan:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\export-windows-logs.ps1 -Preset security -Out security.json
```

### Setelah file terbentuk

1. Buka SentinelGraph → menu **Import**.
2. Klik **Choose file**, pilih `security.json` (atau file yang tadi dibuat).
3. Klik **Import**.
4. Halaman menampilkan `records_total` / `records_ok` / `records_failed`, periksa ini.
5. Buka **Dashboard** → **Load demo** tidak perlu diklik; data Anda sudah masuk.
   Lihat apakah ada alert muncul.

### Apa yang dipetakan skrip

Skrip menerjemahkan event ID Windows ke tipe event yang dikenali SentinelGraph:

| Event ID Windows | Tipe di SentinelGraph |
|---|---|
| 4688 (Security), 1 (Sysmon) | `process_create` |
| 4624 | `logon_success` |
| 4625, 4771, 4776 | `logon_failed` |
| 5156, 5157 (Firewall), 3 (Sysmon) | `network_connect` |
| 22 (Sysmon) | `dns_query` |
| 4663, 4656 (Security), 11 (Sysmon) | `file_access` |

Skrip juga mengekstrak alamat IP dari isi pesan ke kolom `dst_ip`, supaya korelasi graf
dan rule IOC (R-003) bisa bekerja.

### Keterbatasan yang perlu diketahui

**Race condition pada analisis konkuren (diperbaiki 2026-11-04).**

FastAPI menjalankan endpoint sinkron di thread pool, dan seluruh proses berbagi
**satu** koneksi SQLite. `analyze_project()` melakukan DELETE-lalu-INSERT pada
`alerts`, `incidents`, dan `graph_nodes`/`graph_edges`. Dua analisis yang berjalan
bersamaan akan saling menimpa dan gagal dengan:

```
sqlite3.IntegrityError: UNIQUE constraint failed:
    graph_nodes.project_id, graph_nodes.node_key
```

atau, bila bertabrakan di tengah `commit()`:

```
SystemError: error return without exception set
```

Gejalanya di UI: `DELETE /api/artifacts/<id>` mengembalikan **HTTP 500**, dan
alert/insiden bisa kosong setelah impor.

Pemicunya nyata dan mudah terjadi: menghapus lebih dari satu artifact berturut-turut,
atau mengimpor sambil UI menjalankan analisis ulang.

Perbaikan: `analyze_project()` diserialisasi dengan `db_lock()` (RLock reentrant di
`db.py`), dan `cursor()` mengambil lock yang sama sehingga transaksi tidak pernah
bertumpang tindih. Deteksi bersifat CPU-bound dan membaca seluruh tabel event, jadi
serialisasi memang benar, bukan sekadar jalan pintas.

Bukti: `tools/repro_delete_race.py`, sebelum perbaikan 3/4 penghapusan konkuren
gagal (HTTP 500); sesudahnya 8/8 sukses, diulang 5 kali tanpa kegagalan.
Regression test: `test_concurrent_analyze_does_not_corrupt_graph` (terbukti gagal
bila lock dilepas).

**Mengapa impor log asli sering menghasilkan 0 alert, dan itu bukan bug.**

Log Security dan Firewall Windows pada mesin kerja normal **memang tidak memuat pola
serangan**. Setelah mengimpor `security.json` (5000 event) + `firewall.json` (626 event)
dari mesin ini, hasilnya: 5 alert, semuanya R-006 (volume spike, severity low), dan graf
hanya berisi node `event`/`alert`/`ip`/`host`.

Penyebabnya bisa diperiksa langsung:

| Yang dibutuhkan rule | Yang ada di log |
|---|---|
| IOC match (R-003) | **0** event cocok. IP tujuan hanya `224.0.0.251` (mDNS multicast) dan `127.0.0.1` (loopback) |
| Brute force (R-001) | hanya **2** `logon_failed`, R-001 butuh ≥5 dalam jendela waktu |
| Rantai proses (R-002) | 26 event punya `parent_process`, tapi semua pola normal (`wininit.exe → lsass.exe`, `smss.exe → csrss.exe`) |
| Akses file + transfer (R-004) | **0** `file_path`, **0** `bytes_out` |
| Query DNS (R-003) | **0** `domain` |

Kesimpulan: **rule engine bekerja benar; datanya memang bersih.** Untuk membuktikannya,
suntikkan event yang seharusnya memicu: 6× `logon_failed` + 1× `logon_success`
menghasilkan R-001 HIGH, dan satu koneksi ke IOC menghasilkan R-003 CRITICAL. Keduanya
muncul seketika.

**Mengapa graf tidak menunjukkan apa pun yang berbahaya.** Graf hanya menggambar node
untuk field yang benar-benar terisi. Tanpa `user_name`, `process_name`, `domain`, atau
`file_path`, graf tidak punya entitas untuk dihubungkan, hanya node event, alert, dan
IP. Ini konsekuensi dari prinsip produk: **tidak menggambar relasi yang tidak punya
bukti.** Graf yang ramai tapi tanpa dasar justru pelanggaran desain.

**Agar impor log nyata menghasilkan deteksi:**

1. **Pasang Sysmon.** Ini yang paling menentukan. Sysmon mengisi `process_name`,
   `parent_process`, `command_line`, `dst_ip`, `file_path`, bahan bakar R-002, R-003,
   R-004. Tanpa Sysmon, telemetri proses dan jaringan hampir kosong.
   ```
   .\tools\export-windows-logs.ps1 -Preset sysmon -Hours 24 -Out sysmon.json
   ```
2. **Tambahkan IOC nyata** yang relevan dengan lingkungan Anda. R-003 hanya menyala bila
   ada tujuan yang cocok dengan daftar indikator (saat ini berisi 5 IOC contoh dari
   dataset demo).
3. **Perbesar jendela waktu.** `-Hours 72` atau lebih agar pola lintas jam tertangkap.
4. **Ingat bahwa R-006 bukan indikator serangan.** Volume spike hanya berarti "banyak
   event di jam ini", bisa jadi Windows Update. Severity-nya `low` dan itu tepat.

- **Model reasoning memakan budget token untuk penalaran tersembunyi.** Sebagian model
  (mis. keluarga reasoning) menghabiskan seluruh `max_tokens` sebelum sempat menulis
  jawaban, lalu mengembalikan `content` kosong dengan `finish_reason: length`.
  Gejalanya: analisis gagal dengan pesan menyesatkan seperti "Response contained no JSON
  object". Solusinya: naikkan `max_tokens` untuk provider tersebut (default sekarang
  8192). Adapter sudah mendeteksi kondisi ini dan melaporkan `output_truncated`
  disertai saran, bukan "JSON tidak ada".

- **Provider cloud dengan kunci nyata pernah diuji** dan berhasil: `deepseek-v4.1-flash`
  lewat gateway OpenAI-compatible menghasilkan analisis lengkap dengan 0 sitasi
  karangan. Latensi ~18,8 detik untuk 9 event.

- **`event_type` hasil pemetaan log Windows bersifat perkiraan.** Log Windows tidak
  selalu menyatakan jenis aktivitasnya secara eksplisit; skrip menebak dari event ID
  dan isi pesan.

- **`event_type` hasil pemetaan bersifat perkiraan.** Log Windows tidak selalu
  menyatakan jenis aktivitasnya secara eksplisit; skrip menebak dari event ID dan isi
  pesan. Periksa hasilnya di halaman Events sebelum mempercayai alert yang muncul.
- **Rule yang butuh kolom spesifik tidak akan menyala** bila log sumber tidak memuatnya.
  Contoh: R-002 (rantai proses mencurigakan) butuh `parent_process`, log Windows 4688
  memuatnya di dalam teks pesan, bukan kolom terpisah, jadi rule ini kemungkinan besar
  tidak aktif kecuali Anda memasang Sysmon.
- **Sysmon tidak terpasang** di mesin ini (sudah diperiksa). Tanpa Sysmon, telemetry
  proses dan jaringan jauh lebih terbatas. Untuk hasil terbaik, pasang Sysmon.
- **Exchange/email gateway** hanya tersedia bila ada server Exchange di lingkungan Anda.

### Yang sudah diverifikasi di mesin ini

- Preset `powershell` (tanpa admin): **179 event diekspor, 179/179 diterima** oleh
  SentinelGraph, 0 gagal.
- Preset `security` (tanpa admin): gagal dengan pesan jelas dan saran, tidak crash.
- Format JSON keluaran skrip cocok dengan parser impor tanpa penyesuaian manual.

## 4. Kemasan rilis: jangan pernah mengirim data mesin nyata

Working tree sengaja memuat telemetri nyata (`data/*.db`, `*-wal`, `*-shm`, ekspor
`firewall.json`/`security.json`/`sysmon.json`, `.env`, log). Semua itu **tidak boleh**
ikut paket distribusi. `.gitignore` sudah mengecualikannya dari repo; untuk paket zip,
pakai generator rilis:

```bash
python tools/make_release.py                # -> release/sentinelgraph-ai
```

`tools/make_release.py`:

1. menyalin hanya source + docs + `frontend/dist` + skrip, melewati `.git`, `.venv`,
   `node_modules`, `data/`, `*.db`, `*-wal`, `*-shm`, ekspor telemetri, `.env`, log;
2. membangun DB demo dari dataset **sintetis** lewat jalur bootstrap biasa
   (`sentinelgraph init` + `load-demo`) di direktori **scratch**, DB runtime tidak
   pernah ikut ke paket;
3. menjalankan `tools/check_pii_db.py` terhadap DB scratch itu; **exit != 0 jika ada match**;
4. mengekspor dataset sintetis ke `data/demo/demo-events.jsonl`, itu yang dikirim,
   bukan database.

### Deteksi PII (`tools/check_pii_db.py`)

Read-only. Mencari penanda identitas nyata: pola `DESKTOP-*`, SID `S-1-5-*`, plus <!-- PII-SCAN-ALLOW: documents the scanner's own patterns, not leaked data -->
**hostname dan username mesin yang sedang menjalankan scan** (deteksi runtime, tanpa
nama yang di-hardcode ke repo). Dataset sintetis (`WS-FIN-07`, `r.santoso`,
IP RFC 5737, `*.example`) tidak cocok.

```bash
python tools/check_pii_db.py --db data/sentinelgraph.db
# DB mesin nyata  -> TOTAL PII ROW-MATCHES: ~17k  (memang berisi telemetri)

# Paket rilis tidak memuat *.db sama sekali; yang dikirim hanya dataset sintetis:
ls release/sentinelgraph-ai/data/demo/
# -> demo-events.jsonl  README.md
```

Jangan hapus database instalasi aktif tanpa backup. Pembersihan dilakukan pada
salinan rilis; DB aktif tetap milik analis.
