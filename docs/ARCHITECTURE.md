# Arsitektur SentinelGraph AI

Dokumen ini menjelaskan aliran data, batas kepercayaan, dan alasan di balik keputusan
desain. Tujuannya agar orang lain bisa mengaudit sistem ini tanpa harus membaca seluruh
kode.

---

## 1. Aliran data

```
Artifact (file) ──► ingest.py ──► events (tabel)
                                     │
                                     ├──► detection.py ──► alerts + alert_events
                                     │
                                     └──► correlation.py ──► graph_nodes
                                                              graph_edges
                                                              edge_events
                                                              incidents
                                                              incident_alerts
                                                                   │
                                            ┌──────────────────────┴───────────┐
                                            ▼                                  ▼
                                     ai_analysis.py                     reporting.py
                                     (opsional)                         (selalu bisa)
```

Setiap tahap menulis ke tabel yang bisa diperiksa terpisah. Tidak ada tahap yang
menyembunyikan hasilnya di memori saja.

## 2. Skema database

| Tabel | Isi | Kunci bukti |
|---|---|---|
| `projects` | Workspace |, |
| `artifacts` | File yang diimpor + SHA-256 | `sha256` |
| `events` | Event ternormalisasi | `raw` (payload asli disimpan) |
| `iocs` | Indikator ancaman lokal |, |
| `alerts` | Temuan rule engine | `rule_id`, narasi |
| `alert_events` | Alert → event | **Setiap alert wajib punya baris di sini** |
| `graph_nodes` | Entitas (host, user, proses, file, domain, IP) | `node_key` |
| `graph_edges` | Relasi antar entitas | `status` (`observed` / `inferred`) |
| `edge_events` | Edge → event | **Setiap edge `observed` wajib punya baris di sini** |
| `incidents` | Pengelompokan alert |, |
| `incident_alerts` | Insiden → alert |, |
| `reports` | Laporan yang digenerate | `content` |
| `ai_runs` | Riwayat pemanggilan AI | `request_context` (manifest) |
| `ai_run_evidence` | AI run → event yang dikutip | **Hanya ID yang lolos verifikasi** |
| `audit_log` | Jejak aksi |, |

### Mengapa `alert_events` dan `edge_events` dipisah

Alert dan edge adalah **klaim**. Klaim tanpa rujukan tidak bisa diaudit. Memisahkan
relasi bukti ke tabel sendiri berarti:

- Mustahil menyimpan alert tanpa sumber (foreign key + logika pipeline).
- Query "alert mana yang menyentuh event X" menjadi murah.
- Penghapusan event otomatis membersihkan rujukan (`ON DELETE CASCADE`).

## 3. Rule engine

Enam rule deterministik. Semua hanya membaca tabel `events` dan `iocs`.

| ID | Nama | Logika ringkas |
|---|---|---|
| R-001 | Failed logon burst | ≥ ambang gagal login pada host/akun dalam jendela waktu; membedakan ada/tidak ada sukses setelahnya |
| R-002 | Suspicious process chain | Proses anak berisiko tinggi dipanggil parent berisiko tinggi |
| R-003 | IOC match | `dst_ip`/`domain`/`url` cocok dengan `iocs`; dedup per (host, indikator) |
| R-004 | Sensitive access then transfer | Akses path sensitif lalu `bytes_out` melewati ambang pada host sama dalam jendela |
| R-005 | Lateral authentication | Satu akun autentikasi ke banyak host dalam jendela pendek |
| R-006 | Volume anomaly | `bytes_out` jauh di atas baseline host (ilustratif, belum dikalibrasi) |

**Kontrak setiap rule:**

1. Mengembalikan `RuleDraft` dengan `event_ids` yang benar-benar ada.
2. Narasi memisahkan **observed** dari **interpretation** secara eksplisit.
3. Tidak melakukan I/O jaringan.
4. Exception ditangkap dan dikumpulkan ke `engine_errors`, tidak ditelan.

Contoh narasi R-004 (dipangkas):

> Host 'WS-FIN-07' accessed sensitive path 'C:\...\Q4_forecast_confidential.xlsx' at
> 2026-11-03T08:25:00Z, then sent 14,782,464 bytes to 203.0.113.66 at 2026-11-03T08:31:00Z
> (360s later). **Both events are observed facts. Whether data left the network is NOT
> established by these events alone**, the transfer may be unrelated or legitimate.

## 4. Attack graph

### Status edge

- `observed`, relasi tercatat langsung di event (mis. `process_create` memberi
  `host --spawned--> process`). **Wajib** punya `edge_events`.
- `inferred`, relasi diturunkan dari pola (mis. akun muncul di event non-logon pada
  host → `active_on` dengan confidence `low`). Tidak mengklaim fakta langsung.

Setiap edge menyertakan `method` yang menjelaskan cara penurunannya, sehingga analis
bisa menilai sendiri apakah penalaran itu masuk akal.

### Layout graf

Layout radial dengan radius tetap per kelas entitas:

```
        [ perimeter: domain / IP ]
     [ users ]              [ users ]
        [ hosts ]        [ hosts ]
              [ alerts: core ]
```

Radius tetap dipilih agar tangkapan layar dapat direproduksi dan struktur langsung
terlihat. Node tipe `event` disembunyikan secara default karena jumlahnya menenggelamkan
struktur entitas; bisa diaktifkan lewat filter.

## 5. Batas kepercayaan

```
 ┌──────────────┐   tidak dipercaya    ┌──────────────────┐
 │ Input file   │ ───────────────────► │ Ingest + validasi│
 └──────────────┘                      └────────┬─────────┘
                                                │
 ┌──────────────┐   TIDAK dipercaya            ▼
 │ Output LLM   │ ───────────────► Evidence guard ──► baru boleh masuk DB
 └──────────────┘   (divalidasi skema + ID)
```

Yang **tidak** dipercaya:

1. **Isi file yang diunggah.** Divalidasi bentuk dan tipe; timestamp rusak ditandai.
2. **Output model bahasa.** Dianggap klaim yang harus dibuktikan.

Yang dipercaya:

1. **Database** sebagai sumber kebenaran tunggal.
2. **Rule engine** sebagai penentu apa yang menjadi alert. Model tidak bisa membuat alert.

## 6. Evidence guard (inti pertahanan terhadap halusinasi)

`ai_analysis.run_analysis` melakukan, secara berurutan:

1. Membangun manifest: daftar ID event yang benar-benar dikirim ke model.
2. Mengirim hanya event insiden tersebut (maks. 60 event, 400 karakter/event).
3. Menerima respons, mengekstrak objek JSON.
4. **Memvalidasi skema.** Bila gagal → `validation_failed`, tidak ada yang disimpan.
5. **Menyaring setiap sitasi** `supporting_event_ids` / `contradicting_event_ids`:
   hanya integer asli yang ada di manifest yang dipertahankan. `int(1.5)` **tidak**
   diterima, karena akan diam-diam menjadi `1`, ID event yang berbeda.
6. **Menandai setiap hipotesis:**
   - `supported`, punya ≥1 sitasi valid, tanpa kontradiksi
   - `contested`, punya sitasi valid dan sitasi kontradiktif
   - `unsupported`, semua sitasi dibuang
7. **Menghitung `stripped_reference_count`** agar jumlah kebohongan yang tertangkap
   terlihat, bukan tersembunyi.
8. Menyimpan hasil ke `ai_runs`, dan hanya ID yang lolos ke `ai_run_evidence`.

Yang **tidak** bisa dilakukan guard ini: memverifikasi kebenaran kalimat bebas.
Karena itu `summary` selalu ditandai `summary_is_unverified: true` dan ditampilkan
dengan peringatan eksplisit di UI serta laporan.

## 7. Penanganan waktu

`timeutil.py` mencatat asal setiap timestamp:

| `ts_status` | Arti |
|---|---|
| `explicit` | Zona waktu dinyatakan di input |
| `assumed` | Tidak ada zona; ditafsirkan dengan `SG_DEFAULT_TZ` yang dideklarasikan |
| `UNKNOWN` | Tidak ada atau tidak bisa diparse |

Timestamp dengan `UNKNOWN` tetap disimpan, tidak dibuang. Urutan timeline menempatkannya
di akhir dan memberi tanda, sehingga analis tahu bahwa posisinya tidak dapat dipercaya.

## 8. Keamanan provider AI

`security.py` menegakkan:

- Skema URL hanya `http`/`https`.
- Tidak boleh ada kredensial tertanam di URL.
- Resolusi DNS diperiksa; alamat privat/link-local/loopback diblokir untuk provider
  cloud (pencegahan SSRF).
- Pengecualian eksplisit hanya untuk `ollama` dan `custom_openai` lokal, yang memang
  didesain menunjuk ke localhost.
- Semua pesan error di-redaksi sebelum disimpan (`redact_secrets`).

Kunci API dienkripsi dengan Fernet sebelum masuk database. Kunci utama diambil dari
`SG_MASTER_KEY`; bila tidak diset, satu kunci dibuat otomatis di
`<data dir>/master.key` saat pertama dipakai. Aplikasi tidak pernah menyimpan kunci
dalam bentuk plaintext.

## 9. Jalur kegagalan yang disengaja

| Kondisi | Perilaku |
|---|---|
| Tidak ada provider AI | `no_provider`, semua fitur inti tetap jalan |
| Provider tidak bisa dihubungi | `error` + kategori, laporan tetap bisa digenerate |
| Output AI bukan JSON | `validation_failed`, tidak ada konten AI di laporan |
| Output AI melanggar skema | Validasi ketat, field buruk dibuang/di-coerce dengan catatan |
| Sitasi event tidak ada | Dibuang, dihitung, dilaporkan |
| Rule melempar exception | Dicatat di `engine_errors`, rule lain tetap jalan |
| Timestamp rusak | Disimpan dengan `ts_status`, bukan dibuang |
| Record event kosong | Ditolak dengan pesan jelas |

## 10. Keterbatasan arsitektural yang diketahui

1. **SQLite single-writer.** Cukup untuk satu analis, tidak untuk tim paralel.
2. **Tanpa autentikasi.** Batas kepercayaan berhenti di level jaringan.
3. **Graph dirender client-side.** Insiden besar akan mengirim graf penuh ke browser.
4. **Tidak ada streaming ingest.** Seluruh artifact dibaca ke memori.
5. **Heuristik pengelompokan insiden** tidak belajar dari koreksi analis.
