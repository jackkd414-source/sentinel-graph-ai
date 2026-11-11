# SentinelGraph AI — From Signals to Story

Platform investigasi insiden keamanan berbantuan AI untuk **Kartika Cyber Hackathon 2026**,
kategori **Defensive Shield (Penangkalan)**.

SentinelGraph AI mengimpor telemetri, menormalisasi event, menjalankan deteksi deterministik
yang bisa diaudit, mengkorelasikan entitas menjadi attack graph berbukti, membangun timeline,
dan menghasilkan laporan insiden dengan sitasi bukti, tingkat keyakinan, serta batas
ketidakpastian yang dinyatakan terbuka.

> Prinsip inti: **AI adalah asisten interpretasi, bukan sumber kebenaran.**
> Semua deteksi berjalan tanpa LLM dan tanpa jaringan.

---

## 1. Ringkasan produk

Masalah yang disasar: tim blue team sering menerima banyak alert terpisah yang sulit
dirangkai menjadi cerita serangan yang bisa dipertanggungjawabkan. Banyak alat menambahkan
lapisan LLM yang merangkum, tetapi justru mengaburkan mana yang fakta dan mana yang dugaan.

SentinelGraph memisahkan tiga lapis secara eksplisit:

| Lapis | Sumber | Bisa diverifikasi? |
|---|---|---|
| **Observed fact** | Event yang diimpor ke database | Ya — setiap klaim membawa ID event |
| **Derived finding** | Rule engine deterministik (R-001..R-006) | Ya — logika rule ditampilkan |
| **AI hypothesis** | Model bahasa, opsional | Sebagian — hanya klaim yang punya sitasi event |

## 2. Arsitektur

```
                    ┌──────────────────────────────────────────┐
   JSON/CSV/NDJSON  │  Ingest (parsing, normalisasi, dedup)     │
   ────────────────►│  backend/sentinelgraph/ingest.py          │
                    └───────────────┬──────────────────────────┘
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │  SQLite (stdlib, tanpa ORM)              │
                    │  events · artifacts · iocs · alerts      │
                    │  graph_nodes · graph_edges · edge_events │
                    │  incidents · reports · ai_runs · audit   │
                    └───────────────┬──────────────────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────────┐
        │  Detection rule engine (DETERMINISTIK, tanpa AI)      │
        │  detection.py — R-001..R-006, tiap alert → event IDs  │
        └───────────────┬───────────────────────────────────────┘
                        ▼
        ┌───────────────────────────────────────────────────────┐
        │  Correlation → attack graph + incident grouping       │
        │  correlation.py                                       │
        └───────────────┬───────────────────────────────────────┘
                        ▼
   ┌────────────────────────────────────────────────────────────┐
   │  AI layer (OPSIONAL) — ai_providers.py + ai_analysis.py    │
   │  · hanya event insiden yang dikirim                        │
   │  · output divalidasi skema                                 │
   │  · setiap ID event yang dikutip diverifikasi ke database   │
   │  · ID karangan dibuang dan dilaporkan                      │
   └───────────────┬────────────────────────────────────────────┘
                   ▼
        ┌──────────────────────────────────────────┐
        │  Reporting (md / html / json)            │
        │  reporting.py — 10 seksi + batasan       │
        └───────────────┬──────────────────────────┘
                        ▼
        ┌──────────────────────────────────────────┐
        │  REST API + React SPA                    │
        │  api.py (FastAPI) · frontend/ (Vite)     │
        └──────────────────────────────────────────┘
```

### Keputusan teknis dan alasannya

- **SQLite + `sqlite3` stdlib, tanpa ORM.** Setiap query bisa dibaca langsung saat audit;
  tidak ada perilaku "ajaib" yang menyembunyikan JOIN atau filter.
- **Attack graph digambar dengan SVG tulisan tangan, bukan React Flow.** Kontrol penuh atas
  pembedaan visual observed vs inferred, dan menghindari menambah dependensi besar pada
  supply chain yang harus dipercaya di lingkungan bertahan.
- **Deteksi tidak pernah memanggil LLM atau jaringan.** Hasil deteksi deterministik dan
  dapat direproduksi; LLM hanya menafsirkan hasil yang sudah ada.
- **Degradasi jujur, bukan kegagalan senyap.** Error rule dikumpulkan ke `engine_errors`
  dan ditampilkan; timestamp yang tidak bisa diparse disimpan dengan status `assumed` atau
  `UNKNOWN`, bukan dibuang diam-diam.
- **`no_provider` ≠ error.** Laporan membedakan "tidak ada AI yang dikonfigurasi" dari
  "AI gagal".

## 3. Struktur direktori

```
sentinelgraph-ai/
├── backend/
│   ├── sentinelgraph/
│   │   ├── __main__.py         # CLI: init / serve / load-demo
│   │   ├── api.py              # Seluruh endpoint REST (FastAPI)
│   │   ├── config.py           # Konfigurasi via environment
│   │   ├── db.py               # Skema + koneksi SQLite
│   │   ├── ingest.py           # Parsing & normalisasi artifact
│   │   ├── detection.py        # Rule engine deterministik R-001..R-006
│   │   ├── correlation.py      # Graph builder + incident grouping
│   │   ├── pipeline.py         # Orkestrasi ingest → detect → correlate
│   │   ├── ai_providers.py     # Adapter provider (OpenAI/Anthropic/Gemini/dll)
│   │   ├── ai_analysis.py      # Validasi output AI + evidence guard
│   │   ├── provider_store.py   # Penyimpanan konfigurasi provider
│   │   ├── reporting.py        # Generator laporan md/html/json
│   │   ├── security.py         # SSRF guard, redaksi rahasia, enkripsi
│   │   ├── timeutil.py         # Parsing waktu + pelacakan asumsi
│   │   └── demo_data.py        # Dataset demo sintetis
│   ├── tests/                  # 136 test (pytest)
│   └── tools/fake_provider.py  # Provider stub untuk uji anti-halusinasi
├── frontend/
│   └── src/
│       ├── App.tsx             # Shell + routing
│       ├── api.ts              # Tipe + client API
│       ├── components/         # ui.tsx, AttackGraph.tsx
│       └── pages/              # Dashboard, Incidents, IncidentView, dst
├── tools/verify.py             # Verifikasi end-to-end (verdict PASS/FAIL)
├── docs/                       # Dokumentasi tambahan
├── data/                       # Database SQLite (dibuat saat runtime)
└── README.md
```

## 4. Fitur yang berfungsi (terverifikasi)

Semua klaim di bawah diverifikasi dengan `tools/verify.py` dan test otomatis.

| Fitur | Status | Bukti |
|---|---|---|
| Impor telemetri JSON/CSV/NDJSON | Berfungsi | Artifact demo dimuat jadi 29 event |
| Normalisasi + penanganan timestamp rusak | Berfungsi | Status `assumed`/`UNKNOWN` disimpan |
| 6 rule deteksi deterministik | Berfungsi | 10 alert dari 29 event, 6 rule terpicu |
| Attack graph dengan bukti per edge | Berfungsi | 60 node / 52 edge, tiap edge → ID event |
| Pengelompokan insiden | Berfungsi | 4 insiden terpisah (malicious vs benign) |
| Timeline per insiden | Berfungsi | 9 event pada INC-0001 |
| Laporan md/html/json | Berfungsi | 10 seksi, ~16 KB markdown |
| Konfigurasi provider AI lewat UI | Berfungsi | Provider dibuat & diaktifkan tanpa ubah kode |
| Uji koneksi provider | Berfungsi | Request jaringan nyata; 401 dilaporkan jujur |
| Evidence guard untuk output AI | Berfungsi | 6 sitasi karangan dibuang & dilaporkan |
| Mode tanpa AI | Berfungsi | Semua fitur inti tetap jalan |

## 5. Fitur yang belum selesai / terbatas

Dinyatakan terbuka agar tidak menyesatkan penilai:

- **Belum ada autentikasi pengguna.** Aplikasi berjalan sebagai single-analyst
  workspace. Siapa pun yang bisa menjangkau port 8088 punya akses penuh.
- **Belum ada enkripsi at-rest untuk database.** Kunci API provider dienkripsi
  (`SG_MASTER_KEY`), tetapi isi tabel event tidak.
- **Rule R-006 (volume anomaly) bersifat ilustratif**, belum dikalibrasi terhadap
  baseline nyata karena dataset demo kecil.
- **Belum ada konektor langsung** ke SIEM/EDR (Syslog, Splunk, Elastic, Wazuh).
  Impor masih melalui unggahan file.
- **Pengelompokan insiden memakai heuristik** (host/akun bersama dalam jendela 6 jam),
  bukan model probabilistik.
- **Graph layout radial sederhana**; belum ada force-directed layout untuk graf besar.
- **Belum ada multi-tenant / RBAC.**

## 6. Provider AI yang diuji

| Provider | Diuji | Hasil |
|---|---|---|
| OpenAI | Ya (konektivitas) | Request nyata ke `api.openai.com`, **HTTP 401** karena kunci tidak valid. Dilaporkan `ok:false`, `error_category:"auth"`. |
| **custom_openai (model reasoning cloud)** | **Ya (end-to-end, kunci nyata)** | Diuji terhadap `deepseek-v4.1-flash` lewat gateway OpenAI-compatible. Analisis lengkap dihasilkan: `status: ok`, 0 issue, 4 hipotesis, **semua sitasi valid (13/13 ID ada di DB, 0 karangan)**, latensi ~18,8 detik, 3965 token keluaran. |
| Ollama (lokal) | Ya (end-to-end) | Diuji terhadap stub lokal. Koneksi, pemilihan model, analisis, dan evidence guard berjalan penuh. |
| Anthropic / Gemini / OpenRouter | Tidak | Adapter ada dan memakai jalur kode yang sama, tetapi **tidak diuji dengan kunci nyata**. |

**Temuan penting saat menguji model cloud nyata:** model reasoning menghabiskan
*seluruh* budget `max_tokens` untuk penalaran tersembunyi dan mengembalikan `content`
kosong dengan `finish_reason: length`. Ini awalnya dilaporkan sebagai
"Response contained no JSON object" — **menyesatkan**, karena outputnya sebenarnya
terpotong, bukan tidak ada. Perbaikan:

1. Adapter kini mendeteksi `finish_reason: length` + `content` kosong dan melaporkan
   `output_truncated` dengan saran menaikkan `max_tokens`.
2. Default dinaikkan 2048 → 8192 token agar ada ruang untuk penalaran.
3. Error tetap muncul di laporan sebagai kegagalan eksplisit — tidak ada konten AI
   yang dimasukkan bila validasi gagal.

**Yang masih belum diukur:** kualitas analisis model nyata baru diuji pada satu insiden
demo. Belum ada pengukuran kuantitatif (presisi/recall) terhadap dataset berlabel.

## 7. Konfigurasi provider dan model

Melalui UI: **AI Providers** → pilih tipe → isi model ID dan kunci → **Test** → **Activate**.

Variabel lingkungan terkait:

| Variabel | Fungsi |
|---|---|
| `SG_MASTER_KEY` | Kunci enkripsi untuk menyimpan API key provider di database. Tanpa ini, kunci tidak dipersistensi. |
| `SG_DB_PATH` | Lokasi database SQLite |
| `SG_DEFAULT_TZ` | Zona waktu default untuk timestamp tanpa zona |

Provider didukung: `openai`, `anthropic`, `gemini`, `openrouter`, `ollama`, `custom_openai`.

**SSRF guard.** Base URL provider divalidasi sebelum ada request keluar. Alamat privat,
link-local, dan loopback diblokir — kecuali untuk `ollama` dan `custom_openai` lokal
yang memang diarahkan ke localhost secara sengaja.

## 8. Perintah instalasi dan menjalankan

```bash
# 1. Siapkan virtualenv
cd sentinelgraph-ai
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r backend/requirements.txt   # Windows

# 2. Inisialisasi database
export PYTHONPATH=backend
./.venv/Scripts/python.exe -m sentinelgraph init

# 3. Muat data demo
./.venv/Scripts/python.exe -m sentinelgraph load-demo

# 4. Bangun frontend (sekali saja, atau setelah mengubah src/)
cd frontend && npm install && npm run build && cd ..

# 5. Jalankan server
export SG_MASTER_KEY="$(./.venv/Scripts/python.exe -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
./.venv/Scripts/python.exe -m sentinelgraph serve --port 8088
```

Buka `http://127.0.0.1:8088/`.

Mode pengembangan frontend (hot reload):

```bash
cd frontend && npm run dev     # http://127.0.0.1:5173, proxy /api → 8088
```

Menjalankan test dan verifikasi:

```bash
export PYTHONPATH=backend
./.venv/Scripts/python.exe -m pytest backend/tests -q      # 136 test
./.venv/Scripts/python.exe tools/verify.py                 # verdict PASS/FAIL
```

## 9. Hasil pengujian sebenarnya

### Test otomatis

```
136 passed, 3 warnings in 6.85s
```

Tiga warning berasal dari `on_event` FastAPI yang sudah deprecated — bukan kegagalan.

### Verifikasi end-to-end

```
26/26 checks passed
VERDICT: PASS
```

### Bug yang ditemukan dan diperbaiki selama pengembangan

Ini bukan daftar prestise — setiap baris adalah cacat nyata yang sempat ada:

| Bug | Dampak | Perbaikan |
|---|---|---|
| Alias `MAP` menghilangkan nama field sendiri | Sebagian field tidak ternormalisasi | Alias memuat nama aslinya |
| `h.split("=",1)[1]` pada rule IOC | `IndexError` saat input tanpa `=` | Parsing aman |
| Exception rule tertelan | Alert hilang tanpa jejak | `engine_errors` dikumpulkan & ditampilkan |
| Incident grouping terlalu luas | Insiden malicious & benign menyatu | Predikat diperketat |
| `int(1.5)` koersi diam-diam | ID event salah ditafsirkan | Hanya integer asli diterima |
| `KeyError` provider tak dikenal | 500 internal | Divalidasi jadi 400 |
| `cursor` tidak diimpor di reporting | Export gagal | Import ditambahkan |
| Record kosong diterima | Artifact sampah masuk | Ditolak dengan pesan jelas |
| Module reload di fixture test | Dua kelas exception berbeda | Fixture tidak reload |
| `/api/alerts` vs `/api/incidents/{id}` beda bentuk bukti | Tab Overview crash (`undefined.map`) | Bentuk disatukan |
| Layout graph bertumpuk | Graf tak terbaca | Node event disembunyikan + layout radial |
| Kolom waktu wrap | Sulit dibaca | Lebar kolom diperlebar |
| **`/api/graph` tidak menyertakan `evidence_event_ids`** | Edge "observed" mengklaim fakta tanpa sumber yang bisa diperiksa | `get_graph` & `get_node_detail` menyertakan bukti |
| **Status `missing_credential` untuk Ollama** | Konfigurasi yang berfungsi tampak rusak | Cek `needs_key` per tipe provider |
| **Ringkasan AI tidak ditandai** | Teks model bisa dibaca sebagai fakta | Penanda "tidak terverifikasi" di UI & laporan |
| **Hipotesis tanpa bukti tampak setara** | Klaim karangan terlihat seperti temuan | Tag `evidence_status` |

Dua bug terakhir ditemukan justru oleh uji adversarial terhadap model yang sengaja
berbohong — bukan oleh test biasa.

### Skenario adversarial yang diuji

Stub provider mengembalikan tiga jenis kebohongan:

1. **Campuran** — 6 ID karangan bersama 1 ID asli. Hasil: 6 dibuang, hipotesis dengan
   bukti asli ditandai `evidence-linked`, hipotesis tanpa bukti ditandai
   `no surviving evidence`.
2. **Semua karangan** — 3 ID palsu. Hasil: seluruhnya dibuang, satu-satunya hipotesis
   ditandai `unsupported`.
3. **JSON rusak** — bukan JSON sama sekali. Hasil: `validation_failed`, tidak ada konten
   AI yang masuk laporan, dan laporan menyatakan kegagalan secara eksplisit.

## 10. Langkah demo (3 menit)

1. **Dashboard** — tunjukkan event, alert, insiden, aset; sebutkan bahwa setiap angka
   berasal dari tabel, bukan konstanta.
2. **Load demo** — memuat dataset sintetis: 29 event, 4 insiden.
3. **INC-0001 → Overview** — tunjukkan pemisahan tegas: "IOC match adalah fakta; host
   terkompromi adalah hipotesis".
4. **Timeline** — 9 event berurutan dari email phishing sampai transfer keluar.
5. **Attack graph** — sorot edge; tunjukkan setiap edge membawa ID event sumbernya.
   Toggle node event untuk melihat struktur entitas.
6. **AI analysis** — jalankan analisis. Tunjukkan:
   - hipotesis dengan bukti → `evidence-linked`
   - hipotesis karangan → `no surviving evidence`
   - jumlah sitasi yang dibuang oleh evidence guard
7. **Report** — unduh markdown. Buka seksi 7: "Confirmed compromise: NOT established".
   Ini titik yang membedakan produk ini dari dashboard yang menakut-nakuti.

## 11. Lokasi dokumentasi

| Dokumen | Lokasi |
|---|---|
| README (dokumen ini) | `README.md` |
| Proposal submission | `docs/PROPOSAL.md` |
| Slide deck (10 slide + versi 3 menit) | `docs/SLIDES.md` |
| Skrip video demo | `docs/VIDEO_SCRIPT.md` |
| Arsitektur mendetail | `docs/ARCHITECTURE.md` |
| Model ancaman & batasan | `docs/SECURITY.md` |
| Panduan demo | `docs/DEMO.md` |
| **Kelola data & ambil log Windows** | `docs/DATA_MANAGEMENT.md` |
| **Pasang Sysmon (agar deteksi nyata bekerja)** | `docs/SYSMON.md` || Screenshot asli (dari aplikasi berjalan) | `docs/screenshots/` |
| Verifikasi mandiri | `tools/verify.py` |

## 12. Risiko keamanan dan batasan

- **Tanpa autentikasi.** Siapa pun dengan akses jaringan ke port bisa membaca semua
  insiden dan mengubah status. Untuk demo ini diterima; untuk produksi tidak.
- **API key provider disimpan terenkripsi hanya jika `SG_MASTER_KEY` diset.**
  Tanpa itu, kunci tidak dipersistensi sama sekali (bukan disimpan plaintext).
- **`allow_private` hanya untuk provider lokal.** SSRF guard memblokir alamat privat
  untuk provider cloud; ini membatasi pengujian terhadap endpoint lokal.
- **Unggahan file belum dibatasi ukurannya secara ketat.** File sangat besar bisa
  menghabiskan memori.
- **AI dapat menghasilkan teks menyesatkan.** Mitigasi: sitasi diverifikasi, ringkasan
  ditandai tidak terverifikasi, dan deteksi tidak pernah bergantung pada AI. Namun teks
  bebas tetap tidak bisa diverifikasi mesin dan harus dibaca sebagai klaim.
- **Dataset demo bersifat sintetis** dan bukan bukti kemampuan deteksi pada data nyata.

## 13. Langkah berikutnya

1. **Autentikasi + RBAC** — multi-analyst, pemisahan hak baca/tulis.
2. **Konektor SIEM/EDR** — Syslog, Wazuh, Elastic, Splunk HEC.
3. **Kalibrasi rule** terhadap baseline nyata; R-006 khususnya.
4. **Uji provider cloud dengan kredensial valid** dan ukur kualitas analisis secara
   kuantitatif (misalnya berapa persen hipotesis yang lolos verifikasi analis).
5. **Penyimpanan bukti immutable** — hash chain untuk artifact.
6. **Ekspor STIX/TAXII** agar temuan bisa dibagikan ke platform lain.
7. **Perbaikan layout graph** untuk ribuan node.
