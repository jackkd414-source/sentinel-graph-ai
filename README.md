# SentinelGraph AI, From Signals to Story

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
| **Observed fact** | Event yang diimpor ke database | Ya, setiap klaim membawa ID event |
| **Derived finding** | Rule engine deterministik (R-001..R-006) | Ya, logika rule ditampilkan |
| **AI hypothesis** | Model bahasa, opsional | Sebagian, hanya klaim yang punya sitasi event |

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
        │  detection.py, R-001..R-006, tiap alert → event IDs  │
        └───────────────┬───────────────────────────────────────┘
                        ▼
        ┌───────────────────────────────────────────────────────┐
        │  Correlation → attack graph + incident grouping       │
        │  correlation.py                                       │
        └───────────────┬───────────────────────────────────────┘
                        ▼
   ┌────────────────────────────────────────────────────────────┐
   │  AI layer (OPSIONAL), ai_providers.py + ai_analysis.py    │
   │  · hanya event insiden yang dikirim                        │
   │  · output divalidasi skema                                 │
   │  · setiap ID event yang dikutip diverifikasi ke database   │
   │  · ID karangan dibuang dan dilaporkan                      │
   └───────────────┬────────────────────────────────────────────┘
                   ▼
        ┌──────────────────────────────────────────┐
        │  Reporting (md / html / json)            │
        │  reporting.py, 10 seksi + batasan       │
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
│   ├── tests/                  # 311 test (pytest)
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
| **OpenRouter (`deepseek-v4.1-flash`)** | **Ya (end-to-end, kunci nyata)** | Tiga `ai_runs` berstatus `ok` pada DB runtime (2026-11-12) terhadap insiden nyata; iterasi juga mencatat `validation_failed` (output terpotong, `finish_reason=length`) dan satu `timeout` sebelum default token/timeout dinaikkan. Output lengkap: hipotesis bertag `evidence_status`, `stripped_reference_count: 0`. |
| OpenAI | Ya (konektivitas saja) | Request nyata ke `api.openai.com` dengan kunci tidak valid -> **HTTP 401**, dilaporkan `ok:false`, `error_category:"auth"` (direproduksi 2026-11-14). Jalur jaringan terbukti; kualitas analisis tidak diukur. |
| Ollama | Ya, terhadap stub lokal (**bukan Ollama asli**) | provider_config `Stub Local` (`http://127.0.0.1:8099`). Koneksi, pemilihan model, analisis, dan evidence guard berjalan - tetapi modelnya stub. |
| Anthropic / Gemini / custom_openai | Tidak | Adapter ada dan memakai jalur kode yang sama, tetapi **tidak diuji dengan kunci nyata**. |

**Temuan penting saat menguji model cloud nyata:** model reasoning menghabiskan
*seluruh* budget `max_tokens` untuk penalaran tersembunyi dan mengembalikan `content`
kosong dengan `finish_reason: length`. Ini awalnya dilaporkan sebagai
"Response contained no JSON object", **menyesatkan**, karena outputnya sebenarnya
terpotong, bukan tidak ada. Perbaikan:

1. Adapter kini mendeteksi `finish_reason: length` + `content` kosong dan melaporkan
   `output_truncated` dengan saran menaikkan `max_tokens`.
2. Default dinaikkan 2048 → 8192 token agar ada ruang untuk penalaran.
3. Error tetap muncul di laporan sebagai kegagalan eksplisit, tidak ada konten AI
   yang dimasukkan bila validasi gagal.

**Yang masih belum diukur:** kualitas analisis model nyata baru diuji pada satu insiden
demo. Belum ada pengukuran kuantitatif (presisi/recall) terhadap dataset berlabel.

## 7. Konfigurasi provider dan model

Melalui UI: **AI Providers** → pilih tipe → isi model ID dan kunci → **Test** → **Activate**.

Variabel lingkungan terkait:

| Variabel | Fungsi |
|---|---|
| `SG_MASTER_KEY` | Kunci enkripsi API key provider di database. Bila kosong, kunci dibuat otomatis di `<data dir>/master.key` saat pertama dipakai. |
| `SG_DB_PATH` | Lokasi database SQLite |
| `SG_DEFAULT_TZ` | Zona waktu default untuk timestamp tanpa zona |

Provider didukung: `openai`, `anthropic`, `gemini`, `openrouter`, `ollama`, `custom_openai`.

**SSRF guard.** Base URL provider divalidasi sebelum ada request keluar. Alamat privat,
link-local, dan loopback diblokir, kecuali untuk `ollama` dan `custom_openai` lokal
yang memang diarahkan ke localhost secara sengaja.

## 8. Perintah instalasi dan menjalankan

```bash
# 1. Siapkan virtualenv (Windows: .venv\Scripts\python.exe · Linux/macOS: .venv/bin/python)
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt   # Windows
# ./.venv/bin/python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt         # Linux/macOS

# 2. Inisialisasi database + muat dataset demo sintetis
export PYTHONPATH=backend
./.venv/Scripts/python.exe -m sentinelgraph init
./.venv/Scripts/python.exe -m sentinelgraph load-demo

# 3. Bangun frontend (sekali saja, atau setelah mengubah src/)
cd frontend && npm install && npm run build && cd ..

# 4. Jalankan server (default: localhost-only)
export SG_MASTER_KEY="$(./.venv/Scripts/python.exe -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
./.venv/Scripts/python.exe -m sentinelgraph serve --port 8088
```

Buka `http://127.0.0.1:8088/`.

Dependensi dikunci di `backend/requirements.txt` (runtime, 29 pin) dan
`backend/requirements-dev.txt` (5 pin dev). Semua pin diverifikasi cocok dengan
lingkungan yang dipakai menjalankan test ini. Python >= 3.10 (diuji 3.11 di
Windows 10; Linux belum diverifikasi dari nol).

### Deployment safety (localhost-only + login)

Server sengaja hanya bind ke loopback. Memilih `--host` non-loopback **ditolak
saat startup** kecuali ada autentikasi: `SG_AUTH_TOKEN` (bearer bersama untuk
skrip) atau akun analis. Begitu API bisa dijangkau jaringan, setiap request
`/api/*` wajib kredensial. CORS bukan autentikasi.

Saat pertama dijalankan, satu akun dibuat otomatis: **admin / admin123**. Password
disimpan sebagai hash scrypt bersalt, dan token sesi disimpan di database hanya
sebagai SHA-256. Password bawaan wajib diganti; aplikasi menampilkan peringatan
selama masih dipakai. Tidak ada multi-user: ini alat satu analis, dijelaskan di
`docs/SECURITY.md`.

```bash
# cara biasa: bind ke jaringan, lalu login lewat UI dengan admin / admin123
./.venv/Scripts/python.exe -m sentinelgraph serve --host 0.0.0.0 --port 8088

# bearer token bersama, untuk skrip atau akses headless
export SG_AUTH_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
./.venv/Scripts/python.exe -m sentinelgraph serve --host 0.0.0.0 --port 8088
```

### Menjalankan untuk juri (container)

```bash
# token bersama bersifat opsional kalau juri login lewat UI
docker compose up -d --build
```

Satu image menyajikan SPA dan API pada port yang sama, jadi yang dibagikan ke juri
hanya URL, lalu mereka login dengan akun analis (bawaan **admin / admin123**).
Kalau `SG_AUTH_TOKEN` ikut diset, bearer token bersama tetap berlaku sebagai jalur
kedua. Alasan GitHub Pages dan Vercel tidak dipakai, cara kerja
volume `/data`, dan catatan verifikasi Linux ada di `docs/DEPLOY.md`.

### Release bersih (tanpa data mesin nyata)

```bash
./.venv/Scripts/python.exe tools/make_release.py
# -> release/sentinelgraph-ai : source + docs + scripts + frontend/dist
#    + data/demo/demo-events.jsonl (dataset sintetis). TIDAK ada DB runtime,
#    .env, WAL/SHM, telemetri Sysmon/firewall/security, atau log.
#    Gagal (exit != 0) bila ada match PII atau file terlarang lolos.
```

Mode pengembangan frontend (hot reload):

```bash
cd frontend && npm run dev     # http://127.0.0.1:5173, proxy /api → 8088
```

Menjalankan test dan verifikasi:

```bash
export PYTHONPATH=backend
./.venv/Scripts/python.exe -m pytest backend/tests -q      # 311 test
./.venv/Scripts/python.exe tools/verify.py                 # verdict PASS/FAIL
```

Pintu masuk kanonik: `scripts\verify.ps1` (Windows) / `bash scripts/verify.sh`
(test + typecheck + release gate, keluar dengan `VERIFY: PASS`), atau
`.venv/Scripts/python.exe -m pytest` langsung (pyproject.toml mengatur `pythonpath`).

## 9. Hasil pengujian sebenarnya

### Test otomatis

```
311 passed, 1 warning in ~21s
```

Warning yang tersisa berasal dari `starlette.testclient` (httpx deprecated), bukan kegagalan.

### Verifikasi end-to-end

```
22/22 checks passed   (tanpa provider AI; cek AI di-skip via --skip-ai)
VERDICT: PASS
```

### Bug yang ditemukan dan diperbaiki selama pengembangan

Ini bukan daftar prestise, setiap baris adalah cacat nyata yang sempat ada:

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
berbohong, bukan oleh test biasa.

### Skenario adversarial yang diuji

Stub provider mengembalikan tiga jenis kebohongan:

1. **Campuran**, 6 ID karangan bersama 1 ID asli. Hasil: 6 dibuang, hipotesis dengan
   bukti asli ditandai `evidence-linked`, hipotesis tanpa bukti ditandai
   `no surviving evidence`.
2. **Semua karangan**, 3 ID palsu. Hasil: seluruhnya dibuang, satu-satunya hipotesis
   ditandai `unsupported`.
3. **JSON rusak**, bukan JSON sama sekali. Hasil: `validation_failed`, tidak ada konten
   AI yang masuk laporan, dan laporan menyatakan kegagalan secara eksplisit.

## 10. Langkah demo (3 menit)

1. **Dashboard**, tunjukkan event, alert, insiden, aset; sebutkan bahwa setiap angka
   berasal dari tabel, bukan konstanta.
2. **Load demo**, memuat dataset sintetis: 29 event, 4 insiden.
3. **INC-0001 → Overview**, tunjukkan pemisahan tegas: "IOC match adalah fakta; host
   terkompromi adalah hipotesis".
4. **Timeline**, 9 event berurutan dari email phishing sampai transfer keluar.
5. **Attack graph**, sorot edge; tunjukkan setiap edge membawa ID event sumbernya.
   Toggle node event untuk melihat struktur entitas.
6. **AI analysis**, jalankan analisis. Tunjukkan:
   - hipotesis dengan bukti → `evidence-linked`
   - hipotesis karangan → `no surviving evidence`
   - jumlah sitasi yang dibuang oleh evidence guard
7. **Report**, unduh markdown. Buka seksi 7: "Confirmed compromise: NOT established".
   Ini titik yang membedakan produk ini dari dashboard yang menakut-nakuti.

## 11. Lokasi dokumentasi

| Dokumen | Lokasi |
|---|---|
| README (dokumen ini) | `README.md` |
| Indeks semua dokumen | `docs/README.md` |
| Proposal submission | `docs/PROPOSAL.md` |
| Slide deck (10 slide + versi 3 menit) | `docs/SLIDES.md` |
| **Slide deck siap presentasi (.pptx)** | `docs/presentation/` |
| Skrip video demo | `docs/VIDEO_SCRIPT.md` |
| Arsitektur mendetail | `docs/ARCHITECTURE.md` |
| Model ancaman & batasan | `docs/SECURITY.md` |
| Panduan demo | `docs/DEMO.md` |
| **Kelola data & ambil log Windows** | `docs/DATA_MANAGEMENT.md` |
| **Pasang Sysmon (agar deteksi nyata bekerja)** | `docs/SYSMON.md` |
| **Pemetaan MITRE ATT&CK per rule** | `docs/ATTACK_MAPPING.md` |
| Screenshot asli (dari aplikasi berjalan) | `docs/screenshots/` |
| Verifikasi mandiri | `tools/verify.py` |
| Catatan proses internal (remediasi, rilis) | `docs/internal/` |

## 12. Risiko keamanan, remediasi, dan batasan

Audit remediasi (P0/P1/P2) sudah diterapkan dan diuji ulang. Ringkasannya:

| Area | Sebelum | Sesudah (terverifikasi) |
|---|---|---|
| **SSRF (IPv4-mapped IPv6)** | `http://[::ffff:127.0.0.1]:8088` lolos validasi | Semua alamat dinormalisasi (mapped, 6to4, Teredo), dicek `is_global`; non-global ditolak |
| **DNS rebinding** | Resolusi ulang saat koneksi | Alamat diverifikasi lalu **di-pin** di transport; host yang berubah ditolak |
| **Upload memory exhaustion** | `await file.read()` sebelum cek ukuran | Baca chunk berbatas; berhenti di atas `SG_MAX_UPLOAD_BYTES`, tanpa artefak parsial |
| **Binding non-loopback tanpa auth** | Diizinkan diam-diam | Startup **gagal** kecuali `SG_AUTH_TOKEN`; lalu `/api/*` wajib Bearer |
| **Attack graph keluar viewport** | Radius melebar > viewBox tetap | Auto-fit bounding box + zoom-to-fit + center + cap/grouping + filter incident |
| **PII di repo/release** | Tool mengandung hostname/user asli; DB nyata di working tree | Tool di-generalisasi; `tools/make_release.py` mengecualikan DB/telemetri dan memverifikasi 0 PII |

Batasan yang tersisa (jujur):

- **Autentikasi single-analyst**, bukan multi-user/RBAC. Satu token bersama; belum ada
  pemisahan hak baca/tulis per pengguna.
- **API key provider** selalu dienkripsi (Fernet) sebelum masuk database. Kunci utama
  diambil dari `SG_MASTER_KEY`, atau dibuat otomatis di `<data dir>/master.key` saat
  pertama dipakai. Tidak ada penyimpanan plaintext; amankan berkas kunci tersebut.
- **`allow_private`** hanya berlaku untuk provider lokal (Ollama) pada host loopback;
  provider cloud tetap diblokir ke alamat privat.
- **AI dapat menghasilkan teks menyesatkan.** Mitigasi: sitasi diverifikasi, ringkasan
  ditandai tidak terverifikasi, deteksi tidak pernah bergantung pada AI. Teks bebas
  tetap harus dibaca sebagai klaim.
- **Dataset demo sintetis**, bukan bukti kemampuan deteksi pada data nyata.
- **Redirect HTTP** tidak diikuti oleh client provider (`follow_redirects=False`),
  sehingga tujuan redirect tak tervalidasi tidak pernah disentuh.

## 13. Langkah berikutnya

1. **RBAC multi-analyst**, pemisahan hak baca/tulis; token saat ini hanya shared-secret.
2. **Konektor SIEM/EDR**, Syslog, Wazuh, Elastic, Splunk HEC.
3. **Kalibrasi rule** terhadap baseline nyata; R-006 khususnya.
4. **Uji provider cloud dengan kredensial valid** dan ukur kualitas analisis secara
   kuantitatif (misalnya berapa persen hipotesis yang lolos verifikasi analis).
5. **Penyimpanan bukti immutable**, hash chain untuk artifact.
6. **Ekspor STIX/TAXII** agar temuan bisa dibagikan ke platform lain.
7. **Virtualisasi graph** (clustering dinamis) untuk >2000 node, cap + grouping saat ini
   menangani kepadatan, tetapi belum meng-cluster secara semantik.

## Tutorial and language

The sidebar has a **Tutorial** tab (group *Learn*) that walks through the whole
workflow in nine steps, each linking to the screen it describes, so the app can
be learned without opening this README.

The sidebar footer has an **EN | ID** switch that translates the entire
interface. The choice is remembered in `localStorage: sg.lang`. Machine-generated
content stays in its original form, because that is data rather than interface:
incident and alert titles, host names, hashes, relationship identifiers.
