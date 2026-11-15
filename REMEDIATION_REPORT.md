# REMEDIATION_REPORT, SentinelGraph AI

Tanggal: 2026-11-11. Lingkup: audit remediasi keamanan + kesiapan lomba (Kartika Cyber
Hackathon 2026). Semua angka di bawah berasal dari eksekusi nyata pada workspace ini.

## 1. Temuan audit yang diperbaiki

| Temuan | Status | Perbaikan |
|---|---|---|
| SSRF bypass IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`) | FIXED | normalisasi alamat + `is_global` |
| DNS rebinding (validasi ≠ alamat koneksi) | FIXED | alamat diverifikasi lalu di-pin di transport |
| Redirect ke tujuan tak tervalidasi | FIXED | `follow_redirects=False` |
| Upload memory exhaustion (`await file.read()` dulu) | FIXED | bounded chunked read 64 KiB |
| `/api/ingest/text` tanpa batas eksplisit | FIXED | 413 di atas `SG_MAX_UPLOAD_BYTES` |
| API tanpa autentikasi | FIXED | Bearer token + startup guard |
| Binding non-loopback tanpa auth | FIXED | startup ditolak tanpa `SG_AUTH_TOKEN` |
| Attack graph keluar viewport | FIXED | bbox auto-fit + zoom-to-fit + cap/grouping |
| Tool berisi hostname/username asli | FIXED | disanitasi / deteksi runtime |
| Runtime DB & telemetry bisa terkemas | FIXED | release builder + PII gate |
| Manifest dependency tidak lengkap | FIXED | `backend/requirements.txt` (29 pin) |
| Attack graph gagal fit pada graf sangat besar (`K_MIN` menahan auto-fit) | FIXED | ambang fit terpisah `K_FIT_MIN=0.03` |
| Cap node per-tipe (bukan global) → 740 node dirender | FIXED | cap global 320 + agregat per tipe |
| `scripts/start.ps1` gagal jalan (`$Host` variabel read-only) | FIXED | parameter `$BindHost` |
| Master key acak tiap start → API key provider tersimpan tak terbaca | FIXED | key dipersistenkan (`.env` → `data/.master_key`) |
| Race konkurensi: `DatabaseError('not an error')` saat analyze paralel | FIXED | helper baca terkunci `fetchone`/`fetchall`; 13 situs `get_conn().execute()` dialihkan |

## 2. File yang diubah

Modified (18): `.gitignore`, `.env.example`, `README.md`, `requirements.txt`,
`requirements-dev.txt`, `backend/sentinelgraph/security.py`, `ai_providers.py`, `api.py`,
`config.py`, `__main__.py`, `backend/tests/test_security.py`, `test_ai.py`,
`docs/SECURITY.md`, `docs/DATA_MANAGEMENT.md`, `frontend/src/App.tsx`,
`frontend/src/components/AttackGraph.tsx`, `tools/export-windows-logs.ps1`.

Added (14): `backend/requirements.txt`, `backend/requirements-dev.txt`,
`backend/tests/test_deployment.py`, `test_ssrf_redirect.py`, `test_upload_limits.py`,
`tools/check_pii_db.py`, `tools/make_release.py`, `scripts/setup.ps1`, `start.ps1`,
`setup.sh`, `start.sh`, `docs/SETUP.md`, `TESTING.md`, `AI_PROVIDERS.md`,
`DEMO_GUIDE.md`, `LIMITATIONS.md`, `REMEDIATION_PROGRESS.md`, `REMEDIATION_REPORT.md`.

Backup: `backup/source-20261111-232051.tar.gz`, `backup/sentinelgraph-real-20261111-232051.db`.

## 3. Implementasi security yang ditambahkan

**SSRF (`backend/sentinelgraph/security.py`)**
- `_normalise_address`: membuka IPv4-mapped IPv6, 6to4, Teredo.
- `_is_blocked_address`: `is_global` + blocklist (private/loopback/link-local/reserved/
  unspecified/multicast).
- `validate_and_resolve`: fail-closed bila DNS kosong; validasi semua hasil; kembalikan
  satu alamat terverifikasi.
- `PinnedHTTPTransport` + `_rewrite_to_pinned`: koneksi selalu ke alamat terverifikasi,
  Host & `sni_hostname` dipertahankan, host berubah → `TransportError`.
- `open_pinned_client`: `follow_redirects=False`, timeout eksplisit.
- Pengecualian Ollama: hanya loopback + provider `ollama` + `allow_private`.

**Upload (`api.py`)**
- `_read_upload_bounded`: chunk 64 KiB, hentikan saat melewati batas, `finally: close`,
  tidak menulis artefak bila ditolak; UTF-8 & UTF-16 dipertahankan.
- `/api/ingest/text`: cek ukuran UTF-8 → 413.

**Auth/deployment**
- `config.enforce_secure_binding`: tolak bind non-loopback tanpa token, pesan jelas
  menyebut CORS bukan autentikasi.
- `api._require_auth`: Bearer + `hmac.compare_digest`, kecuali `/api/health`.
- `__main__.cmd_serve`: guard sebelum uvicorn bind.

**Graph (`AttackGraph.tsx`, `App.tsx`)**
- `fitView` bbox → scale+translate, tombol ⤢, reset, auto-center.
- Cap 320 node + agregat per tipe (menampilkan jumlah yang digroup).
- Filter incident (`focusHosts`), filter relasi (chip), node→evidence, panel evidence.

**Release**
- `tools/make_release.py` (exclude runtime/telemetry, bootstrap sintetis, PII gate).
- `tools/check_pii_db.py` (marker `DESKTOP-*`, `S-1-5-*`, hostname/user runtime).

## 4-5. Test yang dijalankan dan hasil

| Perintah | Hasil | Exit |
|---|---|---|
| `scripts/verify.ps1` (kanonik: test+typecheck+release) | **VERIFY: PASS** | 0 |
| `pytest backend/tests -q` | **311 passed**, 0 failed, 0 skipped, 3 warnings (deprecation FastAPI) | 0 |
| `tsc -b` | bersih | 0 |
| `vite build` | `index-*.js` 239.19 kB, `index-*.css` 9.24 kB | 0 |
| `tools/verify.py --skip-ai` | **22/22 checks passed**, VERDICT: PASS | 0 |
| `tools/make_release.py` | RELEASE OK, PII 0 match | 0 |

Baseline audit sebelumnya 148 passed -> kini 311. Tidak ada test yang dihapus/dilemahkan.
Warning yang tersisa hanya `@app.on_event` deprecated (bukan kegagalan).

Kelompok test keamanan: `test_security.py` (SSRF + redaksi), `test_ssrf_redirect.py`
(redirect), `test_upload_limits.py` (batas/encoding/artefak), `test_deployment.py`
(binding + auth per-endpoint), `test_ai.py` (mock provider).

## 6. Frontend build

`vite build` sukses: 41 modul, JS 239.19 kB (gzip 70.07 kB), CSS 9.24 kB (gzip 2.66 kB).
TypeScript `tsc -b` bersih.

## 7. End-to-end verification

Server dijalankan dari **pohon release itu sendiri** (`PYTHONPATH=release/.../backend`,
DB dibootstrap ke direktori scratch, release tidak membawa DB). Alur: health → import
dataset → normalisasi → deteksi → korelasi → insiden → attack graph → bukti → report
markdown/html/json → frontend served. Hasil: **22/22 PASS** (health 200, root 200).

Verifikasi graph tambahan (browser, dataset 219 node/387 edge):

| Skenario | Render | outOfView | scale |
|---|---|---|---|
| Demo default | 30 | 0 | 0.826 |
| Subgraf `WS-FIN-07` | 14 | 0 | 0.826 |
| 219 node (cap+group) | 195 | 0 | 0.446 |
| Filter incident | 8 | 0 | 0.826 |
| Filter relasi | edge 344→301 |, |, |
| Tanpa data | empty state |, |, |

## 8. Status acceptance criteria

**Security**
- [x] IPv4-mapped IPv6 SSRF bypass ditutup
- [x] DNS rebinding dimitigasi (alamat di-pin, host berubah ditolak)
- [x] Redirect tidak melewati validasi (tidak diikuti)
- [x] Upload bounded streaming
- [x] Oversized ditolak sebelum terbaca penuh
- [x] Tidak ada artefak parsial setelah ditolak
- [x] Remote binding butuh autentikasi
- [x] API key tidak bocor ke frontend/log (masking + enkripsi opsional)
- [x] Repository bebas credential & telemetry pribadi (0 match pada release)

**Functionality**
- [x] Fitur MVP tetap berfungsi (311 test + E2E)
- [x] Dashboard memakai data aktual
- [x] Incident investigation berfungsi
- [x] Timeline sesuai data sumber
- [x] Attack graph auto-fit (outOfView 0 pada 8/14/195 node)
- [x] Node & edge dapat ditelusuri ke bukti
- [x] AI provider dapat dikonfigurasi
- [~] Test Connection, jalur kode ada & diuji dengan mock; **belum** dengan kredensial nyata
- [x] Mode tanpa AI tetap bekerja (core-only)
- [x] Reports dapat diekspor (md/html/json)

**Quality**
- [x] Dependency manifest tersedia (29 pin, 0 mismatch)
- [~] Instalasi bersih, manifest diverifikasi; **instalasi dari nol lintas-OS BLOCKED** (tanpa jaringan)
- [x] Frontend production build berhasil
- [x] Backend tests berhasil (311)
- [x] Security regression tests berhasil
- [x] End-to-end verification berhasil (22/22)
- [x] Dokumentasi sesuai implementasi
- [x] Release package bebas runtime data pribadi (0 PII)

## 9. Masalah yang masih belum selesai

1. **Clean install dari nol (venv baru, lintas-OS)**, tidak dapat dijalankan karena
   `pip install`/jaringan diblokir di lingkungan ini. Bukti yang ada: 29 pin cocok dengan
   environment berjalan; bootstrap DB bersih berhasil. Tidak ada klaim uji Linux.
2. **Screenshot `docs/screenshots/03_attack_graph.png`** sudah diregenerasi 14 Nov 2026
   (Playwright 1.65.1 + Chromium headless). Fitur fit-to-view terbukti lewat pengukuran.
3. **Live AI provider** sudah diverifikasi dengan kredensial nyata (OpenRouter + `deepseek-v4.1-flash`); 3 dari 6 `ai_runs` berstatus `ok` pada DB runtime (lihat `docs/LIMITATIONS.md`).
4. **Frontend unit test runner** tidak ada (sengaja, tanpa dependency baru).
5. **Rate limiting** endpoint mahal belum ada.

## 10. Cara menjalankan

```powershell
scripts\setup.ps1      # sekali
scripts\start.ps1      # http://127.0.0.1:8088
```

```bash
bash scripts/setup.sh
bash scripts/start.sh
```

Manual: lihat `docs/SETUP.md`. Ekspos ke LAN:

```bash
export SG_AUTH_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
./.venv/Scripts/python.exe -m sentinelgraph serve --host 0.0.0.0 --port 8088
```

## 11. Cara membuat release package

```bash
./.venv/Scripts/python.exe tools/make_release.py
# -> release/sentinelgraph-ai  (source + docs + scripts + frontend/dist
#    + data/demo/demo-events.jsonl). TIDAK memuat DB runtime / .env / telemetri / log.
#    exit != 0 bila ada PII atau file runtime/telemetry lolos
```

Hasil nyata: **106 file, 1.9 MB**, 0 file terlarang, PII 0 match.
Fresh install membuat DB sendiri: `python -m sentinelgraph init && ... load-demo`.

## 12. Lokasi dokumentasi

| Dokumen | Path |
|---|---|
| Setup & troubleshooting | `docs/SETUP.md` |
| Testing | `docs/TESTING.md` |
| AI providers | `docs/AI_PROVIDERS.md` |
| Demo guide | `docs/DEMO_GUIDE.md` |
| Batasan | `docs/LIMITATIONS.md` |
| Keamanan | `docs/SECURITY.md` |
| Manajemen data & PII | `docs/DATA_MANAGEMENT.md` |
| Arsitektur | `docs/ARCHITECTURE.md` |
| Progres remediasi | `REMEDIATION_PROGRESS.md` |
| Ringkasan produk | `README.md` |

## 13. Risiko yang masih tersisa

- **Single shared token**, bukan RBAC; token bocor = akses penuh. Rotasi = ganti env.
- **Tanpa TLS internal**, butuh reverse proxy untuk akses jaringan.
- **SQLite teks-jelas** lokal; hanya API key provider yang terenkripsi (jika master key).
- **SSRF berbasis "harus global"**, bukan allowlist host; egress policy OS tetap disarankan.
- **Tanpa rate limiting** pada `/api/analyze`, upload.
- **AI bisa menyesatkan**, dimitigasi evidence guard + label tidak terverifikasi, bukan
  dihilangkan.
- **Dataset demo sintetis**, bukan ukuran kemampuan pada data nyata.
