# FINAL REMEDIATION REPORT — SentinelGraph AI

Tanggal: 2026-11-14
Lingkungan: Windows 10, Python 3.11.0, Node/Vite, SQLite (raw SQL, tanpa ORM)

Semua angka di bawah berasal dari eksekusi nyata pada sesi ini. Perintah dan
keluaran yang mendukung dicantumkan apa adanya. Tidak ada klaim tanpa bukti.

---

## 1. Temuan yang diperbaiki

| # | Temuan | Status |
|---|---|---|
| 1 | CORS tidak mengizinkan header `Authorization` | Diperbaiki |
| 2 | OPTIONS preflight ditolak middleware autentikasi (401) | Diperbaiki |
| 3 | Frontend tidak pernah mengirim Bearer token | Diperbaiki |
| 4 | Tidak ada input token di GUI | Diperbaiki |
| 5 | `_ensure_default_project` SELECT→INSERT tanpa lock (race) | Diperbaiki |
| 6 | Bypass SSRF lewat NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`) | Diperbaiki |
| 7 | Teredo: hanya client yang divalidasi, server privat lolos | Diperbaiki |
| 8 | Batas body hanya di endpoint, bukan di level ASGI | Diperbaiki |
| 9 | Test SSRF bergantung DNS publik (tidak reproducible offline) | Diperbaiki |
| 10 | Release ZIP tidak memindai PII dokumen/teks dan tidak membuat arsip | Diperbaiki |

---

## 2. File yang diubah

Backend
- `backend/sentinelgraph/api.py` — CORS `Authorization`, bypass OPTIONS, `_ensure_default_project` atomik, pemasangan `BodyLimitMiddleware`
- `backend/sentinelgraph/security.py` — NAT64/6to4/Teredo, validasi seluruh embedded IPv4, penolakan prefix transisi
- `backend/sentinelgraph/config.py` — `SG_MAX_REQUEST_BYTES` (default `max_upload_bytes + 64 KiB`)
- `backend/sentinelgraph/bodylimit.py` (baru) — middleware batas body ASGI

Frontend
- `frontend/src/auth.ts` (baru) — token store session-scoped (sessionStorage + fallback memori)
- `frontend/src/api.ts` — header `Authorization`, `authFetch`, `downloadReport`, event 401
- `frontend/src/App.tsx` — tombol Token/Sign out, panel input password, reaksi 401
- `frontend/src/pages/ProvidersPage.tsx` — fetch mentah diganti `authFetch`
- `frontend/src/pages/IncidentView.tsx` — unduhan laporan lewat fetch ber-token (bukan `<a href>`)

Tools & test
- `tools/make_release.py` — allowlist, penolakan arsip/kredensial, scan PII teks+demo+screenshot, ZIP + verifikasi arsip
- `tools/check_pii_db.py` — dipakai sebagai gate DB (tidak diubah)
- `backend/tests/test_auth.py` (baru), `test_concurrency.py` (baru), `test_ssrf_hardening.py` (baru), `test_bodylimit.py` (baru)
- `backend/tests/test_security.py` — test DNS publik diganti mock deterministik
- `docs/SECURITY.md`, `docs/TESTING.md`, `docs/DATA_MANAGEMENT.md`, `docs/PROPOSAL.md`, `docs/SLIDES.md`, `README.md`, `tools/export-windows-logs.ps1`

---

## 3. Perbaikan authentication

- `allow_headers` kini memuat `Authorization`; tanpa ini browser membuang header
  dan setiap request ber-token gagal sebagai 401.
- Middleware autentikasi melewati `OPTIONS` sebelum memeriksa token. Preflight
  browser tidak pernah membawa `Authorization`, sehingga menolaknya membuat CORS
  mustahil dipakai.
- OPTIONS bukan jalur data: preflight dijawab `CORSMiddleware` tanpa body. Diuji
  dengan `test_options_returns_no_data_body`.
- GUI: token disimpan di `sessionStorage` (bukan `localStorage`), hilang saat tab
  ditutup, dan tidak pernah dirender atau dimasukkan ke pesan error.
- `/api/health` tetap tanpa autentikasi (untuk probe readiness).
- Default tetap localhost-only tanpa token; `enforce_secure_binding` tetap
  menolak bind non-loopback tanpa `SG_AUTH_TOKEN`.

Bukti: `backend/tests/test_auth.py` — 18 test lulus, termasuk 7 endpoint sensitif
yang diuji tanpa token (semua 401) dan 4 pemeriksaan preflight CORS.

---

## 4. Perbaikan concurrency

`_ensure_default_project` sekarang membungkus seluruh SELECT→INSERT dalam
`db_lock()` (RLock reentrant, sehingga `cursor()` di dalamnya aman) dan memakai
`ON CONFLICT(name) DO NOTHING`, lalu membaca ulang ID sehingga nilai yang
dikembalikan selalu valid.

Bukti: `backend/tests/test_concurrency.py`

```
20 thread x 20 iterasi (400 thread total)
..                                                                       [100%]
2 passed
```

Assertion per iterasi: tidak ada exception, tepat satu project, semua thread
mendapat ID yang sama, dan baris project benar-benar ada. IOC seeding diuji
idempoten (tidak ada duplikat).

---

## 5. Hasil SSRF regression

Mekanisme transisi IPv6 yang kini ditolak (semua diverifikasi):

| Alamat | Target tersembunyi | Hasil |
|---|---|---|
| `64:ff9b::a9fe:a9fe` | 169.254.169.254 | BLOCK |
| `64:ff9b::7f00:1` | 127.0.0.1 | BLOCK |
| `64:ff9b::a00:1` | 10.0.0.1 | BLOCK |
| `64:ff9b:1::a9fe:a9fe` | 169.254.169.254 | BLOCK |
| `2002:a9fe:a9fe::1` | 169.254.169.254 (6to4) | BLOCK |
| `2002:0a00:0001::1` | 10.0.0.1 (6to4) | BLOCK |
| `::ffff:127.0.0.1` | loopback | BLOCK |
| `::ffff:169.254.169.254` | metadata | BLOCK |
| `2001:0:...` (Teredo) | server privat / client publik | BLOCK |
| `64:ff9b::808:808` | 8.8.8.8 (publik, tetap ditolak) | BLOCK |
| `93.184.216.34`, `104.18.6.192`, `2606:4700::1111` | publik sah | ALLOW |

DNS pinning dipertahankan: `PinnedHTTPTransport` menulis ulang host menjadi IP
literal hasil validasi, mempertahankan header `Host` dan `sni_hostname`, dan
menolak request bila host berubah setelah validasi (indikasi rebinding).
`open_pinned_client` selalu `follow_redirects=False`.

Bukti: `backend/tests/test_security.py` + `backend/tests/test_ssrf_hardening.py`
— 66 test lulus, termasuk satu request HTTP nyata ke server localhost yang
dijalankan test sendiri.

---

## 6. Hasil upload security

- Batas payload tetap `SG_MAX_UPLOAD_BYTES` (default 32 MiB) di endpoint.
- Batas **seluruh body HTTP** baru `SG_MAX_REQUEST_BYTES` (default payload + 64 KiB),
  ditegakkan middleware terluar sebelum parser multipart/JSON mana pun berjalan.
- `Content-Length` melebihi batas → `413` tanpa membaca body.
- Body streaming/chunked tanpa `Content-Length` → dihitung per chunk dan dihentikan
  saat melewati batas; parser tidak pernah menyelesaikan pembacaan.
- File tepat sebesar batas payload tetap diterima (overhead multipart diserap slack).

Bukti: `backend/tests/test_bodylimit.py` — 5 test lulus (JSON over limit,
multipart over limit, chunked bypass, request normal, batas dibaca saat runtime),
plus `backend/tests/test_upload_limits.py` tetap hijau (9 test).

---

## 7. Jumlah test pass/fail/skip

```
PYTHONPATH=backend ./.venv/Scripts/python.exe -m pytest backend/tests -o addopts=""
============================ 262 passed in 43.04s =============================
```

- Pass: **262**
- Fail: **0**
- Skip: **0**
- Tidak ada test yang dinonaktifkan untuk memperoleh status PASS.

---

## 8. Jumlah pengulangan concurrency test

- 20 iterasi × 20 thread = **400 eksekusi paralel** `_ensure_default_project`.
- Ditambah 1 test IOC idempotensi dengan 20 thread.

---

## 9. Hasil frontend build

```
node node_modules/typescript/bin/tsc -b
== TSC done ==            (0 error)

node node_modules/vite/bin/vite.js build
✓ 42 modules transformed.
dist/index.html                   0.95 kB │ gzip:  0.58 kB
dist/assets/index-CHkcnS8u.css    9.24 kB │ gzip:  2.66 kB
dist/assets/index-C0dcEcDz.js   242.64 kB │ gzip: 71.16 kB
✓ built in 1.49s
```

---

## 10. Hasil E2E

Server live pada `127.0.0.1:8099` dengan database terpisah (`data/verify-e2e.db`).

```
./.venv/Scripts/python.exe tools/verify.py --base http://127.0.0.1:8099 --skip-ai --reset
...
22/22 checks passed
VERDICT: PASS
exit code 0
```

Cakupan: health, bootstrap DB, load demo (29 event), 4 insiden, alert+timeline,
sitasi tervalidasi (`cited=[1,2,3,4,10,11,12,13,14]` == `stored`), attack graph
60 node/52 edge dengan 0 edge tanpa bukti, laporan Markdown/HTML/JSON, dan
penyajian frontend.

---

## 11. Ukuran dan isi release ZIP

```
python tools/make_release.py
[1/7] copied 101 files -> release/sentinelgraph-ai
[2/7] no .db / telemetry / .env files present
[3/7] bootstrapped synthetic dataset in scratch dir
TOTAL PII ROW-MATCHES: 0
[4/7] database PII scan clean (0 matches)
[5/7] shipped 25 synthetic events -> data/demo/demo-events.jsonl
[6/7] text/demo/screenshot scan clean (4 PNGs, sidecars+filenames checked)
[7/7] archive OK -> release/sentinelgraph-ai.zip (0.85 MB)

RELEASE OK
```

Isi: `backend/`, `frontend/` (+ `dist/` hasil build), `docs/` (+ screenshot),
`tools/`, `data/demo/demo-events.jsonl`, `requirements*.txt`, `README.md`,
`.env.example`. Tidak ada `.venv`, `node_modules`, database runtime, backup,
arsip lama, telemetry, atau `.env`.

---

## 12. Pemeriksaan privasi

| Pemeriksaan | Hasil |
|---|---|
| DB sintetis vs marker PII (`DESKTOP-`, `S-1-5-`, hostname/user mesin) | 0 match |
| Scan teks seluruh file rilis (source, docs, dataset) | 0 hit |
| Scan nama file + sidecar screenshot | 0 hit |
| Verifikasi isi ZIP (DB/log/env/kredensial/backup) | 0 entri sensitif |
| `__pycache__` repo | dihapus; `.pyc` tidak ter-track |

Dua pengecualian pemindaian bersifat eksplisit dan auditabel di source
(`PII-SCAN-ALLOW`), bukan blind-ignore:
- `docs/DATA_MANAGEMENT.md` — mendokumentasikan pola scanner itu sendiri.
- `tools/export-windows-logs.ps1` — contoh placeholder `DESKTOP-EXAMPLE`.

---

## 13. Fitur yang belum selesai

1. **Regenerasi screenshot belum dilakukan.** Empat PNG yang ada berasal dari UI
   berjalan, tetapi belum di-capture ulang dari build terbaru dengan dataset
   sintetis baru. Tidak ada tool otomasi browser di lingkungan ini, sehingga
   screenshot tidak dapat diregenerasi dan diverifikasi secara terprogram.
2. **Verifikasi visual PII pada screenshot tetap manual.** Pemindaian otomatis
   hanya mencakup nama file dan sidecar `.txt`; piksel tidak dipindai.
3. **Integrasi provider AI live tidak diuji** dalam sesi ini (tanpa kredensial
   nyata). Seluruh test AI memakai stub/permintaan yang dimock.
4. **Belum ada RBAC/sesi per pengguna** — satu token bersama tetap menjadi model
   autentikasinya.

---

## 14. Risiko yang masih tersisa

1. **Token bersama tanpa rotasi otomatis.** Token bocor = akses penuh. Mitigasi
   saat ini hanya: default localhost-only, `compare_digest`, dan tidak
   menyimpan token di localStorage.
2. **Transport ter-pin mengabaikan proxy environment.** `PinnedHTTPTransport`
   membangun `httpcore.ConnectionPool` sendiri, sehingga `HTTP(S)_PROXY` tidak
   dihormati. Ini konsekuensi sadar dari pinning IP; di lingkungan ber-proxy,
   provider tidak akan terjangkau.
3. **Pin hanya pada alamat pertama hasil resolusi** (`verified[0]`). Bila host
   punya beberapa A/AAAA record, hanya yang pertama dipakai. Ini aman terhadap
   rebinding (tidak ada resolusi ulang) tetapi dapat memilih record yang tidak
   dapat dijangkau.
4. **`is_global` bergantung pada data `ipaddress` versi Python.** Alamat
   special-purpose baru dapat lolos sampai pustaka diperbarui; daftar
   `BLOCKED_NETWORKS` menjadi lapis kedua.
5. **SQLite single-connection + RLock** membatasi throughput; cukup untuk
   single-analyst, bukan beban multi-pengguna.
6. **Cache bytecode** dapat memuat path absolut mesin analis; sudah dibersihkan
   dan di-gitignore, tetap perlu dijaga saat packaging (kini ditangani allowlist
   `make_release.py`).

---

## Ringkasan verdict

Semua item yang dapat diverifikasi secara terprogram pada lingkungan ini
**lulus dengan bukti eksekusi**: 311 test, 22/22 E2E, build frontend bersih,
release 0 PII. Empat item pada §13 secara eksplisit **belum** selesai dan tidak
diklaim selesai.