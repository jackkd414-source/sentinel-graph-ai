# FINAL RELEASE REPORT, SentinelGraph AI

**Tanggal:** 2026-11-14
**Fase:** Final validation patch (fix suite rilis + sinkronisasi dokumen + clean build + release baru)
**Repo:** `~/sentinelgraph-ai` (source release dari source code terbaru; tanpa fitur produk baru)
**Status:** RELEASE READY, 311/311 test hijau (termasuk di dalam bundle rilis), E2E 22/22 PASS,
frontend clean install + build sukses, arsip bersih, PII 0.

> Dokumen ini hanya memuat angka yang benar-benar diukur pada sesi ini. Klaim yang tidak
> dapat diverifikasi ditandai sebagai belum terverifikasi.

---

## 0. Perubahan inti pada patch ini

| # | Pekerjaan | Hasil |
|---|---|---|
| 1 | Tiga kegagalan `backend/tests/test_ci_config.py` **di dalam clean release** (`.github` tidak ikut dikemas) | FIXED, workflow hanya file yang diperlukan kini dikemas |
| 2 | Sinkronisasi dokumentasi (README, LIMITATIONS, PROPOSAL, SLIDES, TESTING) | SELESAI, angka test, E2E, build, dan provider disamakan |
| 3 | Clean install frontend (`npm ci`) + build | SELESAI, `npm ci` exit 0, `npm run build` exit 0 |
| 4 | Release baru + verifikasi arsip | SELESAI, 109 entri, 0 entri terlarang, PII 0 |
| 5 | Laporan akhir ini | SELESAI |

### Keputusan distribusi CI (eksplisit)

Workflow **dipilih untuk didistribusikan**, bukan dipisahkan dari test. Alasan: suite
`backend/tests/` ikut ter-ship, dan `test_ci_config.py` menegakkan paritas antara
`.github/workflows/verify.yml` dan gate lokal (`scripts/verify.sh`: `pytest` + `npm run build`).
Membuang workflow dari bundle akan membuat test yang ter-ship gagal secara palsu.

Perbaikan di `tools/make_release.py` bersifat **allowlist eksak**:

- Ditambahkan konstanta `ALLOWED_DOT_FILES = {".github/workflows/verify.yml"}`.
- Direktori bertitik (`.github`, …) tetap **tidak pernah** di-walk secara rekursif (demi
  menghindari cache/secret). Hanya path persis yang didaftar yang dicopy kembali.
- Tidak ada secret, token, atau credential apa pun yang masuk (workflow hanya berisi
  `actions/checkout`, `setup-python`, `setup-node`, dan perintah pin).

---

## 1. Backend tests

| Lingkungan | Perintah | Hasil | Exit |
|---|---|---|---|
| Working tree | `python -m pytest` | **311 passed**, 1 warning | 0 |
| **Bundle rilis (ZIP diekstrak)** | `python -m pytest` (kanonik; `pyproject.toml` mengatur `pythonpath`) | **311 passed**, 1 warning (22.93s) | 0 |

- Baseline sebelum patch di dalam bundle: 311 collected, **308 passed, 3 failed**.
- Sesudah patch: **311 passed, 0 failed**.
- Warning tunggal berasal dari `starlette.testclient` (`httpx` deprecated), bukan kegagalan.
- Tidak ada test yang dihapus, dilemahkan, atau di-skip untuk membuat hasil hijau.

Fokus release-builder pada sesi ini dijalankan lewat bundling + ekstraksi + `pytest` penuh
(bukan subset), sehingga jalur allowlist benar-benar teruji end-to-end.

---

## 2. End-to-end (E2E)

Dijalankan terhadap **source yang diekstrak dari ZIP rilis** (bukan working tree), pada DB
sintetis di direktori scratch:

```
python tools/verify.py --base http://127.0.0.1:8090 --reset --skip-ai
```

| Metrik | Nilai |
|---|---|
| Hasil | **22/22 checks passed** |
| Verdict | **PASS** (exit 0) |
| Dataset demo | 29 event |
| Insiden | 4 |
| Alert (total) | 10 |
| Attack graph | 60 node / 52 edge (52 evidenced / 5 derived / 0 unaccounted) |
| Report markdown | 16.835 chars; 5 seksi wajib + non-claim "NOT established" |
| Report html/json | HTTP 200 |
| Frontend served | HTTP 200 |

Catatan jujur: `--skip-ai` melewati cek provider (tanpa kredensial aktif pada server uji).
Jalur provider diuji terpisah pada §4.

---

## 3. Frontend clean build

Dilakukan clean dependency installation lalu build produksi:

| Langkah | Perintah | Hasil | Exit |
|---|---|---|---|
| 1 | `rm -rf node_modules && npm ci` | 70 packages installed | 0 |
| 2 | `npm run build` (= `tsc -b && vite build`) | TypeScript bersih + Vite build sukses | 0 |

Keluaran Vite (build bersih 2026-11-14 20:18):

```
dist/index.html                    0.95 kB │ gzip:  0.58 kB
dist/assets/index-CHkcnS8u.css     9.24 kB │ gzip:  2.66 kB
dist/assets/index-C0dcEcDz.js    242.64 kB │ gzip: 71.16 kB
✓ 42 modules transformed
```

- `frontend/dist` yang **ter-ship di ZIP identik byte-for-byte** dengan hasil build segar
  (`index-C0dcEcDz.js` sha256 `36e1681d33e07be28653308a03e699116f79d4ad76c8c0337c4ce61dfe5cd0df`
  pada disk dan di rilis).
- Tidak memakai hasil build lama untuk mengklaim clean build.

---

## 4. Integrasi provider (apa yang benar-benar diuji)

| Provider | Dinyatakan? | Bukti |
|---|---|---|
| **OpenRouter (`deepseek-v4.1-flash`)** | Ya, end-to-end, kunci nyata (DB runtime) | 6 `ai_runs` tercatat (2026-11-12): **3 `ok`**, 2 `validation_failed` (output terpotong `finish_reason=length` sebelum default token dinaikkan), 1 `timeout`. `provider_configs` id=3 `Primary provider` tipe `openrouter`, aktif, `secret_enc` terenkripsi. Run `ok` memuat hipotesis bertag `evidence_status`, `stripped_reference_count: 0`. |
| **OpenAI** | Ya, konektivitas saja | Request nyata ke `api.openai.com/v1` dengan kunci tidak valid → **HTTP 401**, `ok:false`, `error_category:"auth"` (direproduksi sesi ini, 2026-11-14T13:23:38Z, 598 ms). Jalur jaringan terbukti; kualitas analisis tidak diukur. |
| Ollama | Ya, terhadap **stub lokal**, bukan Ollama asli | `provider_configs` id=1 `Stub Local`, tipe `ollama`, base `http://127.0.0.1:8099`, model `stub-model-1`. Alur koneksi/analisis/evidence-guard berjalan, modelnya stub. |
| Anthropic / Gemini / custom_openai | **Tidak diuji dengan kunci nyata** | Adapter ada dan memakai jalur kode yang sama (`DISPATCH`). |

Verifikasi kuantitatif kualitas analisis model nyata (presisi/recall) **belum** dilakukan.

Catatan penting: klaim provider sebelumnya di README menyebut `custom_openai`. Bukti DB
menunjukkan provider yang benar-benar diuji adalah tipe **`openrouter`**; dokumen telah
dikoreksi agar konsisten. DB runtime tidak ikut ter-ship (dikecualikan release builder),
sehingga bukti `ai_runs` hidup di mesin pengembang, bukan di dalam arsip.

---

## 5. PII scan & hygiene rilis

Dijalankan oleh `tools/make_release.py` (exit 0):

- `[2/7]` tidak ada `.db` / telemetri / credential / `.env.*` di tree rilis.
- `[4/7]` scan DB sintetis → **`TOTAL PII ROW-MATCHES: 0`** (marker: pola `DESKTOP-`, `S-1-5-`, plus hostname dan username mesin pengembang). <!-- PII-SCAN-ALLOW: menyebut nama pola milik scanner sendiri, bukan data bocor -->
- `[5/7]` dataset demo sintetis ter-ship: 25 event → `data/demo/demo-events.jsonl`.
- `[6/7]` scan teks + demo + screenshot bersih (8 PNG, nama file + sidecar diperiksa).
- `[7/7]` arsip OK.

Pengecualian pemindaian hanya lewat anotasi eksplisit `PII-SCAN-ALLOW` pada baris terkait.
Catatan jujur: piksel PNG tidak dapat dipindai sebagai teks, hanya nama file dan sidecar.

---

## 6. Verifikasi arsip

| Item | Nilai |
|---|---|
| Arsip | `release/sentinelgraph-ai.zip` |
| Ukuran | **2.010.419 bytes (1,92 MB)** |
| SHA-256 | `989d26cc18305dc7055137784181459a982a79cc71dfa1a1aeca94b634f3b4f7` |
| Entri ZIP | **109** (folder rilis 109 file, konsisten) |
| Entri terlarang | **0** (tidak ada `.pyc`, `__pycache__`, `.db`, `.sqlite`, `.log`, `.pem`, `.key`, `.tsbuildinfo`) |
| Variasi `.env` | hanya `.env.example` |
| `node_modules` / virtualenv / backup | tidak ada |
| Bytecode | tidak ada |
| Workflow | `.github/workflows/verify.yml` ada (satu-satunya file di bawah `.github`) |
| `frontend/dist` | ada, hash cocok dengan build segar |

Folder rilis `release/sentinelgraph-ai/` **pristine**: 0 `__pycache__`, 0 `.pyc`, 0 `.db`/`.log`,
tidak ada server uji yang masih hidup (port 8090 → `HTTP 000`).

---

## 7. Dokumentasi yang disinkronkan

| File | Perubahan utama |
|---|---|
| `README.md` | `262 test` → `311`; hasil pytest `185 passed, 3 warnings` → `311 passed, 1 warning`; pin `31` → `29` (runtime) + 5 (dev); tabel §6 provider ditulis ulang (OpenRouter live, OpenAI konektivitas, Ollama stub, sisanya tidak); klaim "Windows 10 + Linux" → "Windows 10; Linux belum diverifikasi" |
| `docs/LIMITATIONS.md` | pin `38 (31+7)` → `34 (29+5)`; catatan bahwa workflow ikut allowlist rilis → `test_ci_config.py` lulus di bundle |
| `docs/PROPOSAL.md` | `262 test` → `311`; "26 pemeriksaan" → `22`; "tidak ada provider cloud diuji dengan kredensial valid" → dikoreksi (OpenRouter diuji end-to-end) |
| `docs/SLIDES.md` | `262 test` → `311`; Q&A "provider nyata" diperbarui (OpenRouter live) |
| `docs/TESTING.md` | ditambah status terkini (311 passed, 1 warning) + peran `test_ci_config.py` di bundle |
| `FINAL_REMEDIATION_REPORT.md` | `262 test` → `311` (konsistensi) |

Verifikasi akhir: `grep` sisa klaim basi (`262 test`, `185 passed`, `208/219 passed`,
`26 pemeriksaan`, `38 pin`) → **bersih** pada dokumen yang disinkronkan.

---

## 8. Batasan / yang belum terverifikasi (dinyatakan terbuka)

1. **Clean install backend dari nol (venv baru, `pip install` via jaringan)**, belum dijalankan
   ulang dari nol; yang terbukti adalah 34 pin manifest cocok dengan environment berjalan
   dan bootstrap DB bersih berhasil. **Frontend** clean install (`npm ci`) justru sudah
   dijalankan penuh dan sukses.
2. **Provider selain OpenRouter** (Anthropic/Gemini, dan Ollama asli) belum diuji dengan
   kredensial/model nyata, hanya jalur kode + stub.
3. **Kualitas analisis AI** belum diukur secara kuantitatif (presisi/recall).
4. **CI belum pernah berjalan di GitHub** (repo tanpa remote), verifikasi bersifat lokal;
   konfigurasi workflow hanya diuji secara statis oleh `test_ci_config.py`.
5. **`make` tidak tersedia** di mesin ini (target Makefile dijalankan manual dengan perintah
   identik).
6. **Rate limiting** endpoint mahal (`/api/analyze`, upload) belum ada.
7. **Frontend unit-test runner** tidak ada (sengaja, tanpa dependency tambahan).
8. **Pemindaian PII screenshot** hanya mencakup nama file + sidecar, bukan piksel.

---

## 9. Kesimpulan

Source release `release/sentinelgraph-ai.zip` (1,92 MB, 109 entri, sha256 `989d26cc…`)
adalah hasil validasi akhir yang konsisten:

- **Backend:** 311/311 passed, termasuk di dalam bundle rilis (sebelumnya 308/311).
- **E2E:** 22/22 PASS pada source yang diekstrak dari ZIP.
- **Frontend:** clean install + `tsc -b` + `vite build` sukses; dist ter-ship identik byte-for-byte.
- **PII:** 0 match pada DB sintetis, teks, demo, dan artefak screenshot.
- **Arsip:** 109 entri, 0 entri terlarang, tanpa DB runtime / credential / node_modules / venv / bytecode.

Tidak ada klaim yang dibuat melebihi bukti yang ada. Item yang belum dapat ditutup
dinyatakan eksplisit pada §8.
