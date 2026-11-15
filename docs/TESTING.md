# Testing — cara menjalankan dan apa artinya

## Perintah kanonik

```bash
# Windows (dari root repo) - tidak perlu export PYTHONPATH; pyproject.toml mengatur pythonpath
.venv\Scripts\python.exe -m pytest

# Linux / macOS
.venv/bin/python -m pytest
```

Pintu masuk tunggal untuk semua pemeriksaan (test + typecheck + release gate):

```powershell
scripts\verify.ps1          # Windows  -> "VERIFY: PASS"
bash scripts/verify.sh      # Linux/macOS
```

`Makefile` menyediakan target setara (`make test|typecheck|build|verify|release`)
bila `make` tersedia.

## Suite backend

Mencakup: ingest/normalisasi, rule engine R-001..R-006, korelasi, graph, evidence,
reporting, provider adapter (mock), SSRF, upload, auth/deployment.

Status terkini (2026-11-14): **311 passed, 1 warning** (`python -m pytest`). Satu warning
berasal dari `starlette.testclient` (httpx deprecated) — bukan kegagalan. Suite ini juga
memuat `test_ci_config.py`, yang memverifikasi `.github/workflows/verify.yml`; workflow
tersebut ikut dikemas di rilis (hanya file itu, bukan seluruh `.github`) agar test ini
lulus juga di dalam bundle (311/311).

File test keamanan yang penting:

| File | Isi |
|---|---|
| `test_security.py` | SSRF (normalisasi alamat, DNS, rebinding, redirect), redaksi kredensial |
| `test_ssrf_redirect.py` | redirect 302 tidak diikuti (localhost/private/metadata) |
| `test_upload_limits.py` | batas chunked upload, encoding, artefak parsial |
| `test_deployment.py` | binding guard + Bearer auth per-endpoint |

## Frontend

```bash
cd frontend
node ./node_modules/typescript/bin/tsc -b     # type-check
npm run build                                  # tsc + vite build
```

Tidak ada runner unit-test frontend di repo ini (tidak menambah dependency). Perilaku
graph diverifikasi lewat pengukuran di browser: jumlah node, `scale`, dan `outOfView`
(lihat `REMEDIATION_REPORT.md`).

## End-to-end

```bash
# server harus berjalan pada DB sintetis
./.venv/Scripts/python.exe tools/verify.py --base http://127.0.0.1:8088 --skip-ai
```

`--skip-ai` melewati cek provider (tanpa kredensial). Exit code = verdict.

## Release hygiene

```bash
./.venv/Scripts/python.exe tools/make_release.py
```

Membangun `release/sentinelgraph-ai`, membootstrap DB sintetis dari fixture, lalu:

1. menolak `.db`/telemetry/`.env` yang lolos ke tree rilis;
2. menjalankan `tools/check_pii_db.py` pada DB sintetis (harus `0` match);
3. memindai **seluruh file teks** rilis (docs, source, dataset demo) untuk marker PII;
4. memindai nama file dan sidecar screenshot;
5. membuat `release/sentinelgraph-ai.zip` lalu memverifikasi isi arsip.

Pengecualian pemindaian hanya berlaku lewat anotasi eksplisit `PII-SCAN-ALLOW` pada
baris yang bersangkutan, sehingga setiap pengecualian auditabel di source.

Catatan jujur: piksel PNG tidak dapat dipindai sebagai teks. Screenshot diverifikasi
lewat nama file dan sidecar `.txt`; pemeriksaan visual tetap manual.

## Aturan

- Jangan menonaktifkan/menghapus test untuk membuat hasil hijau.
- Test jaringan memakai mock atau server lokal terkontrol; tidak ada request ke
  alamat sensitif sungguhan.
- Selalu bedakan "suite hijau" dari "verifikasi ad-hoc" saat melaporkan.
