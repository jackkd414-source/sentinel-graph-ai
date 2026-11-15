# Setup, instalasi bersih SentinelGraph AI

Prasyarat: **Python >= 3.10** (diuji 3.11), **Node.js >= 18** + npm, git. Windows 10
atau Linux/macOS. Tidak ada binary native khusus OS.

## Cara cepat

Windows (PowerShell):

```powershell
scripts\setup.ps1     # venv + backend deps + frontend build
scripts\start.ps1     # http://127.0.0.1:8088
```

Linux / macOS / WSL:

```bash
bash scripts/setup.sh
bash scripts/start.sh
```

## Cara manual

```bash
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt  # Windows
# ./.venv/bin/python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt        # Linux

export PYTHONPATH=backend
./.venv/Scripts/python.exe -m sentinelgraph init        # buat schema kosong
./.venv/Scripts/python.exe -m sentinelgraph load-demo   # dataset sintetis

cd frontend && npm install && npm run build && cd ..
./.venv/Scripts/python.exe -m sentinelgraph serve --port 8088
```

## Konfigurasi environment

Salin `.env.example` → `.env` (jangan pernah commit `.env`). Variabel penting:

| Variabel | Default | Catatan |
|---|---|---|
| `SG_HOST` | `127.0.0.1` | non-loopback wajib `SG_AUTH_TOKEN` |
| `SG_PORT` | `8088` | |
| `SG_AUTH_TOKEN` | *(kosong)* | Bearer token untuk `/api/*` |
| `SG_DB_PATH` | `data/sentinelgraph.db` | jangan di-commit |
| `SG_MAX_UPLOAD_BYTES` | `33554432` | batas upload (32 MiB) |
| `SG_ARTIFACT_DIR` | `data/artifacts` | penyimpanan artefak |
| `SG_MASTER_KEY` | *(auto)* | kunci enkripsi API key provider; bila kosong dibuat otomatis di `<data dir>/master.key` |
| `SG_CORS_ORIGINS` | dev vite | **bukan** autentikasi |

## Bootstrap database

- Instalasi baru: `python -m sentinelgraph init` lalu `load-demo` (dataset sintetis).
- Reset total: `POST /api/data/reset` (atau hapus `data/sentinelgraph.db` saat server mati).
- DB rilis bersih: `python tools/make_release.py`.

## Shutdown

Tekan `Ctrl+C` di terminal server. Tidak ada daemon/background service.

## Troubleshooting

| Gejala | Penyebab | Solusi |
|---|---|---|
| `Refusing to bind ... non-loopback host` | `--host 0.0.0.0` tanpa token | set `SG_AUTH_TOKEN`, atau pakai `127.0.0.1` |
| `401 Unauthorized` di semua `/api` | `SG_AUTH_TOKEN` aktif | kirim `Authorization: Bearer <token>` |
| Halaman kosong / 404 di `/` | `frontend/dist` belum dibangun | `cd frontend && npm run build` |
| `ModuleNotFoundError: sentinelgraph` | `PYTHONPATH` belum diset | `export PYTHONPATH=backend` |
| Import file ditolak `413` | melebihi `SG_MAX_UPLOAD_BYTES` | naikkan batas atau pecah file |
| Provider "core only" | belum ada provider aktif | lihat `docs/AI_PROVIDERS.md` |
| Provider: "credential unreadable / master key changed" | `SG_MASTER_KEY` berbeda dari saat key disimpan | set `SG_MASTER_KEY` permanen di `.env`, lalu masukkan ulang API key sekali. Start script menyimpan kunci di `data/.master_key` agar stabil. |

Lihat juga: `README.md`, `docs/SECURITY.md`, `docs/DATA_MANAGEMENT.md`, `docs/SYSMON.md`.
