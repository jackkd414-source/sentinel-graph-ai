# Menjalankan SentinelGraph AI untuk juri

Tujuan: juri bisa membuka satu URL dan memakai produknya langsung, bukan melihat
tangkapan layar.

## Kenapa bukan GitHub Pages atau Vercel

Aplikasi ini satu proses Python yang hidup terus, dengan SQLite yang harus bisa
ditulis, plus direktori artifact dan master key.

- **GitHub Pages** hanya menyajikan berkas statis. Tidak ada Python, jadi tidak ada
  API, analisis, atau laporan.
- **Vercel** menjalankan fungsi serverless berumur pendek dengan filesystem yang
  tidak persisten. Database dan data demo yang dimuat hilang di antara request.

Dua-duanya gagal tepat di titik yang paling penting: juri menelusuri satu
investigasi dari awal sampai akhir. Karena itu runtime-nya harus tempat yang
menjalankan proses lama dengan disk yang bertahan: VPS, atau PaaS berbasis
container (Render, Railway, Fly.io).

GitHub tetap dipakai, tapi sebagai tempat kode dan bahan submission, bukan runtime.

## Satu image, satu port

Server menyajikan SPA dan API dari port yang sama (`frontend/dist` disajikan
FastAPI), jadi tidak perlu memisahkan frontend dan backend.

```bash
docker build -t sentinelgraph-ai .

docker run -d --name sentinelgraph \
  -p 8088:8088 \
  -e SG_AUTH_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  -v sg-data:/data \
  sentinelgraph-ai
```

Atau lewat Compose:

```bash
export SG_AUTH_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
docker compose up -d --build
```

## Yang perlu diterima juri

Dua hal saja:

1. URL, misalnya `https://sg.namadomain.com`
2. Token Bearer dari `SG_AUTH_TOKEN`

Juri membuka URL, aplikasi meminta token, mereka menempelkannya, lalu bisa memakai
semuanya. SPA sudah punya input token dan mengirim header `Authorization` pada
setiap request, termasuk unduhan laporan.

Token wajib. Server sengaja menolak bind ke alamat non-loopback kalau
`SG_AUTH_TOKEN` kosong, dan tiap `/api/*` kecuali `/api/health` menuntut header itu.
CORS bukan autentikasi. Rinciannya di `docs/SECURITY.md`.

## Yang tersimpan di volume

Database SQLite, direktori artifact, dan master key yang dibuat otomatis saat
pertama dijalankan. Semua di bawah `/data`, jadi satu volume menjaga keadaan
deployment tetap utuh setelah restart. Jangan pakai volume itu untuk pengembangan
lokal; data lokal Anda terpisah.

## Data yang tidak ikut ke image

`.dockerignore` mengeluarkan `data/`, `logs/`, `backup/`, `release/`, dan tiga
ekspor telemetri di root repo (`sysmon.json`, `security.json`, `firewall.json`).
Tiga berkas terakhir itu log mesin asli dan tidak dipakai aplikasi.

Dataset demo tidak perlu dikirim sebagai berkas: `demo_data.py` membuatnya di dalam
kode, dan `POST /api/demo/load` memuatnya. Juri bisa mereset kapan saja.

## Provider AI

Provider dikonfigurasi lewat UI dan disimpan terenkripsi di database. Tidak ada
variabel lingkungan untuk itu.

Kalau tidak ada provider, bagian deterministik tetap jalan penuh: event, alert,
insiden, graf, evidence guard pada laporan. Yang tidak bisa dijalankan juri adalah
analisis AI-nya.

Kalau ingin juri bisa menjalankan analisis AI sendiri, ada dua pilihan:

- Taruh key provider cloud di server lewat UI. Hanya pemegang token yang bisa
  memakainya, tapi biayanya ditanggung Anda.
- Jalankan Ollama di host yang sama, lalu daftarkan provider `ollama` mengarah ke
  `http://127.0.0.1:11434`. Lebih berat, tapi tidak ada biaya per panggilan.

## Catatan penting sebelum dibilang live

- Aplikasi ini dikembangkan dan diverifikasi di Windows. README mencatat Linux
  belum diverifikasi dari nol. Dependensinya semua punya wheel Linux dan tidak ada
  kode khusus Windows, tapi deployment Linux pertama tetap harus diuji, bukan
  diasumsikan.
- Letakkan di belakang reverse proxy dengan HTTPS kalau memakai domain. Token
  Bearer lewat HTTP polos bisa disadap.
- Set `SG_CORS_ORIGINS` hanya kalau frontend dan API benar-benar berbeda origin.
  Pada deployment satu image ini tidak perlu.
