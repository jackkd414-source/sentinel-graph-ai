# AI Providers, konfigurasi, keamanan, dan batasan

SentinelGraph berjalan **tanpa AI** untuk semua fungsi inti (deteksi, korelasi, graph,
timeline, report). AI hanya menambah analisis naratif, dan setiap klaim AI harus
merujuk bukti yang ada di database.

## Provider yang didukung

| Tipe | Base URL default | Kredensial |
|---|---|---|
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` / disimpan terenkripsi |
| `anthropic` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` |
| `gemini` | Google Generative Language | `GEMINI_API_KEY` |
| `openrouter` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` |
| `ollama` | `http://127.0.0.1:11434` | tanpa key (lokal) |
| `custom_openai` | diisi pengguna | key opsional, validasi SSRF ketat |

## Keamanan kredensial

- API key **tidak pernah** dikembalikan ke frontend; API mengembalikan status
  `has_key`/masker, bukan nilai.
- Di DB, key selalu dienkripsi (Fernet) sebelum disimpan. Kunci utama dari
  `SG_MASTER_KEY`, atau dibuat otomatis di `<data dir>/master.key` saat pertama
  dipakai, tidak pernah plaintext.
- Tidak ada key di log. `redact_secrets()` menyamarkan nilai yang mirip kredensial
  pada pesan error.
- Tidak ada fallback berbayar otomatis ke provider lain.

## SSRF dan endpoint custom

Endpoint `custom_openai` / base URL divalidasi sebelum dipakai:

- semua hasil DNS dinormalisasi (IPv4-mapped IPv6, 6to4, Teredo) dan harus `is_global`;
- private/loopback/link-local/reserved/unspecified/multicast ditolak;
- alamat terverifikasi **di-pin** pada koneksi (anti DNS-rebinding);
- redirect tidak diikuti (`follow_redirects=False`);
- pengecualian loopback hanya untuk `ollama`.

`allow_private` **tidak** membuka alamat privat untuk provider cloud; ia hanya
mengizinkan Ollama di loopback.

## Test Connection

`POST /api/ai/providers/{id}/test` dan `POST /api/ai/test-unsaved` memanggil provider
dengan prompt minimal dan mengembalikan status. Kesalahan autentikasi/kuota/model
dipetakan ke pesan yang jelas tanpa membocorkan nilai key.

## Data yang dikirim ke AI

Hanya data yang dibutuhkan untuk analisis insiden yang dipilih, bukan seluruh
database. Setiap hasil analisis menyimpan referensi `evidence_event_ids`; sitasi
yang tidak ada di DB ditandai `unsupported` dan tidak masuk laporan sebagai fakta.

## Uji tanpa API key

Test memakai provider mock (`backend/tests/test_ai.py`, fixture `fake_provider`) -
tidak memerlukan kredensial dan tidak mengirim request keluar.

Untuk demo manual Evidence Guard tanpa kredensial, jalankan
`tools/adversarial_provider.py`. Endpoint lokal itu menjawab lewat protokol Ollama
dan sengaja mengarang enam referensi event. Daftarkan provider tipe `ollama` ke
`http://127.0.0.1:11434`, lalu jalankan analisis: hipotesis yang bersitasi palsu
ditandai `unsupported`, jumlah referensi yang dibuang muncul di laporan.
Ollama satu-satunya tipe provider yang boleh memakai alamat loopback, karena itu
tool ini berbicara protokol Ollama, bukan OpenAI.

## Batas token (max_tokens), penyebab umum "AI analysis gagal"

Model reasoning (mis. keluarga deepseek/`-flash`) memakai sebagian budget token untuk
**hidden reasoning** sebelum menulis jawaban. Kalau `max_tokens` terlalu kecil, balasan
terpotong di tengah JSON dan analisis dibuang.

Gejala lama yang menyesatkan: `validation_failed / Response contained no JSON object`.
Sejak perbaikan, kondisi ini dilaporkan jujur sebagai:

```
output_truncated: openrouter stopped at the 2048-token ceiling (2048 completion
tokens, 900 spent on hidden reasoning); the reply is incomplete and was discarded.
```

Aturan praktis: **jangan di bawah 4096**, gunakan 8192 untuk model reasoning.
Ubah lewat UI AI Providers atau:

```bash
curl -X PATCH http://127.0.0.1:8088/api/ai/providers/<id> \
     -H "Content-Type: application/json" -d '{"max_output_tokens": 8192}'
```

Perilaku ini diverifikasi untuk keempat adapter (OpenAI-compatible, Anthropic, Gemini,
Ollama) oleh `test_partial_output_at_token_ceiling_reports_truncation`.

## Timeout klien, "Request timed out" pada insiden besar

Insiden dengan banyak event menghasilkan prompt besar; dengan `max_tokens` tinggi,
generasi bisa melewati batas waktu klien. Sebelum perbaikan pesannya hanya
`Request timed out. (timeout)`, tidak memberi tahu apa yang harus diubah.

Sekarang pesannya menyebut anggaran dan jalan keluarnya:

```
timeout: openrouter did not answer within the 180s client timeout; generation was
aborted. Reasoning models answering a large max_tokens budget need longer - raise
the timeout for this provider (or lower max tokens) and retry.
```

Panduan: `timeout_s` default kini **120 s**. Untuk model reasoning dengan
`max_output_tokens` 8192 pada insiden 50+ event, gunakan **180 s**.

```bash
curl -X PATCH http://127.0.0.1:8088/api/ai/providers/<id> \
     -H "Content-Type: application/json" -d '{"timeout_s": 180}'
```

## Report AI-assisted (narrative opsional)

`POST /api/incidents/{id}/report?use_ai=true` (dan GET yang sama untuk unduhan)
menambahkan **satu bagian narrative** yang ditulis model di atas laporan
deterministik.

- Model hanya menerima fakta yang sudah ada di database (ringkasan mesin, temuan,
  event bukti, relasi graf). Prompt melarang mengarang host/user/IP/hash/timestamp.
- Keluarannya dibingkai dan diberi label **hipotesis, bukan bukti**, diikuti catatan
  bahwa bagian deterministik tetap menjadi laporan resmi.
- Tanpa provider aktif: laporan deterministik tetap utuh, `ai.status = "no_provider"`.
- Bila provider gagal: `ai.status = "error"` (+ kategori, pesan ter-redaksi) dan
  laporan deterministik tetap dikembalikan, tidak ada bagian AI palsu.
- Setiap percobaan dicatat di tabel `ai_runs` dengan `task = "report"`.
- Di UI: halaman **Reports** punya toggle **Narrative → AI-assisted**.

## Lokasi kunci enkripsi

Kunci utama untuk enkripsi API key di database diambil berurutan dari:

1. `SG_MASTER_KEY` (env / `.env`), disarankan.
2. Berkas `<data dir>/master.key`, dibuat otomatis saat pertama dipakai (izin
   owner-only). Lokasi bisa dipindah dengan `SG_MASTER_KEY_FILE`.

Halaman **AI Providers** menampilkan sumber kunci yang sedang dipakai. Cadangkan
berkas kunci itu: kehilangannya membuat API key tersimpan tidak bisa didekripsi.
