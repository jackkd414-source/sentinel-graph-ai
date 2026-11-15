# Limitations — batasan yang diakui

Dokumen ini jujur tentang apa yang **belum** dilakukan. Jangan menutupi batasan ini
saat presentasi.

## Keamanan

- **Autentikasi single-analyst.** Satu shared-secret (`SG_AUTH_TOKEN`), bukan
  multi-user/RBAC. Tidak ada sesi, audit per-pengguna, atau pemisahan hak baca/tulis.
- **Default tanpa TLS.** Aplikasi tidak menangani TLS sendiri. Untuk akses jaringan,
  taruh di belakang reverse proxy TLS.
- **Data lokal teks-jelas.** SQLite tidak dienkripsi; hanya API key provider yang
  dienkripsi (bila `SG_MASTER_KEY` diset). Lindungi izin filesystem `data/`.
- **SSRF:** validasi berbasis DNS + koneksi ter-pin. Tidak ada allowlist host provider
  keras; kebijakan berbasis "alamat harus global". Egress network policy di level OS
  tetap disarankan.
- **Rate limiting** belum ada pada endpoint mahal (`/api/analyze`, upload).

## Fungsi

- **AI opsional.** Tanpa provider, analisis naratif tidak tersedia; deteksi, korelasi,
  graph, timeline, report tetap berjalan.
- **Deteksi berbasis rule** (R-001..R-006) — bukan ML; bisa false positive/negative.
- **Dataset demo sintetis** — bukan bukti kemampuan pada data nyata.
- **Timeline** bergantung pada kualitas timestamp sumber; event dengan timestamp
  meragukan ditandai `ts_status`.

## Cakupan deteksi

- **Belum ada dukungan protokol OT** (Modbus, DNP3, IEC-61850, OPC-UA) maupun ingest
  langsung dari perangkat industri. Deteksi saat ini bekerja pada log IT/Sysmon/EDR.
  Taktik yang khas lingkungan OT karena itu belum tercakup.
- **Pemetaan ATT&CK bersifat deskriptif, bukan klaim cakupan.** Yang dipetakan hanya
  rule deterministik R-001..R-005; R-006 (lonjakan volume) sengaja tidak dipetakan
  karena merupakan deviasi statistik. Rinciannya di `docs/ATTACK_MAPPING.md`.
- **Analisis AI tidak dipetakan ke ATT&CK** — outputnya interpretasi, bukan deteksi,
  dan setiap klaimnya tetap harus menunjuk event ID yang terverifikasi.

## Skala

- **Attack graph** menangani ratusan node dengan cap + grouping. Untuk >2000 node belum
  ada clustering semantik (lihat `README.md` §13).
- **SQLite** cukup untuk single-analyst; bukan untuk konkurensi tinggi.

## Pengujian

- **CI:** `.github/workflows/verify.yml` sudah ada dan memakai perintah yang sama dengan
  `scripts/verify.sh` (`pytest` + `npm run build`). Konfigurasinya sendiri diuji oleh `backend/tests/test_ci_config.py`
  (YAML valid, paritas perintah, versi Python 3.11). **Belum pernah dijalankan di GitHub**
  karena repo belum punya remote — verifikasi yang terbukti masih lokal:
  `pytest` (311 passed), `tsc -b`, `vite build`, `tools/verify.py`, `scripts/verify.ps1`.
  Workflow ini kini ikut dalam allowlist rilis (`tools/make_release.py`, hanya file ini
  yang dikemas — bukan seluruh `.github`), sehingga `test_ci_config.py` juga lulus di
  dalam bundle rilis (311/311).
- **Frontend tidak punya unit-test runner** (sengaja, tanpa dependency tambahan).
  Perilaku graph diverifikasi lewat pengukuran di browser (`outOfView`, `scale`).
- **Instalasi bersih lintas-OS belum diuji ulang dari nol di lingkungan tanpa jaringan.**
  Yang diverifikasi: 34 pin manifest (29 runtime + 5 dev) cocok dengan environment berjalan,
  dan bootstrap DB bersih berhasil (schema + 6 rule + 5 IOC ter-seed, lalu `tools/verify.py`
  22/22 PASS pada DB kosong itu). Klaim "teruji di Linux" tidak dibuat karena hanya Windows yang diuji.
- **Screenshot di `docs/screenshots/` diregenerasi 15 Nov 2026** dari build produksi
  redesign TRACEWORK (Chromium headless), pada data demo nyata. 14 PNG: dashboard,
  daftar insiden, investigasi insiden (overview, evidence, AI analysis, attack graph),
  attack graph global, events, evidence repository, detection rules, AI providers
  (+ form tambah provider), reports, settings, dan imports — semua diverifikasi visual.
- **Live AI provider sudah diverifikasi** dengan kredensial nyata (OpenRouter +
  `deepseek-v4.1-flash`): analisis insiden berstatus `ok` dengan ringkasan + timeline yang
  merujuk event ID. Yang belum diverifikasi: provider lain (Anthropic/Gemini/Ollama) hanya
  lewat mock, dan perilaku di bawah kredit/kuota habis tidak diuji.
- **Model reasoning butuh budget token lebih besar**: pada `max_tokens=2048` jawaban
  terpotong (`finish_reason=length`) dan dilaporkan sebagai `output_truncated`. Default
  yang dipakai sekarang 8192 token / 180 s timeout.
