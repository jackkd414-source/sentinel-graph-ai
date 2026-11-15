# REMEDIATION_PROGRESS

Log audit remediasi SentinelGraph AI. Setiap baris = temuan, perubahan, test, status,
dan bukti nyata. Diperbarui 2026-11-14.

## Ringkasan status

| Prioritas | Item | Status |
|---|---|---|
| P0 | Repository hygiene (`.gitignore`, exclude runtime/telemetry) | DONE |
| P0 | Audit PII file demo & screenshot | DONE (2 kebocoran teks diperbaiki) |
| P0 | Release packaging bersih + bootstrap DB sintetis | DONE |
| P0 | Dependency manifest + dokumentasi instalasi | DONE |
| P1 | SSRF IPv4-mapped IPv6 + DNS rebinding + redirect | DONE |
| P1 | Upload memory exhaustion (bounded chunked read) | DONE |
| P1 | API authentication + deployment safety | DONE |
| P1 | Attack graph auto-fit / grouping / filter / navigasi | DONE |
| P2 | Regression suite, build, E2E, release, docs | DONE |
| — | Clean install lintas-OS dari nol | BLOCKED (tanpa jaringan) |
| — | Regenerasi screenshot attack graph | DONE (8 PNG, 14 Nov 2026) |

## Temuan → perubahan → test

| # | Temuan | Perubahan | Test | Bukti |
|---|---|---|---|---|
| 1 | IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`) lolos SSRF | Normalisasi mapped/6to4/Teredo + `is_global` di `security.py` | `test_ssrf_blocks_internal_addresses` (14 URL) | 311 passed |
| 2 | DNS rebinding: alamat divalidasi ≠ alamat dipakai | `PinnedHTTPTransport` + `_rewrite_to_pinned` (Host+SNI, tolak host berubah) | `test_ssrf_dns_rebinding_pins_the_verified_address`, `test_ssrf_transport_refuses_host_change` | pass |
| 3 | Redirect ke tujuan tak tervalidasi | `follow_redirects=False` di client ter-pin | `test_ssrf_redirect.py` (metadata/localhost/private) | pass |
| 4 | Ollama exception terlalu luas | Hanya loopback + provider `ollama` | `test_ssrf_ollama_exception_is_loopback_only` | pass |
| 5 | Upload baca seluruh file sebelum cek ukuran | `_read_upload_bounded` chunk 64 KiB, stop di batas, tutup file, tanpa artefak | `test_upload_limits.py` (10 kasus) | pass |
| 6 | `/api/ingest/text` tanpa batas eksplisit | Cek `len(utf8) > SG_MAX_UPLOAD_BYTES` → 413 | `test_ingest_text_rejects_oversized_body` | pass |
| 7 | API tanpa autentikasi | `SG_AUTH_TOKEN` + middleware Bearer (`hmac.compare_digest`), `/api/health` exempt | `test_deployment.py` (13 endpoint + mode) | pass |
| 8 | Binding non-loopback tanpa auth | `enforce_secure_binding` di CLI + startup | `test_cli_serve_refuses_external_bind_without_token` | pass |
| 9 | Attack graph keluar viewport | bbox auto-fit, ⤢ zoom-to-fit, center, cap 320 + grouping, filter incident & relasi, node→evidence | pengukuran browser | outOfView=0 |
| 10 | Tool memuat hostname/user asli | Sanitasi `export-windows-logs.ps1`; `check_pii_db.py` deteksi runtime | `make_release` gate | 0 match |
| 11 | DB/telemetri bisa ikut terkemas | `tools/make_release.py` exclude + bootstrap + PII gate | `make_release.py` | RELEASE OK |
| 12 | Manifest dependency tidak lengkap | `backend/requirements.txt` (29 pin) + dev; root delegasi | cocokkan 29 pin vs `importlib.metadata` | 0 mismatch |

## Bukti eksekusi (final)

```
pytest backend/tests -q .......... 311 passed, 3 warnings in 28.24s   (exit 0)
tsc -b (node tsc) ................ exit 0
vite build ....................... exit 0  (dist/assets/index-*.js 239.19 kB, css 9.24 kB)
tools/verify.py --skip-ai ........ 22/22 checks passed · VERDICT: PASS (exit 0)
tools/make_release.py ............ RELEASE OK - PII 0 match - 108 file, 1.92 MB, 0 artefak terlarang (exit 0)
check_pii_db.py (DB aktif nyata) .. TOTAL PII ROW-MATCHES: 17791  ← membuktikan detektor bekerja
```

Baseline audit sebelumnya: 148 passed -> sekarang 311 passed (+163 test, +23 pada turn ini).

## Verifikasi attack graph (pengukuran di browser, bukan klaim visual)

| Skenario | Node dirender | outOfView | scale |
|---|---|---|---|
| Default demo (52 node, event disembunyikan) | 30 | 0 | 0.826 |
| Setelah cari `WS-FIN-07` (subgraf) | 14 | 0 | 0.826 |
| Dataset besar 219 node / 387 edge | 195 (24 digroup) | 0 | 0.446 |
| Filter incident INC-0001 | 8 | 0 | 0.826 |
| Filter relasi `resolved` dimatikan | — | — | edge 344 → 301 |
| Pencarian tanpa hasil | 0 | — | empty state tampil |

viewBox tetap 960×680; `nodeBox` selalu di dalamnya (mis. 203–757 × 63–617).

## Temuan saat menjalankan di data nyata (bukan dataset demo)

Dijalankan pada DB instalasi aktif: 9.147 event, 2.884 node / 2.882 edge. Tiga bug
hanya muncul pada skala ini dan tidak terlihat di dataset demo 52 node.

| # | Gejala terukur | Akar masalah | Perbaikan | Setelah |
|---|---|---|---|---|
| 13 | 642 dari 740 node di luar viewport, `scale` mentok 0.12 | auto-fit memakai `K_MIN` (batas zoom manual) sehingga tidak boleh mengecil | `K_FIT_MIN=0.03` khusus fit | outOfView **0**, scale 0.072 |
| 14 | 740 node dirender padahal cap 320 | cap dihitung **per tipe**, bukan total | cap global 320 + agregat | 326 node (320+6 grup) |
| 15 | `scripts/start.ps1` gagal: "Cannot overwrite variable Host" | `$Host` variabel otomatis PowerShell (read-only) | param `$BindHost` | start berhasil |
| 16 | `credential_hint: (unreadable - master key changed?)` | start script membuat `SG_MASTER_KEY` acak tiap run | key dipersistenkan: `.env` → `data/.master_key` → generate sekali | fingerprint stabil `07be9a5e…` lintas restart |
| 17 | `test_concurrent_analyze_does_not_corrupt_graph` gagal intermiten: `DatabaseError('not an error')` | 13 pembacaan memakai `get_conn().execute()` **tanpa** `_lock` padahal koneksi dibagi seluruh proses | helper `fetchone()`/`fetchall()` terkunci di `db.py`; semua situs dialihkan (api, detection, provider_store) | 6 run `test_api.py` + 3 run suite penuh: 0 gagal |
| 18 | Legend attack graph terpotong di bawah viewport (panel 735px vs viewport 568px) | grid container hanya `grid-template-columns`, baris `auto` → tinggi SVG mengikuti rasio viewBox (1038×680/960 = 735) | `gridTemplateRows: minmax(0,1fr)` + `minHeight:0` (App & IncidentView); legend `maxHeight` + `overflowY:auto` | panel 429px (bottom 568), legend & 7 chip RELATIONS terlihat penuh |
| 19 | AI analysis gagal: `validation_failed — Response contained no JSON object` | `max_output_tokens=2048`; model reasoning menghabiskan budget → `finish_reason=length`, JSON terpotong. Kasus "length dengan teks" tidak ditangani sehingga salah diklasifikasi sebagai schema error | guard `_guard_truncation()` di 4 adapter (openai-like/anthropic/gemini/ollama) → kategori `output_truncated` + pesan actionable; batas provider dinaikkan ke 8192 | analisis INC-146 `status: ok` (ringkasan + timeline + evidence refs); 4 test parametrik baru; suite 212 passed |
| 20 | AI analysis gagal lagi: `Request timed out. (timeout)` pada INC-0002 (50 event) | setelah `max_tokens` 8192, generasi insiden besar melewati `timeout_s=60`; pesan error tidak menyebut budget maupun solusi | `_net_error(exc, spec)` menyebut `timeout_s` + saran (naikkan timeout / turunkan max tokens); `REQUEST_TIMEOUT_DEFAULT` 60→120; provider aktif `timeout_s=180` | analisis INC-147 `status: ok` 16.7 s; 1 test regresi baru (31 test di `test_ai.py`) |

Konsekuensi #16: API key provider yang tersimpan **sebelum** perbaikan tidak dapat
didekripsi lagi (kunci lamanya tidak diketahui). Perlu dimasukkan ulang sekali lewat
UI/`POST /api/ai/providers`; setelah itu kunci stabil.

## Perubahan file

Modified: `.gitignore`, `.env.example`, `README.md`, `requirements*.txt`,
`backend/sentinelgraph/{security,ai_providers,api,config,__main__}.py`,
`backend/tests/{test_ai,test_security}.py`, `docs/{SECURITY,DATA_MANAGEMENT}.md`,
`frontend/src/App.tsx`, `frontend/src/components/AttackGraph.tsx`,
`tools/export-windows-logs.ps1`.

Added: `backend/requirements{,-dev}.txt`, `backend/tests/{test_deployment,test_ssrf_redirect,test_upload_limits}.py`,
`tools/{check_pii_db,make_release}.py`, `scripts/{setup,start}.{ps1,sh}`,
`docs/{SETUP,TESTING,AI_PROVIDERS,DEMO_GUIDE,LIMITATIONS}.md`.

## Backup

`backup/source-20261111-232051.tar.gz` (source) dan
`backup/sentinelgraph-real-20261111-232051.db` (DB runtime asli 18,7 MB).
Direktori `backup/` masuk `.gitignore` dan tidak ikut release.

## Belum selesai / blocker

1. **Clean install lintas-OS dari nol** — tidak bisa `pip install` di lingkungan baru
   karena jaringan/pip diblokir. Yang terbukti: 29 pin cocok dengan environment berjalan
   + bootstrap DB bersih berhasil. Klaim "teruji Linux" **tidak** dibuat.
2. **Screenshot `03_attack_graph.png`** — sudah diregenerasi 14 Nov 2026 (Playwright 1.65.1
   + Chromium headless). Fitur fit-to-view dibuktikan lewat pengukuran dan PNG.
3. **Live AI provider** — hanya mock; tidak ada verifikasi kredensial nyata.
