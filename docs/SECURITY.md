# Model ancaman dan batasan keamanan

Dokumen ini menyatakan apa yang SentinelGraph AI **lindungi**, apa yang **tidak**, dan
sisa risiko yang harus diterima operator.

---

## 1. Asumsi lingkungan

SentinelGraph dijalankan di lingkungan **tertutup**:

- Server dijalankan pada workstation analis atau host lab, bukan internet terbuka.
- Data yang diimpor berasal dari lingkungan sendiri atau data sintetis.
- Pengguna yang bisa menjangkau port aplikasi dianggap terpercaya.

**Bila salah satu asumsi ini tidak berlaku, bagian 4 wajib dibaca sebelum deploy.**

## 2. Permukaan serangan yang diperhitungkan

| Permukaan | Ancaman | Mitigasi |
|---|---|---|
| Unggahan artifact | Payload raksasa, JSON dalam, field asing | Batas ukuran, validasi bentuk per record, hanya informasi yang diterima |
| Output LLM | Halusinasi, sitasi karangan, instruksi tersembunyi | Validasi skema + verifikasi setiap ID event + penandaan hipotesis |
| Konfigurasi provider | SSRF ke metadata cloud / layanan internal | Blokade alamat privat & link-local; pengecualian hanya untuk provider lokal |
| Penyimpanan kunci API | Kunci bocor dari database | Enkripsi Fernet; kunci utama dari `SG_MASTER_KEY` atau dibuat otomatis di `<data dir>/master.key` |
| Pesan error | Kebocoran kunci di log | `redact_secrets` sebelum persist |
| Konten yang dirender | XSS lewat nama host/file | React meng-escape; laporan HTML meng-escape semua nilai dinamis |

## 3. Yang TIDAK dilindungi

Dinyatakan terbuka, bukan disembunyikan:

1. **Tidak ada autentikasi maupun otorisasi.** Siapa pun yang bisa melakukan HTTP ke
   port aplikasi bisa membaca seluruh insiden dan mengubah status insiden.
2. **Tidak ada TLS.** Trafik HTTP polos. Bila diakses lewat jaringan, isi insiden
   dapat disadap.
3. **Tidak ada enkripsi at-rest untuk tabel event.** Hanya kunci provider yang
   dienkripsi.
4. **Tidak ada rate limiting** pada endpoint API.
5. **Tidak ada perlindungan terhadap pengguna berbahaya** (mis. analis internal yang
   menghapus audit log).
6. **Tidak ada isolasi antar proyek** di luar filter `project_id` pada query.

## 4. Syarat deploy yang aman

Bila aplikasi dipakai di luar demo:

1. Jalankan di belakang reverse proxy dengan TLS.
2. Tambahkan autentikasi (paling tidak HTTP Basic + IP allowlist) di lapisan proxy.
3. Batasi bind ke `127.0.0.1` bila hanya untuk workstation lokal.
4. Set `SG_MASTER_KEY` dan simpan di secret manager, bukan di shell history.
5. Jangan arahkan konektor langsung ke internet.

## 5. Risiko sisa yang diterima

| Risiko | Tingkat | Alasan diterima |
|---|---|---|
| Ringkasan AI bisa menyesatkan | **Tinggi** | Teks bebas tidak bisa diverifikasi mesin. Mitigasi: penanda eksplisit, dan deteksi tidak bergantung pada AI. |
| Rule engine bisa false positive | Sedang | Wajar untuk deteksi berbasis rule. Mitigasi: narasi menyatakan ketidakpastian, bukan menyimpulkan kompromi. |
| Dataset demo tidak representatif | Sedang | Data sintetis. Kemampuan deteksi pada data nyata belum diukur. |
| Heuristik pengelompokan insiden | Rendah–sedang | Dapat memisahkan atau menggabungkan insiden secara keliru. Ditandai sebagai heuristik di laporan. |
| Timestamp `assumed` menyesatkan urutan | Rendah | Ditandai eksplisit dan ditempatkan dengan penanda. |

## 6. Sikap terhadap klaim

Produk ini sengaja **tidak** mengklaim:

- Mendeteksi zero-day.
- Menetapkan bahwa suatu host terkompromi.
- Menetapkan bahwa data keluar dari jaringan.
- Bahwa AI menghasilkan analisis yang benar.

Yang diklaim hanya:

- Event tercatat dan bisa diperiksa ulang.
- Rule yang dijalankan bersifat deterministik dan dapat direproduksi.
- Setiap klaim yang membawa sitasi telah diperiksa terhadap database.
- Ketidakpastian dinyatakan, bukan disembunyikan.

## 7. Pelaporan kerentanan

Ini adalah prototipe hackathon. Temuan keamanan sebaiknya dilaporkan sebagai issue
dengan langkah reproduksi; jangan diuji pada instance yang memuat data pihak lain.

## 8. Mode single-analyst dan autentikasi (audit remediasi)

SentinelGraph adalah **alat single-analyst**, bukan layanan multi-tenant. Konsekuensi
keamanan yang diterima secara sadar:

- **Default localhost-only.** `serve` hanya bind ke `127.0.0.1`. Ini batas keamanan
  utama: tidak ada permukaan jaringan yang terekspos secara default.
- **Binding non-loopback butuh autentikasi.** Menjalankan `--host` non-loopback
  (mis. `0.0.0.0`) **gagal saat startup** kecuali `SG_AUTH_TOKEN` diset. Setelah diset,
  setiap `/api/*` (kecuali `/api/health`) wajib `Authorization: Bearer <token>`;
  perbandingan memakai `hmac.compare_digest` (constant-time).
- **CORS bukan autentikasi.** `SG_CORS_ORIGINS` hanya mengatur header browser; ia tidak
  memberi perlindungan apa pun terhadap klien non-browser. Jangan mengandalkannya.
- **Satu token bersama.** Belum ada RBAC, sesi, atau pemisahan hak per pengguna. Token
  bocor = akses penuh ke database investigasi. Rotasi dengan mengganti `SG_AUTH_TOKEN`.
- **Data tetap teks-jelas di SQLite lokal** kecuali kunci provider (dienkripsi dengan
  kunci utama: `SG_MASTER_KEY` atau `<data dir>/master.key`). Lindungi berkas `data/`
  dan berkas kunci itu dengan izin filesystem.

## 9. Kontrol teknis yang diverifikasi

| Kontrol | Implementasi | Regression test |
|---|---|---|
| SSRF: normalisasi IPv4-mapped IPv6 / 6to4 / Teredo, `is_global` | `security.py` | `test_security.py::test_ssrf_blocks_internal_addresses` |
| SSRF: pinned address (anti DNS-rebinding) | `security.PinnedHTTPTransport` | `test_ssrf_dns_rebinding_pins_the_verified_address`, `test_ssrf_transport_refuses_host_change` |
| Upload memory exhaustion | `api._read_upload_bounded` | `test_upload_limits.py` |
| Binding guard + Bearer auth | `config.enforce_secure_binding`, `api._require_auth` | `test_deployment.py` |
| Attack graph fit-to-view | `AttackGraph.fitView` (+ zoom-to-fit) | diverifikasi di browser (outOfView=0) |
| CORS mengizinkan `Authorization` | `CORSMiddleware(allow_headers=[..., "Authorization"])` | `test_auth.py::test_preflight_advertises_authorization_header` |
| OPTIONS preflight tidak diblokir auth | `api._require_auth` melewati `OPTIONS` sebelum cek token | `test_auth.py::test_preflight_is_not_blocked_by_auth` |
| OPTIONS bukan jalur data | preflight dijawab `CORSMiddleware`, tanpa body | `test_auth.py::test_options_returns_no_data_body` |
| Token Bearer di semua request GUI | `frontend/src/auth.ts` (sessionStorage, bukan localStorage) | `test_auth.py` (semua endpoint sensitif) |
| Race pembuatan default project | `api._ensure_default_project` di dalam `db_lock()` + `ON CONFLICT DO NOTHING` | `test_concurrency.py` (20 thread x 20 iterasi) |
| SSRF: NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`) | `security._embedded_ipv4_addresses` + tolak prefix transisi | `test_ssrf_hardening.py::test_transition_mechanisms_are_blocked` |
| SSRF: Teredo server **dan** client divalidasi | `security._embedded_ipv4_addresses` | `test_ssrf_hardening.py::test_teredo_private_server_public_client_is_blocked` |
| Batas body request di level ASGI | `bodylimit.BodyLimitMiddleware` (Content-Length + guard streaming) | `test_bodylimit.py` (JSON, multipart, chunked) |

## 10. Batas ukuran yang berlaku

| Variabel | Default | Arti |
|---|---|---|
| `SG_MAX_UPLOAD_BYTES` | `33554432` (32 MiB) | Ukuran **payload** file/teks yang diterima endpoint ingest. |
| `SG_MAX_REQUEST_BYTES` | `SG_MAX_UPLOAD_BYTES + 65536` | Batas **seluruh body HTTP**, ditegakkan di ASGI sebelum parser apa pun berjalan. |

Keduanya berbeda dengan sengaja: batas payload menjaga ukuran file, sedangkan batas
request menyediakan ruang untuk boundary multipart dan framing JSON. Konsekuensinya
file berukuran tepat `SG_MAX_UPLOAD_BYTES` tetap diterima, sementara body yang lebih
besar dari `SG_MAX_REQUEST_BYTES` ditolak `413` sebelum masuk ke disk atau parser —
termasuk saat klien memakai `Transfer-Encoding: chunked` tanpa `Content-Length`.
