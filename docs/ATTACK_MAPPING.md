# MITRE ATT&CK Mapping

Setiap rule deterministik dipetakan ke teknik ATT&CK yang benar-benar dijelaskan oleh
logikanya. Pemetaan disimpan sebagai kode (`backend/sentinelgraph/attack_map.py`) agar
nama dan taktik punya satu sumber kebenaran; tabel `rules` hanya menyimpan ID-nya.

Pemetaan tersedia di tiga tempat: `GET /api/rules` (field `attack`), halaman **Detection
Rules** di UI (chip teknik), dan bagian temuan pada laporan MD/HTML/JSON (`**ATT&CK:** ...`).

| Rule | Nama | Kategori | Teknik ATT&CK | Taktik |
|---|---|---|---|---|
| R-001 | Failed logon burst followed by success | credential_access | T1110.001 Brute Force: Password Guessing<br>T1078 Valid Accounts | Credential Access<br>Defense Evasion |
| R-002 | Suspicious child process after unusual parent | execution | T1566.001 Phishing: Spearphishing Attachment<br>T1204.002 User Execution: Malicious File<br>T1059.001 PowerShell | Initial Access<br>Execution<br>Execution |
| R-003 | Connection to known threat indicator | command_and_control | T1071.001 Application Layer Protocol: Web Protocols<br>T1105 Ingress Tool Transfer | Command and Control<br>Command and Control |
| R-004 | Sensitive file access followed by outbound transfer | collection_exfiltration | T1005 Data from Local System<br>T1041 Exfiltration Over C2 Channel | Collection<br>Exfiltration |
| R-005 | Cross-host activity in short window | lateral_movement | T1021 Remote Services<br>T1078 Valid Accounts | Lateral Movement<br>Defense Evasion |
| R-006 | Event volume spike on host | anomaly_baseline | — (tidak dipetakan) | — |

## Mengapa R-006 tidak dipetakan

Lonjakan volume event adalah **deviasi statistik terhadap baseline**, bukan perilaku
penyerang tertentu. Teknik ATT&CK yang relevan bergantung pada aktivitas yang tersembunyi
di dalam lonjakan itu (bisa T1110 brute force, bisa T1059 eksekusi masif, bisa noise
operasional). Memaksakan satu ID akan menyesatkan analis, jadi rule ini menyatakan
dirinya sebagai baseline anomali.

## Cakupan dan batasan

- Yang dipetakan adalah **rule deterministik** (R-001..R-006). Analisis AI tidak
  dipetakan ke ATT&CK karena outputnya adalah interpretasi, bukan deteksi — dan setiap
  klaimnya tetap harus merujuk event ID yang terverifikasi.
- Pemetaan ini deskriptif, bukan klaim cakupan: SentinelGraph tidak mendeteksi semua
  teknik dalam taktik di atas, hanya perilaku yang logikanya tertulis di katalog rule.
- Belum ada dukungan protokol OT (Modbus/DNP3/IEC-61850/OPC-UA), sehingga taktik yang
  khas lingkungan OT belum tercakup. Ini tercatat di `docs/LIMITATIONS.md`.

## Menjaga konsistensi

`backend/tests/test_attack_map.py` menegakkan empat hal:

1. setiap rule punya teknik **atau** alasan tertulis mengapa tidak ada;
2. setiap ID berformat `T####` / `T####.###` dan punya nama + taktik;
3. tidak ada teknik yatim di katalog (setiap ID dipakai minimal satu rule);
4. metadata benar-benar muncul di `/api/rules` dan di laporan yang diekspor.
