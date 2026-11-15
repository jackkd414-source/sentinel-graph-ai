/**
 * Bilingual UI (English / Indonesian).
 *
 * Why a DOM layer instead of a `t()` call on every string: the product has
 * ~450 user-visible strings across 15 components. Wrapping each one is noisy
 * and easy to miss. Instead we keep English as the single source of truth in
 * the components and translate the rendered tree through a MutationObserver.
 *
 * Properties that make this safe:
 *  - Unknown strings pass through untouched, so a missing entry degrades to
 *    English instead of showing a key or a blank.
 *  - MutationObserver callbacks are microtasks: they run before the browser
 *    paints, so a React re-render never flashes English before we translate.
 *  - Switching language remounts the app (see main.tsx), so English is restored
 *    by React itself — we never need to "un-translate" anything.
 */
import {
  createContext, useCallback, useContext, useEffect, useState, type ReactNode,
} from "react";

export type Lang = "en" | "id";

const LS_KEY = "sg.lang";

/** Literal UI strings. Keys are exactly what the components render. */
const ID: Record<string, string> = {
  // ---- shell / navigation ------------------------------------------------
  "Workspace": "Ruang Kerja",
  "Dashboard": "Dasbor",
  "Investigate": "Investigasi",
  "Incidents": "Insiden",
  "Attack Graph": "Graf Serangan",
  "Events": "Peristiwa",
  "Evidence": "Bukti",
  "Imports": "Impor",
  "Evidence Repository": "Repositori Bukti",
  "Engine": "Mesin",
  "Detection Rules": "Aturan Deteksi",
  "AI Providers": "Penyedia AI",
  "System": "Sistem",
  "Reports": "Laporan",
  "Settings": "Pengaturan",
  "Tutorial": "Tutorial",
  "Learn": "Pelajari",
  "System Healthy": "Sistem Sehat",
  "Backend unreachable": "Backend tidak terjangkau",
  "Connected": "Terhubung",
  "Global search": "Pencarian global",
  "Search events, incidents, or entities…": "Cari peristiwa, insiden, atau entitas…",
  "Session": "Sesi",
  "Alerts": "Peringatan",
  "Language": "Bahasa",
  "Primary": "Utama",
  "off": "mati",
  "on": "aktif",

  // ---- values that arrive from the API in lower case ---------------------
  "critical": "kritis",
  "high": "tinggi",
  "medium": "sedang",
  "low": "rendah",
  "advisory": "advisory",
  "open": "terbuka",
  "closed": "selesai",
  "investigating": "sedang diinvestigasi",
  "Title": "Judul",
  "Affected asset": "Aset terdampak",
  "Last activity": "Aktivitas terakhir",
  "Rule": "Aturan",
  "Inferred edges": "Sisi inferensi",
  "Event nodes": "Simpul peristiwa",
  "Go to Evidence Repository": "Buka Repositori Bukti",
  "Finding": "Temuan",
  // The graph footer is built from interpolations, so React emits these as
  // standalone literal fragments between the numbers.
  "nodes ·": "simpul ·",
  "edges · zoom": "sisi · zoom",
  "edges": "sisi",
  "observed relationship": "relasi teramati",
  "inferred (needs verification)": "inferensi (perlu verifikasi)",

  // ---- detection-rule catalogue (static strings seeded by the backend) ----
  "Failed logon burst followed by success": "Ledakan logon gagal lalu berhasil",
  "Suspicious child process after unusual parent": "Proses anak mencurigakan dari induk tak wajar",
  "Connection to known threat indicator": "Koneksi ke indikator ancaman yang diketahui",
  "Sensitive file access followed by outbound transfer": "Akses berkas sensitif lalu transfer keluar",
  "Cross-host activity in short window": "Aktivitas lintas host dalam jendela singkat",
  "Activity deviating from synthetic baseline": "Aktivitas menyimpang dari baseline sintetis",
  "credential_access": "akses kredensial",
  "execution": "eksekusi",
  "command_and_control": "command and control",
  "collection_exfiltration": "koleksi & eksfiltrasi",
  "lateral_movement": "pergerakan lateral",
  "anomaly": "anomali",
  "Detects N or more failed authentications for the same account/host inside a window, followed by a successful logon for that account.":
    "Mendeteksi N atau lebih autentikasi gagal untuk akun/host yang sama dalam satu jendela waktu, lalu diikuti logon yang berhasil untuk akun tersebut.",
  "A process is spawned by a parent process associated with document readers, script hosts, or email clients - a common phishing execution chain.":
    "Sebuah proses dijalankan oleh induk yang terkait pembaca dokumen, host skrip, atau klien email - rantai eksekusi phishing yang umum.",
  "Network event destination IP, domain, or URL matches an entry in the local threat-intelligence dataset.":
    "IP tujuan, domain, atau URL pada peristiwa jaringan cocok dengan entri di dataset intelijen ancaman lokal.",
  "A file access event on a sensitive path is followed within a short window by a large outbound transfer from the same host.":
    "Peristiwa akses berkas pada jalur sensitif diikuti dalam jendela singkat oleh transfer keluar berukuran besar dari host yang sama.",
  "The same user account authenticates to multiple distinct hosts inside a short window, which requires correlation across sources to be visible.":
    "Akun pengguna yang sama terautentikasi ke beberapa host berbeda dalam jendela singkat, yang baru terlihat melalui korelasi lintas sumber.",
  "Event volume for a host/time-of-day bucket exceeds the observed baseline mean by more than the configured factor. Baseline is derived from the loaded data only.":
    "Volume peristiwa untuk host/rentang jam melebihi rata-rata baseline teramati lebih dari faktor yang dikonfigurasi. Baseline hanya diturunkan dari data yang dimuat.",
  "Removes every imported event, alert, incident, graph node and artifact. Threat-intelligence indicators are kept.":
    "Menghapus semua peristiwa, peringatan, insiden, simpul graf, dan artefak yang diimpor. Indikator intelijen ancaman tetap disimpan.",
  "Removes every imported event, alert, incident, graph node, artifact AND the threat-intelligence indicators. The workspace becomes empty.":
    "Menghapus semua peristiwa, peringatan, insiden, simpul graf, artefak, DAN indikator intelijen ancaman yang diimpor. Ruang kerja menjadi kosong.",
  "Removes every imported event, alert, incident, graph node and artifact. Use this when you want a clean slate but keep your threat-intelligence indicators.":
    "Menghapus semua peristiwa, peringatan, insiden, simpul graf, dan artefak yang diimpor. Pakai ini bila ingin mulai bersih tetapi tetap menyimpan indikator intelijen ancaman.",

  // ---- dashboard ---------------------------------------------------------
  "Security overview": "Ikhtisar keamanan",
  "A clear view of events, investigations, and detection activity.":
    "Gambaran jelas atas peristiwa, investigasi, dan aktivitas deteksi.",
  "Last updated": "Terakhir diperbarui",
  "Refresh": "Muat ulang",
  "Load demo dataset": "Muat dataset demo",
  "Events normalized": "Peristiwa dinormalisasi",
  "Active alerts": "Peringatan aktif",
  "Affected assets": "Aset terdampak",
  "Recent incidents": "Insiden terbaru",
  "Detection posture": "Postur deteksi",
  "by alert severity": "berdasarkan tingkat peringatan",
  "System status": "Status sistem",
  "Detection engine": "Mesin deteksi",
  "Database": "Basis data",
  "Correlation engine": "Mesin korelasi",
  "Reports stored": "Laporan tersimpan",
  "Recent detections": "Deteksi terbaru",
  "every detection links to stored event IDs":
    "setiap deteksi tertaut ke ID peristiwa tersimpan",
  "No alerts on the current dataset.": "Tidak ada peringatan pada dataset saat ini.",
  "Nothing fired on the current dataset.": "Tidak ada yang terpicu pada dataset saat ini.",
  "No incidents yet": "Belum ada insiden",
  "No detections": "Tidak ada deteksi",
  "AI provider not configured": "Penyedia AI belum dikonfigurasi",
  "Core detection and investigation remain available without AI.":
    "Deteksi inti dan investigasi tetap tersedia tanpa AI.",
  "rule engine (deterministic)": "mesin aturan (deterministik)",
  "Total alerts": "Total peringatan",

  // ---- dashboard guide ---------------------------------------------------
  "Start here": "Mulai dari sini",
  "Where to go next": "Langkah selanjutnya",
  "Bring evidence in": "Masukkan bukti",
  "See what fired": "Lihat apa yang terpicu",
  "Write it up": "Susun laporan",
  "No data yet.": "Belum ada data.",
  "Next step:": "Langkah berikutnya:",
  "Nothing is waiting on you.": "Tidak ada yang menunggu Anda.",
  "Go to Imports": "Buka Impor",
  "What the words mean": "Arti istilah",
  "How this works": "Cara kerja",
  "Hide this guide (bring it back from Settings)":
    "Sembunyikan panduan ini (bisa dibuka lagi dari Pengaturan)",
  "SentinelGraph turns raw telemetry into an investigation you can defend. Four stages, in order:":
    "SentinelGraph mengubah telemetri mentah menjadi investigasi yang bisa Anda pertanggungjawabkan. Empat tahap, berurutan:",
  "You have evidence loaded. Each card below is one stage of the investigation — click any of them.":
    "Bukti sudah dimuat. Setiap kartu di bawah adalah satu tahap investigasi — klik salah satunya.",
  "Import Sysmon / log exports, or load the synthetic demo set. Nothing is analysed until it is stored.":
    "Impor ekspor Sysmon / log, atau muat dataset demo sintetis. Tidak ada yang dianalisis sebelum tersimpan.",
  "Deterministic rules scan the stored events. A hit is a lead with cited evidence — not a verdict.":
    "Aturan deterministik memindai peristiwa tersimpan. Temuan adalah petunjuk dengan bukti yang dikutip — bukan vonis.",
  "Alerts that share a host or account become one incident, with a timeline and an attack graph.":
    "Peringatan yang berbagi host atau akun menjadi satu insiden, lengkap dengan linimasa dan graf serangan.",
  "Generate a report where every claim cites stored events. Facts and guesses stay separated.":
    "Buat laporan di mana setiap klaim mengutip peristiwa tersimpan. Fakta dan dugaan tetap dipisahkan.",
  "The demo dataset is synthetic and clearly labelled — it is the fastest way to see the whole pipeline working.":
    "Dataset demo bersifat sintetis dan diberi label jelas — cara tercepat melihat seluruh alur bekerja.",
  "Event": "Peristiwa",
  "Alert": "Peringatan",
  "Incident": "Insiden",
  "AI": "AI",
  "One normalised log line. The raw material everything else is built from.":
    "Satu baris log yang dinormalisasi. Bahan mentah pembentuk semua hal lain.",
  "A detection rule matched these events. A lead worth checking, not a conclusion.":
    "Sebuah aturan deteksi cocok dengan peristiwa ini. Petunjuk yang perlu diperiksa, bukan kesimpulan.",
  "Alerts sharing a host or account, merged so you investigate once, not ten times.":
    "Peringatan dengan host atau akun sama, digabung agar Anda menginvestigasi sekali, bukan sepuluh kali.",
  "The stored events behind a claim. Open any finding and you land on them.":
    "Peristiwa tersimpan di balik sebuah klaim. Buka temuan mana pun dan Anda akan sampai ke sana.",
  "Helps read and write up. It never decides what is true — the evidence does.":
    "Membantu membaca dan menyusun laporan. AI tidak pernah memutuskan yang benar — bukti yang memutuskan.",
  "Facts and hypotheses are always kept visually apart: what was observed is marked separately from what is inferred.":
    "Fakta dan hipotesis selalu dipisahkan secara visual: yang teramati ditandai berbeda dari yang disimpulkan.",

  // ---- tutorial ----------------------------------------------------------
  "How to use SentinelGraph": "Cara menggunakan SentinelGraph",
  "A guided tour of the whole workflow — no manual needed. Work through it top to bottom, or jump to a step.":
    "Panduan seluruh alur kerja — tanpa perlu manual. Ikuti dari atas ke bawah, atau langsung ke langkah tertentu.",
  "Step": "Langkah",
  "Open the app": "Buka aplikasi",
  "Get data in": "Masukkan data",
  "Read the detections": "Baca deteksi",
  "Open an incident": "Buka insiden",
  "Follow the attack graph": "Ikuti graf serangan",
  "Check the evidence": "Periksa bukti",
  "Write the report": "Tulis laporan",
  "Add AI (optional)": "Tambahkan AI (opsional)",
  "Tune the rules": "Sesuaikan aturan",
  "Go to Dashboard": "Buka Dasbor",
  "Go to Detection Rules": "Buka Aturan Deteksi",
  "Go to Attack Graph": "Buka Graf Serangan",
  "Go to Reports": "Buka Laporan",
  "Go to Settings": "Buka Pengaturan",
  "Go to AI Providers": "Buka Penyedia AI",
  "Open Incidents": "Buka Insiden",
  "The workspace opens on the Dashboard. Every number there is live — it reflects the database, not a mock.":
    "Ruang kerja terbuka di Dasbor. Setiap angka di sana bersifat langsung — mencerminkan basis data, bukan data palsu.",
  "Nothing works without data, so this is always the first step.":
    "Tidak ada yang berjalan tanpa data, jadi ini selalu langkah pertama.",
  "Load the demo dataset from the Dashboard, or import your own Sysmon / JSON / CSV export under Imports.":
    "Muat dataset demo dari Dasbor, atau impor ekspor Sysmon / JSON / CSV Anda sendiri di Impor.",
  "Everything you import is stored with its SHA-256, so you can prove later exactly which bytes were analysed.":
    "Semua yang Anda impor disimpan bersama SHA-256-nya, sehingga nanti Anda bisa membuktikan byte mana yang dianalisis.",
  "The demo dataset is synthetic and labelled as such. Use it freely to explore.":
    "Dataset demo bersifat sintetis dan diberi label. Gunakan dengan bebas untuk eksplorasi.",
  "Open Detection Rules and read what fired.":
    "Buka Aturan Deteksi dan baca apa yang terpicu.",
  "Each alert cites the exact events that triggered it. A detection is a lead to check, never a conclusion.":
    "Setiap peringatan mengutip peristiwa persis yang memicunya. Deteksi adalah petunjuk untuk diperiksa, bukan kesimpulan.",
  "You can toggle a rule off and the whole pipeline re-runs — useful to see what one rule contributes.":
    "Anda bisa mematikan sebuah aturan dan seluruh alur dijalankan ulang — berguna untuk melihat kontribusi satu aturan.",
  "Alerts that share a host or account are already grouped into one incident. Open the one that matters.":
    "Peringatan yang berbagi host atau akun sudah dikelompokkan menjadi satu insiden. Buka yang paling penting.",
  "Inside an incident you get the summary, the timeline, the findings and the linked evidence in one place.":
    "Di dalam insiden Anda mendapat ringkasan, linimasa, temuan, dan bukti tertaut dalam satu tempat.",
  "Mark it as investigating or closed as you work. Status is yours to set — the tool does not guess it.":
    "Tandai sebagai sedang diinvestigasi atau selesai saat Anda bekerja. Status Anda yang menentukan — alat tidak menebak.",
  "The graph shows how entities relate, derived from the events themselves.":
    "Graf menunjukkan hubungan antar entitas, diturunkan dari peristiwa itu sendiri.",
  "Solid edges are observed relationships; dashed edges are inferred. Hover or click a node for detail.":
    "Garis penuh adalah hubungan teramati; garis putus-putus adalah inferensi. Arahkan atau klik simpul untuk detail.",
  "Start from the incident scope and switch to the global graph when you want the wider picture.":
    "Mulai dari lingkup insiden dan beralih ke graf global bila ingin gambaran lebih luas.",
  "Open Evidence Repository to see the exact stored records behind any claim.":
    "Buka Repositori Bukti untuk melihat catatan persis yang tersimpan di balik setiap klaim.",
  "The raw record is shown as stored — nothing is paraphrased, so you can verify by hand.":
    "Catatan mentah ditampilkan apa adanya — tidak ada parafrase, sehingga Anda bisa memverifikasi manual.",
  "If a citation points at an event that is missing, the report says so instead of hiding it.":
    "Jika sebuah kutipan menunjuk peristiwa yang hilang, laporan mengatakannya, bukan menyembunyikannya.",
  "Pick an incident and generate Markdown, HTML or JSON. Every claim in the output cites stored events.":
    "Pilih insiden lalu buat Markdown, HTML, atau JSON. Setiap klaim dalam hasil mengutip peristiwa tersimpan.",
  "Facts are stated as facts; anything inferred is marked as a hypothesis. Nothing is invented to fill a gap.":
    "Fakta dinyatakan sebagai fakta; apa pun yang disimpulkan ditandai sebagai hipotesis. Tidak ada yang dikarang untuk menutup celah.",
  "The app runs completely without AI. Detection, correlation, the graph, the timeline and reports all work.":
    "Aplikasi berjalan penuh tanpa AI. Deteksi, korelasi, graf, linimasa, dan laporan semuanya bekerja.",
  "If you want model-written narrative, add a provider under AI Providers. Keys are encrypted before storage.":
    "Jika ingin narasi tulisan model, tambahkan penyedia di Penyedia AI. Kunci dienkripsi sebelum disimpan.",
  "AI never replaces the evidence: its output is fenced, labelled, and clearly marked as interpretation.":
    "AI tidak pernah menggantikan bukti: keluarannya dibatasi, diberi label, dan ditandai jelas sebagai interpretasi.",
  "Rules are deterministic functions over normalized events.":
    "Aturan adalah fungsi deterministik atas peristiwa yang dinormalisasi.",
  "Read one, understand what it matches, and disable the ones that do not fit your environment.":
    "Baca satu aturan, pahami apa yang dicocokkan, dan matikan yang tidak sesuai lingkungan Anda.",
  "That is the whole loop. Import, detect, investigate, report — repeat.":
    "Itulah keseluruhan alurnya. Impor, deteksi, investigasi, laporan — ulangi.",

  // ---- common actions / labels -------------------------------------------
  "Save": "Simpan",
  "Cancel": "Batal",
  "Delete": "Hapus",
  "Edit": "Ubah",
  "Close": "Tutup",
  "Retry": "Coba lagi",
  "Clear": "Bersihkan",
  "Clear filter": "Bersihkan filter",
  "Copy": "Salin",
  "Reset": "Reset",
  "Find": "Cari",
  "Search": "Cari",
  "Filter": "Filter",
  "Filter types": "Jenis filter",
  "Detail": "Detail",
  "Actions": "Aksi",
  "Status": "Status",
  "Severity": "Tingkat",
  "Host": "Host",
  "Hosts": "Host",
  "Time": "Waktu",
  "Source": "Sumber",
  "Destination": "Tujuan",
  "Category": "Kategori",
  "Hash": "Hash",
  "Size": "Ukuran",
  "Filename": "Nama berkas",
  "Format": "Format",
  "Summary": "Ringkasan",
  "Timeline": "Linimasa",
  "Relationships": "Relasi",
  "Relations": "Relasi",
  "Attributes": "Atribut",
  "Inspector": "Inspektur",
  "Legend": "Legenda",
  "Loading": "Memuat",
  "Loading workspace…": "Memuat ruang kerja…",
  "Loading incidents…": "Memuat insiden…",
  "Loading incident…": "Memuat insiden…",
  "Loading events…": "Memuat peristiwa…",
  "Loading artifacts…": "Memuat artefak…",
  "Loading rules…": "Memuat aturan…",
  "Loading providers…": "Memuat penyedia…",
  "Loading reports…": "Memuat laporan…",
  "Loading settings…": "Memuat pengaturan…",
  "Generating report…": "Membuat laporan…",
  "Parsing…": "Mengurai…",
  "Building attack graph…": "Membangun graf serangan…",
  "Building layout…": "Menyusun tata letak…",

  // ---- filters / tables --------------------------------------------------
  "All event types": "Semua jenis peristiwa",
  "All hosts": "Semua host",
  "All severities": "Semua tingkat",
  "All statuses": "Semua status",
  "All users": "Semua pengguna",
  "Event type": "Jenis peristiwa",
  "Filter by event type": "Filter berdasarkan jenis peristiwa",
  "Filter by host": "Filter berdasarkan host",
  "Filter by severity": "Filter berdasarkan tingkat",
  "Filter by status": "Filter berdasarkan status",
  "Newest first": "Terbaru dulu",
  "Oldest first": "Terlama dulu",
  "Sort order": "Urutan",
  "most recent first": "terbaru dulu",
  "From date": "Dari tanggal",
  "To date": "Sampai tanggal",
  "Window ": "Jendela ",
  "First seen": "Pertama terlihat",
  "Last seen": "Terakhir terlihat",
  "Records": "Catatan",
  "Records read": "Catatan dibaca",
  "Rejected records": "Catatan ditolak",
  "Duplicates skipped": "Duplikat dilewati",
  "Inserted": "Dimasukkan",
  "Imported": "Diimpor",
  "Accepted": "Diterima",
  "Rejected": "Ditolak",
  "Parse status": "Status parsing",
  "Parse notes": "Catatan parsing",
  "Validation notes": "Catatan validasi",
  "Preview (not saved)": "Pratinjau (belum disimpan)",
  "Import result": "Hasil impor",
  "Still unknown": "Belum diketahui",
  "Nothing to show": "Tidak ada yang ditampilkan",

  // ---- incidents / evidence ---------------------------------------------
  "Incident summary": "Ringkasan insiden",
  "Incident status": "Status insiden",
  "Investigation status": "Status investigasi",
  "Impacted assets": "Aset terdampak",
  "Findings — why this fired": "Temuan — mengapa ini terpicu",
  "Hypotheses": "Hipotesis",
  "Timeline interpretation": "Interpretasi linimasa",
  "Evidence events": "Peristiwa bukti",
  "Evidence boundary.": "Batas bukti.",
  "Evidence →": "Bukti →",
  "No linked evidence": "Tidak ada bukti tertaut",
  "No event evidence linked.": "Belum ada peristiwa bukti yang tertaut.",
  "No findings": "Tidak ada temuan",
  "Open incident": "Buka insiden",
  "Open printable view": "Buka tampilan cetak",
  "Clear incident filter": "Bersihkan filter insiden",
  "Scope to incident": "Batasi ke insiden",
  "Global graph (all incidents)": "Graf global (semua insiden)",
  "Raw record (as stored)": "Catatan mentah (apa adanya)",
  "Copy event ID": "Salin ID peristiwa",
  "Close inspector": "Tutup inspektur",
  "Node inspector": "Inspektur simpul",
  "Fit to view": "Sesuaikan tampilan",
  "Fit graph to view": "Sesuaikan graf ke tampilan",
  "Reset view": "Atur ulang tampilan",
  "Zoom in": "Perbesar",
  "Zoom out": "Perkecil",
  "Find entity": "Cari entitas",
  "Find entity (host, user, ip…)": "Cari entitas (host, pengguna, ip…)",
  "No graph data": "Tidak ada data graf",
  "No graph yet": "Belum ada graf",
  "No incident selected": "Belum ada insiden dipilih",
  "No incidents available": "Tidak ada insiden tersedia",
  "Pick an incident from the Incidents list to open the investigation workspace.":
    "Pilih insiden dari daftar Insiden untuk membuka ruang investigasi.",
  "Load the demo dataset or import events, then run analysis.":
    "Muat dataset demo atau impor peristiwa, lalu jalankan analisis.",
  "Load the demo dataset or import events, then run analysis to build the attack graph.":
    "Muat dataset demo atau impor peristiwa, lalu jalankan analisis untuk membangun graf serangan.",
  "Import data or load the demo dataset, then run analysis.":
    "Impor data atau muat dataset demo, lalu jalankan analisis.",
  "Import a file or load the demo dataset.":
    "Impor berkas atau muat dataset demo.",
  "Adjust the filters, or import data first.":
    "Sesuaikan filter, atau impor data terlebih dahulu.",
  "No events match the filter": "Tidak ada peristiwa yang cocok dengan filter",
  "No events in this window": "Tidak ada peristiwa pada rentang ini",
  "No events": "Tidak ada peristiwa",
  "No artifacts": "Tidak ada artefak",
  "No audit entries": "Tidak ada entri audit",
  "No reports yet": "Belum ada laporan",
  "No rules registered": "Belum ada aturan terdaftar",
  "No incidents": "Tidak ada insiden",

  // ---- import ------------------------------------------------------------
  "Import data": "Impor data",
  "Paste or drop data": "Tempel atau jatuhkan data",
  "Paste or drop JSON, JSONL/NDJSON, CSV, or simple text logs.":
    "Tempel atau jatuhkan JSON, JSONL/NDJSON, CSV, atau log teks sederhana.",
  "Paste a JSON array, JSONL lines, or CSV here…":
    "Tempel array JSON, baris JSONL, atau CSV di sini…",
  "Auto-detect source": "Deteksi sumber otomatis",
  "Source type": "Jenis sumber",
  "Stored path": "Lokasi tersimpan",
  "Artifact": "Artefak",
  "Artifacts": "Artefak",
  "Artifact detail": "Detail artefak",
  "Delete artifact": "Hapus artefak",
  "Clear imported data": "Hapus data yang diimpor",
  "Clear data (keep IOCs)": "Hapus data (simpan IOC)",
  "Clear data + IOCs": "Hapus data + IOC",
  "Analysis": "Analisis",
  "Run analysis": "Jalankan analisis",
  "Analysis mode": "Mode analisis",
  "Run history": "Riwayat eksekusi",
  "Events analysed": "Peristiwa dianalisis",
  "Alerts created": "Peringatan dibuat",
  "Logic": "Logika",
  "Rule detail": "Detail aturan",

  // ---- providers / reports ----------------------------------------------
  "Configuration name": "Nama konfigurasi",
  "Provider type": "Jenis penyedia",
  "Model ID": "ID model",
  "Fast model": "Model cepat",
  "Fast model ID (optional)": "ID model cepat (opsional)",
  "cheaper model for light tasks": "model lebih murah untuk tugas ringan",
  "Base URL": "Base URL",
  "Timeout": "Tenggang waktu",
  "Timeout (s)": "Tenggang waktu (dtk)",
  "Max output": "Keluaran maksimum",
  "Max output tokens": "Token keluaran maksimum",
  "Credential": "Kredensial",
  "API connection": "Koneksi API",
  "Test connection": "Uji koneksi",
  "Last tested": "Terakhir diuji",
  "Latency": "Latensi",
  "Credentials are encrypted at rest.": "Kredensial dienkripsi saat disimpan.",
  "Secure credential storage is unavailable.": "Penyimpanan kredensial aman tidak tersedia.",
  "Provider configuration is stored server-side. Keys are encrypted at rest and never returned to the browser.":
    "Konfigurasi penyedia disimpan di sisi server. Kunci dienkripsi saat disimpan dan tidak pernah dikembalikan ke peramban.",
  "No AI provider is active. Configure one under ": "Tidak ada penyedia AI aktif. Konfigurasikan di ",
  "SentinelGraph runs fully without AI: detection, correlation, attack graph, timeline and reports are all available. Configure a provider to add model-assisted interpretation.":
    "SentinelGraph berjalan penuh tanpa AI: deteksi, korelasi, graf serangan, linimasa, dan laporan semuanya tersedia. Konfigurasikan penyedia untuk menambah interpretasi berbantuan model.",
  "Report format": "Format laporan",
  "Report preview": "Pratinjau laporan",
  "Narrative": "Narasi",
  "AI-assisted": "Berbantuan AI",
  "Generate a report": "Buat laporan",
  "Generate one from an incident above.": "Buat satu dari insiden di atas.",
  "Stored reports": "Laporan tersimpan",
  "Investigation reports generated from stored data only — facts and hypotheses stay separated.":
    "Laporan investigasi dibuat hanya dari data tersimpan — fakta dan hipotesis tetap dipisahkan.",
  "Markdown": "Markdown",
  "HTML (printable)": "HTML (siap cetak)",
  "JSON": "JSON",
  "Every import, with record counts, parse status and the SHA-256 of the exact bytes received.":
    "Setiap impor, lengkap dengan jumlah catatan, status parsing, dan SHA-256 dari byte persis yang diterima.",
  "Every normalized event, searchable down to the raw record.":
    "Setiap peristiwa yang dinormalisasi, dapat dicari hingga catatan mentahnya.",
  "Correlated groups of detections that share a host or account.":
    "Kelompok deteksi terkorelasi yang berbagi host atau akun.",
  "Deterministic functions over normalized events. Toggling one re-runs the full pipeline.":
    "Fungsi deterministik atas peristiwa yang dinormalisasi. Menyalakan/mematikan satu aturan menjalankan ulang seluruh alur.",
  "Entity relationships derived from events. Solid edges are observed; dashed edges are inferred.":
    "Relasi antar entitas yang diturunkan dari peristiwa. Garis penuh teramati; garis putus-putus adalah inferensi.",
  "Application configuration, session and connection state.":
    "Konfigurasi aplikasi, sesi, dan status koneksi.",
  "What the SHA-256 proves:": "Apa yang dibuktikan SHA-256:",
  "AI output is interpretation, not evidence.":
    "Keluaran AI adalah interpretasi, bukan bukti.",
  "AI-generated — distinct from observed facts":
    "Dihasilkan AI — berbeda dari fakta teramati",
  "Every citation referenced events that do not exist in this incident.":
    "Setiap kutipan merujuk peristiwa yang tidak ada di insiden ini.",
  "Uncertainty:": "Ketidakpastian:",
  "Application": "Aplikasi",
  "Connection": "Koneksi",
  "Server time": "Waktu server",
  "Backend health": "Kesehatan backend",
  "Version": "Versi",
  "Session token": "Token sesi",
  "Bearer token": "Token Bearer",
  "Clear token": "Hapus token",
  "Projects": "Proyek",
  "Data": "Data",
  "Audit log": "Log audit",
  "Next steps": "Langkah berikutnya",
  "AI-generated": "Dihasilkan AI",
  "Documentation": "Dokumentasi",
  "Search events": "Cari peristiwa",
  "Search events…": "Cari peristiwa…",
  "Search raw / process / file / domain…": "Cari mentah / proses / berkas / domain…",
  "Graph": "Graf",
  "Next →": "Berikutnya →",
  "Previous": "Sebelumnya",
  "User": "Pengguna",
  "Users": "Pengguna",
  "Process": "Proses",
  "File": "Berkas",
  "Domain": "Domain",
  "DNS": "DNS",
  "Proxy": "Proxy",
  "Firewall": "Firewall",
  "Endpoint": "Endpoint",
  "Email gateway": "Gerbang email",
  "Windows Security": "Windows Security",
  "EDR": "EDR",
  "Timestamp": "Stempel waktu",
  "SHA-256": "SHA-256",
  "e.g. gpt-4o-mini": "mis. gpt-4o-mini",
  "filename.json": "nama-berkas.json",
  "Leave empty to use the documented default: ": "Biarkan kosong untuk memakai bawaan terdokumentasi: ",
  "Dismiss": "Tutup",
  "Open": "Terbuka",
  "Closed": "Selesai",
  "Open ": "Terbuka ",
  "Breadcrumb": "Remah navigasi",
  "Model: ": "Model: ",
  "Master key loaded from ": "Kunci master dimuat dari ",
  "Master key supplied by ": "Kunci master disediakan oleh ",
  "Time (page):": "Waktu (halaman):",
};

/** Strings that embed values. Matched against the trimmed text. */
const ID_RULES: Array<[RegExp, (m: RegExpMatchArray) => string]> = [
  [/^(\d+) event\(s\) stored$/, (m) => `${m[1]} peristiwa tersimpan`],
  [/^(\d+) alert\(s\)$/, (m) => `${m[1]} peringatan`],
  [/^(\d+) incident\(s\)$/, (m) => `${m[1]} insiden`],
  [/^(\d+) report\(s\)$/, (m) => `${m[1]} laporan`],
  [/^(\d+) artifact\(s\)$/, (m) => `${m[1]} artefak`],
  [/^(\d+) IOC\(s\) loaded$/, (m) => `${m[1]} IOC dimuat`],
  [/^(\d+) critical$/, (m) => `${m[1]} kritis`],
  [/^(\d+) open$/, (m) => `${m[1]} terbuka`],
  [/^(\d+) total · grouped by shared host \/ account$/, (m) => `${m[1]} total · dikelompokkan per host / akun bersama`],
  [/^(\d+) nodes \/ (\d+) edges$/, (m) => `${m[1]} simpul / ${m[2]} sisi`],
  [/^(\d+) checks passed$/, (m) => `${m[1]} pemeriksaan lulus`],
  [/^(\d+) nodes · (\d+) edges · zoom (\d+)%$/, (m) => `${m[1]} simpul · ${m[2]} sisi · zoom ${m[3]}%`],
  [/^Total alerts: (\d+)$/, (m) => `Total peringatan: ${m[1]}`],
];

function lookup(raw: string): string | null {
  // JSX collapses multi-line text; normalise so wrapped source strings match.
  const text = raw.replace(/\s+/g, " ").trim();
  if (ID[text]) return ID[text];
  for (const [re, fn] of ID_RULES) {
    const m = text.match(re);
    if (m) return fn(m);
  }
  return null;
}

interface Ctx { lang: Lang; setLang: (l: Lang) => void; }
const LangCtx = createContext<Ctx>({ lang: "en", setLang: () => {} });
export const useLang = () => useContext(LangCtx);

const ATTRS = ["placeholder", "title", "aria-label"];

function translateTextNode(node: Text) {
  const raw = node.nodeValue || "";
  const core = raw.trim();
  if (!core || core.length < 2) return;
  const out = lookup(core);
  if (!out) return; // unknown -> leave English, never touch
  const lead = raw.slice(0, raw.indexOf(core));
  const trail = raw.slice(raw.indexOf(core) + core.length);
  const next = lead + out + trail;
  if (next !== raw) node.nodeValue = next;
}

function translateAttrs(el: Element) {
  for (const a of ATTRS) {
    const v = el.getAttribute(a);
    if (!v) continue;
    const out = lookup(v.trim());
    if (out && out !== v) el.setAttribute(a, out);
  }
}

function walk(node: Node) {
  if (node.nodeType === 3) { translateTextNode(node as Text); return; }
  if (node.nodeType !== 1) return;
  const el = node as Element;
  translateAttrs(el);
  el.childNodes.forEach(walk);
}

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(
    () => ((localStorage.getItem(LS_KEY) as Lang) === "id" ? "id" : "en"),
  );

  const setLang = useCallback((l: Lang) => {
    localStorage.setItem(LS_KEY, l);
    setLangState(l);
  }, []);

  useEffect(() => {
    document.documentElement.lang = lang;
    if (lang !== "id") return; // English is the source text; nothing to rewrite

    const root = document.getElementById("root") ?? document.body;
    walk(root);

    const mo = new MutationObserver((records) => {
      for (const r of records) {
        if (r.type === "characterData") walk(r.target);
        else r.addedNodes.forEach(walk);
      }
    });
    mo.observe(root, { childList: true, subtree: true, characterData: true });
    return () => mo.disconnect();
  }, [lang]);

  return <LangCtx.Provider value={{ lang, setLang }}>{children}</LangCtx.Provider>;
}

/** EN | ID toggle. Lives in the sidebar so it applies to the whole app. */
export function LangSwitch() {
  const { lang, setLang } = useLang();
  return (
    <div className="tw-lang" role="group" aria-label="Language">
      {(["en", "id"] as Lang[]).map((l) => (
        <button key={l} type="button" aria-pressed={lang === l}
                className={`tw-lang-btn ${lang === l ? "on" : ""}`}
                onClick={() => setLang(l)}>
          {l.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
