# SentinelGraph AI — Slide Deck (Revisi Editorial)

**Format:** 10 slide, rasio 16:9.  
**Durasi:** 10 menit untuk final; versi ringkas 3 menit tersedia di bagian akhir.  
**Kategori:** Penangkalan / Defensive Shield.  
**Pesan utama:** SentinelGraph AI membantu analis menghubungkan security events menjadi investigasi yang dapat ditelusuri kembali ke evidence.

> **Catatan verifikasi sebelum presentasi:** angka pengujian, hasil provider, jumlah node/relasi, dan status fitur di bawah dipertahankan dari naskah sumber. Cocokkan kembali dengan build dan output test terbaru sebelum direkam atau dipresentasikan. Jangan menyajikan angka yang sudah berubah sebagai hasil terkini.

---

## Slide 1 — SentinelGraph AI

### From Signals to Story

**Investigasi insiden yang berpusat pada evidence**

Kartika Cyber Hackathon 2026 · Penangkalan / Defensive Shield  
`[Nama Tim]` · `[Anggota tim]`

**Visual utama:** screenshot terbaik dari aplikasi, dengan logo dan tagline. Hindari ilustrasi hacker generik.

**Catatan pembicara (±15 detik):**  
"SentinelGraph AI membantu mengubah security signals yang tersebar menjadi investigasi yang lebih terstruktur dan dapat ditelusuri. Kami akan menunjukkan bagaimana sistem ini bekerja, termasuk bagaimana ia menangani klaim AI yang tidak didukung evidence."

---

## Slide 2 — The Investigation Gap

### Banyak alert. Konteksnya tersebar.

- Alert berasal dari berbagai sumber dan tidak semuanya memiliki tingkat kepastian yang sama.
- Sebagian aktivitas baru terlihat bermakna ketika dihubungkan dengan event lain.
- Analis perlu menelusuri hubungan dan sumber bukti, bukan hanya membaca ringkasan alert.

**Kalimat kunci:**  
*"Tantangannya bukan sekadar menemukan alert. Tantangannya adalah memahami hubungan antaraktivitas dan membuktikan dasar kesimpulannya."*

**Visual utama:** tiga sampai empat event terpisah yang belum membentuk satu rangkaian investigasi.

**Catatan pembicara (±50 detik):**  
"Alert adalah titik awal, bukan otomatis kesimpulan. Satu login gagal, satu proses mencurigakan, atau satu koneksi jaringan mungkin perlu konteks tambahan. Analis harus mengetahui apakah event-event itu saling berkaitan, entitas mana yang terlibat, dan evidence apa yang mendukung kesimpulan."

---

## Slide 3 — Beyond Alerts and AI Summaries

### Detection, correlation, dan interpretasi harus bisa diperiksa.

| Pendekatan | Kebutuhan yang kami tangani |
|---|---|
| Alert monitoring saja | Menghubungkan event lintas entitas dan menelusuri sumbernya |
| Ringkasan LLM saja | Memeriksa apakah klaim dan sitasi benar-benar didukung evidence |

**Kalimat kunci:**  
*"AI dapat membantu menyusun hipotesis. Analis tetap membutuhkan jawaban tentang apa yang benar-benar didukung oleh data."*

**Visual utama:** perbandingan sederhana: `Alert → ?` versus `Event → Correlation → Evidence-linked investigation`.

**Catatan pembicara (±45 detik):**  
"SentinelGraph tidak berasumsi bahwa semua SIEM hanya menghasilkan alert atau tidak memiliki correlation. Produk SIEM modern dapat memiliki kemampuan tersebut. Fokus kami adalah pendekatan investigasi berbasis graph dan evidence traceability, serta validasi output AI agar klaim yang tidak didukung tidak disajikan sebagai fakta."

---

## Slide 4 — Three Layers of Trust

### Fakta, temuan turunan, dan hipotesis tidak dicampur.

```text
┌─────────────────────────────────────────────┐
│ AI HYPOTHESIS                               │
│ Interpretasi model · Opsional               │
│ Tidak otomatis menjadi fakta               │
├─────────────────────────────────────────────┤
│ DERIVED FINDING                             │
│ Hasil detection rules · Deterministik       │
│ Dapat direproduksi dari input dan aturan    │
├─────────────────────────────────────────────┤
│ OBSERVED FACT                               │
│ Event yang diimpor · Membawa ID sumber      │
│ Menunjukkan apa yang tercatat di data       │
└─────────────────────────────────────────────┘
```

**Kalimat kunci:**  
*"Setiap lapisan memiliki status dan dasar yang jelas. Hipotesis tidak dinaikkan menjadi fakta hanya karena terdengar meyakinkan."*

**Visual utama:** diagram tiga lapisan. Gunakan warna berbeda yang konsisten, bukan efek 3D.

**Catatan pembicara (±55 detik):**  
"Observed Fact adalah apa yang tercatat pada event sumber. Derived Finding adalah hasil aturan deteksi yang dijalankan terhadap data tersebut. AI Hypothesis adalah interpretasi tambahan dari model. Ketiganya berguna, tetapi memiliki tingkat kepastian dan cara verifikasi yang berbeda."

---

## Slide 5 — Evidence Guard

### AI claims must be verifiable.

**Alur kerja:**

```text
Catat ID evidence yang tersedia
          ↓
Kirim konteks ke model
          ↓
Validasi struktur dan tipe data
          ↓
Periksa setiap referensi evidence
          ↓
Laporkan referensi yang ditolak
          ↓
Tandai status: supported / contested / unsupported
```

**Poin pendukung:**

- Referensi ID yang tidak tersedia ditolak.
- Nilai non-integer seperti `1.5` ditolak, bukan diam-diam diubah menjadi `1`.
- Jumlah referensi yang ditolak dilaporkan kepada pengguna.
- Hipotesis tanpa evidence yang lolos tetap dapat ditampilkan sebagai `no surviving evidence`.

**Kalimat kunci:**  
*"Kami tidak menganggap model selalu benar. Kami membuat referensi evidence-nya dapat diperiksa."*

**Visual utama:** cuplikan nyata hasil validasi Evidence Guard, dengan ID yang disamarkan bila perlu.

**Catatan pembicara (±65 detik):**  
"Evidence Guard memeriksa struktur respons dan apakah referensi yang dikembalikan model benar-benar merujuk pada evidence yang tersedia. Ini tidak membuktikan bahwa seluruh interpretasi model benar. Mekanismenya memastikan bahwa sitasi yang tidak valid tidak diam-diam diperlakukan sebagai dukungan. Hipotesis yang tidak memiliki evidence tetap diberi status yang jelas."

---

## Slide 6 — Adversarial Validation

### Kami menguji respons yang berisi referensi palsu.

| Input dari model uji | Perilaku sistem yang tercatat |
|---|---|
| 6 ID karangan + 1 ID asli | 6 ditolak dan dilaporkan; referensi valid dipertahankan |
| 3 ID palsu seluruhnya | Semua ditolak; hipotesis ditandai `unsupported` |
| JSON tidak valid | `validation_failed`; konten AI tidak dimasukkan ke laporan |

**Angka utama dari pengujian:**  
`6 referensi palsu ditolak` · `0 referensi palsu lolos`

**Kalimat kunci:**  
*"Kami menguji bukan hanya jawaban yang baik, tetapi juga respons yang sengaja memberikan referensi tidak valid."*

**Visual utama:** screenshot input dan output pengujian yang benar-benar dijalankan. Tampilkan hasil aktual, bukan tabel dekoratif saja.

**Catatan pembicara (±65 detik):**  
"Pada skenario pertama, model uji mengembalikan enam ID yang tidak ada dan satu ID valid. Sistem menolak enam referensi yang tidak valid dan mempertahankan referensi yang valid. Pada skenario kedua, semua referensi ditolak. Pada skenario ketiga, respons JSON yang rusak gagal divalidasi sehingga konten AI tidak masuk ke laporan. Ini menguji integritas referensi dan penanganan format, bukan membuktikan akurasi deteksi terhadap seluruh ancaman."

---

## Slide 7 — One Incident, Connected

### Dari event terpisah menjadi jalur investigasi.

**Demo produk langsung:**

1. Tampilkan dashboard dan ringkasan event.
2. Buka daftar alert dan pilih satu insiden.
3. Telusuri event yang terkait dengan insiden.
4. Buka Attack Graph dan pilih satu node.
5. Tampilkan relasi beserta ID event sumber.
6. Buka evidence yang mendasari temuan.
7. Tampilkan AI analysis hanya jika provider aktif dan hasilnya tersedia.

**Skenario demo:** gunakan dataset sintetis yang tersedia di aplikasi. Jika data demo mencakup rangkaian login, proses, dan koneksi jaringan, jelaskan sebagai *simulasi investigasi aktivitas mencurigakan pada lingkungan internal*. Jangan menyebutnya sebagai insiden nyata atau sebagai validasi keamanan OT.

**Bukti produk yang dicantumkan setelah diverifikasi:**

- `311` automated tests lulus.
- `22/22` pemeriksaan end-to-end PASS (verdict berbasis exit code).
- `4` insiden, `60` node, dan `52` relasi graf pada dataset demo.
- Setiap relasi graf membawa ID event sumber.
- Rule engine berjalan tanpa AI dan tanpa jaringan.

**Kalimat kunci:**  
*"Setiap relasi pada graf dapat ditelusuri kembali ke event sumbernya."*

**Visual utama:** satu screenshot dashboard, satu screenshot Attack Graph, dan satu screenshot inspector/evidence. Untuk presentasi lisan, utamakan screen recording alur langsung.

**Catatan pembicara (±100 detik):**  
"Di sini kita melihat dashboard dan insiden yang dibentuk dari dataset demo. Saya membuka satu insiden, menelusuri event yang terkait, lalu berpindah ke Attack Graph. Ketika node dipilih, inspector menampilkan informasi entitas dan evidence yang terkait. Perhatikan bahwa relasi pada graf memiliki rujukan ke event sumber. Dengan demikian, analis dapat menelusuri dasar hubungan yang ditampilkan, bukan hanya menerima visualisasi tanpa asal-usul data."

---

## Slide 8 — What We Can Actually Prove

### Laporan yang baik juga menyatakan batas bukti.

**Contoh output laporan:**

```text
Confirmed compromise:        NOT established by this evidence set.
Confirmed data exfiltration: NOT established.
```

**Kalimat kunci:**  
*"Tidak ditemukannya bukti yang cukup bukan berarti insiden pasti tidak terjadi. Artinya, kesimpulan tersebut belum dapat ditegakkan dari evidence yang tersedia."*

**Visual utama:** potongan laporan asli dengan status dan sumber evidence.

**Catatan pembicara (±45 detik):**  
"SentinelGraph membedakan antara sesuatu yang terindikasi dan sesuatu yang sudah dapat ditegakkan oleh evidence yang tersedia. Contoh ini tidak menyatakan bahwa kompromi atau eksfiltrasi mustahil terjadi. Sistem menyatakan bahwa dataset dan evidence pada investigasi ini belum cukup untuk mengonfirmasinya. Batas kesimpulan seperti ini penting agar laporan tidak melebih-lebihkan temuan."

---

## Slide 9 — Implementation Path

### Arsitektur ringan, dengan jalur hardening yang jelas.

**Stack saat ini:**

- Python 3.11 + FastAPI
- SQLite tanpa ORM
- React + TypeScript + Vite
- Attack graph berbasis SVG

**Kebutuhan sebelum penerapan operasional yang lebih luas:**

1. Autentikasi dan role-based access control (RBAC).
2. TLS melalui reverse proxy dan konfigurasi deployment yang aman.
3. Konektor SIEM/EDR dan sumber data yang disetujui.
4. Enkripsi at-rest serta kebijakan pengelolaan data.
5. Pengujian rule dan baseline menggunakan data lingkungan target.

**Relevansi IT/OT:**  
SentinelGraph dapat dikembangkan untuk menerima data keamanan dari lingkungan IT/OT melalui konektor dan skema yang sesuai. Integrasi, validasi, serta pengujian pada lingkungan OT nyata masih merupakan pekerjaan lanjutan, bukan klaim kemampuan yang sudah selesai.

**Kalimat kunci:**  
*"Fondasi investigasinya sudah berjalan; integrasi dan hardening operasional adalah tahapan berikutnya."*

**Visual utama:** diagram arsitektur saat ini di kiri dan roadmap implementasi di kanan.

**Catatan pembicara (±60 detik):**  
"Prototype saat ini menggunakan stack yang relatif ringan. Untuk penerapan pada lingkungan organisasi, diperlukan kontrol akses, transport security, enkripsi penyimpanan, konektor, dan pengujian terhadap sumber data target. Kami tidak mengklaim integrasi OT produksi sudah tersedia. Fokus berikutnya adalah membangun integrasi secara bertahap dan memvalidasi rule terhadap baseline lingkungan yang dituju."

---

## Slide 10 — From Signals to Story

### Memahami insiden membutuhkan lebih dari sekadar alert.

> Deteksi deterministik yang dapat diperiksa.  
> Graf investigasi yang dapat ditelusuri ke event sumber.  
> AI yang membantu analisis tanpa menggantikan evidence.

**SentinelGraph AI**  
**From Signals to Story.**

**Visual utama:** logo dan satu visual graph yang sederhana.

**Catatan pembicara (±25 detik):**  
"SentinelGraph AI menghubungkan deteksi, korelasi, graf, dan evidence dalam satu alur investigasi. AI dapat membantu analis menyusun hipotesis, tetapi evidence tetap menjadi dasar untuk menilai kesimpulan. SentinelGraph AI, From Signals to Story. Terima kasih."

---

# Versi 3 menit

| Slide | Waktu | Yang wajib ditampilkan |
|---|---:|---|
| 1 | 0:00–0:10 | Nama dan tujuan produk |
| 2 | 0:10–0:30 | Masalah investigasi |
| 4 | 0:30–0:55 | Tiga lapisan trust |
| 5 | 0:55–1:25 | Evidence Guard |
| 6 | 1:25–1:55 | Hasil uji adversarial |
| 7 | 1:55–2:35 | Demo alur investigasi |
| 10 | 2:35–3:00 | Penutup |

Slide 3, 8, dan 9 tidak ditampilkan dalam versi singkat, tetapi substansinya tetap dapat dijawab saat sesi tanya jawab.

---

# Antisipasi pertanyaan juri

## 1. "Apa bedanya dengan SIEM?"

"SentinelGraph bukan klaim pengganti semua SIEM. Fokusnya adalah investigasi berbasis graph dan evidence traceability, serta pemisahan fakta, temuan turunan, dan hipotesis AI. Integrasi SIEM merupakan salah satu jalur pengembangan."

## 2. "Ini cuma wrapper API LLM?"

"Tidak. Detection, correlation, graph, dan alur laporan inti berjalan tanpa AI. AI merupakan komponen opsional untuk membantu interpretasi hasil yang sudah tersedia."

## 3. "Bagaimana kalau model berhalusinasi?"

"Evidence Guard memeriksa struktur dan referensi evidence yang dikembalikan model. Referensi yang tidak tersedia ditolak dan dilaporkan. Interpretasi model tetap perlu dinilai; validasi referensi bukan bukti bahwa seluruh kesimpulan model benar."

## 4. "Apakah bisa bekerja tanpa internet?"

"Detection dan correlation engine inti dapat berjalan tanpa provider AI dan tanpa jaringan. Fitur analisis AI eksternal tentu membutuhkan konektivitas ke provider terkait."

## 5. "Apakah sudah mendeteksi zero-day?"

"Kami tidak mengklaim kemampuan zero-day detection. Prototype saat ini menggunakan detection rules dan korelasi terhadap event yang tersedia."

## 6. "Apakah sudah diuji dengan data nyata?"

"Dataset demonstrasi yang digunakan bersifat sintetis. Pengujian saat ini memvalidasi alur sistem dan mekanisme evidence, bukan mengukur akurasi deteksi pada data produksi."

## 7. "Bagaimana relevansinya terhadap IT/OT?"

"Pendekatan korelasi dan evidence dapat dikembangkan untuk sumber data IT/OT. Namun, konektor dan validasi pada lingkungan OT target masih menjadi pekerjaan lanjutan. Kami tidak menjalankan pengujian pada infrastruktur OT nyata dalam demo ini."

## 8. "Apakah sudah siap produksi?"

"Prototype inti sudah berjalan dan diuji. Penerapan operasional membutuhkan hardening, autentikasi, RBAC, TLS, enkripsi at-rest, integrasi sumber data, dan validasi di lingkungan target."

## 9. "Bagaimana kalau AI provider tidak tersedia?"

"Fitur inti tetap berjalan. Antarmuka menunjukkan bahwa provider AI belum dikonfigurasi atau tidak tersedia, alih-alih menganggap analisis AI berhasil."

## 10. "Apakah AI bisa mengubah evidence?"

"AI digunakan untuk menghasilkan analisis tambahan. Evidence sumber tetap berasal dari data yang diimpor dan harus dapat ditelusuri melalui ID sumber. Tunjukkan implementasi aktual saat demo untuk menjelaskan batas akses dan alur datanya."

## 11. "Bagaimana menghindari false positive?"

"Detection rules dapat menghasilkan temuan yang perlu ditinjau analis. Pengukuran false-positive rate membutuhkan dataset berlabel dan evaluasi terukur. Kami tidak mengklaim angka akurasi yang belum diuji."

## 12. "Apa rencana pengembangan berikutnya?"

"Prioritasnya adalah autentikasi dan RBAC, konektor SIEM/EDR, kemudian kalibrasi rules menggunakan baseline dan dataset lingkungan target. Integrasi IT/OT dilakukan setelah skema dan kontrol keselamatannya divalidasi."

---

# Catatan desain dan penyampaian

- Maksimal sekitar 30 kata utama per slide; detail masuk ke speaker notes.
- Satu pesan utama dan satu visual utama per slide.
- Gunakan screenshot asli aplikasi untuk membuktikan fitur.
- Jangan mengganti bukti produk dengan mockup yang terlihat lebih bagus.
- Hindari animasi transisi yang tidak menambah informasi.
- Konsisten: judul di kiri atas, satu warna aksen, nomor slide kecil di kanan bawah.
- Gunakan istilah `Observed Fact`, `Derived Finding`, `AI Hypothesis`, `Evidence Guard`, dan `Attack Graph` secara konsisten.
- Tandai data sintetis sebagai sintetis.
- Jangan menyebut fitur roadmap sebagai fitur yang sudah tersedia.
- Sebelum presentasi, jalankan ulang seluruh test yang dikutip dan rekam demo dari build yang sama dengan yang akan diberikan kepada juri.
