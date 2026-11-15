#!/usr/bin/env python
"""Build the presentation deck from the content in docs/SLIDES.md.

    .venv/Scripts/python.exe tools/make_slides.py
    -> docs/presentation/SentinelGraph-AI-slides.pptx

The deck follows the TRACEWORK palette so it reads as part of the product:
warm neutral canvas, white cards, deep teal accent, dark rail for slides 1 and 10.

Conventions taken from the "Catatan desain" section of docs/SLIDES.md:
title top-left, one accent colour, small slide number bottom-right, and detail
pushed into the speaker notes rather than onto the slide.

Text rules: no en dash, no em dash. Numbers cited here must match the current
build; see the verification note in docs/SLIDES.md.
"""

from __future__ import annotations

import os
import sys
import zipfile
from datetime import datetime

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "docs", "presentation")
OUT = os.path.join(OUT_DIR, "SentinelGraph-AI-slides.pptx")
SHOTS = os.path.join(ROOT, "docs", "screenshots")

# Fixed timestamps: a generated deck must not dirty the tree when nothing
# changed. See make_reproducible().
STAMP = datetime(2026, 1, 1, 0, 0, 0)
STAMP_TUPLE = (2026, 1, 1, 0, 0, 0)

# --- palette (mirrors frontend/src/styles/tokens.css) -----------------------
CANVAS = RGBColor(0xF2, 0xF4, 0xF1)
SURFACE = RGBColor(0xFF, 0xFF, 0xFF)
SUNKEN = RGBColor(0xEE, 0xF1, 0xED)
INK = RGBColor(0x19, 0x24, 0x21)
INK2 = RGBColor(0x46, 0x56, 0x50)
MUTED = RGBColor(0x65, 0x72, 0x6D)
BORDER = RGBColor(0xDC, 0xE3, 0xDE)
PRIMARY = RGBColor(0x17, 0x6B, 0x5B)
PRIMARY_SOFT = RGBColor(0xE8, 0xF1, 0xED)
RAIL = RGBColor(0x0D, 0x32, 0x2D)
RAIL_TEXT = RGBColor(0xB9, 0xCC, 0xC6)
RAIL_ACCENT = RGBColor(0x7F, 0xD1, 0xBE)
CRITICAL = RGBColor(0xB6, 0x3D, 0x49)
CRIT_BG = RGBColor(0xFC, 0xEB, 0xED)
WARN_BG = RGBColor(0xF7, 0xF3, 0xE3)
WARN = RGBColor(0x92, 0x72, 0x1B)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

BODY = "Segoe UI"
MONO = "Consolas"

W = Inches(13.333)
H = Inches(7.5)
M = Inches(0.72)          # left/right margin
CW = W - 2 * M            # content width


# --- primitives -------------------------------------------------------------
def blank(prs):
    return prs.slides.add_slide(prs.slide_layouts[6])


def rect(slide, x, y, w, h, fill=None, line=None, radius=None, lw=0.75):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE, x, y, w, h
    )
    if radius:
        shape.adjustments[0] = radius
    if fill is None:
        shape.fill.background()
    else:
        shape.fill.solid()
        shape.fill.fore_color.rgb = fill
    if line is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line
        shape.line.width = Pt(lw)
    shape.shadow.inherit = False
    return shape


def textbox(slide, x, y, w, h, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(x, y, w, h)
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    return tf


def para(tf, text, *, size=16, bold=False, italic=False, color=INK, font=BODY,
         align=PP_ALIGN.LEFT, before=0, after=0, line=1.24, first=False):
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.alignment = align
    p.line_spacing = line
    p.space_before = Pt(before)
    p.space_after = Pt(after)
    run = p.add_run()
    run.text = text
    f = run.font
    f.size = Pt(size)
    f.bold = bold
    f.italic = italic
    f.name = font
    f.color.rgb = color
    return p


def canvas(slide, color=CANVAS):
    rect(slide, 0, 0, W, H, fill=color)


def header(slide, title, kicker, *, size=26):
    """Section tag on top, message as the title, accent rule under it."""
    y = Inches(0.58)
    tf = textbox(slide, M, y, CW, Inches(0.28))
    para(tf, kicker.upper(), size=11.5, bold=True, color=PRIMARY, first=True)
    tf = textbox(slide, M, y + Inches(0.34), CW, Inches(0.72))
    para(tf, title, size=size, bold=True, color=INK, line=1.12, first=True)
    rect(slide, M, y + Inches(1.12), Inches(1.15), Pt(3.2), fill=PRIMARY)


def footer(slide, n):
    tf = textbox(slide, W - M - Inches(1.2), H - Inches(0.6), Inches(1.2), Inches(0.3))
    para(tf, str(n), size=10.5, color=MUTED, align=PP_ALIGN.RIGHT, first=True)
    tf = textbox(slide, M, H - Inches(0.6), Inches(6), Inches(0.3))
    para(tf, "SentinelGraph AI", size=10.5, color=MUTED, first=True)


def keyline(slide, text, y=None, *, size=14.5):
    """The one sentence the audience must remember."""
    y = y or (H - Inches(1.5))
    rect(slide, M, y, CW, Inches(0.84), fill=PRIMARY_SOFT, radius=0.12)
    rect(slide, M, y, Pt(3.2), Inches(0.84), fill=PRIMARY)
    tf = textbox(slide, M + Inches(0.26), y + Inches(0.12), CW - Inches(0.5), Inches(0.6),
                 anchor=MSO_ANCHOR.MIDDLE)
    para(tf, text, size=size, italic=True, color=PRIMARY, line=1.22, first=True)


def notes(slide, *blocks):
    slide.notes_slide.notes_text_frame.text = "\n\n".join(b.strip() for b in blocks)


def bullets(slide, items, x, y, w, *, size=15, gap=9, color=INK2, mark="\u2022   "):
    tf = textbox(slide, x, y, w, Inches(3.4))
    for i, item in enumerate(items):
        para(tf, mark + item, size=size, color=color, before=0 if i == 0 else gap,
             line=1.3, first=(i == 0))
    return tf


def table(slide, rows, x, y, w, col_w, *, size=13.5, row_h=Inches(0.62)):
    shape = slide.shapes.add_table(len(rows), len(rows[0]), x, y, w, row_h * len(rows))
    tbl = shape.table
    tbl.first_row = False
    tbl.horz_banding = False
    for i, cw in enumerate(col_w):
        tbl.columns[i].width = Emu(int(cw))
    for r, row in enumerate(rows):
        for c, cell_text in enumerate(row):
            cell = tbl.cell(r, c)
            cell.margin_left = cell.margin_right = Inches(0.12)
            cell.margin_top = cell.margin_bottom = Inches(0.06)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            head = r == 0
            if head:
                cell.fill.fore_color.rgb = RAIL
            else:
                cell.fill.fore_color.rgb = SURFACE if r % 2 else SUNKEN
            tf = cell.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            p.line_spacing = 1.18
            run = p.add_run()
            run.text = cell_text
            f = run.font
            f.size = Pt(size - 0.5 if head else size)
            f.bold = head
            f.name = BODY
            f.color.rgb = WHITE if head else (INK if c == 0 else INK2)
    return tbl


def shots(slide, names, captions, y, *, gap=Inches(0.22)):
    """A row of screenshots with captions, all the same width."""
    sw = (CW - gap * (len(names) - 1)) / len(names)
    sh = sw * 568 / 1262
    for i, name in enumerate(names):
        path = os.path.join(SHOTS, name)
        x = M + i * (sw + gap)
        if not os.path.exists(path):
            continue
        rect(slide, x - Inches(0.045), y - Inches(0.045), sw + Inches(0.09),
             Emu(int(sh) + int(Inches(0.09))), fill=SURFACE, line=BORDER, radius=0.06)
        slide.shapes.add_picture(path, x, y, width=Emu(int(sw)))
        tf = textbox(slide, x, y + Emu(int(sh)) + Inches(0.1), sw, Inches(0.26))
        para(tf, captions[i], size=10.5, color=MUTED, align=PP_ALIGN.CENTER, first=True)
    return Emu(int(sh))


# --- slides -----------------------------------------------------------------
def slide_title(prs, n=1):
    s = blank(prs)
    canvas(s, RAIL)
    rect(s, 0, H - Inches(0.1), W, Inches(0.1), fill=PRIMARY)

    tf = textbox(s, M, Inches(2.0), CW, Inches(1.4))
    para(tf, "SentinelGraph AI", size=52, bold=True, color=WHITE, line=1.05, first=True)

    tf = textbox(s, M, Inches(3.05), CW, Inches(0.6))
    para(tf, "From Signals to Story", size=23, color=RAIL_ACCENT, first=True)

    rect(s, M, Inches(3.78), Inches(1.15), Pt(3.2), fill=PRIMARY)

    tf = textbox(s, M, Inches(4.04), Inches(10.2), Inches(0.5))
    para(tf, "Investigasi insiden yang berpusat pada evidence", size=17,
         color=RAIL_TEXT, first=True)

    tf = textbox(s, M, H - Inches(1.4), CW, Inches(0.9))
    para(tf, "Kartika Cyber Hackathon 2026 \u00b7 Penangkalan / Defensive Shield",
         size=13.5, bold=True, color=WHITE, first=True)
    para(tf, "[Nama Tim] \u00b7 [Anggota tim]", size=12.5, color=RAIL_TEXT, before=4)

    notes(s,
          "CATATAN VERIFIKASI SEBELUM PRESENTASI",
          "Angka pada deck ini sudah dicocokkan dengan build terakhir: 315 test "
          "otomatis lulus (bukan 311 pada naskah awal), 22/22 pemeriksaan end-to-end "
          "PASS, dan dataset demo berisi 4 insiden, 60 node, 52 relasi. Jalankan ulang "
          "test sebelum merekam atau mempresentasikan, dan jangan menyajikan angka "
          "yang sudah berubah sebagai hasil terkini.",
          "URUTAN VERSI 3 MENIT",
          "1) 0:00-0:10 nama dan tujuan produk. 2) 0:10-0:30 masalah investigasi. "
          "4) 0:30-0:55 tiga lapisan trust. 5) 0:55-1:25 Evidence Guard. "
          "6) 1:25-1:55 hasil uji adversarial. 7) 1:55-2:35 demo alur investigasi. "
          "10) 2:35-3:00 penutup. Slide 3, 8, dan 9 tidak ditampilkan, tetapi "
          "substansinya siap dijawab saat tanya jawab.",
          "NASKAH PEMBICARA (sekitar 15 detik)",
          "SentinelGraph AI membantu mengubah security signals yang tersebar menjadi "
          "investigasi yang lebih terstruktur dan dapat ditelusuri. Kami akan "
          "menunjukkan bagaimana sistem ini bekerja, termasuk bagaimana ia menangani "
          "klaim AI yang tidak didukung evidence.",
          "Visual utama: screenshot terbaik dari aplikasi dengan logo dan tagline. "
          "Hindari ilustrasi hacker generik.")
    return s


def slide_gap(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Banyak alert. Konteksnya tersebar.", "The Investigation Gap")
    bullets(s, [
        "Alert berasal dari berbagai sumber dan tidak semuanya memiliki tingkat "
        "kepastian yang sama.",
        "Sebagian aktivitas baru terlihat bermakna ketika dihubungkan dengan event lain.",
        "Analis perlu menelusuri hubungan dan sumber bukti, bukan hanya membaca "
        "ringkasan alert.",
    ], M, Inches(2.3), CW - Inches(0.3), size=16.5, gap=15)
    keyline(s, "Tantangannya bukan sekadar menemukan alert. Tantangannya adalah "
               "memahami hubungan antaraktivitas dan membuktikan dasar kesimpulannya.")
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 50 detik)",
          "Alert adalah titik awal, bukan otomatis kesimpulan. Satu login gagal, satu "
          "proses mencurigakan, atau satu koneksi jaringan mungkin perlu konteks "
          "tambahan. Analis harus mengetahui apakah event-event itu saling berkaitan, "
          "entitas mana yang terlibat, dan evidence apa yang mendukung kesimpulan.",
          "Visual utama: tiga sampai empat event terpisah yang belum membentuk satu "
          "rangkaian investigasi.")
    return s


def slide_beyond(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Detection, correlation, dan interpretasi harus bisa diperiksa.",
           "Beyond Alerts and AI Summaries")
    table(s, [
        ["Pendekatan", "Kebutuhan yang kami tangani"],
        ["Alert monitoring saja", "Menghubungkan event lintas entitas dan menelusuri sumbernya"],
        ["Ringkasan LLM saja", "Memeriksa apakah klaim dan sitasi benar-benar didukung evidence"],
    ], M, Inches(2.35), CW, [Inches(3.5), CW - Inches(3.5)], size=14, row_h=Inches(0.78))
    keyline(s, "AI dapat membantu menyusun hipotesis. Analis tetap membutuhkan jawaban "
               "tentang apa yang benar-benar didukung oleh data.")
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 45 detik)",
          "SentinelGraph tidak berasumsi bahwa semua SIEM hanya menghasilkan alert atau "
          "tidak memiliki correlation. Produk SIEM modern dapat memiliki kemampuan "
          "tersebut. Fokus kami adalah pendekatan investigasi berbasis graph dan "
          "evidence traceability, serta validasi output AI agar klaim yang tidak "
          "didukung tidak disajikan sebagai fakta.",
          "ANTISIPASI PERTANYAAN JURI",
          "Apa bedanya dengan SIEM? SentinelGraph bukan klaim pengganti semua SIEM. "
          "Fokusnya investigasi berbasis graph dan evidence traceability, serta "
          "pemisahan fakta, temuan turunan, dan hipotesis AI. Integrasi SIEM adalah "
          "salah satu jalur pengembangan.",
          "Ini cuma wrapper API LLM? Tidak. Detection, correlation, graph, dan alur "
          "laporan inti berjalan tanpa AI. AI komponen opsional untuk membantu "
          "interpretasi hasil yang sudah tersedia.",
          "Visual utama: Alert -> ? versus Event -> Correlation -> Evidence-linked "
          "investigation.")
    return s


def slide_layers(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Fakta, temuan turunan, dan hipotesis tidak dicampur.",
           "Three Layers of Trust")

    layers = [
        ("AI HYPOTHESIS", "Interpretasi model, opsional",
         "Tidak otomatis menjadi fakta", CRIT_BG, CRITICAL),
        ("DERIVED FINDING", "Hasil detection rules, deterministik",
         "Dapat direproduksi dari input dan aturan", WARN_BG, WARN),
        ("OBSERVED FACT", "Event yang diimpor, membawa ID sumber",
         "Menunjukkan apa yang tercatat di data", PRIMARY_SOFT, PRIMARY),
    ]
    top = Inches(2.5)
    bh = Inches(0.94)
    gap = Inches(0.16)
    for i, (name, sub, right, bg, fg) in enumerate(layers):
        y = top + i * (bh + gap)
        rect(s, M, y, Inches(6.6), bh, fill=bg, line=fg, radius=0.12, lw=1.0)
        tf = textbox(s, M + Inches(0.24), y + Inches(0.15), Inches(3.7), bh - Inches(0.24))
        para(tf, name, size=14, bold=True, color=fg, first=True)
        para(tf, sub, size=11.5, color=INK2, before=3)
        tf = textbox(s, M + Inches(6.85), y, Inches(4.9), bh, anchor=MSO_ANCHOR.MIDDLE)
        para(tf, right, size=13, color=INK2, first=True)

    keyline(s, "Setiap lapisan memiliki status dan dasar yang jelas. Hipotesis tidak "
               "dinaikkan menjadi fakta hanya karena terdengar meyakinkan.")
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 55 detik)",
          "Observed Fact adalah apa yang tercatat pada event sumber. Derived Finding "
          "adalah hasil aturan deteksi yang dijalankan terhadap data tersebut. AI "
          "Hypothesis adalah interpretasi tambahan dari model. Ketiganya berguna, "
          "tetapi memiliki tingkat kepastian dan cara verifikasi yang berbeda.",
          "Visual utama: diagram tiga lapisan dengan warna berbeda yang konsisten, "
          "bukan efek 3D.")
    return s


def slide_guard(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "AI claims must be verifiable.", "Evidence Guard")

    steps = ["Catat ID\nevidence", "Kirim konteks\nke model", "Validasi\nstruktur",
             "Periksa\nreferensi", "Laporkan yang\nditolak", "Tandai\nstatus"]
    bw = (CW - Inches(0.14) * 5) / 6
    bh = Inches(1.06)
    y = Inches(2.34)
    for i, label in enumerate(steps):
        x = M + i * (bw + Inches(0.14))
        fill = PRIMARY if i == 0 else SURFACE
        rect(s, x, y, bw, bh, fill=fill, line=PRIMARY if i == 0 else BORDER, radius=0.14)
        tf = textbox(s, x + Inches(0.06), y, bw - Inches(0.12), bh, anchor=MSO_ANCHOR.MIDDLE)
        for j, line in enumerate(label.split("\n")):
            para(tf, line, size=10.5, bold=(i == 0), color=WHITE if i == 0 else INK,
                 align=PP_ALIGN.CENTER, line=1.14, first=(j == 0))
        if i < len(steps) - 1:
            rect(s, x + bw + Inches(0.015), y + bh / 2 - Inches(0.06),
                 Inches(0.11), Inches(0.12), fill=BORDER)

    bullets(s, [
        "Referensi ID yang tidak tersedia ditolak.",
        "Nilai non-integer seperti 1.5 ditolak, bukan diam-diam diubah menjadi 1.",
        "Jumlah referensi yang ditolak dilaporkan kepada pengguna.",
        "Hipotesis tanpa evidence yang lolos tetap tampil sebagai no surviving evidence.",
    ], M, Inches(3.82), CW - Inches(0.3), size=13.5, gap=6)
    keyline(s, "Kami tidak menganggap model selalu benar. Kami membuat referensi "
               "evidence-nya dapat diperiksa.", y=Inches(5.88))
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 65 detik)",
          "Evidence Guard memeriksa struktur respons dan apakah referensi yang "
          "dikembalikan model benar-benar merujuk pada evidence yang tersedia. Ini "
          "tidak membuktikan bahwa seluruh interpretasi model benar. Mekanismenya "
          "memastikan bahwa sitasi yang tidak valid tidak diam-diam diperlakukan "
          "sebagai dukungan. Hipotesis yang tidak memiliki evidence tetap diberi "
          "status yang jelas.",
          "ANTISIPASI PERTANYAAN JURI",
          "Bagaimana kalau model berhalusinasi? Evidence Guard memeriksa struktur dan "
          "referensi evidence yang dikembalikan model. Referensi yang tidak tersedia "
          "ditolak dan dilaporkan. Interpretasi model tetap perlu dinilai; validasi "
          "referensi bukan bukti bahwa seluruh kesimpulan model benar.",
          "Apakah AI bisa mengubah evidence? AI digunakan untuk menghasilkan analisis "
          "tambahan. Evidence sumber tetap berasal dari data yang diimpor dan harus "
          "dapat ditelusuri melalui ID sumber.",
          "Visual utama: cuplikan nyata hasil validasi Evidence Guard, dengan ID "
          "disamarkan bila perlu.")
    return s


def slide_adversarial(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Kami menguji respons yang berisi referensi palsu.",
           "Adversarial Validation")

    table(s, [
        ["Input dari model uji", "Perilaku sistem yang tercatat"],
        ["6 ID karangan + 1 ID asli", "6 ditolak dan dilaporkan; referensi valid dipertahankan"],
        ["3 ID palsu seluruhnya", "Semua ditolak; hipotesis ditandai unsupported"],
        ["JSON tidak valid", "validation_failed; konten AI tidak dimasukkan ke laporan"],
    ], M, Inches(2.3), CW, [Inches(3.6), CW - Inches(3.6)], size=13, row_h=Inches(0.6))

    y = Inches(4.82)
    for i, (big, cap) in enumerate([("6", "referensi palsu ditolak"),
                                    ("0", "referensi palsu lolos")]):
        x = M + i * Inches(3.6)
        rect(s, x, y, Inches(3.3), Inches(0.92), fill=SURFACE, line=BORDER, radius=0.14)
        tf = textbox(s, x + Inches(0.22), y + Inches(0.1), Inches(2.9), Inches(0.74))
        para(tf, big, size=26, bold=True, color=CRITICAL, line=1.0, first=True)
        para(tf, cap, size=12.5, color=INK2, before=1)

    keyline(s, "Kami menguji bukan hanya jawaban yang baik, tetapi juga respons yang "
               "sengaja memberikan referensi tidak valid.", y=Inches(5.94))
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 65 detik)",
          "Pada skenario pertama, model uji mengembalikan enam ID yang tidak ada dan "
          "satu ID valid. Sistem menolak enam referensi yang tidak valid dan "
          "mempertahankan referensi yang valid. Pada skenario kedua, semua referensi "
          "ditolak. Pada skenario ketiga, respons JSON yang rusak gagal divalidasi "
          "sehingga konten AI tidak masuk ke laporan. Ini menguji integritas referensi "
          "dan penanganan format, bukan membuktikan akurasi deteksi terhadap seluruh "
          "ancaman.",
          "ANTISIPASI PERTANYAAN JURI",
          "Apakah sudah mendeteksi zero-day? Kami tidak mengklaim kemampuan zero-day "
          "detection. Prototype ini menggunakan detection rules dan korelasi terhadap "
          "event yang tersedia.",
          "Bagaimana menghindari false positive? Detection rules dapat menghasilkan "
          "temuan yang perlu ditinjau analis. Pengukuran false-positive rate "
          "membutuhkan dataset berlabel dan evaluasi terukur. Kami tidak mengklaim "
          "angka akurasi yang belum diuji.",
          "Visual utama: screenshot input dan output pengujian yang benar-benar "
          "dijalankan, bukan tabel dekoratif saja.")
    return s


def slide_incident(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Dari event terpisah menjadi jalur investigasi.", "One Incident, Connected")

    sh = shots(s, ["01_dashboard.png", "07_global_attack_graph.png", "16_node_inspector.png"],
               ["Dashboard", "Attack Graph", "Inspector"], Inches(2.16))

    y = Inches(2.16) + sh + Inches(0.34)
    tf = textbox(s, M, y, Inches(6.5), Inches(2.2))
    para(tf, "ALUR DEMO", size=10.5, bold=True, color=PRIMARY, first=True)
    for i, step in enumerate([
        "Tampilkan dashboard dan ringkasan event.",
        "Buka daftar alert dan pilih satu insiden.",
        "Telusuri event yang terkait dengan insiden.",
        "Buka Attack Graph dan pilih satu node.",
        "Tampilkan relasi beserta ID event sumber.",
        "Buka evidence yang mendasari temuan.",
        "Tampilkan AI analysis bila provider aktif.",
    ]):
        para(tf, f"{i + 1}.   {step}", size=10.5, color=INK2, before=2, line=1.16)

    x2 = M + Inches(6.8)
    tf = textbox(s, x2, y, CW - Inches(6.8), Inches(2.2))
    para(tf, "BUKTI PRODUK (SUDAH DIVERIFIKASI)", size=10.5, bold=True, color=PRIMARY,
         first=True)
    for item in [
        "315 automated tests lulus.",
        "22/22 pemeriksaan end-to-end PASS (verdict berbasis exit code).",
        "4 insiden, 60 node, dan 52 relasi graf pada dataset demo.",
        "Setiap relasi graf membawa ID event sumber.",
        "Rule engine berjalan tanpa AI dan tanpa jaringan.",
    ]:
        para(tf, "\u2022   " + item, size=10.5, color=INK2, before=2, line=1.16)

    keyline(s, "Setiap relasi pada graf dapat ditelusuri kembali ke event sumbernya.",
            y=Inches(6.06), size=14)
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 100 detik)",
          "Di sini kita melihat dashboard dan insiden yang dibentuk dari dataset demo. "
          "Saya membuka satu insiden, menelusuri event yang terkait, lalu berpindah ke "
          "Attack Graph. Ketika node dipilih, inspector menampilkan informasi entitas "
          "dan evidence yang terkait. Perhatikan bahwa relasi pada graf memiliki "
          "rujukan ke event sumber. Dengan demikian, analis dapat menelusuri dasar "
          "hubungan yang ditampilkan, bukan hanya menerima visualisasi tanpa "
          "asal-usul data.",
          "SKENARIO DEMO",
          "Gunakan dataset sintetis yang tersedia di aplikasi. Jika data demo mencakup "
          "rangkaian login, proses, dan koneksi jaringan, jelaskan sebagai simulasi "
          "investigasi aktivitas mencurigakan pada lingkungan internal. Jangan "
          "menyebutnya sebagai insiden nyata atau sebagai validasi keamanan OT.",
          "Untuk presentasi lisan, utamakan screen recording alur langsung.",
          "ANTISIPASI PERTANYAAN JURI",
          "Apakah bisa bekerja tanpa internet? Detection dan correlation engine inti "
          "dapat berjalan tanpa provider AI dan tanpa jaringan. Fitur analisis AI "
          "eksternal membutuhkan konektivitas ke provider terkait.",
          "Apakah sudah diuji dengan data nyata? Dataset demonstrasi bersifat sintetis. "
          "Pengujian saat ini memvalidasi alur sistem dan mekanisme evidence, bukan "
          "mengukur akurasi deteksi pada data produksi.",
          "Bagaimana kalau AI provider tidak tersedia? Fitur inti tetap berjalan. "
          "Antarmuka menunjukkan bahwa provider AI belum dikonfigurasi atau tidak "
          "tersedia, alih-alih menganggap analisis AI berhasil.")
    return s


def slide_prove(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Laporan yang baik juga menyatakan batas bukti.",
           "What We Can Actually Prove")

    y = Inches(2.6)
    rect(s, M, y, CW, Inches(1.42), fill=RAIL, radius=0.1)
    tf = textbox(s, M + Inches(0.34), y + Inches(0.26), CW - Inches(0.7), Inches(0.95))
    para(tf, "Confirmed compromise:        NOT established by this evidence set.",
         size=15, color=RAIL_ACCENT, font=MONO, line=1.5, first=True)
    para(tf, "Confirmed data exfiltration: NOT established.",
         size=15, color=RAIL_ACCENT, font=MONO, line=1.5)

    tf = textbox(s, M, Inches(4.28), CW, Inches(0.5))
    para(tf, "Potongan nyata dari laporan yang dihasilkan sistem.", size=12.5,
         color=MUTED, first=True)

    keyline(s, "Tidak ditemukannya bukti yang cukup bukan berarti insiden pasti tidak "
               "terjadi. Artinya, kesimpulan tersebut belum dapat ditegakkan dari "
               "evidence yang tersedia.", y=Inches(5.5), size=13.5)
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 45 detik)",
          "SentinelGraph membedakan antara sesuatu yang terindikasi dan sesuatu yang "
          "sudah dapat ditegakkan oleh evidence yang tersedia. Contoh ini tidak "
          "menyatakan bahwa kompromi atau eksfiltrasi mustahil terjadi. Sistem "
          "menyatakan bahwa dataset dan evidence pada investigasi ini belum cukup "
          "untuk mengonfirmasinya. Batas kesimpulan seperti ini penting agar laporan "
          "tidak melebih-lebihkan temuan.",
          "Visual utama: potongan laporan asli dengan status dan sumber evidence.")
    return s


def slide_implementation(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Arsitektur ringan, dengan jalur hardening yang jelas.",
           "Implementation Path")

    y = Inches(2.34)
    ch = Inches(2.5)
    rect(s, M, y, Inches(6.0), ch, fill=SURFACE, line=BORDER, radius=0.1)
    tf = textbox(s, M + Inches(0.3), y + Inches(0.24), Inches(5.4), Inches(2.1))
    para(tf, "STACK SAAT INI", size=10.5, bold=True, color=PRIMARY, first=True)
    for item in ["Python 3.11 + FastAPI", "SQLite tanpa ORM",
                 "React + TypeScript + Vite", "Attack graph berbasis SVG"]:
        para(tf, "\u2022   " + item, size=12.5, color=INK2, before=6, line=1.22)

    x2 = M + Inches(6.3)
    rect(s, x2, y, CW - Inches(6.3), ch, fill=SUNKEN, line=BORDER, radius=0.1)
    tf = textbox(s, x2 + Inches(0.3), y + Inches(0.24), CW - Inches(6.9), Inches(2.1))
    para(tf, "SEBELUM PENERAPAN OPERASIONAL", size=10.5, bold=True, color=PRIMARY,
         first=True)
    for i, item in enumerate(["Autentikasi dan role-based access control (RBAC).",
                              "TLS melalui reverse proxy dan deployment yang aman.",
                              "Konektor SIEM/EDR dan sumber data yang disetujui.",
                              "Enkripsi at-rest serta kebijakan pengelolaan data.",
                              "Pengujian rule dan baseline pada data target."]):
        para(tf, f"{i + 1}.   {item}", size=12, color=INK2, before=5, line=1.2)

    tf = textbox(s, M, Inches(5.0), CW, Inches(0.8))
    para(tf, "Relevansi IT/OT: SentinelGraph dapat dikembangkan untuk menerima data "
             "keamanan dari lingkungan IT/OT melalui konektor dan skema yang sesuai. "
             "Integrasi dan pengujian pada lingkungan OT nyata masih pekerjaan "
             "lanjutan, bukan klaim kemampuan yang sudah selesai.",
         size=11.5, italic=True, color=MUTED, line=1.35, first=True)

    keyline(s, "Fondasi investigasinya sudah berjalan; integrasi dan hardening "
               "operasional adalah tahapan berikutnya.", y=Inches(6.0), size=14)
    footer(s, n)
    notes(s,
          "NASKAH PEMBICARA (sekitar 60 detik)",
          "Prototype saat ini menggunakan stack yang relatif ringan. Untuk penerapan "
          "pada lingkungan organisasi, diperlukan kontrol akses, transport security, "
          "enkripsi penyimpanan, konektor, dan pengujian terhadap sumber data target. "
          "Kami tidak mengklaim integrasi OT produksi sudah tersedia. Fokus berikutnya "
          "adalah membangun integrasi secara bertahap dan memvalidasi rule terhadap "
          "baseline lingkungan yang dituju.",
          "ANTISIPASI PERTANYAAN JURI",
          "Bagaimana relevansinya terhadap IT/OT? Pendekatan korelasi dan evidence "
          "dapat dikembangkan untuk sumber data IT/OT. Namun konektor dan validasi "
          "pada lingkungan OT target masih pekerjaan lanjutan. Kami tidak menjalankan "
          "pengujian pada infrastruktur OT nyata dalam demo ini.",
          "Apakah sudah siap produksi? Prototype inti sudah berjalan dan diuji. "
          "Penerapan operasional membutuhkan hardening, autentikasi, RBAC, TLS, "
          "enkripsi at-rest, integrasi sumber data, dan validasi di lingkungan target.",
          "Apa rencana pengembangan berikutnya? Autentikasi dan RBAC, konektor "
          "SIEM/EDR, lalu kalibrasi rules menggunakan baseline dan dataset lingkungan "
          "target. Integrasi IT/OT setelah skema dan kontrol keselamatannya divalidasi.",
          "Visual utama: diagram arsitektur saat ini di kiri dan roadmap implementasi "
          "di kanan.")
    return s


def slide_closing(prs, n):
    s = blank(prs)
    canvas(s, RAIL)
    rect(s, 0, 0, W, Inches(0.1), fill=PRIMARY)

    tf = textbox(s, M, Inches(1.5), CW, Inches(0.8))
    para(tf, "From Signals to Story", size=36, bold=True, color=WHITE, first=True)
    rect(s, M, Inches(2.47), Inches(1.15), Pt(3.2), fill=PRIMARY)

    tf = textbox(s, M, Inches(2.85), Inches(11.6), Inches(0.5))
    para(tf, "Memahami insiden membutuhkan lebih dari sekadar alert.", size=16,
         color=RAIL_TEXT, first=True)

    tf = textbox(s, M, Inches(3.7), Inches(11.6), Inches(1.9))
    for i, line in enumerate([
        "Deteksi deterministik yang dapat diperiksa.",
        "Graf investigasi yang dapat ditelusuri ke event sumber.",
        "AI yang membantu analisis tanpa menggantikan evidence.",
    ]):
        para(tf, line, size=19, color=RAIL_ACCENT if i == 2 else RAIL_TEXT,
             before=0 if i == 0 else 11, line=1.3, first=(i == 0))

    tf = textbox(s, M, H - Inches(1.15), CW, Inches(0.6))
    para(tf, "SentinelGraph AI", size=16, bold=True, color=WHITE, first=True)
    para(tf, "From Signals to Story.", size=13, color=RAIL_ACCENT, before=3)

    notes(s,
          "NASKAH PEMBICARA (sekitar 25 detik)",
          "SentinelGraph AI menghubungkan deteksi, korelasi, graf, dan evidence dalam "
          "satu alur investigasi. AI dapat membantu analis menyusun hipotesis, tetapi "
          "evidence tetap menjadi dasar untuk menilai kesimpulan. SentinelGraph AI, "
          "From Signals to Story. Terima kasih.",
          "Visual utama: logo dan satu visual graph yang sederhana.")
    return s


def make_reproducible(path):
    """Rewrite the container with fixed metadata so a rebuild is byte identical.

    python-pptx stamps the current time into docProps and zipfile stamps it into
    every entry, which makes a generated deck dirty the git tree on every run
    even when nothing changed. Pinning both keeps ``make slides`` idempotent.
    """
    tmp = path + ".tmp"
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            info = zipfile.ZipInfo(item.filename, date_time=STAMP_TUPLE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = item.external_attr
            dst.writestr(info, src.read(item.filename))
    os.replace(tmp, path)


def main():
    prs = Presentation()
    prs.slide_width = W
    prs.slide_height = H

    props = prs.core_properties
    props.title = "SentinelGraph AI"
    props.author = "SentinelGraph AI"
    props.last_modified_by = "SentinelGraph AI"
    props.created = props.modified = STAMP
    props.revision = 1

    builders = [
        slide_title, slide_gap, slide_beyond, slide_layers, slide_guard,
        slide_adversarial, slide_incident, slide_prove, slide_implementation,
        slide_closing,
    ]
    for i, build in enumerate(builders, start=1):
        build(prs, i)

    os.makedirs(OUT_DIR, exist_ok=True)
    prs.save(OUT)
    make_reproducible(OUT)
    print(f"OK  {OUT}")
    print(f"    {len(prs.slides)} slides, {os.path.getsize(OUT) / 1024:.0f} KB")


if __name__ == "__main__":
    sys.exit(main())
