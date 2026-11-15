#!/usr/bin/env python
"""Build the presentation deck from the content in docs/SLIDES.md.

    .venv/Scripts/python.exe tools/make_slides.py
    -> docs/presentation/SentinelGraph-AI-slides.pptx

The deck follows the TRACEWORK palette so it reads as part of the product:
warm neutral canvas, white cards, deep teal accent, one dark rail slide.

Text rules: no en dash, no em dash. One idea per slide.
"""

from __future__ import annotations

import os
import sys

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "docs", "presentation")
OUT = os.path.join(OUT_DIR, "SentinelGraph-AI-slides.pptx")
SHOTS = os.path.join(ROOT, "docs", "screenshots")

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


def header(slide, title, kicker=None):
    """Title top-left with a short accent rule, per the slide design rules."""
    y = Inches(0.62)
    if kicker:
        tf = textbox(slide, M, y, CW, Inches(0.28))
        para(tf, kicker.upper(), size=11.5, bold=True, color=PRIMARY, first=True)
        y += Inches(0.34)
    tf = textbox(slide, M, y, CW, Inches(0.72))
    para(tf, title, size=28, bold=True, color=INK, line=1.1, first=True)
    rect(slide, M, y + Inches(0.78), Inches(1.15), Pt(3.2), fill=PRIMARY)


def footer(slide, n):
    tf = textbox(slide, W - M - Inches(1.2), H - Inches(0.62), Inches(1.2), Inches(0.3))
    para(tf, str(n), size=10.5, color=MUTED, align=PP_ALIGN.RIGHT, first=True)
    tf2 = textbox(slide, M, H - Inches(0.62), Inches(6), Inches(0.3))
    para(tf2, "SentinelGraph AI", size=10.5, color=MUTED, first=True)


def keyline(slide, text, y=None):
    """The one sentence the audience must remember, on a teal card."""
    y = y or (H - Inches(1.62))
    rect(slide, M, y, CW, Inches(0.86), fill=PRIMARY_SOFT, radius=0.12)
    rect(slide, M, y, Pt(3.2), Inches(0.86), fill=PRIMARY)
    tf = textbox(slide, M + Inches(0.26), y + Inches(0.13), CW - Inches(0.5), Inches(0.6),
                 anchor=MSO_ANCHOR.MIDDLE)
    para(tf, text, size=14.5, italic=True, color=PRIMARY, line=1.22, first=True)


def notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def bullets(slide, items, x, y, w, *, size=15.5, gap=9, dot=PRIMARY, color=INK2):
    tf = textbox(slide, x, y, w, Inches(3.4))
    for i, item in enumerate(items):
        para(tf, "\u2022   " + item, size=size, color=color, before=0 if i == 0 else gap,
             line=1.3, first=(i == 0))
    return tf


def table(slide, rows, x, y, w, col_w, *, head=True, size=13.5, row_h=Inches(0.62)):
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
            if head and r == 0:
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
            f.size = Pt(size if not (head and r == 0) else size - 0.5)
            f.bold = head and r == 0
            f.name = BODY
            f.color.rgb = WHITE if (head and r == 0) else (INK if c == 0 else INK2)
    return tbl


# --- slides -----------------------------------------------------------------
def slide_title(prs, n=1):
    s = blank(prs)
    canvas(s, RAIL)
    rect(s, 0, H - Inches(0.1), W, Inches(0.1), fill=PRIMARY)

    tf = textbox(s, M, Inches(2.05), CW, Inches(1.5))
    para(tf, "SentinelGraph AI", size=52, bold=True, color=WHITE, line=1.05, first=True)

    tf = textbox(s, M, Inches(3.12), CW, Inches(0.6))
    para(tf, "From Signals to Story", size=23, color=RAIL_ACCENT, first=True)

    rect(s, M, Inches(3.86), Inches(1.15), Pt(3.2), fill=PRIMARY)

    tf = textbox(s, M, Inches(4.12), Inches(9.5), Inches(0.5))
    para(tf, "Investigasi insiden yang bisa dipertanggungjawabkan", size=17,
         color=RAIL_TEXT, first=True)

    tf = textbox(s, M, H - Inches(1.42), CW, Inches(0.9))
    para(tf, "Kartika Cyber Hackathon 2026, Defensive Shield", size=13.5, bold=True,
         color=WHITE, first=True)
    para(tf, "[Nama Tim] \u00b7 [Anggota 1] \u00b7 [Anggota 2]", size=12.5,
         color=RAIL_TEXT, before=4)
    notes(s, "Jangan mulai dengan fitur. Slide ini 5 detik saja, lalu langsung ke "
             "masalahnya di slide berikutnya. Ganti placeholder nama tim dan anggota "
             "sebelum presentasi.")
    return s


def slide_problem(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Kita punya terlalu banyak alert, terlalu sedikit cerita", "Masalahnya")
    bullets(s, [
        "Analis menerima puluhan alert per hari. Masing-masing benar. Semuanya terpisah.",
        "Cerita serangan disusun manual di kepala analis, dan hilang saat pindah shift.",
        "Laporan akhirnya berisi klaim yang tidak bisa dipertahankan saat dipersoalkan.",
    ], M, Inches(2.35), CW - Inches(0.3), size=17, gap=14)
    keyline(s, "Masalahnya bukan kekurangan data. Masalahnya tidak ada yang bisa "
               "membuktikan bahwa cerita yang kita susun itu benar.")
    footer(s, n)
    notes(s, "Kalimat kunci: masalahnya bukan kekurangan data, tapi tidak ada yang bisa "
             "membuktikan cerita yang kita susun benar.")
    return s


def slide_failed(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "SIEM terlalu mentah, LLM terlalu percaya diri", "Dua pendekatan yang gagal")
    table(s, [
        ["Pendekatan", "Masalah"],
        ["SIEM saja", "Memberi alert, tidak merangkai. Kesimpulan tidak bisa direproduksi."],
        ["LLM untuk merangkum", "Menghasilkan teks meyakinkan tanpa jaminan benar. Tidak ada cara memeriksa."],
    ], M, Inches(2.3), CW, [Inches(2.9), CW - Inches(2.9)], size=14, row_h=Inches(0.78))
    keyline(s, "LLM menjawab pertanyaan 'apa yang mungkin terjadi'. Kami butuh jawaban "
               "atas 'apa yang bisa saya buktikan'.")
    footer(s, n)
    notes(s, "Kalimat kunci: LLM menjawab 'apa yang mungkin terjadi', kami butuh 'apa "
             "yang bisa saya buktikan'.")
    return s


def slide_layers(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Fakta, turunan, hipotesis, dipisahkan secara eksplisit", "Solusi")

    layers = [
        ("AI HYPOTHESIS", "model bahasa, opsional", "diperlakukan sebagai tersangka", CRIT_BG, CRITICAL),
        ("DERIVED FINDING", "rule engine R-001..R-006", "deterministik, dapat direproduksi", WARN_BG, WARN),
        ("OBSERVED FACT", "event yang diimpor", "setiap klaim membawa ID event", PRIMARY_SOFT, PRIMARY),
    ]
    top = Inches(2.45)
    bh = Inches(0.86)
    gap = Inches(0.14)
    for i, (name, sub, right, bg, fg) in enumerate(layers):
        y = top + i * (bh + gap)
        rect(s, M, y, Inches(6.5), bh, fill=bg, line=fg, radius=0.12, lw=1.0)
        tf = textbox(s, M + Inches(0.24), y + Inches(0.13), Inches(3.6), bh - Inches(0.2))
        para(tf, name, size=14, bold=True, color=fg, first=True)
        para(tf, sub, size=11.5, color=INK2, before=2)
        tf2 = textbox(s, M + Inches(6.75), y, Inches(5.0), bh, anchor=MSO_ANCHOR.MIDDLE)
        para(tf2, right, size=13.5, color=INK2, first=True)

    keyline(s, "Setiap lapis punya aturan pembuktian sendiri. Tidak ada klaim yang naik "
               "lapis tanpa bukti.")
    footer(s, n)
    notes(s, "Kalimat kunci: tiap lapis punya aturan pembuktian sendiri.")
    return s


def slide_guard(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "AI tidak bisa berbohong tanpa ketahuan", "Mekanisme inti: evidence guard")

    steps = ["Catat ID\nyang dikirim", "Kirim ke\nmodel", "Validasi\nskema",
             "Periksa\nsetiap sitasi", "Tandai: supported /\ncontested / unsupported"]
    bw = Inches(2.22)
    bgap = Inches(0.19)
    y = Inches(2.32)
    bh = Inches(1.02)
    for i, label in enumerate(steps):
        x = M + i * (bw + bgap)
        fill = PRIMARY if i == 0 else SURFACE
        rect(s, x, y, bw, bh, fill=fill, line=PRIMARY if i == 0 else BORDER, radius=0.14)
        tf = textbox(s, x + Inches(0.1), y, bw - Inches(0.2), bh, anchor=MSO_ANCHOR.MIDDLE)
        for j, line in enumerate(label.split("\n")):
            para(tf, line, size=11.5, bold=(i == 0), color=WHITE if i == 0 else INK,
                 align=PP_ALIGN.CENTER, line=1.14, first=(j == 0))
        if i < len(steps) - 1:
            ar = rect(s, x + bw + Inches(0.015), y + bh / 2 - Inches(0.07),
                      bgap - Inches(0.03), Inches(0.14), fill=BORDER)
            ar.text_frame.text = ""

    bullets(s, [
        "ID karangan dibuang. Nilai non-integer seperti 1.5 ditolak, bukan diam-diam menjadi 1.",
        "Jumlah sitasi yang dibuang dilaporkan ke pengguna, tidak dibersihkan diam-diam.",
        "Hipotesis tanpa bukti tetap tampil, bertanda no surviving evidence.",
    ], M, Inches(3.75), CW - Inches(0.3), size=14.5, gap=8)
    keyline(s, "Kami tidak membuat model jadi jujur. Kami membuat kebohongannya terlihat.",
            y=H - Inches(1.5))
    footer(s, n)
    notes(s, "Kalimat kunci: kami tidak membuat model jujur, kami membuat kebohongannya "
             "terlihat. Sebutkan bahwa 1.5 ditolak, tidak dibulatkan jadi 1.")
    return s


def slide_adversarial(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Diuji dengan model yang sengaja tidak jujur", "Bukti")

    table(s, [
        ["Yang dikirim model", "Yang dilakukan sistem"],
        ["6 ID karangan + 1 ID asli", "6 dibuang dan dilaporkan; hipotesis berbukti tetap evidence-linked"],
        ["3 ID palsu seluruhnya", "Semua dibuang; hipotesis bertanda unsupported"],
        ["JSON rusak", "validation_failed; tidak ada konten AI masuk laporan"],
    ], M, Inches(2.15), CW, [Inches(3.5), CW - Inches(3.5)], size=13, row_h=Inches(0.58))

    y = Inches(4.66)
    for i, (big, cap) in enumerate([("6", "sitasi karangan dibuang"), ("0", "lolos validasi")]):
        x = M + i * Inches(3.6)
        rect(s, x, y, Inches(3.3), Inches(0.95), fill=SURFACE, line=BORDER, radius=0.14)
        tf = textbox(s, x + Inches(0.22), y + Inches(0.11), Inches(2.9), Inches(0.75))
        para(tf, big, size=27, bold=True, color=CRITICAL, line=1.0, first=True)
        para(tf, cap, size=12.5, color=INK2, before=1)

    keyline(s, "Ini bukan simulasi di atas kertas. Ini output nyata dari sistem yang "
               "berjalan.", y=Inches(5.82))
    footer(s, n)
    notes(s, "Kalimat kunci: ini bukan simulasi di atas kertas, ini output nyata dari "
             "sistem yang berjalan. Slide ini wajib ada di versi 3 menit.")
    return s


def slide_product(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Bukan mockup", "Produknya berjalan")

    shots = ["01_dashboard.png", "07_global_attack_graph.png", "16_node_inspector.png"]
    captions = ["Dashboard", "Attack graph", "Node inspector"]
    sw = (CW - Inches(0.44)) / 3
    y = Inches(2.28)
    sh = int(sw * 568 / 1262)
    for i, name in enumerate(shots):
        path = os.path.join(SHOTS, name)
        x = M + i * (sw + Inches(0.22))
        if os.path.exists(path):
            rect(s, x - Inches(0.045), y - Inches(0.045), sw + Inches(0.09),
                 Emu(int(sh) + int(Inches(0.09))), fill=SURFACE, line=BORDER, radius=0.06)
            s.shapes.add_picture(path, x, y, width=Emu(int(sw)))
        tf = textbox(s, x, y + Emu(int(sh)) + Inches(0.11), sw, Inches(0.28))
        para(tf, captions[i], size=11, color=MUTED, align=PP_ALIGN.CENTER, first=True)

    bullets(s, [
        "311 test otomatis lulus.",
        "22/22 pemeriksaan end-to-end PASS, verdict berbasis exit code.",
        "4 insiden, 60 node, 52 relasi graf, setiap relasi membawa ID event sumbernya.",
        "Rule engine berjalan tanpa AI dan tanpa jaringan.",
    ], M, y + Emu(int(sh)) + Inches(0.52), CW, size=13, gap=5)
    footer(s, n)
    notes(s, "Kalimat kunci: cabut provider AI-nya, semua fitur deteksi, korelasi, graf "
             "dan laporan tetap berjalan.")
    return s


def slide_honest(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Kami menyatakan apa yang tidak bisa dibuktikan", "Yang membedakan")

    y = Inches(2.5)
    rect(s, M, y, CW, Inches(1.5), fill=RAIL, radius=0.1)
    tf = textbox(s, M + Inches(0.34), y + Inches(0.26), CW - Inches(0.7), Inches(1.0))
    para(tf, "Confirmed compromise:        NOT established by this evidence set.",
         size=15, color=RAIL_ACCENT, font=MONO, line=1.5, first=True)
    para(tf, "Confirmed data exfiltration: NOT established.",
         size=15, color=RAIL_ACCENT, font=MONO, line=1.5)

    tf = textbox(s, M, Inches(4.35), CW, Inches(0.6))
    para(tf, "Potongan nyata dari seksi 7 laporan yang dihasilkan sistem.",
         size=12.5, color=MUTED, first=True)
    keyline(s, "Laporan yang berguna di ruang rapat adalah laporan yang berani "
               "mengatakan 'saya belum bisa membuktikan ini'.")
    footer(s, n)
    notes(s, "Kalimat kunci: laporan yang berguna berani mengatakan 'saya belum bisa "
             "membuktikan ini'.")
    return s


def slide_feasibility(prs, n):
    s = blank(prs)
    canvas(s)
    header(s, "Ringan, auditabel, jalan tanpa internet", "Kelayakan")

    y = Inches(2.3)
    ch = Inches(2.75)
    rect(s, M, y, Inches(6.4), ch, fill=SURFACE, line=BORDER, radius=0.1)
    tf = textbox(s, M + Inches(0.3), y + Inches(0.26), Inches(5.8), Inches(2.3))
    para(tf, "STACK", size=11, bold=True, color=PRIMARY, first=True)
    for i, item in enumerate([
        "Python 3.11 + FastAPI",
        "SQLite tanpa ORM, setiap query bisa dibaca saat audit",
        "React + TypeScript + Vite",
        "Attack graph SVG tulisan tangan, tanpa dependensi berat",
    ]):
        para(tf, "\u2022   " + item, size=13, color=INK2, before=7, line=1.24)

    x2 = M + Inches(6.7)
    rect(s, x2, y, CW - Inches(6.7), ch, fill=SUNKEN, line=BORDER, radius=0.1)
    tf = textbox(s, x2 + Inches(0.3), y + Inches(0.26), CW - Inches(7.3), Inches(2.3))
    para(tf, "JALUR PRODUKSI (SUDAH DIPETAKAN)", size=11, bold=True, color=PRIMARY, first=True)
    for i, item in enumerate(["Autentikasi + RBAC", "TLS di belakang reverse proxy",
                              "Konektor SIEM/EDR", "Enkripsi at-rest"]):
        para(tf, f"{i + 1}.   {item}", size=13, color=INK2, before=7, line=1.24)

    keyline(s, "Bukan prototipe yang harus ditulis ulang untuk dipakai.")
    footer(s, n)
    notes(s, "Kalimat kunci: bukan prototipe yang harus ditulis ulang untuk dipakai.")
    return s


def slide_closing(prs, n):
    s = blank(prs)
    canvas(s, RAIL)
    rect(s, 0, 0, W, Inches(0.1), fill=PRIMARY)

    tf = textbox(s, M, Inches(1.75), CW, Inches(0.8))
    para(tf, "Dari sinyal menjadi cerita", size=36, bold=True, color=WHITE, first=True)
    rect(s, M, Inches(2.72), Inches(1.15), Pt(3.2), fill=PRIMARY)

    tf = textbox(s, M, Inches(3.16), Inches(11.4), Inches(2.0))
    for i, line in enumerate([
        "Deteksi deterministik yang bisa diaudit.",
        "Graf yang setiap garisnya berbukti.",
        "AI yang diperlakukan sebagai tersangka, bukan saksi.",
    ]):
        para(tf, line, size=20, color=RAIL_ACCENT if i == 2 else RAIL_TEXT,
             before=0 if i == 0 else 12, line=1.3, first=(i == 0))

    tf = textbox(s, M, H - Inches(1.3), CW, Inches(0.5))
    para(tf, "SentinelGraph AI.", size=17, bold=True, color=WHITE, first=True)
    notes(s, "Tutup dengan 'SentinelGraph AI.' lalu diam. Pertanyaan yang sering muncul: "
             "'ini cuma wrapper API OpenAI?'. Jawab: deteksi, korelasi, graf dan laporan "
             "jalan tanpa AI sama sekali; cabut provider-nya, aplikasi tetap berfungsi penuh.")
    return s


def main():
    prs = Presentation()
    prs.slide_width = W
    prs.slide_height = H

    builders = [
        slide_title, slide_problem, slide_failed, slide_layers, slide_guard,
        slide_adversarial, slide_product, slide_honest, slide_feasibility, slide_closing,
    ]
    for i, build in enumerate(builders, start=1):
        build(prs, i)

    os.makedirs(OUT_DIR, exist_ok=True)
    prs.save(OUT)
    print(f"OK  {OUT}")
    print(f"    {len(prs.slides)} slides, {os.path.getsize(OUT) / 1024:.0f} KB")


if __name__ == "__main__":
    sys.exit(main())
