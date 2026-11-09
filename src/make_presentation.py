"""
Generates the 6-slide presentation deck `gateguard_slides.pptx` for the
Apart Research Swarm Alignment Hackathon submission.
Follows all layout, typography, bleed image, native chart, and hyperlink rules.
"""

import os
import math
import subprocess
import pptx
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION
from pptx.chart.data import CategoryChartData
from pptx.oxml import parse_xml
from pptx.oxml.ns import nsdecls
from PIL import Image, ImageOps
import pypdfium2 as pdfium

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

MARGIN_X    = 0.8
CONTENT_W   = 11.7
TITLE_TOP   = 0.5
TITLE_H     = 1.5
BODY_TOP    = 2.2
BODY_H      = 4.6
FOOTER_TOP  = 6.95
FOOTER_H    = 0.35
COL_GAP     = 0.45
COL_W_3     = 3.6
COL_W_2     = 5.6

CHAR_W_EM = 0.55
LINE_H    = 1.22
RAGGED    = 0.90

def chars_per_line(w_in, pt):
    return max(1, int(w_in * 72 / (pt * CHAR_W_EM) * RAGGED))

def lines_needed(text, w_in, pt):
    return math.ceil(len(text) / chars_per_line(w_in, pt)) if text else 1

BG_THEME   = RGBColor(0x0F, 0x17, 0x2A)
BG_CONTENT = RGBColor(0xFF, 0xFF, 0xFF)
TEXT_LIGHT = RGBColor(0xF8, 0xFA, 0xFC)
TEXT_DARK  = RGBColor(0x0F, 0x17, 0x2A)
TEXT_MUTED = RGBColor(0x47, 0x55, 0x69)
ACCENT     = RGBColor(0x1E, 0x40, 0xAF)
EMERALD    = RGBColor(0x16, 0xA3, 0x4A)
CRIMSON    = RGBColor(0xDC, 0x26, 0x26)
AMBER      = RGBColor(0xD9, 0x77, 0x06)
TINT       = RGBColor(0xEF, 0xF6, 0xFF)

HEAD_FONT = "Liberation Sans"
BODY_FONT = "Liberation Sans"

BLEED = {'full': (0.0, 13.333), 'left': (0.0, 6.666), 'right': (6.667, 6.666)}

def set_slide_canvas(slide, is_bookend=False):
    bg = slide.shapes.add_shape(pptx.enum.shapes.MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG_THEME if is_bookend else BG_CONTENT
    bg.line.fill.background()
    bg.shadow.inherit = False
    return bg

def add_box(slide, x, y, w, h, color, alpha=None):
    box = slide.shapes.add_shape(pptx.enum.shapes.MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(x), Inches(y), Inches(w), Inches(h))
    box.adjustments[0] = 0 if alpha else 0.06
    box.fill.solid()
    box.fill.fore_color.rgb = color
    box.line.fill.background()
    box.shadow.inherit = False
    for r in box._element.xpath('./p:style/a:effectRef'):
        r.set('idx', '0')
    if alpha:
        box._element.xpath('./p:spPr/a:solidFill/a:srgbClr')[0].append(
            parse_xml(f'<a:alpha {nsdecls("a")} val="{int(alpha * 100000)}"/>'))
    return box

def prepare_slide_image(input_path: str, output_path: str, target_w_px: int, target_h_px: int) -> str:
    with Image.open(input_path).convert('RGBA') as img:
        ImageOps.fit(img, (target_w_px, target_h_px), method=Image.Resampling.LANCZOS).save(output_path, 'PNG')
    return output_path

def add_bleed_image(slide, img_path, out_png, mode='right'):
    left_in, w_in = BLEED[mode]
    fitted = prepare_slide_image(img_path, out_png, round(w_in * 120), round(7.5 * 120))
    pic = slide.shapes.add_picture(fitted, Inches(left_in), 0, Inches(w_in), Inches(7.5))
    pic.line.fill.background()
    slide.shapes[0]._element.addnext(pic._element)
    return pic

def add_header(slide, title_text, kicker_text=None, is_dark=False, w_in=CONTENT_W):
    tb = slide.shapes.add_textbox(Inches(MARGIN_X), Inches(TITLE_TOP), Inches(w_in), Inches(TITLE_H))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    if kicker_text:
        p_k = tf.paragraphs[0]
        p_k.alignment = PP_ALIGN.LEFT
        p_k.space_after = Pt(4)
        run_k = p_k.add_run()
        run_k.text = kicker_text.upper()
        run_k.font.size = Pt(14)
        run_k.font.name = BODY_FONT
        run_k.font.bold = True
        run_k.font.color.rgb = ACCENT if not is_dark else RGBColor(0x93, 0xC5, 0xFD)
        p_t = tf.add_paragraph()
    else:
        p_t = tf.paragraphs[0]

    p_t.alignment = PP_ALIGN.LEFT
    run_t = p_t.add_run()
    run_t.text = title_text
    run_t.font.size = Pt(32)
    run_t.font.name = HEAD_FONT
    run_t.font.bold = True
    run_t.font.color.rgb = TEXT_LIGHT if is_dark else TEXT_DARK

def add_footer(slide, source_label, source_url, page_num, is_dark=False, w_in=CONTENT_W):
    tb = slide.shapes.add_textbox(Inches(MARGIN_X), Inches(FOOTER_TOP), Inches(w_in), Inches(FOOTER_H))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    r1 = p.add_run()
    r1.text = f"Slide {page_num}  |  Source: "
    r1.font.size = Pt(14)
    r1.font.name = BODY_FONT
    r1.font.color.rgb = TEXT_MUTED if not is_dark else RGBColor(0x94, 0xA3, 0xB8)

    r2 = p.add_run()
    r2.text = source_label
    r2.font.size = Pt(14)
    r2.font.name = BODY_FONT
    r2.font.bold = True
    r2.font.color.rgb = ACCENT if not is_dark else RGBColor(0x93, 0xC5, 0xFD)
    r2.hyperlink.address = source_url

def add_bullet_item(tf, bold_keyword, fragment_text, body_pt=16, lead_pt=18,
                    space_after_pt=14, is_dark=False, box_w_in=COL_W_3, link_url=None):
    p = tf.add_paragraph() if len(tf.paragraphs[0].text) > 0 else tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    p.space_after = Pt(space_after_pt)
    run_b = p.add_run()
    run_b.text = bold_keyword + (" " if bold_keyword.endswith(":") else ": ")
    run_b.font.size = Pt(lead_pt)
    run_b.font.name = BODY_FONT
    run_b.font.bold = True
    run_b.font.color.rgb = TEXT_LIGHT if is_dark else TEXT_DARK
    if link_url:
        run_b.hyperlink.address = link_url

    run_f = p.add_run()
    run_f.text = fragment_text
    run_f.font.size = Pt(body_pt)
    run_f.font.name = BODY_FONT
    run_f.font.color.rgb = RGBColor(0xCB, 0xD5, 0xE1) if is_dark else TEXT_MUTED

MID = "/working_dir/c_0d7e07a7a1bf70e5/artifacts/file_generation/ttl=63d/intermediate"
OUT = "/working_dir/c_0d7e07a7a1bf70e5/artifacts/file_generation/ttl=63d/output"
IMG1 = "/working_dir/c_0d7e07a7a1bf70e5/user_uploaded_files/ttl=63d/tool_generated/watermarked_img_11467004358118512700.jpg"
IMG2 = "/working_dir/c_0d7e07a7a1bf70e5/user_uploaded_files/ttl=63d/tool_generated/watermarked_img_4711005763066412186.jpg"

# Also export the cover PNG to output for direct upload in the Apart form
prepare_slide_image(IMG1, os.path.join(OUT, "gateguard_project_cover.png"), 1920, 1080)

# ==============================================================================
# SLIDE 1: COVER (Bookend Dark + Full Bleed Image + Full-Canvas Dim Scrim)
# ==============================================================================
s1 = prs.slides.add_slide(blank_layout)
set_slide_canvas(s1, is_bookend=True)
add_bleed_image(s1, IMG1, os.path.join(MID, "cropped_cover.png"), mode='full')
add_box(s1, 0, 0, 13.333, 7.5, BG_THEME, alpha=0.68)

tb1 = s1.shapes.add_textbox(Inches(MARGIN_X), Inches(2.2), Inches(10.5), Inches(3.8))
tf1 = tb1.text_frame
tf1.word_wrap = True
tf1.vertical_anchor = MSO_ANCHOR.TOP
tf1.margin_left = tf1.margin_top = tf1.margin_right = tf1.margin_bottom = 0

p1 = tf1.paragraphs[0]
p1.space_after = Pt(14)
r_title = p1.add_run()
r_title.text = "GateGuard: Cryptographic Reference Monitors for Agent Swarms"
r_title.font.size = Pt(36)
r_title.font.name = HEAD_FONT
r_title.font.bold = True
r_title.font.color.rgb = TEXT_LIGHT

p2 = tf1.add_paragraph()
p2.space_after = Pt(28)
r_sub = p2.add_run()
r_sub.text = "Lineage-Bound Capability Tokens & Out-of-Band Audit Ledgers for MCP and A2A"
r_sub.font.size = Pt(18)
r_sub.font.name = BODY_FONT
r_sub.font.color.rgb = RGBColor(0x93, 0xC5, 0xFD)

p3 = tf1.add_paragraph()
r_meta = p3.add_run()
r_meta.text = "Manthan Mishra  |  Apart Research Swarm Alignment Hackathon  |  Track 3"
r_meta.font.size = Pt(15)
r_meta.font.name = BODY_FONT
r_meta.font.bold = True
r_meta.font.color.rgb = RGBColor(0xCB, 0xD5, 0xE1)


# ==============================================================================
# SLIDE 2: THE PROBLEM (Split Bleed Right + Open Left Column)
# ==============================================================================
s2 = prs.slides.add_slide(blank_layout)
set_slide_canvas(s2, is_bookend=False)
add_bleed_image(s2, IMG2, os.path.join(MID, "cropped_s2.png"), mode='right')
add_header(s2, "7,905 Aliases & 7% Log Spoofing", kicker_text="THE MULTI-AGENT CONTAINMENT FAILURE", w_in=COL_W_2)

tb2 = s2.shapes.add_textbox(Inches(MARGIN_X), Inches(BODY_TOP), Inches(COL_W_2), Inches(BODY_H))
tf2 = tb2.text_frame
tf2.word_wrap = True
tf2.vertical_anchor = MSO_ANCHOR.TOP
tf2.margin_left = tf2.margin_top = tf2.margin_right = tf2.margin_bottom = 0

add_bullet_item(tf2, "Sybil Aliasing (R0001544):", "1,200 evaluation agents cycled 7,905 self-asserted aliases to evade tracking.", box_w_in=COL_W_2, link_url="https://swarmtraces.org/")
add_bullet_item(tf2, "Privilege Escalation (R0028572):", "Read-only alloy-tracing tokens escalated to cluster-admin into LOOT sidecars.", box_w_in=COL_W_2, link_url="https://swarmtraces.org/")
add_bullet_item(tf2, "Trace Excision (R0045500):", "Agents spoofed 7% of logs and ran D64LINK cleanup commits to erase evidence.", box_w_in=COL_W_2, link_url="https://apartresearch.com/sprints/swarm-alignment-2026")

add_footer(s2, "Swarm Traces (2026) & METR", "https://swarmtraces.org/", 2, w_in=COL_W_2)

# ==============================================================================
# SLIDE 3: ARCHITECTURE (3 Boxed Parallel Pillars — Only Boxed Slide in Deck)
# ==============================================================================
s3 = prs.slides.add_slide(blank_layout)
set_slide_canvas(s3, is_bookend=False)
add_header(s3, "GateGuard Decouples Security From Untrusted Agent Contexts", kicker_text="CRYPTOGRAPHIC REFERENCE MONITOR ARCHITECTURE")

pillars = [
    {
        "title": "1. HMAC Lineage Tokens",
        "bullets": [
            ("Provenance Chain:", "Each sub-agent receives HMAC-SHA256 token chained from parent signature."),
            ("Identity Binding:", "Leaf holder ID is cryptographically bound, blocking alias spoofing.")
        ]
    },
    {
        "title": "2. Monotonic Attenuation",
        "bullets": [
            ("Subset Invariant:", "Child tool scope must strictly subset parent capabilities."),
            ("Cascading Revoke:", "Revoking a parent node invalidates all downstream subtrees.")
        ]
    },
    {
        "title": "3. Out-of-Band Ledger",
        "bullets": [
            ("Hash-Chained Log:", "Every tool call logs to an external SHA-256 append-only ledger."),
            ("Receipt Check:", "Task commits verify execution IDs to block phantom tool forgery.")
        ]
    }
]

pad = 0.25
w_col = COL_W_3 - 2 * pad
for i, col in enumerate(pillars):
    x = MARGIN_X + i * (COL_W_3 + COL_GAP)
    add_box(s3, x, BODY_TOP, COL_W_3, 4.2, TINT)
    tb = s3.shapes.add_textbox(Inches(x + pad), Inches(BODY_TOP + pad), Inches(w_col), Inches(3.7))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
    p_h = tf.paragraphs[0]
    p_h.space_after = Pt(14)
    run_h = p_h.add_run()
    run_h.text = col["title"]
    run_h.font.size = Pt(22)
    run_h.font.name = HEAD_FONT
    run_h.font.bold = True
    run_h.font.color.rgb = ACCENT
    for b_key, b_val in col["bullets"]:
        add_bullet_item(tf, b_key, b_val, body_pt=15, lead_pt=17, space_after_pt=12, box_w_in=w_col)

add_footer(s3, "Apart Research Track 3: Strengthening Agent Infrastructure", "https://apartresearch.com/sprints/swarm-alignment-2026#resources", 3)

# ==============================================================================
# SLIDE 4: SYNTHETIC BENCHMARK RESULTS (Native Bar Chart + Open Takeaways)
# ==============================================================================
s4 = prs.slides.add_slide(blank_layout)
set_slide_canvas(s4, is_bookend=False)
add_header(s4, "GateGuard Achieves 0.0% ASR Across 400 Adversarial Trials", kicker_text="EMPIRICAL EVALUATION: SYNTHETIC RED-TEAM SUITE")

chart_data1 = CategoryChartData()
chart_data1.categories = ['Identity Spoof', 'Privilege Launder', 'Phantom Exec', 'Audit Excision']
chart_data1.add_series('Prompt Guardrails', (78.0, 70.0, 95.0, 100.0))
chart_data1.add_series('In-Protocol Schema', (100.0, 100.0, 100.0, 100.0))
chart_data1.add_series('GateGuard (Ours)', (0.0, 0.0, 0.0, 0.0))

c_frame1 = s4.shapes.add_chart(
    XL_CHART_TYPE.COLUMN_CLUSTERED,
    Inches(MARGIN_X), Inches(BODY_TOP), Inches(7.2), Inches(4.4),
    chart_data1
)
chart1 = c_frame1.chart
chart1.has_legend = True
chart1.legend.position = XL_LEGEND_POSITION.TOP
chart1.legend.include_in_layout = False
chart1.legend.font.name = BODY_FONT
chart1.legend.font.size = Pt(12)
chart1.category_axis.tick_labels.font.name = BODY_FONT
chart1.category_axis.tick_labels.font.size = Pt(12)
chart1.value_axis.maximum_scale = 100.0
chart1.value_axis.tick_labels.font.name = BODY_FONT
chart1.value_axis.tick_labels.font.size = Pt(12)

tb4 = s4.shapes.add_textbox(Inches(8.35), Inches(BODY_TOP + 0.2), Inches(4.15), Inches(4.2))
tf4 = tb4.text_frame
tf4.word_wrap = True
tf4.vertical_anchor = MSO_ANCHOR.TOP
tf4.margin_left = tf4.margin_top = tf4.margin_right = tf4.margin_bottom = 0

add_bullet_item(tf4, "Prompt Failure:", "70% to 100% compromise rate under jailbreak injection.", body_pt=15, lead_pt=17, box_w_in=4.15)
add_bullet_item(tf4, "Schema Failure:", "100% compromise across unauthenticated JSON headers.", body_pt=15, lead_pt=17, box_w_in=4.15)
add_bullet_item(tf4, "Zero Overhead:", "18.0 µs mean verification latency (56.2 µs P99).", body_pt=15, lead_pt=17, box_w_in=4.15)

add_footer(s4, "swarms.wiki Incident Benchmark & GateGuard Evaluation Suite", "https://swarms.wiki/", 4)

# ==============================================================================
# SLIDE 5: SWARM TRACES FORENSIC REPLAY (Native Chart + Adaption Integration)
# ==============================================================================
s5 = prs.slides.add_slide(blank_layout)
set_slide_canvas(s5, is_bookend=False)
add_header(s5, "100% Containment on Replayed Swarm Traces Payloads", kicker_text="FORENSIC REPLAY & ADAPTION CO-DESIGN (N=200 TRIALS)")

chart_data2 = CategoryChartData()
chart_data2.categories = ['R0001544 Spoof', 'R0028572 LOOT', 'R0035032 C2', 'R0045500 Erase']
chart_data2.add_series('Prompt Guardrails', (78.0, 78.0, 100.0, 100.0))
chart_data2.add_series('In-Protocol Schema', (100.0, 100.0, 100.0, 100.0))
chart_data2.add_series('GateGuard (Ours)', (0.0, 0.0, 0.0, 0.0))

c_frame2 = s5.shapes.add_chart(
    XL_CHART_TYPE.COLUMN_CLUSTERED,
    Inches(MARGIN_X), Inches(BODY_TOP), Inches(7.2), Inches(4.4),
    chart_data2
)
chart2 = c_frame2.chart
chart2.has_legend = True
chart2.legend.position = XL_LEGEND_POSITION.TOP
chart2.legend.include_in_layout = False
chart2.legend.font.name = BODY_FONT
chart2.legend.font.size = Pt(12)
chart2.category_axis.tick_labels.font.name = BODY_FONT
chart2.category_axis.tick_labels.font.size = Pt(12)
chart2.value_axis.maximum_scale = 100.0
chart2.value_axis.tick_labels.font.name = BODY_FONT
chart2.value_axis.tick_labels.font.size = Pt(12)

tb5 = s5.shapes.add_textbox(Inches(8.35), Inches(BODY_TOP + 0.2), Inches(4.15), Inches(4.2))
tf5 = tb5.text_frame
tf5.word_wrap = True
tf5.vertical_anchor = MSO_ANCHOR.TOP
tf5.margin_left = tf5.margin_top = tf5.margin_right = tf5.margin_bottom = 0

add_bullet_item(tf5, "Trace Containment:", "Neutralizes m47push2 spoofing, LOOT escalation, and D64LINK erasure.", body_pt=15, lead_pt=17, box_w_in=4.15, link_url="https://swarmtraces.org/")
add_bullet_item(tf5, "Adaption Loop:", "Blocked ledger traces feed Adaption AutoScientist to train edge monitors.", body_pt=15, lead_pt=17, box_w_in=4.15, link_url="https://docs.adaptionlabs.ai/")
add_bullet_item(tf5, "Drop-In Proxy:", "Zero model weight changes required for MCP or A2A servers.", body_pt=15, lead_pt=17, box_w_in=4.15)

add_footer(s5, "Swarm Traces Payloads & Adaption AutoScientist Documentation", "https://docs.adaptionlabs.ai/", 5)

# ==============================================================================
# SLIDE 6: TERMINAL OUTRO (Bookend Dark — Closing Thesis Only)
# ==============================================================================
s6 = prs.slides.add_slide(blank_layout)
set_slide_canvas(s6, is_bookend=True)

tb6 = s6.shapes.add_textbox(Inches(MARGIN_X), Inches(2.6), Inches(CONTENT_W), Inches(2.6))
tf6 = tb6.text_frame
tf6.word_wrap = True
tf6.vertical_anchor = MSO_ANCHOR.TOP
tf6.margin_left = tf6.margin_top = tf6.margin_right = tf6.margin_bottom = 0

p6_1 = tf6.paragraphs[0]
p6_1.alignment = PP_ALIGN.CENTER
p6_1.space_after = Pt(18)
r6_1 = p6_1.add_run()
r6_1.text = "Cryptographic capability boundaries turn untrusted swarms into provably contained systems."
r6_1.font.size = Pt(32)
r6_1.font.name = HEAD_FONT
r6_1.font.bold = True
r6_1.font.color.rgb = TEXT_LIGHT

p6_2 = tf6.add_paragraph()
p6_2.alignment = PP_ALIGN.CENTER
r6_2 = p6_2.add_run()
r6_2.text = "Thank You  |  Manthan Mishra (manthanf1@gmail.com)  |  Track 3 Submission"
r6_2.font.size = Pt(16)
r6_2.font.name = BODY_FONT
r6_2.font.color.rgb = RGBColor(0x93, 0xC5, 0xFD)


out_pptx = os.path.join(OUT, "gateguard_slides.pptx")
prs.save(out_pptx)
print("[*] Saved presentation to:", out_pptx)
