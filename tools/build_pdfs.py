# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""
Build polished, branded Elder Mind PDFs from curated content.

Pure-Python (reportlab) — no system libraries, no host pollution. Produces
docs/pdf/*.pdf: a marketing Overview, a User Guide, and a one-page Quick Start.
Brand palette/typography from docs/BRAND.md.

Run:  python tools/build_pdfs.py     (reportlab required: pip install reportlab)
"""

from __future__ import annotations

from pathlib import Path

from reportlab import rl_config

# Deterministic output (no embedded build timestamp) so committed PDFs are
# byte-stable across rebuilds — no git churn, clean CI diffs.
rl_config.invariant = 1

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"
OUT = ROOT / "docs" / "pdf"

# --- brand palette (docs/BRAND.md) ---
INDIGO_900 = colors.HexColor("#312e81")
INDIGO_700 = colors.HexColor("#4338ca")
INDIGO_500 = colors.HexColor("#6366f1")
INDIGO_50 = colors.HexColor("#e0e7ff")
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
PAPER = colors.HexColor("#f9fafb")
TIERS = [colors.HexColor("#22c55e"), colors.HexColor("#3b82f6"),
         colors.HexColor("#f97316"), colors.HexColor("#a855f7")]
V_ALLOW, V_WARN, V_ASK, V_BLOCK = (colors.HexColor("#22c55e"), colors.HexColor("#f59e0b"),
                                   colors.HexColor("#f97316"), colors.HexColor("#dc2626"))

FONT, FONT_B, MONO = "Helvetica", "Helvetica-Bold", "Courier"
VERSION = "v0.1.0"


def _styles():
    s = getSampleStyleSheet()
    out = {
        "h1": ParagraphStyle("h1", parent=s["Heading1"], fontName=FONT_B, fontSize=22,
                             textColor=INDIGO_900, spaceAfter=4, spaceBefore=10, leading=26),
        "h2": ParagraphStyle("h2", parent=s["Heading2"], fontName=FONT_B, fontSize=13,
                             textColor=INDIGO_700, spaceAfter=4, spaceBefore=12, leading=16),
        "body": ParagraphStyle("body", parent=s["BodyText"], fontName=FONT, fontSize=10,
                               textColor=INK, leading=15, spaceAfter=6),
        "muted": ParagraphStyle("muted", parent=s["BodyText"], fontName=FONT, fontSize=8.5,
                                textColor=MUTED, leading=12),
        "lead": ParagraphStyle("lead", parent=s["BodyText"], fontName=FONT, fontSize=12.5,
                               textColor=INDIGO_700, leading=18, spaceAfter=8),
        "bullet": ParagraphStyle("bullet", parent=s["BodyText"], fontName=FONT, fontSize=10,
                                 textColor=INK, leading=15, leftIndent=12, spaceAfter=3,
                                 bulletIndent=2),
        "code": ParagraphStyle("code", parent=s["BodyText"], fontName=MONO, fontSize=9,
                               textColor=INDIGO_900, backColor=INDIGO_50, leading=14,
                               leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=8,
                               borderPadding=(6, 6, 6, 6)),
        "tagline": ParagraphStyle("tagline", parent=s["BodyText"], fontName=FONT_B, fontSize=11,
                                  textColor=INDIGO_700, alignment=TA_CENTER, spaceBefore=6),
    }
    return out


def _gradient_bar(width=170 * mm, height=3):
    """The signature green→blue→orange→purple maturity bar as a 1-row table."""
    n = len(TIERS)
    t = Table([[""] * n], colWidths=[width / n] * n, rowHeights=[height])
    style = [("LINEBELOW", (0, 0), (-1, -1), 0, PAPER)]
    for i, c in enumerate(TIERS):
        style.append(("BACKGROUND", (i, 0), (i, 0), c))
    t.setStyle(TableStyle(style))
    return t


def _page_furniture(canvas, doc):
    canvas.saveState()
    # footer rule + text
    canvas.setStrokeColor(INDIGO_50)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 15 * mm, 190 * mm, 15 * mm)
    canvas.setFont(FONT, 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 11 * mm, f"Elder Mind Governance Harness · {VERSION} · Apache-2.0 (code) / CC BY 4.0 (docs)")
    canvas.drawRightString(190 * mm, 11 * mm, f"{doc.page}")
    # thin indigo spine on the left
    canvas.setFillColor(INDIGO_700)
    canvas.rect(0, 0, 4, A4[1], stroke=0, fill=1)
    canvas.restoreState()


def _doc(path: Path) -> BaseDocTemplate:
    d = BaseDocTemplate(str(path), pagesize=A4,
                        leftMargin=20 * mm, rightMargin=20 * mm,
                        topMargin=18 * mm, bottomMargin=22 * mm,
                        title="Elder Mind Governance Harness", author="Elder Mind")
    frame = Frame(d.leftMargin, d.bottomMargin, d.width, d.height, id="main")
    d.addPageTemplates([PageTemplate(id="branded", frames=[frame], onPage=_page_furniture)])
    return d


def _banner():
    img = ASSETS / "logo-banner.png"
    flow = []
    if img.exists():
        # banner is 1280x640 → scale to 150mm wide
        flow.append(Image(str(img), width=150 * mm, height=75 * mm))
    flow.append(Spacer(1, 4))
    flow.append(_gradient_bar())
    flow.append(Spacer(1, 10))
    return flow


def _bullets(st, items):
    return [Paragraph(f"•&nbsp;&nbsp;{x}", st["bullet"]) for x in items]


def _kv_table(rows, col0=55 * mm, col1=115 * mm, head=None):
    data = ([head] if head else []) + rows
    t = Table(data, colWidths=[col0, col1])
    style = [
        ("FONT", (0, 0), (-1, -1), FONT, 9),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, INDIGO_50),
        ("BACKGROUND", (0, 0), (0, -1), PAPER),
        ("FONT", (0, 0 if not head else 1), (0, -1), FONT_B, 9),
        ("TEXTCOLOR", (0, 0), (0, -1), INDIGO_700),
    ]
    if head:
        style += [("BACKGROUND", (0, 0), (-1, 0), INDIGO_700),
                  ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("FONT", (0, 0), (-1, 0), FONT_B, 9)]
    t.setStyle(TableStyle(style))
    return t


# --------------------------------------------------------------------------
def build_overview(st):
    f = _banner()
    f += [
        Paragraph("Local-first agentic governance for coding agents", st["h1"]),
        Paragraph("A deterministic pre-tool-use gate that blocks risky actions, checks dependency "
                  "installs against known-compromised packages, surfaces threat patterns, and can "
                  "escalate high-risk calls to a multi-model council — on <b>your</b> machine, with "
                  "<b>your</b> model.", st["lead"]),
        Paragraph("THE WEDGE", st["h2"]),
        Paragraph("Governance that runs as your coding agent's own pre-tool-use hook — local, "
                  "deterministic, and auditable — not a control plane your agent phones home to. "
                  "It governs the exact moment an agent decides to run <font name=Courier>rm -rf</font>, "
                  "force-push, or <font name=Courier>curl | bash</font>.", st["body"]),
        Paragraph("WHAT'S IN THE HARNESS", st["h2"]),
    ]
    f += _bullets(st, [
        "<b>Pre-tool gate</b> — impact × likelihood → allow / warn / ask / block on a versioned policy.",
        "<b>Supply-chain (opt-in)</b> — OSV + OpenSSF malicious-packages, offline fallback, release-age.",
        "<b>Threat detectors</b> — MITRE-tagged regex surfacing over tool arguments.",
        "<b>Council review (BYO-LLM)</b> — multi-model deliberation using your own model.",
        "<b>Tool-descriptor pinning</b> — catches MCP/tool 'rug-pulls' after approval.",
        "<b>Tamper-evident audit</b> — hash-chained JSONL; <font name=Courier>eldermind verify</font>.",
    ])
    f += [
        Paragraph("HONEST STANDARDS POSTURE", st["h2"]),
        Paragraph("OWASP Agentic Top 10 (2026)–<b>aware</b> and <b>aligned</b> to the NIST AI RMF "
                  "structure — never 'compliant', 'certified', or 'covers all 10'. Enforces ASI02 / "
                  "ASI04 / ASI05, audits ASI03, and openly cedes what a local hook structurally can't see.",
                  st["body"]),
        Spacer(1, 6),
        Paragraph("Govern the action. Teach the operator. Keep it local.", st["tagline"]),
    ]
    return f


def build_user_guide(st):
    f = _banner()
    f += [
        Paragraph("User Guide", st["h1"]),
        Paragraph("Install, configure, and operate the Elder Mind Governance Harness.", st["muted"]),

        Paragraph("1 · INSTALL", st["h2"]),
        Paragraph("Pre-release (from source); becomes <font name=Courier>pipx install eldermind</font> once published:", st["body"]),
        Paragraph("git clone &lt;repo&gt; &amp;&amp; cd elder-mind-harness &amp;&amp; pipx install .<br/>"
                  "eldermind init claude-code&nbsp;&nbsp;# guided setup — or opencode | kiro | cursor", st["code"]),

        Paragraph("2 · GUIDED SETUP", st["h2"]),
        Paragraph("<font name=Courier>eldermind init</font> walks you (and your agent) through: which harness, a "
                  "governance tier, whether to enable supply-chain protection, and which models the "
                  "council may use. It writes <font name=Courier>.eldermind/</font> and wires the pre-tool hook.", st["body"]),

        Paragraph("3 · GOVERNANCE TIERS", st["h2"]),
        _kv_table([
            ["explorer", "Low friction — ask→warn, but a hard block is never relaxed. Learning."],
            ["practitioner", "Sensible default — knowledge-worker safe prototyping."],
            ["governed", "Stricter — warn→ask."],
            ["operator", "Strictest — warn→ask, ask→block."],
        ], head=["Tier", "Behaviour"]),
        Spacer(1, 8),

        Paragraph("4 · ENFORCEMENT BY IDE", st["h2"]),
        _kv_table([
            ["Claude Code", "Hard block (PreToolUse) · Win / macOS / Linux"],
            ["OpenCode", "Hard block (tool.execute.before) · Win / macOS / Linux"],
            ["Kiro", "Hard block (preToolUse) · Win / macOS / Linux"],
            ["Cursor + any MCP client", "Advisory (call govern_check) · Win / macOS / Linux"],
        ], head=["IDE", "Enforcement"]),
        Spacer(1, 8),

        Paragraph("5 · COMMANDS", st["h2"]),
        _kv_table([
            ["init / install", "Wire the harness into a tool (guided or non-interactive)."],
            ["check '<json>'", "Evaluate a tool call (the hook target). Exit 0 allow/warn, 2 ask/block."],
            ["scan <cmd|lockfile>", "Supply-chain check (OSV)."],
            ["explain <id>", "Reconstruct a past decision from the audit log."],
            ["verify", "Confirm the audit chain is intact (tamper-evident)."],
            ["pin <list|check|reset>", "Pin tool/MCP descriptors and detect drift."],
            ["serve / summary", "Advisory MCP server · audit aggregate metrics."],
        ], head=["Command", "Purpose"]),
        Spacer(1, 8),

        Paragraph("6 · WHAT IT DOES NOT DO", st["h2"]),
        Paragraph("Not a prompt-injection classifier, OS sandbox, full SCA, or multi-agent monitor — "
                  "pair it with the right tool for those. The gate only sees calls the harness routes "
                  "through its hook. See THREAT_MODEL.md.", st["body"]),
    ]
    return f


def build_quickstart(st):
    f = _banner()
    f += [
        Paragraph("Quick Start", st["h1"]),
        Paragraph("From zero to your first blocked action in three steps.", st["muted"]),
        Spacer(1, 4),
        Paragraph("1 · Install &amp; wire it into your agent", st["h2"]),
        Paragraph("pipx install .            # from source (pre-release)<br/>"
                  "eldermind init claude-code", st["code"]),
        Paragraph("2 · See it work — try a dangerous command", st["h2"]),
        Paragraph("echo '{\"action\":\"bash\",\"target\":\"git push --force origin main\"}' | eldermind check", st["code"]),
        Paragraph("&#8627;&nbsp; <font color='#dc2626'><b>block</b></font> · risk 16/25 (elevated_review) · "
                  "OWASP ASI02 Tool Misuse · decision EM-2169fd82a466", st["body"]),
        Paragraph("3 · Inspect the evidence", st["h2"]),
        Paragraph("eldermind verify          # audit chain intact<br/>"
                  "eldermind summary         # how many high-risk calls were stopped", st["code"]),
        Spacer(1, 6),
        Paragraph("That's it — every risky action is now checked, explained, logged, and governed "
                  "locally. Turn on supply-chain protection during <font name=Courier>init</font> to also catch "
                  "known-compromised package installs.", st["body"]),
        Spacer(1, 6),
        Paragraph("Govern the action. Teach the operator. Keep it local.", st["tagline"]),
    ]
    return f


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    st = _styles()
    docs = {
        "Elder-Mind-Overview.pdf": build_overview,
        "Elder-Mind-User-Guide.pdf": build_user_guide,
        "Elder-Mind-Quickstart.pdf": build_quickstart,
    }
    for name, builder in docs.items():
        path = OUT / name
        _doc(path).build(builder(st))
        print(f"  wrote {path.relative_to(ROOT)} ({path.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
