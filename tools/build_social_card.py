# SPDX-License-Identifier: Apache-2.0
"""
Render the Elder Mind social/link-preview card (1200x630, the OpenGraph spec) —
the image shown when the repo is shared on GitHub / X / LinkedIn / Slack.

Pure-Python (Pillow) — no host deps. On-message + honest copy (kept in sync with
the README positioning; no overclaims). Brand palette from docs/BRAND.md.
Regenerated in CI (non-empty check only — fonts differ per OS, so no byte check),
like the terminal demo.

Run:  python tools/build_social_card.py     (pip install -e ".[demo]")
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"

# brand palette (docs/BRAND.md)
BG = (24, 22, 45)             # deep indigo
INK = (237, 237, 245)         # near-white
INDIGO_300 = (165, 180, 252)
MUTED = (156, 163, 175)
TIERS = [(34, 197, 94), (59, 130, 246), (249, 115, 22), (168, 85, 247)]  # green→blue→orange→purple

W, H = 1200, 630
MARGIN = 80

_SANS = [
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
]
_SANS_BOLD = [
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
]


def _font(size: int, bold: bool = False):
    for path in (_SANS_BOLD if bold else _SANS):
        try:
            idx = 1 if (bold and path.endswith(".ttc")) else 0
            return ImageFont.truetype(path, size, index=idx)
        except OSError:
            continue
    return ImageFont.load_default()


def build() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # signature maturity-gradient bar across the top
    seg = W // len(TIERS)
    for i, c in enumerate(TIERS):
        d.rectangle([i * seg, 0, (i + 1) * seg, 10], fill=c)

    # logo mark (top-left), if available
    text_x = MARGIN
    icon = ASSETS / "icon.png"
    if icon.exists():
        try:
            mark = Image.open(icon).convert("RGBA").resize((200, 200))
            img.paste(mark, (MARGIN, 70), mark)
            text_x = MARGIN + 200 + 48
        except OSError:
            pass

    # wordmark
    d.text((text_x, 84), "Elder Mind", font=_font(92, bold=True), fill=INK)
    d.text((text_x, 196), "Governance Harness", font=_font(40), fill=INDIGO_300)

    # the promise (the README hero line) — two lines, honest, on-message
    d.text((MARGIN, 320), "The pause before your AI coding agent", font=_font(40, bold=True), fill=INK)
    d.text((MARGIN, 374), "does something it can't undo.", font=_font(40, bold=True), fill=INK)

    # what it is — local / deterministic, honest scope
    d.text((MARGIN, 452),
           "A local, deterministic pre-tool gate for Claude Code, OpenCode & Kiro.",
           font=_font(28), fill=MUTED)

    # footer: maker + honest standards ceiling + license
    d.line([MARGIN, 548, W - MARGIN, 548], fill=(60, 56, 92), width=1)
    d.text((MARGIN, 566),
           "by Cyber Elders  ·  OWASP-Agentic-aware  ·  NIST-AI-RMF-aligned  ·  Apache-2.0 / CC BY 4.0",
           font=_font(22), fill=MUTED)

    out = ASSETS / "social-card.png"
    img.save(out)
    print(f"  wrote {out.relative_to(ROOT)} ({out.stat().st_size // 1024} KB, {W}x{H})")


if __name__ == "__main__":
    build()
