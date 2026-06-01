# SPDX-License-Identifier: Apache-2.0
"""
Render the Elder Mind terminal demo — a branded animated GIF (+ static PNG) of a
real block, for the README. Pure-Python (Pillow) — no ffmpeg / chromium / host
deps. The content is the actual `eldermind` output for a force-push.

Run:  python tools/build_demo.py     (pip install -e ".[demo]")
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets"

# brand palette
BG = (21, 19, 31)            # near-black indigo
CARD = (30, 27, 58)          # card top bar
GREEN = (34, 197, 94)        # prompt / allow / tier-explorer
BLUE = (59, 130, 246)
ORANGE = (249, 115, 22)
PURPLE = (168, 85, 247)
RED = (220, 38, 38)          # block
AMBER = (245, 158, 11)       # preview
WHITE = (237, 237, 245)
MUTED = (156, 163, 175)
INDIGO = (129, 140, 248)
DOTS = [(239, 68, 68), (245, 158, 11), (34, 197, 94)]

W, PAD, BAR_H, LINE = 1200, 28, 46, 34
FONT_CANDIDATES = [
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Monaco.ttf",
]


def _font(size: int, bold: bool = False):
    for path in FONT_CANDIDATES:
        try:
            # Menlo.ttc: index 0 regular, 1 bold
            idx = 1 if (bold and path.endswith(".ttc")) else 0
            return ImageFont.truetype(path, size, index=idx)
        except OSError:
            continue
    return ImageFont.load_default()


F = _font(24)
FB = _font(24, bold=True)
FT = _font(15)  # title

# (text, color, font) — the full block, revealed line-by-line in the animation
PROMPT = ("agent ▸ ", GREEN)
COMMAND = "git push --force origin main"
OUTPUT = [
    ("", WHITE, F),
    ("   Elder Mind blocked  ·  PreToolUse", RED, FB),   # red stop-disc drawn before this line
    ("    git push --force origin main", WHITE, F),
    ("    risk 16/25 (elevated_review)  ·  OWASP ASI02 Tool Misuse  ·  NIST RMF: MANAGE", INDIGO, F),
    ("    ⚠  This tool use can damage your system or exfiltrate data.", AMBER, F),
    ("    decision EM-2169fd82a466  ·  logged to .eldermind/audit.jsonl", MUTED, F),
    ("    to allow: add a rule to .eldermind/policy.yaml", MUTED, F),
]
H = BAR_H + PAD + LINE * (len(OUTPUT) + 2) + PAD


def _base() -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # title bar
    d.rectangle([0, 0, W, BAR_H], fill=CARD)
    for i, c in enumerate(DOTS):
        cx = PAD + i * 26
        d.ellipse([cx, BAR_H // 2 - 7, cx + 14, BAR_H // 2 + 7], fill=c)
    d.text((PAD + 92, BAR_H // 2 - 9), "eldermind — pre-tool gate", font=FT, fill=MUTED)
    # brand gradient accent under the bar
    seg = W // 4
    for i, c in enumerate([GREEN, BLUE, ORANGE, PURPLE]):
        d.rectangle([i * seg, BAR_H, (i + 1) * seg, BAR_H + 3], fill=c)
    return img


def _frame(typed: int, out_lines: int) -> Image.Image:
    img = _base()
    d = ImageDraw.Draw(img)
    y = BAR_H + PAD
    # prompt + (partially) typed command, with a block cursor while typing
    d.text((PAD, y), PROMPT[0], font=FB, fill=PROMPT[1])
    px = PAD + d.textlength(PROMPT[0], font=FB)
    shown = COMMAND[:typed]
    d.text((px, y), shown, font=F, fill=WHITE)
    if typed < len(COMMAND):
        cx = px + d.textlength(shown, font=F)
        d.rectangle([cx + 1, y + 2, cx + 12, y + 26], fill=WHITE)
    y += LINE
    for i in range(out_lines):
        text, color, font = OUTPUT[i]
        if i == 1:  # headline: draw a red "stop" disc instead of an emoji glyph
            d.ellipse([PAD, y + 3, PAD + 20, y + 23], fill=RED)
            d.ellipse([PAD + 7, y + 10, PAD + 13, y + 16], fill=BG)  # inner dot
        if text:
            d.text((PAD, y), text, font=font, fill=color)
        y += LINE
    return img


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    frames: list[Image.Image] = []
    durations: list[int] = []

    # 1) type the command, a few chars per frame
    step = 4
    for t in range(0, len(COMMAND) + 1, step):
        frames.append(_frame(min(t, len(COMMAND)), 0))
        durations.append(70)
    # 2) brief pause on the full command (about to run)
    frames.append(_frame(len(COMMAND), 0)); durations.append(500)
    # 3) reveal the block output line by line
    for n in range(1, len(OUTPUT) + 1):
        frames.append(_frame(len(COMMAND), n)); durations.append(160)
    # 4) hold the final frame
    frames.append(_frame(len(COMMAND), len(OUTPUT))); durations.append(2600)

    gif = OUT / "demo-block.gif"
    frames[0].save(gif, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, optimize=True)
    png = OUT / "demo-block.png"
    frames[-1].save(png)  # static fallback = final frame
    print(f"  wrote {gif.relative_to(ROOT)} ({gif.stat().st_size // 1024} KB, {len(frames)} frames)")
    print(f"  wrote {png.relative_to(ROOT)} ({png.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    build()
