# Elder Mind — Brand Kit

The visual system for the Elder Mind Governance Harness. One identity across the
README, docs, PDFs, and badges. Derived from the existing logo assets.

## Idea in one line

**Calm authority at the moment of action.** Deep indigo = the steady guardian;
a green→blue→orange→purple gradient = the maturity journey (explorer → operator).

## Palette

### Core — Indigo (authority, the shield)
| Token | Hex | Use |
|---|---|---|
| `indigo-900` | `#312e81` | primary text on light, shield base, headings |
| `indigo-700` | `#4338ca` | primary brand, links, key accents |
| `indigo-500` | `#6366f1` | borders, secondary accents |
| `indigo-300` | `#a5b4fc` | rules, subtle dividers |
| `indigo-50` | `#e0e7ff` | tints, callout backgrounds |

### Maturity gradient — the four tiers (also the verdict spectrum)
| Token | Hex | Tier | Meaning |
|---|---|---|---|
| `tier-explorer` | `#22c55e` | Explorer | green — low friction, learning |
| `tier-practitioner` | `#3b82f6` | Practitioner | blue — sensible default |
| `tier-operator` | `#f97316` | Operator | orange — stricter |
| `tier-governed` | `#a855f7` | Governed | purple — maximal control |

Use the gradient `green → blue → orange → purple` as the signature accent bar
(it appears under the logo and as section rules). Never recolor it.

### Verdict colors (functional)
| Verdict | Hex | |
|---|---|---|
| allow | `#22c55e` | green |
| warn | `#f59e0b` | amber |
| ask | `#f97316` | orange |
| block | `#dc2626` | red |

### Neutrals
`#111827` (ink) · `#6b7280` (muted) · `#9ca3af` (faint) · `#f9fafb` (paper).

## Typography

- **System-native sans** by design (matches the logo + the local-first ethos):
  `-apple-system, "Segoe UI", system-ui, sans-serif`. No web-font dependency —
  fitting for an offline tool.
- **Monospace** for commands, verdicts, decision ids: `"SF Mono", "Cascadia Code", ui-monospace, monospace`.
- Weights: 700 headings, 600 sub-heads, 400 body. Tight tracking on display (`-0.5`).

## Logo

- `logo-banner.png` — README/PDF header (width ~640).
- `logo-mark.svg` / `logo-mark` — square mark for avatars, favicons, PDF footer.
- `icon.png` — app/social icon. `social-card.png` — link previews.
- Clear space ≥ the shield's half-height. Never stretch, recolor the shield, or
  put the mark on a busy background — use indigo-900 or paper behind it.

## Voice & tone

Practical, standards-informed, **honest about limits**. Short sentences. Name the
consequence ("This can execute remote code"), not the jargon. Never hype:
the words to avoid are in `docs/STANDARDS-MAP.md` and the CI honesty gate
(no "AI-powered", "compliant", "blocks prompt injection", "covers all 10").

Tagline: **"Govern the action. Teach the operator. Keep it local."**

## Badges (shields.io convention)

License (blue) · Docs CC-BY (grey) · Version (orange) · CI (blue) · Tested
(green) · Standards "OWASP Agentic 2026 — aware" (green) · NIST RMF "aligned"
(green). Keep claims at the honest ceiling — "aware"/"aligned", never "compliant".
