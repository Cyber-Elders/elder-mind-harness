# Licensing — review & recommendation

**Question:** which license is best so a **corporate can adopt Elder Mind easily**?

**Recommendation (short):** **keep Apache-2.0 for the code** and **CC BY 4.0 for
the docs**. It is the most corporate-friendly choice *and* the only permissive
license with an explicit patent grant — which matters for a security/governance
tool. It's also the category standard (MCP, LangChain, OpenAI Agents SDK,
Microsoft Agent Governance Toolkit, OSV-Scanner, Kubernetes all use Apache-2.0),
so enterprise legal teams already have it pre-approved.

## The options, against the goal "easy for a corporate to use"

| License | Type | Patent grant | Corporate adoption | Protects against a closed-SaaS competitor | Verdict for Elder Mind |
|---|---|---|---|---|---|
| **Apache-2.0** | Permissive (OSI) | **Yes (explicit)** | ✅ Easiest — pre-approved at most enterprises | No | ✅ **Recommended (code)** |
| MIT | Permissive (OSI) | No (implicit at best) | ✅ Easy | No | Fine, but Apache's patent grant is strictly better for security IP |
| BSD-3 | Permissive (OSI) | No | ✅ Easy | No | Same gap as MIT |
| MPL-2.0 | Weak copyleft (OSI) | Yes | 🟡 Usually OK (file-level copyleft) | Partial | Overkill; adds friction with no real upside here |
| GPL-3.0 | Strong copyleft (OSI) | Yes | 🔴 Many enterprises restrict | Weakly | Hurts the stated goal |
| **AGPL-3.0** | Network copyleft (OSI) | Yes | 🔴 **Frequently banned** by corporate policy | Yes (network clause) | ✗ Kills corporate adoption |
| BSL 1.1 / Elastic v2 / SSPL | Source-available (not OSI) | varies | 🔴 Legal treats warily; not "open source" | Yes | ✗ Benefit is moot — see below |

## Why permissive (not copyleft / source-available) for *this* product

1. **The goal is adoption.** You want corporates to drop Elder Mind into their dev
   workflow with zero legal review. AGPL and source-available licenses trigger
   exactly the review (and often a hard "no") you want to avoid.
2. **There's little to "protect."** BSL/SSPL/AGPL exist mainly to stop a rival
   from running your software as a paid managed service. Elder Mind is
   **local-first** — there is no cloud service to SaaS-ify. The protection these
   licenses buy is largely irrelevant, while their adoption cost is very real.
3. **Patent grant matters for security/governance IP.** Apache-2.0's explicit
   patent license reassures enterprise legal more than MIT/BSD. For a tool whose
   value is its governance method, that's worth keeping.
4. **Peer signalling.** Every adjacent OSS governance/agent tool is Apache-2.0.
   Matching the norm removes a question from the buyer's mind.

## Keeping monetization options open (without hurting adoption)

You can stay permissive now and still monetize later:
- **Open-core / dual license:** offer the Apache-2.0 project free, and sell a
  separate **commercial license** (indemnity, support, private features) to
  enterprises that want it. This requires you to control contribution rights —
  add a lightweight **DCO** (`Signed-off-by`) or a CLA so you retain the option.
- **Don't** switch the base to AGPL/BSL to force payment — for a local tool it
  mostly just blocks free adopters you'd never have charged anyway.

## Recommended setup (action items)

1. **Keep** `LICENSE` = Apache-2.0 (code), `LICENSE-DOCS` = CC BY 4.0 (docs). ✅ already in place.
2. **Add a `NOTICE` file** (Apache convention): project name, copyright line, and the dual-license note. Corporate scanners look for it.
3. **Add SPDX headers** to source files: `# SPDX-License-Identifier: Apache-2.0` — makes automated license scanning trivial (a frequent enterprise gate).
4. **Add a DCO** (`CONTRIBUTING.md` "sign off with `git commit -s`") to preserve future dual-licensing optionality. Lighter than a CLA.
5. **Methodology repo licensing:** `Cyber-Elders/elder-mind` carries the canonical CC BY 4.0 legalcode and GitHub auto-detects `CC-BY-4.0`. ✅ resolved.
6. State the split plainly in the README "License" section (already done) so a reviewer sees it in 5 seconds.

## One-line answer for a corporate evaluator

> "Elder Mind's code is **Apache-2.0** (permissive, with a patent grant) and its
> docs are **CC BY 4.0** — the same licensing as MCP, LangChain, and the Microsoft
> Agent Governance Toolkit. No copyleft, no source-available restrictions, nothing
> phones home. Adopt it like any other Apache-2.0 dev dependency."
