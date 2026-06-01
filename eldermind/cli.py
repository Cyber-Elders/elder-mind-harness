# SPDX-License-Identifier: Apache-2.0
"""
eldermind CLI — the universal hook target.

Every harness adapter ultimately shells out to:

    eldermind check '<json>'        # or pipe the JSON on stdin

It prints the Decision JSON to stdout and sets the exit code:
    0  -> allow / warn   (proceed)
    2  -> ask  / block   (stop and surface to the user)

Other subcommands:
    eldermind init <claude-code|opencode|kiro>   # guided install
    eldermind scan <pkg-install-cmd|lockfile>    # supply-chain check (OSV)
    eldermind summary        # audit aggregate (NIST MEASURE)
    eldermind serve          # run the MCP server (needs [mcp] extra)
    eldermind version
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .audit import record, summary


def _read_request(arg: str | None) -> dict:
    """Read the decision request from an arg or stdin."""
    raw = arg if arg else sys.stdin.read()
    raw = (raw or "").strip()
    if not raw:
        return {}
    return json.loads(raw)


def cmd_check(args: argparse.Namespace) -> int:
    try:
        request = _read_request(args.request)
    except json.JSONDecodeError as exc:
        # Fail-safe: a malformed request becomes an "ask" rather than silent allow.
        out = {
            "verdict": "ask",
            "reason": f"malformed request JSON: {exc}",
            "rule_id": None,
            "asi": None,
            "risk": {},
            "suggest": "ask",
            "decision_id": "EM-malformed",
            "policy_version": "n/a",
        }
        print(json.dumps(out))
        return 2

    from .gate import evaluate_json

    decision = evaluate_json(request, policy=args.policy)
    if not args.no_audit:
        try:
            record(decision, outcome="decided", context=request.get("context", {}))
        except OSError:
            pass  # never let an audit-write failure block the gate decision
    print(json.dumps(decision))
    return 0 if decision["verdict"] in ("allow", "warn") else 2


def cmd_hook(args: argparse.Namespace) -> int:
    from .harness import run_hook

    return run_hook(args.tool, sys.stdin.read())


def cmd_scan(args: argparse.Namespace) -> int:
    import os

    from .supplychain import scan_command, scan_lockfile, worst

    target = args.target
    if os.path.isfile(target):
        print(json.dumps(scan_lockfile(target), indent=2))
        return 0
    # else treat the arg as an install command, e.g. "npm install axios@1.14.1"
    results = scan_command(target)
    if not results:
        print(json.dumps({"note": "no installable package parsed; pass a lockfile path "
                                   "or an install command like 'npm install pkg@version'"}))
        return 0
    out = [
        {"package": r.package.name, "version": r.package.version, "ecosystem": r.package.ecosystem,
         "status": r.status, "detail": r.detail, "source": r.source}
        for r in results
    ]
    print(json.dumps(out, indent=2))
    w = worst(results)
    return 2 if (w and w.status in ("malicious", "vulnerable")) else 0


def cmd_install(args: argparse.Namespace) -> int:
    from .install import install

    return install(args.tool, target_dir=args.dir, supplychain=args.supplychain)


def cmd_init(args: argparse.Namespace) -> int:
    from .install import guided_init

    return guided_init(tool=args.tool, target_dir=args.dir)


def cmd_summary(args: argparse.Namespace) -> int:
    print(json.dumps(summary(args.path), indent=2))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    from .audit import read_events

    matches = [e for e in read_events() if e.get("decision_id") == args.decision_id]
    if not matches:
        print(f"No audit entry found for {args.decision_id}")
        return 1
    e = matches[-1]  # latest occurrence
    print(f"Decision {e.get('decision_id')}  ({e.get('ts')})")
    print(f"  verdict : {e.get('verdict')}   outcome: {e.get('outcome')}")
    print(f"  rule    : {e.get('rule_id')}   ASI: {e.get('asi')}   score: {e.get('score')}/25 ({e.get('tier')})")
    print(f"  reason  : {e.get('reason')}")
    ctx = e.get("context") or {}
    if ctx:
        print(f"  context : {json.dumps(ctx)}")
    print(f"\n  Seen {len(matches)} time(s) in the audit log.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from .audit import verify

    r = verify(args.path)
    if r["ok"]:
        print(f"✓ audit chain intact — {r['entries']} entr{'y' if r['entries']==1 else 'ies'}")
        return 0
    print(f"✗ audit chain BROKEN at entry {r['broken_at']} of {r['entries']}: {r['reason']}")
    return 2


def cmd_pin(args: argparse.Namespace) -> int:
    from .pinning import check, list_pins, reset

    if args.pin_cmd == "list":
        pins = list_pins()
        if not pins:
            print("no pinned tools yet")
            return 0
        for name, e in sorted(pins.items()):
            print(f"  {name:30} {e.get('hash')}")
        return 0
    if args.pin_cmd == "reset":
        ok = reset(args.name)
        print(f"{'reset' if ok else 'no pin for'} {args.name}")
        return 0
    if args.pin_cmd == "check":
        import json as _json
        desc = _json.loads(args.descriptor)
        r = check(args.name, desc)
        print(_json.dumps({"status": r.status, "tool": r.name, "hash": r.hash, "previous": r.previous}))
        return 0 if r.status in ("new", "ok") else 2
    return 1


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        from .server import run
    except ImportError:
        sys.stderr.write(
            "MCP server requires the [mcp] extra: pip install 'eldermind[mcp]'\n"
        )
        return 1
    run()
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eldermind", description="Elder Mind — local-first agentic governance harness.")
    sub = p.add_subparsers(dest="command", required=True)

    n = sub.add_parser("init", help="guided install (interactive wizard)")
    n.add_argument("tool", nargs="?", choices=["claude-code", "opencode", "kiro", "cursor"], help="harness (prompted if omitted)")
    n.add_argument("--dir", help="project dir to install into (default: cwd)")
    n.set_defaults(func=cmd_init)

    c = sub.add_parser("check", help="evaluate a tool call (the hook target)")
    c.add_argument("request", nargs="?", help="decision request JSON (or pipe on stdin)")
    c.add_argument("--policy", help="path to a policy.yaml (default: auto-resolve)")
    c.add_argument("--no-audit", action="store_true", help="do not write an audit entry")
    c.set_defaults(func=cmd_check)

    h = sub.add_parser("hook", help="translate a harness pre-tool event (internal)")
    h.add_argument("tool", choices=["claude-code", "opencode", "kiro"])
    h.set_defaults(func=cmd_hook)

    i = sub.add_parser("install", help="wire the harness into a tool (non-interactive)")
    i.add_argument("tool", choices=["claude-code", "opencode", "kiro", "cursor"])
    i.add_argument("--dir", help="project dir to install into (default: cwd)")
    i.add_argument("--supplychain", action="store_true", help="enable supply-chain protection")
    i.set_defaults(func=cmd_install)

    sc = sub.add_parser("scan", help="supply-chain check (OSV) for an install command or lockfile")
    sc.add_argument("target", help="'npm install pkg@ver' / 'pip install pkg==ver' / path to a lockfile")
    sc.set_defaults(func=cmd_scan)

    s = sub.add_parser("summary", help="print audit aggregate metrics")
    s.add_argument("--path", help="path to audit.jsonl (default: auto-resolve)")
    s.set_defaults(func=cmd_summary)

    e = sub.add_parser("explain", help="explain a past decision by its id (from the audit log)")
    e.add_argument("decision_id", help="e.g. EM-2169fd82a466")
    e.set_defaults(func=cmd_explain)

    vf = sub.add_parser("verify", help="verify the audit chain is intact (tamper-evident)")
    vf.add_argument("--path", help="path to audit.jsonl (default: auto-resolve)")
    vf.set_defaults(func=cmd_verify)

    p_ = sub.add_parser("pin", help="pin tool/MCP descriptors and detect drift (rug-pulls)")
    psub = p_.add_subparsers(dest="pin_cmd", required=True)
    psub.add_parser("list", help="list pinned tools")
    pr = psub.add_parser("reset", help="forget a pin (re-trust on next sight)")
    pr.add_argument("name")
    pc = psub.add_parser("check", help="check a descriptor against its pin")
    pc.add_argument("name")
    pc.add_argument("descriptor", help="descriptor JSON")
    p_.set_defaults(func=cmd_pin)

    sv = sub.add_parser("serve", help="run the advisory MCP server")
    sv.set_defaults(func=cmd_serve)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)

    return p


def _force_utf8() -> None:
    """Windows consoles default to cp1252, which can't encode the verdict
    glyphs (✓ ⛔ ⚠ · →) — printing them raises UnicodeEncodeError and would
    CRASH the gate. Reconfigure stdout/stderr to UTF-8 (replace on the rare
    terminal that still can't render a glyph) so the harness never dies on output."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # py3.7+
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
