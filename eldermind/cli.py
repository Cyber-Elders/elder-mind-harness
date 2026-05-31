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
    n.add_argument("tool", nargs="?", choices=["claude-code", "opencode", "kiro"], help="harness (prompted if omitted)")
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
    i.add_argument("tool", choices=["claude-code", "opencode", "kiro"])
    i.add_argument("--dir", help="project dir to install into (default: cwd)")
    i.add_argument("--supplychain", action="store_true", help="enable supply-chain protection")
    i.set_defaults(func=cmd_install)

    sc = sub.add_parser("scan", help="supply-chain check (OSV) for an install command or lockfile")
    sc.add_argument("target", help="'npm install pkg@ver' / 'pip install pkg==ver' / path to a lockfile")
    sc.set_defaults(func=cmd_scan)

    s = sub.add_parser("summary", help="print audit aggregate metrics")
    s.add_argument("--path", help="path to audit.jsonl (default: auto-resolve)")
    s.set_defaults(func=cmd_summary)

    sv = sub.add_parser("serve", help="run the advisory MCP server")
    sv.set_defaults(func=cmd_serve)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
