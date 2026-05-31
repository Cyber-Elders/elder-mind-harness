"""
Supply-chain protection — dynamic compromised/vulnerable dependency detection.

Detects package-install commands in a tool call, extracts (ecosystem, name,
version), and checks them — DYNAMICALLY, not against a hand-maintained list:

  Tier 1 (authoritative, online): query the OSV.dev API
          POST https://api.osv.dev/v1/query  (free, no rate limit, <=15-min
          fresh, covers npm/PyPI/crates.io/Go/RubyGems/... and the OpenSSF
          malicious-packages feed). 5s timeout, stdlib urllib (no hard dep).
  Tier 2 (offline fallback): a small bundled blocklist.json snapshot, so the
          gate still catches headline incidents with the wifi off.

This is the one part of the harness that may touch the network, so it lives
OUTSIDE the deterministic decide() path and is invoked explicitly by the CLI /
hook layer only when supply-chain protection is enabled. Offline, it degrades
to the static snapshot and says so (status "unknown" for anything not listed).

`osv-scanner` (the OSV CLI) is used by `eldermind scan <lockfile>` when present
for full lockfile scanning; it is an optional external binary, never required.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

OSV_API = "https://api.osv.dev/v1/query"
DEPSDEV_API = "https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{version}"
_TIMEOUT = 5  # seconds

# OSV ecosystem -> deps.dev system (for release-date lookups). Others unsupported.
_DEPSDEV_SYSTEM = {"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "Go": "go", "Packagist": None, "RubyGems": None}

# package-manager install/add verbs -> OSV ecosystem
_INSTALLERS = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "pip": "PyPI",
    "pip3": "PyPI",
    "uv": "PyPI",
    "poetry": "PyPI",
    "pipx": "PyPI",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
    "go": "Go",
}
_INSTALL_VERBS = {"install", "add", "i", "get"}


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str | None  # None = unpinned


@dataclass(frozen=True)
class ScanResult:
    package: Package
    status: str  # malicious | vulnerable | clean | unknown
    detail: str
    source: str  # osv-api | blocklist | none


def _strip_subshell(command: str) -> list[str]:
    """Return inner command(s) for `bash -c "…"` / `sh -c '…'` so install
    commands hidden inside a subshell are still inspected. Returns [command]
    if there is no subshell wrapper."""
    m = re.search(r"""\b(?:bash|sh|zsh)\s+-c\s+(['"])(.+?)\1""", command)
    if m:
        return [command, m.group(2)]
    return [command]


def _split_name_version(token: str, ecosystem: str) -> Package | None:
    token = token.strip()
    if not token or token.startswith("-"):
        return None
    name, version = token, None
    if ecosystem == "npm":
        # scoped @scope/name@version vs name@version
        if token.startswith("@"):
            at = token.rfind("@")
            if at > 0:
                name, version = token[:at], token[at + 1 :]
        elif "@" in token:
            name, version = token.split("@", 1)
    elif ecosystem == "PyPI":
        m = re.split(r"==|>=|<=|~=|!=|@", token, maxsplit=1)
        if len(m) == 2:
            name = m[0]
            version = m[1] if "==" in token else None  # only exact pins are checkable
    elif ecosystem == "crates.io":
        if "@" in token:
            name, version = token.split("@", 1)
    return Package(ecosystem=ecosystem, name=name.strip(), version=(version.strip() if version else None))


def parse_install_commands(command: str) -> list[Package]:
    """Extract packages from any install/add command in the (possibly
    subshell-wrapped) command string."""
    packages: list[Package] = []
    for cmd in _strip_subshell(command):
        tokens = cmd.replace("&&", " ").replace(";", " ").split()
        i = 0
        while i < len(tokens):
            tool = tokens[i].split("/")[-1]  # handle absolute paths
            eco = _INSTALLERS.get(tool)
            if eco and i + 1 < len(tokens):
                verb = tokens[i + 1]
                if verb in _INSTALL_VERBS or (tool == "go" and verb == "get"):
                    for tok in tokens[i + 2 :]:
                        if tok.startswith("-"):
                            continue
                        pkg = _split_name_version(tok, eco)
                        if pkg and pkg.name:
                            packages.append(pkg)
            i += 1
    return packages


def _query_osv(pkg: Package) -> ScanResult | None:
    """Tier 1: query the OSV API. Returns None on any network/parse failure."""
    body: dict = {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
    if pkg.version:
        body["version"] = pkg.version
    data = json.dumps(body).encode()
    req = urllib.request.Request(OSV_API, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    vulns = payload.get("vulns", []) or []
    if not vulns:
        return ScanResult(pkg, "clean", "no known OSV advisories", "osv-api")
    malicious = any("MAL-" in (v.get("id", "")) for v in vulns)
    ids = ", ".join(v.get("id", "?") for v in vulns[:3])
    status = "malicious" if malicious else "vulnerable"
    return ScanResult(pkg, status, f"OSV: {ids}", "osv-api")


def _load_blocklist() -> list[dict]:
    path = Path(__file__).resolve().parent / "blocklist.json"
    try:
        return (json.loads(path.read_text()) or {}).get("entries", [])
    except (OSError, ValueError):
        return []


def _check_blocklist(pkg: Package) -> ScanResult:
    """Curated local list. Only an EXACT pinned-version match is a hard hit —
    we never blanket-block a package name (e.g. all of `chalk`). Unmatched
    returns 'unknown' so the caller can fall back to OSV / report offline."""
    for entry in _load_blocklist():
        if entry.get("ecosystem") == pkg.ecosystem and entry.get("name", "").lower() == pkg.name.lower():
            versions = entry.get("versions", [])
            if pkg.version and pkg.version in versions:
                return ScanResult(pkg, "malicious", f"blocklist: {entry.get('reason', '')}", "blocklist")
    return ScanResult(pkg, "unknown", "not in curated blocklist", "blocklist")


def check_package(pkg: Package) -> ScanResult:
    """Curated blocklist is a HARD local override (defense in depth — catches
    known-bad versions even if OSV hasn't flagged them); otherwise OSV API is
    authoritative; offline -> 'unknown'.

      curated malicious  ->  malicious (override, no network needed)
      else OSV reachable ->  OSV verdict (clean / vulnerable / malicious)
      else (offline)     ->  unknown
    """
    bl = _check_blocklist(pkg)
    if bl.status == "malicious":
        return bl
    osv = _query_osv(pkg)
    if osv is not None:
        return osv
    return ScanResult(pkg, "unknown", "offline: not in curated blocklist and OSV API unreachable", "blocklist")


def release_age_days(pkg: Package) -> int | None:
    """Age (days) of this exact version per deps.dev, or None if unknown
    (offline, unsupported ecosystem, unpinned version, or no publish date).
    The one network call is in the dynamic layer, like the OSV check."""
    system = _DEPSDEV_SYSTEM.get(pkg.ecosystem)
    if not system or not pkg.version:
        return None
    from datetime import datetime, timezone
    from urllib.parse import quote
    url = DEPSDEV_API.format(system=system, name=quote(pkg.name, safe=""), version=quote(pkg.version, safe=""))
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    published = payload.get("publishedAt") or payload.get("version", {}).get("publishedAt")
    if not published:
        return None
    try:
        ts = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, (datetime.now(timezone.utc) - ts).days)


def scan_command(command: str) -> list[ScanResult]:
    """Parse install commands out of a shell command and check each package.
    Returns [] when nothing installable is found."""
    return [check_package(p) for p in parse_install_commands(command)]


def worst(results: list[ScanResult]) -> ScanResult | None:
    """Return the most severe result (malicious > vulnerable > unknown > clean)."""
    if not results:
        return None
    rank = {"malicious": 3, "vulnerable": 2, "unknown": 1, "clean": 0}
    return max(results, key=lambda r: rank.get(r.status, 0))


def scan_lockfile(path: str) -> dict:
    """`eldermind scan <lockfile>`: use osv-scanner if installed, else report
    that it is unavailable. Lockfile scanning is the one place the external
    osv-scanner binary helps; it is optional."""
    if shutil.which("osv-scanner"):
        try:
            proc = subprocess.run(
                ["osv-scanner", "--format", "json", "--lockfile", path],
                capture_output=True, text=True, timeout=120,
            )
            return {"tool": "osv-scanner", "exit": proc.returncode, "report": proc.stdout}
        except (subprocess.SubprocessError, OSError) as exc:
            return {"tool": "osv-scanner", "error": str(exc)}
    return {
        "tool": None,
        "error": "osv-scanner not installed; install it for full lockfile scanning "
                 "(https://github.com/google/osv-scanner), or scan single packages via the gate.",
    }
