#!/usr/bin/env python3
"""Scoped advisory fetcher — the ONLY network egress impact-analysis
may use (audit D7, remediation plan P1.6).

Replaces a raw Bash(curl:*) grant: under prompt injection a general curl
is an arbitrary-destination exfiltration channel; this script can reach
exactly the advisory hosts named in config/feeds.yaml, with default TLS
verification, and nothing else.

SOURCES ARE CONFIG, EGRESS IS NOT. The source list is generated from the
registry so adding one is a config change — but the resolved URL's host
is re-checked against an allowlist derived from that same registry
before any request. Write access to config/feeds.yaml must not become
request forgery against an arbitrary host, the same reason
config/external-tools.yaml carries a binary allowlist.

Usage:
  fetch_advisory.py <source> <ident> [--ecosystem ECO]

  osv             <package-name>   [--ecosystem npm|Go|PyPI|...]
  nvd             <CVE-ID>
  vex             <CVE-ID>         Red Hat per-product impact status
  redhat-csaf     <RHSA-ID>        NOT CVE-keyed — use vex for a CVE
  ossf-scorecard  <host/org/repo>

Prints the JSON response to stdout. Exit 1 on HTTP/network failure,
2 on usage errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

_HARNESS_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_HARNESS_SRC) not in sys.path:  # skill scripts run outside the venv
    sys.path.insert(0, str(_HARNESS_SRC))

from traust.registry import feeds_config as fc  # noqa: E402

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
RHSA_RE = re.compile(r"^RH[SBE]A-\d{4}[:_]\d{4,}$", re.IGNORECASE)
REPO_RE = re.compile(r"^[A-Za-z0-9.-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

_IDENT_RULES = {
    "cve": (CVE_RE, "not a CVE id"),
    "rhsa": (RHSA_RE, "not an RHSA/RHBA/RHEA id"),
    "repo": (REPO_RE, "not a host/org/repo path"),
}


def _sources() -> dict[str, dict]:
    """Live sources plus the per-document-fetchable cached ones (vex)."""
    out = dict(fc.live_sources())
    for sid, spec in fc.cached_sources().items():
        if spec.get("doc_url_template"):
            out[sid] = spec
    return out


def _allowed_hosts(sources: dict[str, dict]) -> set[str]:
    hosts = set()
    for spec in sources.values():
        for key in ("url_template", "doc_url_template"):
            tpl = spec.get(key)
            if tpl:
                hosts.add(urllib.parse.urlsplit(tpl).netloc)
    return hosts


def _get(url: str, allowed: set[str], data: bytes | None = None) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in allowed:
        raise ValueError(
            f"refusing to fetch {parts.scheme}://{parts.netloc} — not an "
            f"allowlisted advisory host ({', '.join(sorted(allowed))})"
        )
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "traust-impact-analysis",
            **({"Content-Type": "application/json"} if data else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # default TLS verify
        return resp.read().decode("utf-8", errors="replace")


def main(argv=None) -> int:
    try:
        sources = _sources()
    except fc.FeedsConfigError as e:
        print(f"fetch_advisory: {e}", file=sys.stderr)
        return 1
    allowed = _allowed_hosts(sources)

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("source", choices=sorted(sources))
    ap.add_argument("ident")
    ap.add_argument("--ecosystem", default="Go")
    args = ap.parse_args(argv)

    spec = sources[args.source]
    kind = spec.get("ident")
    rule = _IDENT_RULES.get(kind)
    if rule and not rule[0].fullmatch(args.ident):
        ap.error(f"{rule[1]}: {args.ident}")

    try:
        if spec.get("method") == "POST":
            body = json.dumps(
                {"package": {"name": args.ident, "ecosystem": args.ecosystem}}
            ).encode()
            out = _get(spec["url_template"], allowed, data=body)
        elif spec.get("doc_url_template"):
            ident = args.ident.lower()
            out = _get(
                spec["doc_url_template"].format(year=ident.split("-")[1], ident_lower=ident),
                allowed,
            )
        else:
            out = _get(fc.resolve_url(spec, args.ident), allowed)
    except ValueError as e:
        print(f"fetch_advisory: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"fetch_advisory: {e}", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
