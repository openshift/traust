#!/usr/bin/env python3
"""Status-aware ADR index from pinned registers (compliance Phase 2c).

Reads every register in adr-registry.yaml AT ITS PINNED SHA (tree via
the GitHub API, file bodies via raw.githubusercontent — both pinned, so
the index is reproducible) and emits
progress-tracker/metrics/adr/adr-index.json:

    registers[]: {name, repo, pin, decisions[]:
        {id, title, status, path, url}}

Status matters more than most metadata here: **a superseded decision
cited as current compliance evidence is an error**, so the parser
extracts MADR/status lines (accepted / proposed / superseded /
deprecated / rejected), infers `archived` for archives/ paths, and
records `unknown` rather than guessing when no status line exists —
the citation gate treats superseded/deprecated/archived as
non-citable for `satisfied` verdicts and can be configured to warn on
`unknown`.

The index is a derived, committed artifact (small, and its git history
shows decision drift over time). Refresh on consumer runs or when
/drift-watch reports a pin behind upstream; advancing pins stays a
deliberate registry change — this script NEVER moves a pin.

Usage:
    python3 -m traust.cli.index_adrs [--registry <yaml>] [--out <json>]
        [--register <name>]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from traust.context import add_config_home_arg, load_engine, progress_tracker_dir

try:
    import yaml
except ImportError:
    yaml = None

STATUS_RX = re.compile(
    r"(?im)^\s*(?:[-*#>\s]*status\s*[:*]*\s*)"
    r"[\"'`\[\s]*(accepted|proposed|superseded|deprecated|rejected|"
    r"approved|draft)"
)
TITLE_RX = re.compile(r"(?m)^#\s+(.{3,120})$")
DOC_EXTS = (".md", ".adoc")
SKIP_NAMES = ("template", "readme", "guideline", "index")


def _github_repo(url: str) -> str | None:
    m = re.search(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git|/|$)", url)
    return m.group(1) if m else None


def _tree(repo: str, pin: str) -> list[str]:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repo}/git/trees/{pin}?recursive=1", "--jq", ".tree[].path"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[:160] or "gh api failed")
    return proc.stdout.splitlines()


def _raw(repo: str, pin: str, path: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{repo}/{pin}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "traust-index-adrs"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read(262144).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def parse_decision(path: str, text: str | None) -> dict:
    status = "unknown"
    title = Path(path).stem
    if text:
        m = STATUS_RX.search(text)
        if m:
            s = m.group(1).lower()
            status = {"approved": "accepted", "draft": "proposed"}.get(s, s)
        t = TITLE_RX.search(text)
        if t:
            title = t.group(1).strip()
    if "/archives/" in path or path.split("/")[-2:-1] == ["archives"]:
        status = "archived"
    return {"id": Path(path).stem, "title": title, "status": status, "path": path}


def index_register(reg: dict) -> dict:
    repo = _github_repo(reg["repo"])
    if repo is None:
        return {
            "name": reg["name"],
            "repo": reg["repo"],
            "pin": reg["pin"],
            "error": "non-github repo — indexer extension needed",
            "decisions": [],
        }
    try:
        paths = _tree(repo, reg["pin"])
    except (RuntimeError, subprocess.SubprocessError, OSError) as e:
        return {
            "name": reg["name"],
            "repo": reg["repo"],
            "pin": reg["pin"],
            "error": str(e),
            "decisions": [],
        }
    decisions = []
    for p in sorted(paths):
        if not p.lower().endswith(DOC_EXTS):
            continue
        if not any(p.startswith(base.rstrip("/") + "/") for base in reg["paths"]):
            continue
        stem = Path(p).stem.lower()
        if any(s in stem for s in SKIP_NAMES):
            continue
        d = parse_decision(p, _raw(repo, reg["pin"], p))
        if reg.get("declared_status"):
            d["status"] = reg["declared_status"]
            d["status_source"] = "declared"
        d["url"] = f"https://github.com/{repo}/blob/{reg['pin']}/{p}"
        decisions.append(d)
    return {
        "name": reg["name"],
        "repo": reg["repo"],
        "pin": reg["pin"],
        "governs": reg.get("governs") or [],
        "decisions": decisions,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--registry", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--register", default=None, help="index just one register by name")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    tracker = progress_tracker_dir(engine)
    registry_path = args.registry or (tracker / "configs" / "compliance" / "adr-registry.yaml")
    out_path = args.out or (tracker / "metrics" / "adr" / "adr-index.json")
    if yaml is None:
        sys.exit("PyYAML required")
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))

    registers = []
    for reg in registry.get("registers") or []:
        if args.register and reg["name"] != args.register:
            continue
        r = index_register(reg)
        registers.append(r)
        n = len(r["decisions"])
        status_counts = {}
        for d in r["decisions"]:
            status_counts[d["status"]] = status_counts.get(d["status"], 0) + 1
        print(
            f"  {r['name']}: {n} decisions "
            + (
                f"({', '.join(f'{k}:{v}' for k, v in sorted(status_counts.items()))})"
                if n
                else f"— {r.get('error', 'empty')}"
            )
        )

    doc = {
        "metadata": {
            "artifact": "adr-index",
            "role": (
                "status-aware decision index from pinned "
                "registers; superseded/deprecated/archived "
                "decisions are non-citable for satisfied verdicts "
                "(compliance citation gate)"
            ),
            "registry": str(registry_path),
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "registers": registers,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    total = sum(len(r["decisions"]) for r in registers)
    errors = [r["name"] for r in registers if r.get("error")]
    print(
        f"wrote {out_path} — {total} decisions across "
        f"{len(registers)} registers" + (f"; errors: {', '.join(errors)}" if errors else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
