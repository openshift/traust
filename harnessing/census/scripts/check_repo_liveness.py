#!/usr/bin/env python3
"""Repo liveness sweep — archive-awareness for the corpus (Phase 7 of
progress-tracker/plans/metrics-improvement-plan.md).

Sweeps the repo population from the repo-graph spine and records one
liveness status per repository:

    active    repo exists, not archived
    archived  read-only on GitHub (still clonable, still scannable —
              scanning skills record this, they never skip on it)
    moved     repo redirects to a new location (recorded in `moved_to`)
    missing   404 — deleted or made private
    unknown   non-GitHub host (recorded, never silently dropped)

GitHub does not expose an archived-at timestamp, so `status_since`
ratchets: the first sweep that observed the current status keeps its
date across re-runs (merge with the previous artifact). Re-run on the
census cadence — archival happens after inventory intake, so
`/add-inputs`' intake-time filtering cannot catch it.

This is population METADATA, one collector with many consumers (census
population block, audit metadata stamps, threat-model likelihood
evidence, verify-remediation sweep flags, dashboard segmentation, graph
node attrs, owner-routing guards — see the plan phase). Consumers read
the artifact; none re-queries GitHub.

Usage:
    check_repo_liveness.py --spine <repo-graph.json>
        [--out <repo-liveness.json>] [--jobs N] [--limit N]

Exit 0 on a completed sweep (API errors are counted per repo, not
fatal); 2 on usage errors.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_GH_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def gh_repo_info(org: str, name: str) -> dict:
    """One `gh api` call → raw status fields. Separated for testability."""
    # CSV-derived org/name become an API path — constrain so a crafted
    # row can't traverse into another endpoint (plan P3)
    if not (_GH_NAME_RE.fullmatch(org) and _GH_NAME_RE.fullmatch(name)):
        return {"error": f"unsafe org/name: {org}/{name}"}
    proc = subprocess.run(
        ["gh", "api", f"repos/{org}/{name}", "--jq", "{full_name, archived, disabled, pushed_at}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode == 0:
        try:
            return {"ok": True, **json.loads(proc.stdout)}
        except json.JSONDecodeError:
            return {"ok": False, "error": "unparseable"}
    if "404" in proc.stderr or "Not Found" in proc.stderr:
        return {"ok": False, "error": "404"}
    return {"ok": False, "error": proc.stderr.strip()[:120] or "api-error"}


def classify(requested: str, info: dict) -> dict:
    """requested = 'org/name'. → {status, moved_to?, pushed_at?, ...}."""
    if not info.get("ok"):
        if info.get("error") == "404":
            return {"status": "missing"}
        return {"status": "error", "error": info.get("error")}
    entry = {"pushed_at": info.get("pushed_at")}
    full = info.get("full_name") or requested
    if full.lower() != requested.lower():
        entry["moved_to"] = full
        # a moved repo may also be archived at its new home
        entry["status"] = "moved-archived" if info.get("archived") else "moved"
        return entry
    entry["status"] = "archived" if info.get("archived") else "active"
    if info.get("disabled"):
        entry["disabled"] = True
    return entry


def merge_status_since(current: dict, previous: dict, today: str) -> None:
    """Ratchet: keep the first-observed date when the status is unchanged."""
    for url, entry in current.items():
        prev = previous.get(url)
        if prev and prev.get("status") == entry.get("status") and prev.get("status_since"):
            entry["status_since"] = prev["status_since"]
        else:
            entry["status_since"] = today


def sweep(
    spine_path: Path, out_path: Path, jobs: int, limit: int | None, fetch=gh_repo_info
) -> dict:
    spine = json.loads(spine_path.read_text())
    repos = [n for n in spine["nodes"] if n["type"] == "repo"]
    if limit:
        repos = repos[:limit]

    def work(node):
        a = node.get("attrs") or {}
        url = a.get("url") or node["id"].removeprefix("repo:")
        if a.get("host") != "github.com" or not a.get("org") or not a.get("name"):
            return url, {"status": "unknown", "host": a.get("host")}
        requested = f"{a['org']}/{a['name']}"
        return url, classify(requested, fetch(a["org"], a["name"]))

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = dict(pool.map(work, repos))

    previous = {}
    if out_path.is_file():
        try:
            previous = json.loads(out_path.read_text()).get("repos", {})
        except (json.JSONDecodeError, OSError):
            previous = {}
    today = datetime.date.today().isoformat()
    merge_status_since(results, previous, today)

    counts: dict[str, int] = {}
    for e in results.values():
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    artifact = {
        "artifact": "repo-liveness",
        "role": (
            "population metadata — which repos can still act on "
            "findings; consumers read this file, never re-query"
        ),
        "generated": today,
        "source_spine": str(spine_path),
        "counts": dict(sorted(counts.items())),
        "repos": {u: results[u] for u in sorted(results)},
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(artifact, indent=2))
    return artifact


def render_md(artifact: dict) -> str:
    lines = [
        "# Repo Liveness (archive-awareness)",
        "",
        f"Generated {artifact['generated']} from `{artifact['source_spine']}`.",
        "",
        "| Status | Repos |",
        "|---|---|",
    ]
    lines += [f"| {s} | {c} |" for s, c in artifact["counts"].items()]
    non_active = [
        (u, e)
        for u, e in artifact["repos"].items()
        if e["status"] not in ("active", "unknown", "error")
    ]
    lines += [
        "",
        "## Non-active repos",
        "",
        "| Repo | Status | Since | Detail |",
        "|---|---|---|---|",
    ]
    for url, e in non_active:
        detail = e.get("moved_to") or (e.get("pushed_at") or "")[:10]
        lines.append(
            f"| {url.removeprefix('https://')} | {e['status']} | "
            f"{e.get('status_since', '')} | {detail} |"
        )
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sweep repo liveness (active/archived/moved/missing).")
    ap.add_argument("--spine", required=True, help="repo-graph.json (the repo population).")
    ap.add_argument(
        "--out",
        default="repo-liveness.json",
        help="Artifact path; previous artifact at the same path seeds status_since ratcheting.",
    )
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--limit", type=int)
    args = ap.parse_args(argv)

    spine = Path(args.spine)
    if not spine.is_file():
        print(f"spine not found: {spine} — run /repo-graph first", file=sys.stderr)
        return 2
    out = Path(args.out)
    artifact = sweep(spine, out, args.jobs, args.limit)
    md_path = out.with_suffix(".md")
    md_path.write_text(render_md(artifact))
    print(f"repo-liveness: {artifact['counts']} → {out} (+ {md_path.name})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
