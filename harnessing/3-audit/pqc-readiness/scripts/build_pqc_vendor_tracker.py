#!/usr/bin/env python3
"""build_pqc_vendor_tracker.py — vendor/dependency PQC roadmap tracker
(plan v1.3 Phase 3 handoff, delegated/blocked-external class).

Merges the curated registry (<results-root>/pqc/inputs/vendor-registry.json —
dated, reviewable status claims; curated org data, so it lives in the corpus,
not in this repo) with live fleet counts:
  * graph `uses_crypto_dep` edges → repos-depending counts per vendor
  * readiness reports → blocked-external repos and delegated-dominant count

Output: progress-tracker/metrics/dashboards/pqc/pqc-vendor-roadmap.{md,json}
Re-run whenever the registry is reviewed or reports change; counts are
deterministic, status text is curated (each row carries last_reviewed).

Usage: build_pqc_vendor_tracker.py [--results-root PATH] [--config-home PATH]
"""

import argparse
import collections
import datetime
import json
import os
import sqlite3
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
STATUS_ORDER = {"none": 0, "in-progress": 1, "partial": 2, "available": 3}
STATUS_MARK = {
    "none": "✗ none",
    "in-progress": "… in-progress",
    "partial": "◐ partial",
    "available": "✓ available",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()
    results = resolve_results_root(args)
    engine = load_engine(args.config_home)
    out = (
        args.out_dir.resolve()
        if args.out_dir
        else progress_tracker_dir(engine) / "metrics" / "dashboards" / "pqc"
    )
    out.mkdir(parents=True, exist_ok=True)
    # The vendor registry is CURATED ORG DATA, not a skill asset: its 16
    # vendors are the ones our fleet depends on, graph_deps names match our
    # portfolio graph, and last_reviewed is our review cadence with our
    # maintainer behind it. It therefore lives in the corpus beside the
    # findings it describes, resolved the same way portfolio-graph.db is.
    # Override with PQC_VENDOR_REGISTRY; absent, say so rather than crash.
    reg_path = (
        Path(os.environ["PQC_VENDOR_REGISTRY"])
        if os.environ.get("PQC_VENDOR_REGISTRY")
        else results / "pqc" / "inputs" / "vendor-registry.json"
    )
    if not reg_path.is_file():
        print(
            f"[!] vendor registry not found: {reg_path}\n"
            f"    Set PQC_VENDOR_REGISTRY, or place it at "
            f"<results-root>/pqc/inputs/vendor-registry.json.",
            file=sys.stderr,
        )
        return 1
    reg = json.loads(reg_path.read_text(encoding="utf-8"))

    # fleet counts: graph crypto-dep edges per vendor's graph_deps prefixes
    dep_repos: dict[str, set] = collections.defaultdict(set)
    gdb = results / "graph" / "portfolio-graph.db"
    if gdb.exists():
        con = sqlite3.connect(gdb)
        for src, dst in con.execute("SELECT src, dst FROM edges WHERE rel='uses_crypto_dep'"):
            lib = dst.split(":", 1)[1].rsplit("@", 1)[0]
            dep_repos[lib].add(src)
        con.close()
    blocked = sorted(
        f.parent.name
        for f in (results / "pqc").glob("*/*-pqc-readiness.json")
        if json.loads(f.read_text()).get("readiness_bucket") == "blocked-external"
    )

    rows = []
    for v in reg["vendors"]:
        repos = set()
        for d in v.get("graph_deps") or []:
            for lib, rs in dep_repos.items():
                if lib == d or lib.startswith(d):
                    repos |= rs
        rows.append({**v, "fleet_repos_via_graph": len(repos)})
    rows.sort(key=lambda r: (STATUS_ORDER[r["pqc_status"]], -r["fleet_repos_via_graph"]))

    today = datetime.date.today().isoformat()
    L = [
        "# PQC Vendor / Dependency Roadmap Tracker",
        "",
        f"**Generated:** {today} · registry v{reg['version']} "
        f"(curated status claims dated per row — re-verify before external "
        f"use) · fleet counts from the portfolio graph + readiness reports",
        "",
        "The delegated/blocked-external class: crypto the fleet cannot fix "
        "locally. Sorted worst-first.",
        "",
        "| Vendor / dependency | Class | PQC status | Fleet repos (graph) "
        "| Watch signal | Reviewed |",
        "|---|---|---|---:|---|---|",
    ]
    for r in rows:
        L.append(
            f"| **{r['name']}** | {r['class']} "
            f"| {STATUS_MARK[r['pqc_status']]} "
            f"| {r['fleet_repos_via_graph'] or '—'} "
            f"| {r['watch']} | {r['last_reviewed']} |"
        )
    L += ["", "## Status notes", ""]
    for r in rows:
        L.append(f"- **{r['name']}** — {r['status_note']}")
    L += [
        "",
        f"## blocked-external repos ({len(blocked)})",
        "",
        ", ".join(f"`{b}`" for b in blocked),
        "",
        "*Registry: `<results-root>/pqc/inputs/vendor-registry.json` "
        "(edit + re-run `build_pqc_vendor_tracker.py`). Sidecar: "
        "`pqc-vendor-roadmap.json`.*",
    ]
    (out / "pqc-vendor-roadmap.md").write_text("\n".join(L) + "\n")
    (out / "pqc-vendor-roadmap.json").write_text(
        json.dumps(
            {
                "generated": today,
                "registry_version": reg["version"],
                "vendors": rows,
                "blocked_external": blocked,
            },
            indent=1,
        )
        + "\n"
    )
    print(
        f"[+] wrote {out / 'pqc-vendor-roadmap.md'} "
        f"({len(rows)} vendors, {len(blocked)} blocked-external repos)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
