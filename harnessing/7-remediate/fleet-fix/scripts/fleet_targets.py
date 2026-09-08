#!/usr/bin/env python3
"""Resolve the affected-repo fleet for a /fleet-fix campaign (C5 step 1).

One deterministic command instead of operator grepping. Takes a pattern
identifier and emits the affected-repo list from the right source, then
enriches every target from repo-graph (product reach for ordering, owner
team for MR routing, repo URL):

    --cwe CWE-1104         insecure-patterns.json pattern repos list
                           (CWE-class fleets; disposition-aware, owned tree)
    --rollup <regex>       PROGRESS.md rows matching the rollup marker
                           (campaign cross-cutting patterns)
    --module <path>        portfolio-graph.db imports_package/depends_on
                           edges (dependency fleets: every repo importing
                           the module or any package under it). Matches the
                           Go `module:`/`srcpkg:` nodes AND the non-Go
                           `pkg:<eco>/<name>` nodes; pair with --ecosystem
                           for an unambiguous non-Go coordinate.
    --ecosystem <eco>      (with --module) restrict the match to one
                           ecosystem's `pkg:<eco>/<name>` node
                           (npm/pypi/maven/cargo/ruby/nuget/docker/actions/
                           helm). Without it a bare --module still resolves
                           non-Go consumers via any `pkg:%/<name>` node —
                           convenient, but a short name (e.g. `left-pad`)
                           can collide across ecosystems, so prefer
                           --ecosystem when the coordinate is non-Go.
    --repos org/a org/b    explicit passthrough

Enrichment is best-effort: targets missing from repo-graph keep
product_reach 0 / owner_team null and a github.com URL guess — they are
listed, never dropped. Output: fleet table on stdout + --out fleet JSON
consumed by the fleet-fix campaign dir.

CLI:
    python3 harnessing/7-remediate/fleet-fix/scripts/fleet_targets.py \
        (--cwe X | --rollup RX | --module M | --repos ...) \
        [--workspace-root WS] --out fleet.json
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

# Harness root: the directory holding VERSION, walked rather than counted.
# This was `Path(__file__).resolve().parents[2]`, which resolved to `harnessing/` and so pointed one
# level too shallow — the C8 script-placement migration moved this file
# into scripts/ and the count was never updated.
HARNESS = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())


# ---------------------------------------------------------------------------
# sources — each returns {"org/name": evidence-string}
# ---------------------------------------------------------------------------


def from_cwe(tracker: Path, cwe: str) -> dict[str, str]:
    p = tracker / "metrics" / "dashboards" / "insecure-patterns" / "insecure-patterns.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for pat in doc.get("patterns") or []:
        if (pat.get("cwe") or "").upper() != cwe.upper():
            continue
        for repo in pat.get("repos") or []:
            out[repo] = f"insecure-patterns {cwe} ({pat.get('name', '')[:60]})"
    return out


def from_rollup(results: Path, rollup_rx: str) -> dict[str, str]:
    p = results / "findings" / "_manifest" / "PROGRESS.md"
    rx = re.compile(rollup_rx, re.I)
    row_rx = re.compile(r"^\| \d+ \| ([^|\s]+) \|")
    out: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not rx.search(line):
            continue
        m = row_rx.match(line)
        if m and "/" in m.group(1):
            out[m.group(1)] = f"PROGRESS.md rollup match: /{rollup_rx}/"
    return out


def from_module(results: Path, module: str, ecosystem: str | None = None) -> dict[str, str]:
    """Repos whose graph edges import/depend on `module`.

    With --ecosystem: match ONLY that ecosystem's package node,
    `pkg:<eco>/<module>` — the precise, unambiguous form.

    Without it: the historical Go behaviour (the `module:`/`srcpkg:`
    node and its subpackages) is preserved byte-for-byte AND extended to
    match any ecosystem's `pkg:%/<module>` node, so a bare
    `--module left-pad` still finds npm/pypi/etc. consumers. A short name
    can collide across ecosystems under this LIKE — the ambiguity is by
    design; pass --ecosystem when the coordinate is non-Go.
    """
    db = results / "graph" / "portfolio-graph.db"
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    if ecosystem:
        rows = con.execute(
            """SELECT DISTINCT src FROM edges
               WHERE rel IN ('imports_package', 'depends_on')
                 AND dst = 'pkg:' || ? || '/' || ?
                 AND src LIKE 'repo:%'""",
            (ecosystem, module),
        ).fetchall()
        evidence = f"portfolio-graph imports/depends on pkg:{ecosystem}/{module}"
    else:
        rows = con.execute(
            """SELECT DISTINCT src FROM edges
               WHERE rel IN ('imports_package', 'depends_on')
                 AND (dst = 'module:' || ? OR dst = 'srcpkg:' || ?
                      OR dst LIKE 'srcpkg:' || ? || '/%'
                      OR dst LIKE 'pkg:%/' || ?)
                 AND src LIKE 'repo:%'""",
            (module, module, module, module),
        ).fetchall()
        evidence = f"portfolio-graph imports/depends on {module}"
    con.close()
    out: dict[str, str] = {}
    for (src,) in rows:
        host_path = src[len("repo:") :]
        parts = host_path.split("/", 1)
        label = parts[1] if len(parts) == 2 else host_path
        out[label] = evidence
    return out


# ---------------------------------------------------------------------------
# enrichment — repo-graph product reach, owner team, URL
# ---------------------------------------------------------------------------


def load_repo_graph(results: Path) -> dict[str, dict]:
    p = results / "graph" / "repo-graph.json"
    g = json.loads(p.read_text(encoding="utf-8"))
    by_label: dict[str, dict] = {}
    by_id: dict[str, dict] = {}
    for n in g.get("nodes") or []:
        if n.get("type") == "repo":
            entry = {"url": (n.get("attrs") or {}).get("url"), "reach": 0, "owner": None}
            by_label[n.get("label") or ""] = entry
            by_id[n["id"]] = entry
    for e in g.get("edges") or []:
        rel = e.get("rel")
        if rel == "ships" and e.get("to") in by_id:
            by_id[e["to"]]["reach"] += 1
        elif rel == "owned-by":
            if e.get("from") in by_id:
                by_id[e["from"]]["owner"] = str(e.get("to", "")).split(":", 1)[-1]
            elif e.get("to") in by_id:
                by_id[e["to"]]["owner"] = str(e.get("from", "")).split(":", 1)[-1]
    return by_label


def resolve(results: Path, repos: dict[str, str]) -> list[dict]:
    graph = {}
    try:
        graph = load_repo_graph(results)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] repo-graph unavailable ({e}); targets unenriched", file=sys.stderr)
    targets = []
    for label, evidence in sorted(repos.items()):
        g = graph.get(label) or {}
        targets.append(
            {
                "repo": label,
                "url": g.get("url") or f"https://github.com/{label}",
                "in_repo_graph": bool(g),
                "product_reach": g.get("reach", 0),
                "owner_team": g.get("owner"),
                "evidence": evidence,
            }
        )
    targets.sort(key=lambda t: (-t["product_reach"], t["repo"]))
    return targets


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--cwe")
    src.add_argument("--rollup")
    src.add_argument("--module")
    src.add_argument("--repos", nargs="+")
    ap.add_argument(
        "--ecosystem",
        help="(with --module) restrict to one ecosystem's "
        "pkg:<eco>/<name> node — npm/pypi/maven/cargo/"
        "ruby/nuget/docker/actions/helm",
    )
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results root (default: config / $AUDIT_RESULTS_ROOT)",
    )
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    if args.ecosystem and not args.module:
        ap.error("--ecosystem only applies with --module")

    engine = load_engine(args.config_home)
    results = resolve_results_root(args)
    tracker = progress_tracker_dir(engine)
    if args.cwe:
        repos, source = from_cwe(tracker, args.cwe), f"cwe:{args.cwe}"
    elif args.rollup:
        repos, source = from_rollup(results, args.rollup), f"rollup:/{args.rollup}/"
    elif args.module:
        repos = from_module(results, args.module, args.ecosystem)
        source = (
            f"module:{args.module}@{args.ecosystem}" if args.ecosystem else f"module:{args.module}"
        )
    else:
        repos = {r: "explicit" for r in args.repos}
        source = "explicit"

    targets = resolve(results, repos)
    print(f"{'repo':<58} {'reach':>5} {'graph':>5}  owner team")
    print("-" * 100)
    for t in targets:
        print(
            f"{t['repo']:<58} {t['product_reach']:>5} "
            f"{'y' if t['in_repo_graph'] else 'n':>5}  "
            f"{t['owner_team'] or '—'}"
        )
    unenriched = sum(1 for t in targets if not t["in_repo_graph"])
    print(
        f"\n{len(targets)} targets ({unenriched} not in repo-graph — "
        f"listed, never dropped) · source: {source}"
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps({"source": source, "targets": targets}, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
