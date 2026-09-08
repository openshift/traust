#!/usr/bin/env python3
"""scan_crypto_deps_graph.py — graph-backed cross-language crypto-dep discovery.

The PQC lane's own scanner (`pqc_facts.py` / `scan_pqc_dependencies.py`) is
Go/TLS-centric and re-discovers crypto from source. This step instead READS
the portfolio graph's NEW multi-ecosystem dependency layer — built by
`traust portfolio build`:

    repo:<host>/<org>/<name>
        -[depends_on {version, ecosystem, manifest}]->  pkg:<eco>/<name>

for eco in npm / pypi / maven / cargo / ruby / nuget — and surfaces the repos
that depend on a curated set of crypto-relevant packages
(`notes/crypto-packages.yaml`, a STARTER list, easy to extend). For each hit
it emits the repo, the crypto package + version, the `manifest` provenance
path(s) carried on the edge, and the mapped PQC posture (classical-only /
pqc-capable / inherits-from-<card> / unknown).

Output (`analysis-results/pqc/_manifest/crypto-deps.{json,md}`) is aggregated
into the PQC portfolio roll-up by `build_pqc_rollup.py`, which imports
`discover()` from this module and renders a cross-language crypto-dependency
section. So "which repos pull in a classical-only JS/Python/Rust crypto lib"
becomes a deterministic graph lookup, not a per-repo source re-scan.

Robustness: READ-ONLY against the graph (opened `mode=ro`), NO network. If
the graph db is absent or a legacy shape without the expected tables, the
scan skips cleanly with a logged note and `graph_present: false` — never a
crash.

Usage:
  scan_crypto_deps_graph.py [--results-root DIR] [--config-home PATH]
                            [--graph-db <path>] [--seeds <path>] [--out <path>]
"""

import argparse
import collections
import datetime
import json
import sqlite3
import sys
from pathlib import Path

import yaml

from traust.context import add_config_home_arg, resolve_results_root

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
DEFAULT_SEEDS = HERE / "notes" / "crypto-packages.yaml"
# The graph's language-gated ecosystems (build_portfolio_graph.py). Seed keys
# outside this set are ignored (with a note) so a typo can't silently miss.
GRAPH_ECOSYSTEMS = ("npm", "pypi", "maven", "cargo", "ruby", "nuget")
POSTURES = ("classical-only", "pqc-capable", "inherits", "unknown")


def load_seeds(path: Path) -> dict:
    """{eco: {package: {posture, capability_card?, note}}} from the seed YAML.

    Tolerant of unknown ecosystems (dropped with a note by the caller); every
    package gets a normalized posture (unrecognized -> 'unknown')."""
    doc = yaml.safe_load(path.read_text()) or {}
    ecos = doc.get("ecosystems") or {}
    out: dict[str, dict] = {}
    for eco, pkgs in ecos.items():
        norm: dict[str, dict] = {}
        for name, meta in (pkgs or {}).items():
            meta = meta or {}
            posture = meta.get("posture") or "unknown"
            if posture not in POSTURES:
                posture = "unknown"
            norm[name] = {
                "posture": posture,
                "capability_card": meta.get("capability_card"),
                "note": meta.get("note") or "",
            }
        out[eco] = norm
    return out


def posture_label(entry: dict) -> str:
    """Human posture string, folding the governing card into `inherits`."""
    p = entry["posture"]
    if p == "inherits" and entry.get("capability_card"):
        return f"inherits-from-{entry['capability_card']}"
    return p


def _tables_present(con) -> bool:
    names = {
        r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    return {"nodes", "edges"} <= names


def _dep_edge_columns(con) -> bool:
    """The multi-ecosystem layer stores dep provenance in edges.attrs; all we
    require is that `edges` has src/dst/rel/attrs (the standard shape)."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(edges)").fetchall()}
    return {"src", "dst", "rel", "attrs"} <= cols


def discover(graph_db: Path, seeds: dict) -> dict:
    """Query the graph for depends_on edges to seed crypto packages.

    Returns a structured, deterministic result. Never raises on a missing or
    legacy graph db — sets `graph_present: false` + a `note` instead."""
    today = datetime.date.today().isoformat()
    result = {
        "generated": today,
        "graph_db": str(graph_db),
        "graph_present": False,
        "note": None,
        "seed_ecosystems": sorted(e for e in seeds if e in GRAPH_ECOSYSTEMS),
        "seed_counts": {e: len(seeds.get(e, {})) for e in GRAPH_ECOSYSTEMS if seeds.get(e)},
        "ignored_seed_ecosystems": sorted(e for e in seeds if e not in GRAPH_ECOSYSTEMS),
        "totals": {"hits": 0, "repos": 0, "packages_matched": 0},
        "posture_totals": {},
        "ecosystems": {},
    }
    if not graph_db.exists():
        result["note"] = f"graph db not found: {graph_db} — skipped"
        return result

    # read-only connection: legacy/absent-table shapes must skip, not crash
    try:
        con = sqlite3.connect(f"file:{graph_db}?mode=ro", uri=True)
    except sqlite3.Error as e:
        result["note"] = f"could not open graph db read-only: {e} — skipped"
        return result
    try:
        if not _tables_present(con) or not _dep_edge_columns(con):
            result["note"] = "graph db has no nodes/edges tables (legacy shape) — skipped"
            return result

        # target node ids per ecosystem: pkg:<eco>/<name>
        id_to_seed: dict[str, tuple[str, str]] = {}
        for eco in GRAPH_ECOSYSTEMS:
            for name in seeds.get(eco, {}):
                id_to_seed[f"pkg:{eco}/{name}"] = (eco, name)
        if not id_to_seed:
            result["graph_present"] = True
            result["note"] = "no seed packages in graph ecosystems"
            return result

        ids = sorted(id_to_seed)
        rows = []
        # chunk the IN() list well under SQLite's variable limit
        for i in range(0, len(ids), 400):
            chunk = ids[i : i + 400]
            q = (
                "SELECT src, dst, attrs FROM edges WHERE rel='depends_on' "
                f"AND dst IN ({','.join('?' * len(chunk))})"
            )
            rows.extend(con.execute(q, chunk).fetchall())
    except sqlite3.Error as e:
        result["note"] = f"graph query failed: {e} — skipped"
        return result
    finally:
        con.close()

    result["graph_present"] = True
    eco_hits: dict[str, list] = collections.defaultdict(list)
    repos_seen: set[str] = set()
    pkgs_matched: set[str] = set()
    posture_totals: collections.Counter = collections.Counter()
    for src, dst, attrs_json in rows:
        eco, name = id_to_seed[dst]
        try:
            attrs = json.loads(attrs_json) if attrs_json else {}
        except (json.JSONDecodeError, TypeError):
            attrs = {}
        manifest = attrs.get("manifest")
        if isinstance(manifest, str):
            manifest = [manifest]
        elif not isinstance(manifest, list):
            manifest = []
        entry = seeds[eco][name]
        label = posture_label(entry)
        repo = src[len("repo:") :] if src.startswith("repo:") else src
        eco_hits[eco].append(
            {
                "repo": repo,
                "package": name,
                "version": attrs.get("version") or "",
                "manifest": sorted(manifest),
                "manifest_truncated": bool(attrs.get("manifest_truncated")),
                "indirect": int(attrs.get("indirect") or 0),
                "posture": label,
                "capability_card": entry.get("capability_card"),
                "note": entry["note"],
            }
        )
        repos_seen.add(repo)
        pkgs_matched.add(dst)
        posture_totals[label] += 1

    for eco in sorted(eco_hits):
        eco_hits[eco].sort(key=lambda h: (h["package"], h["repo"], h["version"]))
        result["ecosystems"][eco] = eco_hits[eco]
    result["totals"] = {
        "hits": sum(len(v) for v in eco_hits.values()),
        "repos": len(repos_seen),
        "packages_matched": len(pkgs_matched),
    }
    result["posture_totals"] = dict(sorted(posture_totals.items()))
    return result


def render_md(data: dict) -> str:
    L = [
        "# Cross-language crypto dependencies (graph-discovered)",
        "",
        f"**Generated:** {data['generated']} · source: portfolio graph `{data['graph_db']}`",
        "",
    ]
    if not data["graph_present"]:
        L += [f"_Graph not available: {data.get('note')}._", ""]
        return "\n".join(L) + "\n"
    t = data["totals"]
    L += [
        f"Repos depending on a curated crypto package: **{t['repos']}** "
        f"across **{t['hits']}** dependency edges "
        f"(**{t['packages_matched']}** distinct seed packages matched).",
        "",
        "Seed list: `harnessing/3-audit/pqc-readiness/notes/crypto-packages.yaml` "
        "(curated STARTER set — extend it there).",
        "",
        "## Posture mix",
        "",
        "| PQC posture | Dependency edges |",
        "|---|---:|",
    ]
    for posture, c in data["posture_totals"].items():
        L.append(f"| {posture} | {c} |")
    if not data["posture_totals"]:
        L.append("| (none matched) | 0 |")
    L += [
        "",
        "`classical-only` = no ML-KEM / hybrid — the migration-relevant "
        "dependencies. `inherits-from-<card>` = posture follows the named "
        "capability card's stack. `unknown` = needs a capability card.",
        "",
    ]
    for eco in sorted(data["ecosystems"]):
        hits = data["ecosystems"][eco]
        L += [
            f"## {eco} ({len(hits)} edges)",
            "",
            "| Repo | Package | Version | Posture | Manifest |",
            "|---|---|---|---|---|",
        ]
        for h in hits:
            man = ", ".join(f"`{m}`" for m in h["manifest"]) or "—"
            if h["manifest_truncated"]:
                man += " …"
            ver = h["version"] or "—"
            ind = " (indirect)" if h["indirect"] else ""
            L.append(f"| {h['repo']} | {h['package']}{ind} | {ver} | {h['posture']} | {man} |")
        L.append("")
    L += [
        "*Read-only graph lookup over the multi-ecosystem `depends_on` "
        "layer. Rebuild after `/portfolio-graph` refreshes the graph or the "
        "seed list changes. Consumed by `build_pqc_rollup.py`.*"
    ]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results root (default: from config)",
    )
    ap.add_argument("--graph-db", default=None)
    ap.add_argument("--seeds", default=None)
    ap.add_argument("--out", default=None, help="output path stem for crypto-deps.{json,md}")
    args = ap.parse_args()

    results = resolve_results_root(args)
    graph_db = (
        Path(args.graph_db).resolve() if args.graph_db else results / "graph" / "portfolio-graph.db"
    )
    seeds_path = Path(args.seeds).resolve() if args.seeds else DEFAULT_SEEDS
    if not seeds_path.exists():
        print(f"error: seed list not found: {seeds_path}", file=sys.stderr)
        return 1
    seeds = load_seeds(seeds_path)
    data = discover(graph_db, seeds)
    data["seed_source"] = str(seeds_path)

    out_stem = (
        Path(args.out).resolve() if args.out else results / "pqc" / "_manifest" / "crypto-deps"
    )
    out_stem.parent.mkdir(parents=True, exist_ok=True)
    (out_stem.with_suffix(".json")).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    (out_stem.with_suffix(".md")).write_text(render_md(data))

    if not data["graph_present"]:
        print(f"[!] {data['note']}")
        print(f"[+] wrote {out_stem.with_suffix('.json')} (+md, empty)")
        return 0
    t = data["totals"]
    print(
        f"[+] crypto-dep discovery: {t['repos']} repos · {t['hits']} edges "
        f"· {t['packages_matched']} seed packages matched"
    )
    if data["posture_totals"]:
        print(
            "    posture mix: " + ", ".join(f"{k}={v}" for k, v in data["posture_totals"].items())
        )
    print(f"[+] wrote {out_stem.with_suffix('.json')} (+md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
