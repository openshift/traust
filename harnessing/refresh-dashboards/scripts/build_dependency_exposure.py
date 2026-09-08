#!/usr/bin/env python3
"""build_dependency_exposure.py — multi-ecosystem dependency-exposure dashboard.

A deterministic (~$0, no agent, no network) consumer view built from two
sources the campaign already maintains:

  1. The portfolio graph (`analysis-results/graph/portfolio-graph.db`) —
     its L1 multi-ecosystem dependency layer: `pkg:<eco>/<name>` package
     nodes and ecosystem-tagged `depends_on` edges (eco ∈ npm, pypi,
     maven, cargo, ruby, nuget, docker, actions, helm, plus Go's legacy
     `module:` id space). The graph's `depends_on` fan-in IS the blast
     radius — how many repos/products pull each shared package.
  2. Impact artifacts (`analysis-results/impact/*-impact-analysis.json`,
     per-advisory affectedness) and fleet-OSV worklists
     (`analysis-results/impact/fleet-osv-worklist-*.json`, which carry
     `malicious`/`MAL-` rows) — the CVE/malicious-package exposure lane.

It emits per-ecosystem coverage, top shared dependencies by blast
radius, CVE/malicious exposure joined against the graph, a dedicated
malicious-package (MAL-) exposure table, and a per-product
dependency-CVE rollup, into
`progress-tracker/metrics/dependency-exposure/dependency-exposure.{json,md,html}`.

Counts are HEAD-graph-derived. docker/helm are dependency SURFACES only:
they contribute blast-radius fan-in but have NO OSV vuln lane (their
vuln path is the container-SBOM/grype lane), so they never appear in the
CVE/MAL exposure tables — only in coverage and top-shared.

Robust by design: a missing graph or impact directory yields an
empty-but-valid dashboard with a clear "no data" note, never a crash.
The census remains the denominator authority; this dashboard embeds the
standard population block so its numbers reconcile with every other.

Usage:
    python3 scripts/build_dependency_exposure.py
        [--db <portfolio-graph.db>] [--stats <deps-multi-stats.json>]
        [--impact-dir <analysis-results/impact>]
        [--results-root <analysis-results>] [--config <corpus-config.yaml>]
        [--out-dir <dir>] [--top N]
"""

from __future__ import annotations

import argparse
import datetime
import json
import sqlite3
import sys
from pathlib import Path

from traust_engine.escaping import esc_html, md_cell

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

# Ecosystems with an OSV CVE/malicious-advisory lane. docker/helm are
# graph/blast-radius surfaces only (their vuln lane is container-SBOM /
# grype, not OSV), so they are coverage + top-shared only.
GRAPH_ONLY_ECOSYSTEMS = ("docker", "helm")
# Canonical display order for ecosystems in the coverage table.
ECO_ORDER = ("go", "npm", "pypi", "maven", "cargo", "ruby", "nuget", "actions", "docker", "helm")
# Impact classifications that count as live exposure (in vulnerable range
# with a positive or plausible affectedness verdict). The remaining
# classes (version_not_in_range, not_imported, not_observed) are NOT
# exposed and are surfaced only as context counts.
EXPOSED_CLASSES = ("affected", "likely_affected", "inconclusive")


def _load_corpus():
    from traust_engine._util.script_loader import load_script

    from traust.paths import HARNESS_ROOT

    return load_script("corpus", HARNESS_ROOT)


corpus = _load_corpus()


def harness_version() -> str:
    from traust.paths import HARNESS_ROOT

    try:
        return corpus.harness_version()
    except Exception:  # pragma: no cover - best effort
        try:
            return (HARNESS_ROOT / "VERSION").read_text().strip()
        except OSError:
            return "unknown"


def _eco_norm(eco: str | None) -> str:
    """Canonical lower-case ecosystem tag. Go's legacy 'Go' -> 'go'."""
    return (eco or "Go").strip().lower()


# ---------------------------------------------------------------------------
# graph reads
# ---------------------------------------------------------------------------
def read_graph(db_path: Path) -> dict | None:
    """Read the dependency layer from the portfolio graph. Returns None
    when the db is absent/unreadable (caller degrades to no-graph mode)."""
    if not db_path.is_file():
        return None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        con.row_factory = sqlite3.Row
        total_repos = con.execute("SELECT COUNT(*) FROM nodes WHERE kind='repo'").fetchone()[0]

        # repo -> {products}. Products ship/contain/include repos.
        repo_products: dict[str, set[str]] = {}
        for r in con.execute(
            "SELECT ship.dst AS repo, p.label AS product "
            "FROM edges ship JOIN nodes p ON p.id = ship.src "
            "WHERE ship.rel IN ('ships','contains','includes') "
            "AND p.kind='product'"
        ):
            repo_products.setdefault(r["repo"], set()).add(r["product"])

        # one pass over every depends_on edge: per-package requiring-repo
        # sets + ecosystem + internal flag. Fan-in = blast radius.
        pkgs: dict[str, dict] = {}
        for e in con.execute(
            "SELECT e.src AS repo, e.dst AS pkg, n.label AS label, "
            "COALESCE(json_extract(e.attrs,'$.ecosystem'), "
            "json_extract(n.attrs,'$.ecosystem'), 'Go') AS eco, "
            "COALESCE(json_extract(n.attrs,'$.internal'),0) AS internal "
            "FROM edges e JOIN nodes n ON n.id = e.dst "
            "WHERE e.rel='depends_on'"
        ):
            p = pkgs.get(e["pkg"])
            if p is None:
                p = pkgs[e["pkg"]] = {
                    "id": e["pkg"],
                    "label": e["label"],
                    "eco": _eco_norm(e["eco"]),
                    "internal": bool(e["internal"]),
                    "repos": set(),
                }
            p["repos"].add(e["repo"])
    finally:
        con.close()

    # per-ecosystem coverage + top-shared, computed from the single pass
    eco_stats: dict[str, dict] = {}
    for p in pkgs.values():
        eco = p["eco"]
        s = eco_stats.setdefault(eco, {"pkg_nodes": 0, "dep_edges": 0, "repos": set()})
        s["pkg_nodes"] += 1
        s["dep_edges"] += len(p["repos"])
        s["repos"] |= p["repos"]
        # attach product blast radius per package (computed lazily below)
    for _eco, s in eco_stats.items():
        s["repos_with_deps"] = len(s.pop("repos"))

    return {
        "total_repos": total_repos,
        "repo_products": repo_products,
        "packages": pkgs,
        "eco_stats": eco_stats,
    }


def _products_for_repos(repo_products: dict, repos) -> list[str]:
    out: set[str] = set()
    for r in repos:
        out |= repo_products.get(r, set())
    return sorted(out)


def top_shared(graph: dict, top: int) -> dict[str, list[dict]]:
    """Top-N shared packages by repo fan-in (blast radius), per ecosystem."""
    by_eco: dict[str, list[dict]] = {}
    rp = graph["repo_products"]
    for p in graph["packages"].values():
        by_eco.setdefault(p["eco"], []).append(p)
    out: dict[str, list[dict]] = {}
    for eco, plist in by_eco.items():
        plist.sort(key=lambda x: (-len(x["repos"]), x["label"]))
        rows = []
        for p in plist[:top]:
            prods = _products_for_repos(rp, p["repos"])
            rows.append(
                {
                    "package": p["label"],
                    "node_id": p["id"],
                    "ecosystem": eco,
                    "internal": p["internal"],
                    "repo_blast_radius": len(p["repos"]),
                    "product_blast_radius": len(prods),
                    "products": prods[:12],
                }
            )
        out[eco] = rows
    return out


def _pkg_blast_radius(graph: dict | None, module: str, eco: str) -> dict:
    """Look up a module+ecosystem in the graph's dependency layer.
    Returns {matched, repo_blast_radius, product_blast_radius}."""
    if not graph:
        return {"matched": False, "repo_blast_radius": None, "product_blast_radius": None}
    eco = _eco_norm(eco)
    candidates = (
        [f"module:{module}"] if eco == "go" else [f"pkg:{eco}/{module}", f"module:{module}"]
    )
    for nid in candidates:
        p = graph["packages"].get(nid)
        if p:
            prods = _products_for_repos(graph["repo_products"], p["repos"])
            return {
                "matched": True,
                "repo_blast_radius": len(p["repos"]),
                "product_blast_radius": len(prods),
            }
    return {"matched": False, "repo_blast_radius": None, "product_blast_radius": None}


# ---------------------------------------------------------------------------
# impact + fleet reads → advisory exposure
# ---------------------------------------------------------------------------
def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def collect_exposure(impact_dir: Path, graph: dict | None) -> dict:
    """Join impact artifacts + fleet-OSV worklists into a per-advisory
    exposure map keyed by advisory display id. Returns advisories +
    parse stats. Never raises on a malformed file (it is skipped)."""
    advisories: dict[str, dict] = {}
    stats = {
        "impact_files": 0,
        "impact_unreadable": 0,
        "fleet_files": 0,
        "fleet_unreadable": 0,
        "fleet_worklist_rows": 0,
    }

    def _adv(aid: str) -> dict:
        return advisories.setdefault(
            aid,
            {
                "advisory": aid,
                "cve": None,
                "malicious": False,
                "ecosystem": None,
                "packages": set(),
                "severity": None,
                "summary": "",
                "repos": set(),
                "sources": set(),
            },
        )

    if impact_dir.is_dir():
        # per-advisory affectedness reports
        for fp in sorted(impact_dir.glob("*-impact-analysis.json")):
            doc = _load_json(Path(fp))
            if not isinstance(doc, dict):
                stats["impact_unreadable"] += 1
                continue
            stats["impact_files"] += 1
            meta = doc.get("metadata") or {}
            aid = meta.get("cve") or Path(fp).name
            eco = _eco_norm(meta.get("ecosystem"))
            module = meta.get("module") or ""
            a = _adv(aid)
            a["sources"].add("impact")
            if str(aid).startswith("CVE-"):
                a["cve"] = aid
            if str(aid).startswith("MAL-"):
                a["malicious"] = True
            a["ecosystem"] = a["ecosystem"] or eco
            if module:
                a["packages"].add(module)
            if not a["summary"]:
                a["summary"] = str(meta.get("feature_description") or "")[:200]
            for entry in doc.get("repos") or []:
                if not isinstance(entry, dict):
                    continue
                if entry.get("classification") in EXPOSED_CLASSES:
                    repo = entry.get("repo")
                    if repo:
                        a["repos"].add(repo)

        # fleet worklists — the malicious/MAL- lane lives here
        for fp in sorted(impact_dir.glob("fleet-osv-worklist-*.json")):
            doc = _load_json(Path(fp))
            if not isinstance(doc, dict):
                stats["fleet_unreadable"] += 1
                continue
            stats["fleet_files"] += 1
            for row in doc.get("worklist") or []:
                if not isinstance(row, dict):
                    continue
                stats["fleet_worklist_rows"] += 1
                aid = row.get("id") or row.get("osv") or row.get("cve")
                if not aid:
                    continue
                a = _adv(str(aid))
                a["sources"].add("fleet")
                a["malicious"] = a["malicious"] or bool(row.get("malicious"))
                if row.get("cve"):
                    a["cve"] = row["cve"]
                a["ecosystem"] = a["ecosystem"] or _eco_norm(row.get("ecosystem"))
                a["severity"] = a["severity"] or row.get("severity")
                if not a["summary"]:
                    a["summary"] = str(row.get("summary") or "")[:200]
                for m in row.get("modules") or []:
                    a["packages"].add(m)
                # manifest: {module: {repo: [paths]}} — repo keys are the
                # in-range repos for this advisory
                manifest = row.get("manifest") or {}
                if isinstance(manifest, dict):
                    for per_repo in manifest.values():
                        if isinstance(per_repo, dict):
                            a["repos"].update(per_repo.keys())

    # finalise: attach product exposure + graph blast radius per advisory
    rp = (graph or {}).get("repo_products", {})
    out = []
    for a in advisories.values():
        prods = _products_for_repos(rp, a["repos"])
        module = sorted(a["packages"])[0] if a["packages"] else ""
        br = _pkg_blast_radius(graph, module, a["ecosystem"] or "go")
        out.append(
            {
                "advisory": a["advisory"],
                "cve": a["cve"],
                "malicious": a["malicious"],
                "ecosystem": a["ecosystem"] or "go",
                "severity": a["severity"],
                "packages": sorted(a["packages"]),
                "summary": a["summary"],
                "repos_exposed": len(a["repos"]),
                "products_exposed": len(prods),
                "products": prods[:12],
                "graph_matched": br["matched"],
                "graph_repo_blast_radius": br["repo_blast_radius"],
                "sources": sorted(a["sources"]),
                "_repos": sorted(a["repos"]),
            }
        )
    # malicious first, then by repos exposed, then advisory id
    out.sort(key=lambda r: (0 if r["malicious"] else 1, -r["repos_exposed"], r["advisory"]))
    return {"advisories": out, "stats": stats}


def per_product_rollup(advisories: list[dict], rp: dict) -> list[dict]:
    """Products ranked by number of distinct dependency-advisory hits
    (and distinct exposed repos)."""
    prod: dict[str, dict] = {}
    for a in advisories:
        for repo in a["_repos"]:
            for p in rp.get(repo, ()):  # products shipping this repo
                d = prod.setdefault(
                    p,
                    {
                        "product": p,
                        "advisories": set(),
                        "malicious_advisories": set(),
                        "repos": set(),
                    },
                )
                d["advisories"].add(a["advisory"])
                if a["malicious"]:
                    d["malicious_advisories"].add(a["advisory"])
                d["repos"].add(repo)
    rows = [
        {
            "product": d["product"],
            "advisory_hits": len(d["advisories"]),
            "malicious_hits": len(d["malicious_advisories"]),
            "repos_exposed": len(d["repos"]),
        }
        for d in prod.values()
    ]
    rows.sort(key=lambda r: (-r["advisory_hits"], -r["malicious_hits"], r["product"]))
    return rows


# ---------------------------------------------------------------------------
# assemble
# ---------------------------------------------------------------------------
def build(
    db_path: Path, stats_path: Path, impact_dir: Path, results_root: Path, cfg: dict, top: int
) -> dict:
    graph = read_graph(db_path)
    deps_multi = _load_json(stats_path) if stats_path.is_file() else None

    coverage = []
    top_shared_by_eco: dict[str, list[dict]] = {}
    if graph:
        total = graph["total_repos"] or 0
        for eco in ECO_ORDER:
            g = graph["eco_stats"].get(eco)
            if not g and not (deps_multi and eco in deps_multi):
                continue
            # deps-multi-stats keys ecosystems as stored (Go/npm/...);
            # prefer its manifest-coverage denominator when present.
            dm = None
            if isinstance(deps_multi, dict):
                dm = (
                    deps_multi.get(eco)
                    or deps_multi.get(eco.capitalize())
                    or (deps_multi.get("Go") if eco == "go" else None)
                )
            repos_with_manifest = dm.get("repos_with_manifest") if isinstance(dm, dict) else None
            repos_with_deps = (g or {}).get("repos_with_deps", 0)
            denom = repos_with_manifest or repos_with_deps
            coverage.append(
                {
                    "ecosystem": eco,
                    "graph_only": eco in GRAPH_ONLY_ECOSYSTEMS,
                    "repos_with_manifest": repos_with_manifest,
                    "repos_with_deps": repos_with_deps,
                    "pkg_nodes": (g or {}).get("pkg_nodes", 0),
                    "dep_edges": (g or {}).get("dep_edges", 0),
                    "coverage_ratio": (round(denom / total, 4) if total and denom else None),
                }
            )
        top_shared_by_eco = top_shared(graph, top)

    exposure = collect_exposure(impact_dir, graph)
    advisories = exposure["advisories"]
    rp = (graph or {}).get("repo_products", {})
    malicious = [a for a in advisories if a["malicious"]]
    products = per_product_rollup(advisories, rp)

    has_data = bool(graph or advisories)

    return {
        "artifact": "dependency-exposure",
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": harness_version(),
        "note": (
            "Counts are HEAD-graph-derived. docker/helm are "
            "dependency surfaces only (no OSV vuln lane — their vuln "
            "path is the container-SBOM/grype lane), so they appear "
            "in coverage and top-shared but never in the CVE/MAL "
            "exposure tables. The census remains the denominator "
            "authority."
        ),
        "sources": {
            "graph_db": str(db_path),
            "graph_present": bool(graph),
            "deps_multi_stats": str(stats_path),
            "deps_multi_present": bool(deps_multi),
            "impact_dir": str(impact_dir),
        },
        "has_data": has_data,
        "totals": {
            "repos_in_graph": (graph or {}).get("total_repos", 0),
            "ecosystems_covered": len(coverage),
            "advisories": len(advisories),
            "malicious_advisories": len(malicious),
            "products_exposed": len(products),
        },
        "coverage": coverage,
        "top_shared": top_shared_by_eco,
        "exposure": advisories,
        "malicious_exposure": malicious,
        "per_product": products,
        "impact_stats": exposure["stats"],
        "population": _population_lines(results_root, cfg, graph, coverage, advisories, malicious),
    }


def _population_lines(
    results_root: Path,
    cfg: dict,
    graph: dict | None,
    coverage: list,
    advisories: list,
    malicious: list,
) -> list[str]:
    """Standard population block (census-reconcilable). Best-effort — an
    unreadable corpus degrades to a graph-only block, never a crash."""
    roots = []
    try:
        res = corpus.resolve(results_root, cfg)
        roots = corpus.roots_description(cfg, sorted(res.trees))
    except Exception as e:  # pragma: no cover - best effort
        print(f"corpus population degraded: {e}", file=sys.stderr)
    roots = [
        *roots,
        "`analysis-results/graph/portfolio-graph.db` (HEAD dependency layer)",
        "`analysis-results/impact/` (impact + fleet-OSV worklists)",
    ]
    counts = {
        "Repos in graph": (graph or {}).get("total_repos", 0),
        "Ecosystems in coverage": len(coverage),
        "Dependency advisories (CVE + MAL)": len(advisories),
        "Malicious (MAL-) advisories": len(malicious),
    }
    try:
        return corpus.population_block_lines(
            tool="dependency-exposure",
            roots=roots,
            unit="graph depends_on edges / pkg:<eco>/<name> nodes (HEAD "
            "blast radius) joined to per-advisory affectedness",
            filters="docker/helm are graph/blast-radius only (no OSV lane); "
            "CVE/MAL exposure counts only in-range affected/"
            "likely-affected repos; HEAD graph, no branch refs",
            denominator="portfolio-graph.db dependency layer + "
            "analysis-results/impact/*.json; census "
            "(findings.db `repos`) remains the report-population "
            "authority",
            counts=counts,
        )
    except Exception as e:  # pragma: no cover - best effort
        print(f"population block omitted: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------
def _no_data_banner(data: dict) -> str:
    s = data["sources"]
    return (
        "_No dependency-exposure data available — the portfolio graph "
        f"(`{s['graph_db']}`) and the impact artifacts "
        f"(`{s['impact_dir']}`) are both absent or empty. Build the "
        "graph (`/portfolio-graph`) and run `/dependency-watch` / "
        "`/impact-analysis`, then re-run `/refresh-dashboards`._"
    )


def render_md(data: dict) -> str:
    data["generated_at"][:10]
    L: list[str] = []
    A = L.append
    A("# Dependency Exposure — multi-ecosystem blast radius & vuln surface")
    A("")
    A(f"**Generated:** {data['generated_at']} · harness `{data['harness_version']}`")
    A("")
    A(f"> {data['note']}")
    A("")
    if not data["has_data"]:
        A(_no_data_banner(data))
        A("")
        A("\n".join(data["population"]))
        A("")
        return "\n".join(L) + "\n"

    t = data["totals"]
    A(
        f"Repos in graph **{t['repos_in_graph']:,}** · ecosystems "
        f"**{t['ecosystems_covered']}** · dependency advisories "
        f"**{t['advisories']:,}** (malicious **{t['malicious_advisories']:,}**) "
        f"· products exposed **{t['products_exposed']:,}**"
    )
    A("")

    # coverage
    A("## Per-ecosystem coverage")
    A("")
    A("| Ecosystem | Repos w/ manifest | Repos w/ deps | Pkg nodes | Dep edges | Coverage |")
    A("|---|---:|---:|---:|---:|---:|")
    for c in data["coverage"]:
        eco = c["ecosystem"] + (" *(graph-only)*" if c["graph_only"] else "")
        rwm = f"{c['repos_with_manifest']:,}" if c["repos_with_manifest"] is not None else "—"
        cov = f"{c['coverage_ratio'] * 100:.1f}%" if c["coverage_ratio"] is not None else "—"
        A(
            f"| {md_cell(eco)} | {rwm} | {c['repos_with_deps']:,} | "
            f"{c['pkg_nodes']:,} | {c['dep_edges']:,} | {cov} |"
        )
    A("")

    # top shared
    A("## Top shared dependencies by blast radius")
    A("")
    A(
        "_Fan-in from the graph's `depends_on` edges — how many repos "
        "(and products) pull each shared package._"
    )
    A("")
    for eco in ECO_ORDER:
        rows = data["top_shared"].get(eco)
        if not rows:
            continue
        A(f"### {eco}")
        A("")
        A("| # | Package | Repos | Products | Internal |")
        A("|---:|---|---:|---:|:--:|")
        for i, r in enumerate(rows, 1):
            A(
                f"| {i} | {md_cell(r['package'])} | "
                f"{r['repo_blast_radius']:,} | {r['product_blast_radius']:,} | "
                f"{'✓' if r['internal'] else ''} |"
            )
        A("")

    # vulnerable / malicious exposure
    A("## Vulnerable & malicious dependency exposure")
    A("")
    if data["exposure"]:
        A(
            "_Advisories (CVE + malicious) joined against the graph. "
            "`Repos` / `Products` are in-range affected/likely-affected; "
            "`Graph BR` is the total repo fan-in for the package._"
        )
        A("")
        A("| Advisory | Eco | Package(s) | Repos | Products | Graph BR | MAL | Severity |")
        A("|---|---|---|---:|---:|---:|:--:|---|")
        for a in data["exposure"][:100]:
            pkgs = ", ".join(a["packages"][:3]) or "—"
            gbr = (
                f"{a['graph_repo_blast_radius']:,}"
                if a["graph_repo_blast_radius"] is not None
                else "—"
            )
            A(
                f"| {md_cell(a['advisory'])} | {a['ecosystem']} | "
                f"{md_cell(pkgs)} | {a['repos_exposed']:,} | "
                f"{a['products_exposed']:,} | {gbr} | "
                f"{'🦠' if a['malicious'] else ''} | "
                f"{md_cell(a['severity'] or '—')} |"
            )
    else:
        A(
            "_No CVE or malicious-package exposure recorded — no impact "
            "artifacts or fleet-OSV worklists in scope yet._"
        )
    A("")

    # dedicated MAL- table
    A("## Malicious-package (MAL-) exposure")
    A("")
    if data["malicious_exposure"]:
        A("| Package | Advisory | Eco | Affected repos | Products | Summary |")
        A("|---|---|---|---:|---:|---|")
        for a in data["malicious_exposure"]:
            pkgs = ", ".join(a["packages"][:3]) or "—"
            prods = ", ".join(a["products"][:4]) or "—"
            A(
                f"| {md_cell(pkgs)} | {md_cell(a['advisory'])} | "
                f"{a['ecosystem']} | {a['repos_exposed']:,} | "
                f"{md_cell(prods)} | {md_cell((a['summary'] or '')[:80])} |"
            )
    else:
        A("_No malicious-package (MAL-) advisories in the fleet-OSV worklists in scope._")
    A("")

    # per-product rollup
    A("## Per-product dependency-CVE exposure")
    A("")
    if data["per_product"]:
        A("| # | Product | Advisory hits | Malicious | Repos exposed |")
        A("|---:|---|---:|---:|---:|")
        for i, p in enumerate(data["per_product"][:50], 1):
            A(
                f"| {i} | {md_cell(p['product'])} | {p['advisory_hits']:,} | "
                f"{p['malicious_hits']:,} | {p['repos_exposed']:,} |"
            )
    else:
        A(
            "_No product-level dependency exposure (no affected repos map to "
            "a product in the graph)._"
        )
    A("")

    A("\n".join(data["population"]))
    A("")
    return "\n".join(L) + "\n"


def _population_html(lines: list[str]) -> str:
    if not lines:
        return ""
    import re as _re

    lis = []
    for ln in lines:
        if not ln.startswith("- "):
            continue
        t = esc_html(ln[2:])
        t = _re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
        t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        lis.append(f"<li>{t}</li>")
    return '<h2>Population</h2><div class="panel"><ul>' + "".join(lis) + "</ul></div>"


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    """Header cells are trusted (author-controlled); every ROW cell is
    already-escaped HTML supplied by the caller."""
    thead = "".join(f"<th>{esc_html(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{body}</tbody></table>"


def render_html(data: dict) -> str:
    css = """
    :root{--bg:#0d1117;--panel:#161b22;--fg:#e6edf3;--muted:#8b949e;
      --border:#30363d;--accent:#4cc9f0;--mal:#f85149}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--fg);
      font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    .wrap{max-width:1280px;margin:0 auto;padding:28px}
    h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 10px;
      border-bottom:1px solid var(--border);padding-bottom:6px}
    h3{font-size:14px;margin:16px 0 6px;color:var(--accent)}
    .meta,.note{color:var(--muted);font-size:13px}
    .note{margin:8px 0 4px}
    .tiles{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
    .tile{background:var(--panel);border:1px solid var(--border);
      border-radius:8px;padding:12px 16px;min-width:130px}
    .tile b{display:block;font-size:22px} .tile span{color:var(--muted);
      font-size:12px}
    table{border-collapse:collapse;width:100%;margin:6px 0 14px;
      font-size:13px}
    th,td{border:1px solid var(--border);padding:5px 9px;text-align:left}
    th{background:var(--panel);color:var(--muted);font-weight:600}
    td.n,th.n{text-align:right} tr:nth-child(even) td{background:#11161d}
    code{background:#11161d;padding:1px 5px;border-radius:4px;font-size:12px}
    .panel{background:var(--panel);border:1px solid var(--border);
      border-radius:8px;padding:10px 16px}
    .panel ul{margin:0;padding-left:18px;color:var(--muted);
      font-size:13px;line-height:1.9}
    .mal{color:var(--mal);font-weight:600}
    .nodata{background:var(--panel);border:1px solid var(--border);
      border-radius:8px;padding:18px;color:var(--muted)}
    """
    P = []
    A = P.append
    A("<!doctype html><html lang=en><head><meta charset=utf-8>")
    A("<meta name=viewport content='width=device-width,initial-scale=1'>")
    A("<title>Dependency Exposure</title>")
    A(f"<style>{css}</style></head><body><div class=wrap>")
    A("<h1>Dependency Exposure — multi-ecosystem blast radius &amp; vuln surface</h1>")
    A(
        f"<div class=meta>Generated {esc_html(data['generated_at'])} · harness "
        f"<code>{esc_html(data['harness_version'])}</code></div>"
    )
    A(f"<div class=note>{esc_html(data['note'])}</div>")

    if not data["has_data"]:
        banner = _no_data_banner(data).strip("_")
        A(f"<div class=nodata>{esc_html(banner)}</div>")
        A(_population_html(data["population"]))
        A("</div></body></html>")
        return "".join(P)

    t = data["totals"]
    tiles = [
        ("Repos in graph", f"{t['repos_in_graph']:,}"),
        ("Ecosystems", f"{t['ecosystems_covered']}"),
        ("Advisories", f"{t['advisories']:,}"),
        ("Malicious", f"{t['malicious_advisories']:,}"),
        ("Products exposed", f"{t['products_exposed']:,}"),
    ]
    A("<div class=tiles>")
    for label, val in tiles:
        A(f"<div class=tile><b>{esc_html(val)}</b><span>{esc_html(label)}</span></div>")
    A("</div>")

    # coverage
    A("<h2>Per-ecosystem coverage</h2>")
    rows = []
    for c in data["coverage"]:
        eco = esc_html(c["ecosystem"]) + (
            " <span class=meta>(graph-only)</span>" if c["graph_only"] else ""
        )
        rwm = f"{c['repos_with_manifest']:,}" if c["repos_with_manifest"] is not None else "—"
        cov = f"{c['coverage_ratio'] * 100:.1f}%" if c["coverage_ratio"] is not None else "—"
        rows.append(
            [
                eco,
                esc_html(rwm),
                f"{c['repos_with_deps']:,}",
                f"{c['pkg_nodes']:,}",
                f"{c['dep_edges']:,}",
                esc_html(cov),
            ]
        )
    A(
        _html_table(
            [
                "Ecosystem",
                "Repos w/ manifest",
                "Repos w/ deps",
                "Pkg nodes",
                "Dep edges",
                "Coverage",
            ],
            rows,
        )
    )

    # top shared
    A("<h2>Top shared dependencies by blast radius</h2>")
    A(
        "<div class=note>Fan-in from the graph's depends_on edges — how many "
        "repos (and products) pull each shared package.</div>"
    )
    for eco in ECO_ORDER:
        trows = data["top_shared"].get(eco)
        if not trows:
            continue
        A(f"<h3>{esc_html(eco)}</h3>")
        rows = [
            [
                str(i),
                esc_html(r["package"]),
                f"{r['repo_blast_radius']:,}",
                f"{r['product_blast_radius']:,}",
                "✓" if r["internal"] else "",
            ]
            for i, r in enumerate(trows, 1)
        ]
        A(_html_table(["#", "Package", "Repos", "Products", "Internal"], rows))

    # exposure
    A("<h2>Vulnerable &amp; malicious dependency exposure</h2>")
    if data["exposure"]:
        rows = []
        for a in data["exposure"][:100]:
            pkgs = ", ".join(a["packages"][:3]) or "—"
            gbr = (
                f"{a['graph_repo_blast_radius']:,}"
                if a["graph_repo_blast_radius"] is not None
                else "—"
            )
            mal = "<span class=mal>MAL</span>" if a["malicious"] else ""
            rows.append(
                [
                    esc_html(a["advisory"]),
                    esc_html(a["ecosystem"]),
                    esc_html(pkgs),
                    f"{a['repos_exposed']:,}",
                    f"{a['products_exposed']:,}",
                    esc_html(gbr),
                    mal,
                    esc_html(a["severity"] or "—"),
                ]
            )
        A(
            _html_table(
                [
                    "Advisory",
                    "Eco",
                    "Package(s)",
                    "Repos",
                    "Products",
                    "Graph BR",
                    "MAL",
                    "Severity",
                ],
                rows,
            )
        )
    else:
        A("<div class=nodata>No CVE or malicious-package exposure recorded yet.</div>")

    # MAL- table
    A("<h2>Malicious-package (MAL-) exposure</h2>")
    if data["malicious_exposure"]:
        rows = []
        for a in data["malicious_exposure"]:
            pkgs = ", ".join(a["packages"][:3]) or "—"
            prods = ", ".join(a["products"][:4]) or "—"
            rows.append(
                [
                    esc_html(pkgs),
                    esc_html(a["advisory"]),
                    esc_html(a["ecosystem"]),
                    f"{a['repos_exposed']:,}",
                    esc_html(prods),
                    esc_html((a["summary"] or "")[:80]),
                ]
            )
        A(
            _html_table(
                ["Package", "Advisory", "Eco", "Affected repos", "Products", "Summary"], rows
            )
        )
    else:
        A(
            "<div class=nodata>No malicious-package (MAL-) advisories in the "
            "fleet-OSV worklists in scope.</div>"
        )

    # per-product
    A("<h2>Per-product dependency-CVE exposure</h2>")
    if data["per_product"]:
        rows = [
            [
                str(i),
                esc_html(p["product"]),
                f"{p['advisory_hits']:,}",
                f"{p['malicious_hits']:,}",
                f"{p['repos_exposed']:,}",
            ]
            for i, p in enumerate(data["per_product"][:50], 1)
        ]
        A(_html_table(["#", "Product", "Advisory hits", "Malicious", "Repos exposed"], rows))
    else:
        A("<div class=nodata>No product-level dependency exposure.</div>")

    A(_population_html(data["population"]))
    A("</div></body></html>")
    return "".join(P)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _strip_internal(data: dict) -> dict:
    """Drop private helper keys (leading _) from the JSON emission."""
    out = json.loads(json.dumps(data))  # deep copy
    for a in out.get("exposure", []):
        a.pop("_repos", None)
    for a in out.get("malicious_exposure", []):
        a.pop("_repos", None)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--db",
        type=Path,
        default=None,
        help="portfolio-graph.db (default: <analysis-results>/graph/portfolio-graph.db)",
    )
    ap.add_argument(
        "--stats", type=Path, default=None, help="deps-multi-stats.json (default: next to --db)"
    )
    ap.add_argument("--impact-dir", type=Path, default=None, help="impact artifacts directory")
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=None)
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output directory (default: progress-tracker/metrics/dependency-exposure)",
    )
    ap.add_argument(
        "--top", type=int, default=15, help="top-N shared packages per ecosystem (default 15)"
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results = resolve_results_root(args)
    pt = progress_tracker_dir(engine)
    args.db = args.db or (results / "graph" / "portfolio-graph.db")
    args.impact_dir = args.impact_dir or (results / "impact")
    args.out_dir = args.out_dir or (pt / "metrics" / "dependency-exposure")

    stats_path = args.stats or (args.db.resolve().parent / "deps-multi-stats.json")
    try:
        cfg = corpus.load_config(args.config)
    except Exception as e:  # pragma: no cover - best effort
        print(f"corpus config unavailable ({e}); population degraded", file=sys.stderr)
        cfg = {"trees": {}}

    data = build(args.db, stats_path, args.impact_dir, results, cfg, args.top)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "dependency-exposure.json").write_text(
        json.dumps(_strip_internal(data), indent=2) + "\n", encoding="utf-8"
    )
    (args.out_dir / "dependency-exposure.md").write_text(render_md(data), encoding="utf-8")
    (args.out_dir / "dependency-exposure.html").write_text(render_html(data), encoding="utf-8")

    t = data["totals"]
    print(
        f"dependency-exposure: {t['ecosystems_covered']} ecosystems, "
        f"{t['advisories']} advisories ({t['malicious_advisories']} MAL), "
        f"{t['products_exposed']} products -> {args.out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
