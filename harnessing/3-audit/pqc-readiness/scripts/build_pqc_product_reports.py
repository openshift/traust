#!/usr/bin/env python3
"""build_pqc_product_reports.py — per-product PQC status reports.

One leadership-ready markdown file per product (graph `product:* -ships->
repo` edges × the `pqc` repo attrs × readiness-report detail),
plus a worst-first index. Complements the fleet-level roll-up: this is the
"what does MY product look like" view.

Outputs (progress-tracker/metrics/dashboards/pqc/products/):
  README.md            index — every product ranked worst-first (not-ready
                       count, then worst score), linking the per-product files
  <product-slug>.md    bucket summary · repo table (worst-first, score/bucket/
                       HNDL/2030-clock) · 2030-clock item detail · HNDL repos ·
                       cross-language crypto dependencies (graph-discovered)

The cross-language crypto-dependency section reuses the roll-up's
`scan_crypto_deps_graph.discover()` call and the graph `ships` repo→product
mapping so the per-product view stays consistent with the portfolio roll-up's
section. It is additive (the TLS-readiness content is unchanged) and degrades
to a "no data" line — never a crash — when the graph or its multi-ecosystem
`depends_on` layer is absent.

Deterministic full rebuild; re-run alongside the dashboard/roll-up whenever
reports change.

Usage: build_pqc_product_reports.py [--results-root PATH] [--config-home PATH]
"""

import argparse
import collections
import datetime
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

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
# shared escaping helpers (untrusted repo/package/manifest text -> md cells)
from traust_engine.escaping import md_cell  # noqa: E402

BUCKETS = ["ready", "partial", "not-ready", "blocked-external", "not-applicable"]


def _discover_crypto_deps(graph_db: Path):
    """Reuse the roll-up's cross-language crypto-dep discovery.

    Returns (crypto_deps, crypto_by_repo). Never raises: on any failure it
    returns a graph-absent result so the per-product section degrades to a
    clean 'no data' line."""
    crypto_deps = {"graph_present": False, "ecosystems": {}}
    crypto_by_repo: dict[str, list] = collections.defaultdict(list)
    try:
        import scan_crypto_deps_graph as scd

        seeds = scd.load_seeds(scd.DEFAULT_SEEDS)
        crypto_deps = scd.discover(graph_db, seeds)
        for eco, hits in (crypto_deps.get("ecosystems") or {}).items():
            for h in hits:
                crypto_by_repo[h["repo"]].append({**h, "ecosystem": eco})
    except Exception as e:
        print(f"[!] crypto-dep graph discovery skipped: {e}", file=sys.stderr)
    return crypto_deps, crypto_by_repo


def _crypto_deps_section(repo_keys, crypto_by_repo, crypto_deps):
    """Additive per-product 'Cross-language crypto dependencies' section.

    `repo_keys` = the product's repo node ids (minus the `repo:` prefix), from
    the graph `ships` edges — the same identity the roll-up's discovery keys
    on. Degrades to a 'no data' line when the graph / multi-ecosystem layer is
    unavailable, and to a 'none discovered' line when the product has no hits.
    All untrusted text (repo / package / manifest names) is routed through
    `md_cell`."""
    L = ["", "## Cross-language crypto dependencies", ""]
    if not crypto_deps.get("graph_present"):
        L += [
            "_Portfolio graph unavailable (or missing the multi-ecosystem "
            "dependency layer); cross-language crypto deps not computed. "
            "Build it with `/portfolio-graph`._"
        ]
        return L
    hits = [h for rk in sorted(repo_keys) for h in crypto_by_repo.get(rk, [])]
    if not hits:
        L += [
            "_No curated crypto-library dependencies discovered in this "
            "product's repos (npm / pypi / maven / cargo / ruby / nuget "
            "`depends_on` edges)._"
        ]
        return L
    hits.sort(key=lambda h: (h["ecosystem"], h["package"], h["repo"], h.get("version") or ""))
    posture_totals = collections.Counter(h["posture"] for h in hits)
    classical = posture_totals.get("classical-only", 0)
    repos_with = len({h["repo"] for h in hits})
    L += [
        f"{len(hits)} curated crypto-library dependencies across "
        f"{repos_with} of this product's repos (portfolio-graph "
        f"`depends_on` edges — npm / pypi / maven / cargo / ruby / nuget). "
        f"**{classical} are `classical-only`** — the migration-relevant "
        f"dependencies.",
        "",
        "Posture mix: "
        + (", ".join(f"{p}: {c}" for p, c in sorted(posture_totals.items())) or "none")
        + ".",
        "",
        "| Repo | Package | Version | Ecosystem | Posture | Manifest |",
        "|---|---|---|---|---|---|",
    ]
    for h in hits:
        man = ", ".join(f"`{md_cell(m)}`" for m in (h.get("manifest") or [])) or "—"
        if h.get("manifest_truncated"):
            man += " …"
        ver = md_cell(h["version"]) if h.get("version") else "—"
        ind = " (indirect)" if h.get("indirect") else ""
        L.append(
            f"| `{md_cell(h['repo'])}` "
            f"| {md_cell(h['package'])}{ind} | {ver} "
            f"| {md_cell(h['ecosystem'])} | {md_cell(h['posture'])} "
            f"| {man} |"
        )
    L += [
        "",
        "*Seed list: `harnessing/3-audit/pqc-readiness/notes/crypto-packages.yaml`; "
        "full portfolio detail: "
        "`analysis-results/pqc/_manifest/crypto-deps.md`. Read-only graph "
        "lookup — consistent with the roll-up's cross-language section.*",
    ]
    return L


def product_slug(pid: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", pid.split(":", 1)[1].lower()).strip("-")


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
        else progress_tracker_dir(engine) / "metrics" / "dashboards" / "pqc" / "products"
    )
    out.mkdir(parents=True, exist_ok=True)
    today = datetime.date.today().isoformat()

    # slug -> clock/HNDL detail from readiness reports (loaded once)
    detail = {}
    for f in (results / "pqc").glob("*/*-pqc-readiness.json"):
        try:
            rd = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        c2030 = [ci for ci in rd.get("clock_items") or [] if ci.get("deprecated_after") == 2030]
        detail[f.parent.name] = {
            "clock_2030": c2030,
            "clock_total": len(rd.get("clock_items") or []),
        }

    gdb = results / "graph" / "portfolio-graph.db"
    if not gdb.exists():
        print(f"error: graph db not found: {gdb}", file=sys.stderr)
        return 1
    con = sqlite3.connect(gdb)
    prods = collections.defaultdict(list)
    for src, attrs in con.execute(
        "SELECT e.src, n.attrs FROM edges e JOIN nodes n ON n.id=e.dst "
        "WHERE e.rel='ships' AND e.src LIKE 'product:%' AND "
        "n.kind='repo' AND json_extract(n.attrs,'$.pqc') IS NOT NULL"
    ):
        prods[src].append(json.loads(attrs)["pqc"])
    # product -> repo node keys (all shipped repos, not just PQC-assessed
    # ones), keyed identically to the crypto-dep discovery (repo: stripped).
    prod_repo_keys = collections.defaultdict(set)
    for src, dst in con.execute(
        "SELECT e.src, e.dst FROM edges e WHERE e.rel='ships' AND e.src LIKE 'product:%'"
    ):
        prod_repo_keys[src].add(dst[len("repo:") :] if dst.startswith("repo:") else dst)
    con.close()

    # cross-language crypto deps — reuse the roll-up's discover() + graph map
    crypto_deps, crypto_by_repo = _discover_crypto_deps(gdb)

    index_rows = []
    for pid, repos in prods.items():
        pslug = product_slug(pid)
        name = pid.split(":", 1)[1]
        bc = collections.Counter(r.get("readiness_bucket") or "?" for r in repos)
        scored = [
            r
            for r in repos
            if r.get("readiness_bucket") != "not-applicable"
            and isinstance(r.get("overall"), (int, float))
        ]
        scored.sort(key=lambda r: r["overall"])
        hndl = [r for r in repos if r.get("hndl_priority")]
        clock_rows = []
        for r in repos:
            d = detail.get(r.get("slug") or "", {})
            for ci in d.get("clock_2030", []):
                clock_rows.append((r["slug"], ci))
        L = [
            f"# PQC status — {name}",
            "",
            f"**Generated:** {today} · {len(repos)} assessed repos · "
            + " / ".join(f"{bc[b]} {b}" for b in BUCKETS if bc[b]),
            "",
        ]
        if scored:
            L += [
                f"**Worst repo:** `{scored[0]['slug']}` "
                f"({scored[0]['overall']}, "
                f"{scored[0].get('readiness_bucket')})",
                "",
            ]
        L += ["| Repo | Score | Bucket | HNDL | 2030-clock items |", "|---|---:|---|---|---:|"]
        for r in scored:
            d = detail.get(r.get("slug") or "", {})
            L.append(
                f"| `{r['slug']}` | {r['overall']:g} "
                f"| {r.get('readiness_bucket')} "
                f"| {'⚠' if r.get('hndl_priority') else '—'} "
                f"| {len(d.get('clock_2030', [])) or '—'} |"
            )
        na = bc.get("not-applicable", 0)
        if na:
            L += [
                "",
                f"*{na} further repo(s) verified zero-crypto (not-applicable, excluded above).*",
            ]
        if clock_rows:
            L += ["", "## 2030-clock items (deprecated after 2030)", ""]
            for slug, ci in sorted(
                clock_rows, key=lambda x: x[1].get("remediation_effort") != "significant"
            ):
                L.append(
                    f"- **{slug}** "
                    f"[{ci.get('remediation_effort')}] — "
                    f"{(ci.get('primitive') or '')[:180]}"
                )
        if hndl:
            L += ["", "## HNDL-priority repos", "", ", ".join(f"`{r['slug']}`" for r in hndl)]
        repo_keys = prod_repo_keys.get(pid, set())
        L += _crypto_deps_section(repo_keys, crypto_by_repo, crypto_deps)
        L += [
            "",
            "*Rebuilt by `build_pqc_product_reports.py`; fleet view: "
            "[`../pqc-portfolio-rollup.md`](../pqc-portfolio-rollup.md).*",
        ]
        (out / f"{pslug}.md").write_text("\n".join(L) + "\n")
        crypto_hits = sum(len(crypto_by_repo.get(rk, [])) for rk in repo_keys)
        crypto_classical = sum(
            1
            for rk in repo_keys
            for h in crypto_by_repo.get(rk, [])
            if h["posture"] == "classical-only"
        )
        index_rows.append(
            {
                "name": name,
                "slug": pslug,
                "repos": len(repos),
                "not_ready": bc["not-ready"],
                "hndl": len(hndl),
                "clock_2030": len(clock_rows),
                "crypto_deps": crypto_hits,
                "crypto_classical": crypto_classical,
                "worst": scored[0]["overall"] if scored else None,
                "worst_repo": scored[0]["slug"] if scored else "",
            }
        )

    index_rows.sort(key=lambda r: (-r["not_ready"], r["worst"] if r["worst"] is not None else 999))
    L = [
        "# Per-product PQC status reports",
        "",
        f"**Generated:** {today} · {len(index_rows)} products with "
        f"assessed repos, ranked worst-first (not-ready count, then worst "
        f"score). Fleet view: "
        "[`../pqc-portfolio-rollup.md`](../pqc-portfolio-rollup.md). "
        "Graph PQC/isolation attrs describe default-branch (HEAD) "
        "posture; per-ref facts are a separately-costed decision "
        "(branch-awareness plan, Phase 3). The Crypto-deps column counts "
        "graph-discovered cross-language crypto-library dependencies "
        "(classical-only = migration-relevant, in parentheses).",
        "",
        "| Product | Repos | Not-ready | HNDL | 2030-clock "
        "| Crypto-deps (classical) | Worst repo |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for r in index_rows:
        cd = f"{r['crypto_deps']} ({r['crypto_classical']})" if r.get("crypto_deps") else "—"
        L.append(
            f"| [{r['name']}]({r['slug']}.md) | {r['repos']} "
            f"| {r['not_ready']} | {r['hndl']} | {r['clock_2030']} "
            f"| {cd} | `{r['worst_repo']}` ({r['worst']}) |"
        )
    (out / "README.md").write_text("\n".join(L) + "\n")
    print(f"[+] wrote {len(index_rows)} product reports + index under {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
