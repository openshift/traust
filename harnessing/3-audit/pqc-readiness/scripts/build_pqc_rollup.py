#!/usr/bin/env python3
"""build_pqc_rollup.py — Phase 2 portfolio roll-up (plan v1.3 §Phase 2 views).

Deterministic synthesis of the completed Phase-1 sweep into the costed,
portfolio-level migration plan. Inputs are the validated readiness reports
(`analysis-results/pqc/**/*-pqc-readiness.json`), the sibling facts files
(for the hybrid-blocker and toolchain censuses), and the portfolio graph
(for per-product roll-ups via `ships` edges + the `pqc` repo
attrs).

Outputs (progress-tracker/metrics/dashboards/pqc/):
  pqc-portfolio-rollup.md      the Phase-2 report — readiness distribution
                               (both vocabularies), provenance × provider,
                               NIST 2030/2035 timeline-compliance view,
                               effort-classed blocking items, FIPS/PQC
                               matrix, HNDL ranking, hybrid-TLS blockers,
                               toolchain quick wins, per-product roll-up,
                               dependency bottlenecks
  pqc-portfolio-rollup.json    machine-readable sidecar
  csv/pqc-2030-clock.csv       one row per 2030-clock item (repo, primitive,
                               effort, fact IDs)
  csv/pqc-hndl-priority.csv    HNDL-priority repos ranked by overall
  csv/pqc-hybrid-blockers.csv  group/KEX pins with file:line
  csv/pqc-toolchain-quickwins.csv  go-directive <1.24 census
  csv/pqc-per-product.csv      per-product bucket counts + worst repo

Read-only over analysis-results; safe to re-run (full rebuild each time).

Usage: build_pqc_rollup.py [--results-root PATH] [--config-home PATH]
"""

import argparse
import collections
import csv
import datetime
import json
import re
import sqlite3
import sys
from pathlib import Path

import yaml

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
BUCKETS = ["ready", "partial", "not-ready", "blocked-external", "not-applicable"]
EFFORTS = ["trivial", "moderate", "significant", "blocked-external"]
# group/KEX pin rules = the hybrid-negotiation blockers (plan §4.1 HP-GROUPS)
BLOCKER_RULES = {
    "HP_GROUPS_GO_CURVEPREFERENCES",
    "HP_GROUPS_SSHD_KEX",
    "HP_GROUPS_HAPROXY_CURVES",
    "HP_GROUPS_OPENSSL_CNF",
    "HP_GROUPS_ENVOY_ECDH",
    "HP_GROUPS_JAVA_NAMEDGROUPS",
    "HP_GROUPS_NGINX_ECDH_CURVE",
    "SSH_DH_GROUP14_SHA1",
    "SSH_DH_GROUP1",
}
GO_DIRECTIVE_RULE = "HP_CHAIN_GO_TOOLCHAIN"
# Load PQC version thresholds from single source of truth
_matrix = yaml.safe_load((HERE / "notes" / "reference" / "pqc-version-matrix.yaml").read_text())
_go_pqc_minor = int(_matrix["runtimes"]["go"]["pqc_kex_default"]["version"].split(".")[1])
GO_VER_RX = re.compile(r"\b1\.(\d+)")
ADOPTERS = [
    "cluster-logging-operator",
    "ptp-operator",
    "operator-controller",
    "ocs-tls-profiles",
    "feast",
    "sriov-network-operator",
]


def load_reports(pqc: Path):
    reports = {}
    for f in sorted(pqc.glob("*/*-pqc-readiness.json")):
        try:
            reports[f.parent.name] = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()
    results = resolve_results_root(args)
    engine = load_engine(args.config_home)
    pqc = results / "pqc"
    graph_db = results / "graph" / "portfolio-graph.db"
    out = (
        args.out_dir.resolve()
        if args.out_dir
        else progress_tracker_dir(engine) / "metrics" / "dashboards" / "pqc"
    )
    csv_dir = out / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.date.today().isoformat()

    reports = load_reports(pqc)
    if not reports:
        print(f"error: no readiness reports under {pqc}", file=sys.stderr)
        return 1

    # --- core distributions -------------------------------------------------
    buckets = collections.Counter()
    scores = []
    prov_prov = collections.Counter()  # (dominant_provenance, pqca_capable)
    fips = collections.Counter()  # (fips_interaction, bucket)
    efforts = collections.Counter()
    clock_2030_rows, clock_2035 = [], 0
    hndl_rows = []
    per_bucket_scores = collections.defaultdict(list)
    for slug, rd in sorted(reports.items()):
        b = rd.get("readiness_bucket") or "?"
        buckets[b] += 1
        ov = (rd.get("scores") or {}).get("overall")
        if isinstance(ov, (int, float)) and b != "not-applicable":
            scores.append(ov)
            per_bucket_scores[b].append(ov)
        prov = (rd.get("provenance_summary") or {}).get("dominant") or "none"
        pqca = (rd.get("scores") or {}).get("PQCA")
        if isinstance(pqca, dict):
            pqca = pqca.get("score")
        prov_prov[(prov, "pqc-capable" if (pqca or 0) >= 75 else "pre-pqc/unknown")] += 1
        fi = rd.get("fips_interaction")
        if isinstance(fi, dict):
            fi = fi.get("verdict")
        if fi:
            fips[(fi, b)] += 1
        for ci in rd.get("clock_items") or []:
            eff = ci.get("remediation_effort") or "?"
            efforts[eff] += 1
            if ci.get("deprecated_after") == 2030:
                clock_2030_rows.append(
                    {
                        "repo": slug,
                        "bucket": b,
                        "overall": ov,
                        "primitive": (ci.get("primitive") or "")[:200],
                        "effort": eff,
                        "fact_ids": ";".join(ci.get("fact_ids") or []),
                    }
                )
            else:
                clock_2035 += 1
        if (rd.get("flags") or {}).get("hndl_priority"):
            hndl_rows.append(
                {"repo": slug, "overall": ov, "bucket": b, "dominant_provenance": prov}
            )
    hndl_rows.sort(key=lambda r: r["overall"] if r["overall"] is not None else 999)
    clock_2030_rows.sort(key=lambda r: (r["effort"] != "significant", r["repo"]))

    # --- facts-derived censuses (blockers + toolchain quick wins) -----------
    blockers, quickwins = [], []
    for f in sorted(pqc.glob("*/*-pqc-facts.json")):
        slug = f.parent.name
        try:
            doc = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for fact in doc.get("facts", []):
            if fact.get("path_class") != "first_party":
                continue
            rid = fact.get("rule_id", "")
            if rid in BLOCKER_RULES:
                blockers.append(
                    {
                        "repo": slug,
                        "rule": rid,
                        "location": f"{fact.get('file', '')}:{fact.get('line', '')}",
                        "match": (fact.get("match") or "")[:120],
                    }
                )
            elif rid == GO_DIRECTIVE_RULE:
                # version lives in `detail` ("go 1.24"); pqc_capable is the
                # adapter's own attestation — trust it when present
                if fact.get("pqc_capable") is True:
                    continue
                m = GO_VER_RX.search(fact.get("detail") or fact.get("match") or "")
                if m and int(m.group(1)) < _go_pqc_minor:
                    quickwins.append(
                        {
                            "repo": slug,
                            "go_version": f"1.{m.group(1)}",
                            "location": f"{fact.get('file', '')}:{fact.get('line', '')}",
                        }
                    )
    quickwins.sort(key=lambda r: (int(r["go_version"].split(".")[1]), r["repo"]))

    # --- per-product roll-up via the graph ----------------------------------
    products = []
    if graph_db.exists():
        con = sqlite3.connect(graph_db)
        rows = con.execute(
            "SELECT e.src, n.attrs FROM edges e JOIN nodes n ON n.id=e.dst "
            "WHERE e.rel='ships' AND e.src LIKE 'product:%' "
            "AND n.kind='repo' AND json_extract(n.attrs,'$.pqc') IS NOT NULL"
        ).fetchall()
        agg = collections.defaultdict(lambda: {"buckets": collections.Counter(), "worst": None})
        for src, attrs in rows:
            p = json.loads(attrs)["pqc"]
            name = src.split(":", 1)[1]
            a = agg[name]
            a["buckets"][p.get("readiness_bucket") or "?"] += 1
            ov = p.get("overall")
            if (
                p.get("readiness_bucket") not in (None, "not-applicable")
                and isinstance(ov, (int, float))
                and (a["worst"] is None or ov < a["worst"][1])
            ):
                a["worst"] = (p.get("slug"), ov)
        for name, a in agg.items():
            total = sum(a["buckets"].values())
            a["buckets"]["not-ready"]
            products.append(
                {
                    "product": name,
                    "repos": total,
                    **{b: a["buckets"][b] for b in BUCKETS},
                    "worst_repo": a["worst"][0] if a["worst"] else "",
                    "worst_score": a["worst"][1] if a["worst"] else "",
                }
            )
        products.sort(
            key=lambda r: (-r["not-ready"], r["worst_score"] if r["worst_score"] != "" else 999)
        )
        con.close()

    # --- dependency bottlenecks (blocked-external + top crypto deps) --------
    blocked_repos = sorted(
        s for s, rd in reports.items() if rd.get("readiness_bucket") == "blocked-external"
    )
    dep_top = []
    if graph_db.exists():
        con = sqlite3.connect(graph_db)
        dep_top = con.execute(
            "SELECT dst, COUNT(*) c FROM edges WHERE rel='uses_crypto_dep' "
            "GROUP BY dst ORDER BY c DESC LIMIT 15"
        ).fetchall()
        con.close()

    # --- cross-language crypto deps (graph multi-ecosystem depends_on layer) -
    # Reads the NEW pkg:<eco>/ depends_on edges via the sibling scanner, which
    # skips cleanly if the graph is absent/legacy. Also writes the standalone
    # pqc/_manifest/crypto-deps.{json,md} artifact so it exists even when the
    # scanner has not been run out-of-band.
    crypto_deps = {"graph_present": False, "totals": {}, "posture_totals": {}, "ecosystems": {}}
    try:
        sys.path.insert(0, str(HERE))
        import scan_crypto_deps_graph as scd

        seeds = scd.load_seeds(scd.DEFAULT_SEEDS)
        crypto_deps = scd.discover(graph_db, seeds)
        crypto_deps["seed_source"] = str(scd.DEFAULT_SEEDS)
        cd_stem = pqc / "_manifest" / "crypto-deps"
        cd_stem.parent.mkdir(parents=True, exist_ok=True)
        cd_stem.with_suffix(".json").write_text(
            json.dumps(crypto_deps, indent=1, sort_keys=True) + "\n"
        )
        cd_stem.with_suffix(".md").write_text(scd.render_md(crypto_deps))
    except Exception as e:
        print(f"[!] crypto-dep graph discovery skipped: {e}", file=sys.stderr)

    # --- write CSVs ----------------------------------------------------------
    def write_csv(name, rows, fields):
        with (csv_dir / name).open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    write_csv(
        "pqc-2030-clock.csv",
        clock_2030_rows,
        ["repo", "bucket", "overall", "effort", "primitive", "fact_ids"],
    )
    write_csv(
        "pqc-hndl-priority.csv", hndl_rows, ["repo", "overall", "bucket", "dominant_provenance"]
    )
    write_csv("pqc-hybrid-blockers.csv", blockers, ["repo", "rule", "location", "match"])
    write_csv("pqc-toolchain-quickwins.csv", quickwins, ["repo", "go_version", "location"])
    write_csv(
        "pqc-per-product.csv", products, ["product", "repos", *BUCKETS, "worst_repo", "worst_score"]
    )

    # --- markdown report -----------------------------------------------------
    n = len(reports)
    scores.sort()
    med = scores[len(scores) // 2] if scores else 0
    L = [
        "# PQC Portfolio Roll-up — Phase 2",
        "",
        f"**Generated:** {today} · from {n} validated readiness reports · CSV exports in `csv/`",
        "",
        "## Executive Summary",
        "",
        f"Across {n} repositories assessed for post-quantum cryptography readiness:",
        "",
        f"- **{buckets.get('ready', 0)} repos** are PQC-ready today",
        f"- **{buckets.get('partial', 0)} repos** need minor work to be ready",
        f"- **{buckets.get('not-ready', 0)} repos** need significant changes",
        f"- **{buckets.get('blocked-external', 0)} repos** are blocked on upstream vendors",
        "",
        f"**Urgency:** {len(clock_2030_rows)} crypto primitives across "
        f"{len({r['repo'] for r in clock_2030_rows})} repos are on the "
        f"NIST 2030 deprecation clock. {len(hndl_rows)} repos have "
        f"harvest-now-decrypt-later exposure.",
        "",
        "**What the scores mean:**",
        "",
        "| Domain | Plain English |",
        "|---|---|",
        "| **VULN** | Is this repo using crypto vulnerable to quantum attacks? |",
        "| **AGIL** | How easy is it to swap the crypto when needed? |",
        "| **PQCA** | Has this repo already adopted post-quantum crypto? |",
        "| **HNDL** | Is there a harvest-now-decrypt-later risk? |",
        "",
        "## Readiness distribution",
        "",
        "| Bucket | Repos | Median score |",
        "|---|---:|---:|",
    ]
    _rollup_bucket_labels = {
        "ready": "Ready",
        "partial": "Almost ready",
        "not-ready": "Needs work",
        "blocked-external": "Blocked on upstream",
        "not-applicable": "No crypto",
    }
    for b in BUCKETS:
        bs = sorted(per_bucket_scores.get(b, []))
        m = f"{bs[len(bs) // 2]:g}" if bs else "—"
        L.append(f"| {_rollup_bucket_labels.get(b, b)} | {buckets[b]} | {m} |")
    L += [
        "",
        f"Scored population median: **{med:g}** (n={len(scores)}, not-applicable excluded).",
        "",
        "## NIST post-quantum transition timeline",
        "",
        f"- **2030 deadline (RSA-2048 and equivalent — stop using for new "
        f"work):** {len(clock_2030_rows)} items across "
        f"{len({r['repo'] for r in clock_2030_rows})} repos — the urgent "
        f"burndown (`csv/pqc-2030-clock.csv`)",
        f"- **2035 deadline (all classical public-key crypto disallowed):** "
        f"{clock_2035} items — the bulk migration, mostly in upstream "
        f"libraries and ecosystem dependencies",
        "- **Effort to fix (all timeline items):** "
        + " / ".join(
            f"{efforts.get(e, 0)} "
            + {
                "trivial": "quick config fix",
                "moderate": "moderate refactor",
                "significant": "major rework",
                "blocked-external": "blocked on vendor",
            }.get(e, e)
            for e in EFFORTS
        ),
        "",
        "## Blocking items by effort (urgent backlog)",
        "",
        "Significant-effort items on the 2030 deadline — the engineering "
        "backlog that needs planning now:",
        "",
    ]
    for r in [r for r in clock_2030_rows if r["effort"] == "significant"][:20]:
        L.append(f"- **{r['repo']}** ({r['overall']}) — {r['primitive']}")
    L += [
        "",
        "## FIPS / PQC compatibility",
        "",
        "Can PQC work alongside FIPS compliance? Status across repos:",
        "",
        "| FIPS status | Repos | Breakdown |",
        "|---|---:|---|",
    ]
    fi_totals = collections.Counter()
    for (fi, _b), c in fips.items():
        fi_totals[fi] += c
    fips_labels = {
        "no-penalty": "OK — PQC works under FIPS",
        "blocked-by-provider-version": "Blocked — crypto library too old for PQC+FIPS",
        "fips-validation-gap": "Gap — PQC available but not FIPS-validated yet",
        "pqc-blocked-by-fips-mode": "Blocked — FIPS mode disables PQC entirely",
    }
    for fi, total in fi_totals.most_common():
        label = fips_labels.get(fi, fi)
        detail = ", ".join(
            f"{_rollup_bucket_labels.get(b, b)}: {c}"
            for (f2, b), c in sorted(fips.items())
            if f2 == fi
        )
        L.append(f"| {label} | {total} | {detail} |")
    L += [
        "",
        "The `blocked-by-provider-version` cases are resolvable by upgrading "
        "to a crypto library that includes PQC in its FIPS module "
        "(e.g. OpenSSL 3.5.7-fips).",
        "",
        f"## Harvest risk — prioritize these ({len(hndl_rows)} repos)",
        "",
        "These repos protect sensitive long-lived data (secrets, certs, "
        "encrypted storage) with crypto a quantum computer could break. "
        "An attacker recording this traffic today could decrypt it later.",
        "",
        "| Repo | Score | Status | Who controls the crypto |",
        "|---|---:|---|---|",
    ]
    prov_labels = {
        "inherited-platform": "platform (cluster/OS)",
        "inherited-constrained": "constrained (pinned config)",
        "delegated-dependency": "upstream library",
        "native-first-party": "this repo's own code",
        "vendored": "vendored dependency",
        "externalized": "external service",
        "not-assessable-from-source": "can't tell from source",
        "none": "none detected",
    }
    for r in hndl_rows[:25]:
        prov_display = prov_labels.get(r["dominant_provenance"], r["dominant_provenance"])
        bucket_display = _rollup_bucket_labels.get(r["bucket"], r["bucket"])
        L.append(f"| {r['repo']} | {r['overall']} | {bucket_display} | {prov_display} |")
    L += [
        "",
        "Full list: `csv/pqc-hndl-priority.csv`.",
        "",
        f"## Config pins blocking PQC ({len(blockers)} items)",
        "",
        "These are explicit TLS group/curve pins in code that prevent "
        "ML-KEM negotiation, regardless of runtime version "
        "(`csv/pqc-hybrid-blockers.csv`). Top repos:",
        "",
    ]
    for repo, c in collections.Counter(b["repo"] for b in blockers).most_common(15):
        L.append(f"- {repo}: {c}")
    L += [
        "",
        f"## Quick wins — Go version bumps ({len(quickwins)} repos below Go 1.{_go_pqc_minor})",
        "",
        "A one-line `go` directive bump in go.mod enables ML-KEM by default "
        "(`csv/pqc-toolchain-quickwins.csv`). Version histogram: "
        + ", ".join(
            f"go {v}: {c}"
            for v, c in sorted(
                collections.Counter(q["go_version"] for q in quickwins).items(),
                key=lambda kv: int(kv[0].split(".")[1]),
            )
        ),
        "",
        "## Who controls the crypto (provenance breakdown)",
        "",
        "Where the crypto decisions live — determines who needs to act:",
        "",
        "| Who controls it | PQC-capable already | Not yet PQC-capable |",
        "|---|---:|---:|",
    ]
    provs = sorted({p for p, _ in prov_prov})
    for p in provs:
        label = prov_labels.get(p, p)
        L.append(
            f"| {label} | {prov_prov[(p, 'pqc-capable')]} | {prov_prov[(p, 'pre-pqc/unknown')]} |"
        )
    L += [
        "",
        f"## Per-product roll-up ({len(products)} products with assessed repos)",
        "",
        "Products ranked by not-ready count then worst score (`csv/pqc-per-product.csv`). Top 20:",
        "",
        "| Product | Repos | Ready | Partial | Not-ready | Worst repo |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for p in products[:20]:
        L.append(
            f"| {p['product']} | {p['repos']} | {p['ready']} "
            f"| {p['partial']} | {p['not-ready']} "
            f"| {p['worst_repo']} ({p['worst_score']}) |"
        )
    L += [
        "",
        f"## Blocked on upstream ({len(blocked_repos)} repos)",
        "",
        "These repos can't adopt PQC until a vendor or external dependency ships support:",
        "",
        "- **Repos:** " + ", ".join(blocked_repos),
        "- **Most-used crypto libraries (fix these → unblock many repos):**",
    ]
    for dst, c in dep_top:
        name = dst.split(":", 1)[1] if ":" in dst else dst
        L.append(f"  - {name}: {c} repos")
    L += ["", "## Cross-language crypto dependencies (portfolio graph)"]
    if crypto_deps.get("graph_present"):
        ct = crypto_deps.get("totals", {})
        L += [
            "",
            "Beyond the Go/TLS surface, these are repos that pull in a "
            "curated crypto library in npm / pypi / maven / cargo / ruby / "
            "nuget, discovered from the portfolio graph's multi-ecosystem "
            "`depends_on` edges (full detail: "
            "`analysis-results/pqc/_manifest/crypto-deps.md`; seed list: "
            "`harnessing/3-audit/pqc-readiness/notes/crypto-packages.yaml`).",
            "",
            f"- **{ct.get('repos', 0)} repos** across "
            f"**{ct.get('hits', 0)} dependency edges** "
            f"(**{ct.get('packages_matched', 0)}** distinct seed packages).",
            "- Posture mix: "
            + (
                ", ".join(f"{k}: {v}" for k, v in crypto_deps.get("posture_totals", {}).items())
                or "none matched"
            )
            + " — `classical-only` are the migration-relevant deps.",
            "",
        ]
        pt = collections.Counter()
        for eco, hits in crypto_deps.get("ecosystems", {}).items():
            pt[eco] = len(hits)
        if pt:
            L.append("| Ecosystem | Crypto-dep edges |")
            L.append("|---|---:|")
            for eco, c in sorted(pt.items()):
                L.append(f"| {eco} | {c} |")
    else:
        L += [
            "",
            "_Portfolio graph not available (or missing the multi-ecosystem "
            "dependency layer); cross-language crypto deps not computed. "
            "Build it with `/portfolio-graph`._",
        ]
    L += [
        "",
        "## First-party PQC adopters",
        "",
        "- " + " · ".join(ADOPTERS),
        "",
        "*Deterministic roll-up of `analysis-results/pqc/**` + the "
        "portfolio graph. Graph PQC/isolation attrs describe "
        "default-branch (HEAD) posture; per-ref facts are a "
        "separately-costed decision (branch-awareness plan, Phase 3). "
        "Rebuild with "
        "`build_pqc_rollup.py`. Sidecar: `pqc-portfolio-rollup.json`.*",
    ]
    (out / "pqc-portfolio-rollup.md").write_text("\n".join(L) + "\n")

    side = {
        "generated": today,
        "reports": n,
        "buckets": dict(buckets),
        "median_score": med,
        "clock_2030": clock_2030_rows,
        "clock_2035_count": clock_2035,
        "effort_mix": dict(efforts),
        "fips_matrix": {f"{fi}|{b}": c for (fi, b), c in fips.items()},
        "hndl": hndl_rows,
        "hybrid_blockers": blockers,
        "toolchain_quickwins": quickwins,
        "products": products,
        "blocked_external": blocked_repos,
        "top_crypto_deps": [[d, c] for d, c in dep_top],
        "crypto_deps_graph": {
            "graph_present": crypto_deps.get("graph_present", False),
            "totals": crypto_deps.get("totals", {}),
            "posture_totals": crypto_deps.get("posture_totals", {}),
            "by_ecosystem": {
                eco: len(hits) for eco, hits in crypto_deps.get("ecosystems", {}).items()
            },
        },
    }
    (out / "pqc-portfolio-rollup.json").write_text(json.dumps(side, indent=1) + "\n")

    # shared metrics ledger (best-effort): the Phase-2 view series that
    # Executive-Trends charts (2030-clock/blockers/quick-wins burn down)
    try:
        engine.metrics.append_if_changed(
            "pqc-readiness",
            {
                "pqc_2030_clock_items": len(clock_2030_rows),
                "pqc_hybrid_blockers": len(blockers),
                "pqc_toolchain_quickwins": len(quickwins),
            },
        )
    except Exception as e:
        print(f"[!] ledger append skipped: {e}", file=sys.stderr)
    print(f"[+] wrote {out / 'pqc-portfolio-rollup.md'} (+json, 5 CSVs)")
    print(
        f"[+] {n} reports · 2030-clock {len(clock_2030_rows)} items/"
        f"{len({r['repo'] for r in clock_2030_rows})} repos · "
        f"HNDL {len(hndl_rows)} · blockers {len(blockers)} · "
        f"quickwins {len(quickwins)} · products {len(products)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
