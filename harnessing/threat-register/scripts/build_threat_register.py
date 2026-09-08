#!/usr/bin/env python3
"""Build the fleet-wide threat register from THREAT_MODEL.md artifacts.

Deterministic aggregation only — parses every threat-model artifact under
the given roots (reusing the traust_engine.reporting.lint parser, so the register
reads exactly what the contract gate enforces), keys each threat by the
stable compound key `<model-slug>:<Tn>` (threat IDs are never renumbered
or reused per schema.md, so the key is durable across model updates), and
emits:

    threat-register/threat-register.json   full register + roll-ups
    threat-register/threat-register.md     leadership summary
    threat-register/threat-register.html   self-contained dashboard

No conclusions are drawn: statuses, impacts, and likelihoods are reported
as the models state them. The rank score is a fixed ordinal product
(impact weight x likelihood weight, documented in the JSON meta), used
for ordering only — it is not CVSS and never feeds the risk index, which
remains the ledger's job.

Usage:
    python3 build_threat_register.py [--results-root <analysis-results>] [--out <dir>]
"""

from __future__ import annotations

import argparse
import datetime
import html
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from traust_engine import locations
from traust_engine.reporting.lint import (
    BOUNDARY_COLUMNS,
    ISOLATION_DIMENSIONS,
    MITIG_COLUMNS,
    THREATS_COLUMN_VARIANTS,
    collect,
    parse_provenance,
    parse_sections,
    parse_table,
)

from traust.context import (
    add_config_home_arg,
    load_engine,
    resolve_results_root,
)

IMPACT_W = {"low": 1, "medium": 2, "high": 4, "critical": 8, "existential": 16}
LIKELIHOOD_W = {"very_rare": 1, "rare": 2, "possible": 4, "likely": 8, "almost_certain": 16}
IMPACT_ORDER = ["existential", "critical", "high", "medium", "low"]
STATUS_ORDER = ["unmitigated", "partially_mitigated", "risk_accepted", "mitigated"]
QUICK_WIN_EFFORTS = {"XS", "S"}
QUICK_WIN_IMPACTS = {"high", "critical", "existential"}

SCORING = (
    "rank score = impact weight x likelihood weight; "
    f"impact {IMPACT_W}; likelihood {LIKELIHOOD_W}. "
    "Ordering only — not CVSS, not the risk index."
)


def model_slug(path, root):
    rel = path.relative_to(root)
    stem = path.name
    for suffix in ("-threat-model.md",):
        if stem.endswith(suffix):
            return stem[: -len(suffix)], str(rel)
    return rel.parent.name, str(rel)  # THREAT_MODEL.md → parent dir name


def parse_model(path, root):
    text = path.read_text(encoding="utf-8")
    sections = {h: b for h, b in parse_sections(text)}
    slug, rel = model_slug(path, root)
    parts = path.relative_to(root).parts
    product = parts[1] if len(parts) > 2 else parts[0]

    prov = parse_provenance(sections.get("7. Provenance", []))
    threats = []
    # Accept every contract column variant: the legacy ten columns, the
    # attack_refs eleventh (default since harness 0.82.0), and the optional
    # trailing isolation_dimensions twelfth (PEACH lens Phase 1).
    cols, rows = parse_table(sections.get("4. Threats", []))
    if cols not in THREATS_COLUMN_VARIANTS:
        return None
    for r in rows:
        if len(r) != len(cols):
            continue
        row = dict(zip(cols, r, strict=False))
        evidence = [t.strip() for t in re.split(r"[,;]\s*", row["evidence"]) if t.strip()]
        threats.append(
            {
                "key": f"{product}/{slug}:{row['id']}",
                "product": product,
                "model": rel,
                "id": row["id"],
                "threat": row["threat"],
                "actors": [a.strip() for a in row["actor"].split(",") if a.strip()],
                "surface": row["surface"],
                "asset": row["asset"],
                "impact": row["impact"],
                "likelihood": row["likelihood"],
                "status": row["status"],
                "controls": row["controls"],
                "evidence": evidence,
                "linddun": row["threat"].lower().startswith("linddun:"),
                "score": IMPACT_W.get(row["impact"], 0) * LIKELIHOOD_W.get(row["likelihood"], 0),
            }
        )
        # Optional isolation tag (subset of the five hardening dimensions,
        # vocabulary shared with contracts/schemas/isolation-review.schema.json). Key
        # present only when the model tags the threat — older register
        # consumers see unchanged rows.
        iso = [
            d.strip()
            for d in re.split(r"[,;]\s*", row.get("isolation_dimensions", ""))
            if d.strip()
        ]
        if iso:
            threats[-1]["isolation_dimensions"] = iso

    # Optional section 10 (multi-tenant services only): tenant-boundary rows.
    boundaries = []
    bcols, brows = parse_table(sections.get("10. Tenant boundaries", []))
    if bcols == BOUNDARY_COLUMNS:
        for r in brows:
            if len(r) != len(BOUNDARY_COLUMNS):
                continue
            row = dict(zip(BOUNDARY_COLUMNS, r, strict=False))
            entry = {
                "key": f"{product}/{slug}:{row['boundary_id']}",
                "product": product,
                "model": rel,
                "id": row["boundary_id"],
                "interface": row["interface"],
                "kind": row["kind"],
                "exposure": row["exposure"],
                "complexity": row["complexity"],
                "dimensions": {d: row[d] for d in ISOLATION_DIMENSIONS},
                "threat_ids": [
                    t.strip() for t in re.split(r"[,;]\s*", row["threat_ids"]) if t.strip()
                ],
            }
            ref = row["isolation_review_ref"].strip()
            if ref:
                entry["isolation_review_ref"] = ref
            boundaries.append(entry)

    # Join boundary context onto tagged threats (optional register columns:
    # boundary id(s) + isolation_review_ref; absent on untagged rows).
    if boundaries:
        bids_by_tid, ref_by_tid = defaultdict(list), {}
        for b in boundaries:
            for tid in b["threat_ids"]:
                bids_by_tid[tid].append(b["id"])
                if "isolation_review_ref" in b:
                    ref_by_tid.setdefault(tid, b["isolation_review_ref"])
        for t in threats:
            if t["id"] in bids_by_tid:
                t["isolation_boundaries"] = bids_by_tid[t["id"]]
            if t["id"] in ref_by_tid:
                t["isolation_review_ref"] = ref_by_tid[t["id"]]

    mitigations = []
    mcols, mrows = parse_table(sections.get("8. Recommended mitigations", []))
    if mcols == MITIG_COLUMNS:
        for r in mrows:
            if len(r) != len(MITIG_COLUMNS):
                continue
            mitigations.append(
                {
                    "model": rel,
                    "product": product,
                    "mitigation": r[0],
                    "threat_ids": [t.strip() for t in re.split(r"[,;]\s*", r[1]) if t.strip()],
                    "closes_class": r[2],
                    "effort": r[3],
                }
            )

    return {
        "slug": slug,
        "model": rel,
        "product": product,
        "tree": parts[0],
        "date": prov.get("date", ""),
        "mode": prov.get("mode", ""),
        "threats": threats,
        "mitigations": mitigations,
        "tenant_boundaries": boundaries,
    }


# Ownership sub-split ($TRAUST_CONFIG_HOME/corpus-config.yaml tree tags): findings/ is
# owned (Hybrid Platforms), oss-findings/ is upstream. The split is reported
# alongside the portfolio totals — upstream is never folded into the owned
# cut, and the existing headline totals are unchanged.
OWNERSHIP_CUT_TREES = (
    ("findings", "Owned (findings/, Hybrid Platforms)"),
    ("oss-findings", "Upstream (oss-findings/)"),
)


def ownership_cuts(models):
    """Owned vs upstream sub-split from the same per-model stats."""
    cuts = {}
    for tree, label in OWNERSHIP_CUT_TREES:
        tms = [m for m in models if m.get("tree") == tree]
        ths = [t for m in tms for t in m["threats"]]
        open_ths = [t for t in ths if t["status"] in ("unmitigated", "partially_mitigated")]
        cuts[tree] = {
            "label": label,
            "models": len(tms),
            "threats": len(ths),
            "open": len(open_ths),
            "open_critical_plus": sum(
                1 for t in open_ths if t["impact"] in ("critical", "existential")
            ),
        }
    return cuts


def quick_wins(models):
    """Class-closing XS/S mitigations that cover an open high+ threat."""
    wins = []
    for m in models:
        by_id = {t["id"]: t for t in m["threats"]}
        for mit in m["mitigations"]:
            if mit["closes_class"] != "yes" or mit["effort"] not in QUICK_WIN_EFFORTS:
                continue
            covered = [
                by_id[t]
                for t in mit["threat_ids"]
                if t in by_id
                and by_id[t]["status"] == "unmitigated"
                and by_id[t]["impact"] in QUICK_WIN_IMPACTS
            ]
            if covered:
                wins.append(
                    {
                        "product": m["product"],
                        "model": m["model"],
                        "mitigation": mit["mitigation"],
                        "effort": mit["effort"],
                        "covers": [t["key"] for t in covered],
                        "max_score": max(t["score"] for t in covered),
                    }
                )
    wins.sort(key=lambda w: (-w["max_score"], w["product"]))
    return wins


# Dimension-result weights for the weakest-boundary ordering: a failed
# dimension outweighs a partial one; yes/na contribute nothing. Ordering
# only — like the rank score, this is not CVSS and draws no conclusions.
DIM_FAIL_W = {"no": 2, "partial": 1}
COMPLEXITY_RANK = {"high": 2, "medium": 1, "low": 0}


def tenant_boundary_rollup(models):
    """Which tenant boundaries are weakest, fleet-wide (optional: only
    models carrying a section 10 contribute). Each entry keeps the model's
    stated dimension results and gains ordering aids: weakness (sum of
    failed/partial dimension weights), the failed/partial dimension names,
    and the open threats tagged to the boundary. Sorted weakest-first."""
    entries = []
    for m in models:
        by_id = {t["id"]: t for t in m["threats"]}
        for b in m.get("tenant_boundaries", []):
            e = dict(b)
            e["weak_dimensions"] = [d for d, v in b["dimensions"].items() if v == "no"]
            e["partial_dimensions"] = [d for d, v in b["dimensions"].items() if v == "partial"]
            e["weakness"] = sum(DIM_FAIL_W.get(v, 0) for v in b["dimensions"].values())
            e["open_threats"] = [
                by_id[t]["key"]
                for t in b["threat_ids"]
                if t in by_id and by_id[t]["status"] in ("unmitigated", "partially_mitigated")
            ]
            entries.append(e)
    entries.sort(
        key=lambda e: (
            -e["weakness"],
            -COMPLEXITY_RANK.get(e["complexity"], 0),
            -len(e["open_threats"]),
            e["key"],
        )
    )
    return entries


def doc_variance_cut(root: Path) -> dict:
    """Doc-variance lane rollup (P3): every <repo>-doc-variance.json
    register under the findings trees, summarized for leadership —
    open doc-vs-code discrepancies per product, by variance class and
    disposition, oldest open first. Registers are schema-gated at write
    time (emit_doc_variance.py); this cut only aggregates."""
    import json as _json

    rows, per_product = [], defaultdict(lambda: {"open": 0, "total": 0, "overclaim": 0})
    for reg in sorted(root.rglob("*-doc-variance.json")):
        try:
            doc = _json.loads(reg.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rel = reg.relative_to(root)
        product = rel.parts[1] if len(rel.parts) > 2 else "(top)"
        for r in doc.get("records") or []:
            per_product[product]["total"] += 1
            if r.get("disposition") == "open":
                per_product[product]["open"] += 1
                if r.get("variance") == "overclaim":
                    per_product[product]["overclaim"] += 1
                rows.append(
                    {
                        "product": product,
                        "repo": (doc.get("metadata") or {}).get("repository", ""),
                        "id": r.get("id"),
                        "variance": r.get("variance"),
                        "claim": (r.get("claim") or "")[:140],
                        "doc_version": (r.get("source") or {}).get("version"),
                        "verified_at": r.get("verified_at"),
                    }
                )
    rows.sort(key=lambda r: r.get("verified_at") or "")
    return {
        "per_product": dict(per_product),
        "open_records": rows,
        "note": (
            "official docs.redhat.com claims contradicted by "
            "code evidence — overclaims are customer-facing "
            "trust exposure even when the code is "
            "working-as-intended; doc_corrected is a "
            "resolution no finding lifecycle models"
        ),
    }


def build(root, out_dir, engine=None):
    root = Path(root).resolve()
    trees = [d for d in ("findings", "oss-findings") if (root / d).is_dir()]
    files = collect([root / d for d in trees])
    models, skipped = [], 0
    for f in files:
        m = parse_model(f, root)
        if m is None:
            skipped += 1
            continue
        models.append(m)

    # Guarantee key uniqueness: when two models in one product share a
    # slug (e.g. repo/ and repo-gitlab/ holding same-named files), requalify
    # the colliding models' keys with the full relative path.
    prefix_models = defaultdict(set)
    for m in models:
        for t in m["threats"] + m.get("tenant_boundaries", []):
            prefix_models[t["key"].rsplit(":", 1)[0]].add(m["model"])
    for m in models:
        for t in m["threats"] + m.get("tenant_boundaries", []):
            if len(prefix_models[t["key"].rsplit(":", 1)[0]]) > 1:
                t["key"] = (
                    m["model"].replace("-threat-model.md", "").replace("/THREAT_MODEL.md", "")
                    + ":"
                    + t["id"]
                )

    threats = [t for m in models for t in m["threats"]]
    open_threats = [t for t in threats if t["status"] in ("unmitigated", "partially_mitigated")]

    by_product = defaultdict(
        lambda: {"models": 0, "threats": 0, "open": 0, "open_high_plus": 0, "score_sum": 0}
    )
    for m in models:
        by_product[m["product"]]["models"] += 1
    for t in threats:
        p = by_product[t["product"]]
        p["threats"] += 1
        if t["status"] in ("unmitigated", "partially_mitigated"):
            p["open"] += 1
            p["score_sum"] += t["score"]
            if t["impact"] in QUICK_WIN_IMPACTS:
                p["open_high_plus"] += 1

    register = {
        "meta": {
            "generated": datetime.date.today().isoformat(),
            "root": str(root),
            "models": len(models),
            "models_skipped_nonconforming": skipped,
            "threat_count": len(threats),
            "scoring": SCORING,
            "key": "compound key <model-slug>:<Tn>; stable because threat "
            "IDs are never renumbered or reused (schema.md section 4)",
        },
        "totals": {
            "by_status": dict(Counter(t["status"] for t in threats)),
            "by_impact": dict(Counter(t["impact"] for t in threats)),
            "open_by_impact": dict(Counter(t["impact"] for t in open_threats)),
            "evidence_backed": sum(1 for t in threats if t["evidence"]),
            "linddun": sum(1 for t in threats if t["linddun"]),
        },
        "ownership_cuts": ownership_cuts(models),
        "by_product": {
            k: dict(v) for k, v in sorted(by_product.items(), key=lambda kv: -kv[1]["score_sum"])
        },
        "doc_variance": doc_variance_cut(root),
        "quick_wins": quick_wins(models),
        "threats": sorted(
            threats, key=lambda t: (-t["score"], STATUS_ORDER.index(t["status"]), t["key"])
        ),
    }
    # Optional (PEACH lens Phase 1): present only when at least one model
    # carries a section 10 — registers built from boundary-free portfolios
    # are byte-identical to pre-Phase-1 output.
    tb = tenant_boundary_rollup(models)
    if tb:
        register["tenant_boundaries"] = tb
        register["meta"]["tenant_boundary_count"] = len(tb)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_text, html_text = render_md(register), render_html(register)
    pop = _population_lines(trees, register, engine)
    if pop:
        md_text += "\n---\n\n" + "\n".join(pop) + "\n"
        html_text = html_text.replace("</body></html>", _population_html(pop) + "\n</body></html>")
    (out / "threat-register.json").write_text(json.dumps(register, indent=1), encoding="utf-8")
    (out / "threat-register.md").write_text(md_text, encoding="utf-8")
    (out / "threat-register.html").write_text(html_text, encoding="utf-8")
    return register


def _doc_variance_md(reg) -> list:
    """Markdown lines for the doc-variance cut (empty when no open
    records — the section only appears once registers exist)."""
    dv = reg.get("doc_variance") or {}
    if not dv.get("open_records"):
        return []
    out = [
        "",
        "## Documentation variance (official docs vs code)",
        "",
        dv.get("note", ""),
        "",
        "| Product | Open | Overclaims | Total records |",
        "|---|---:|---:|---:|",
    ]
    for prod, c in sorted((dv.get("per_product") or {}).items()):
        out.append(f"| {prod} | {c['open']} | {c['overclaim']} | {c['total']} |")
    out += ["", "Oldest open records:"]
    for r in dv["open_records"][:10]:
        out.append(
            f"- `{r['id']}` ({r['product']}, "
            f"docs v{r['doc_version']}, {r['variance']}) — "
            f"{r['claim']}"
        )
    return out


def render_md(reg):
    m, t = reg["meta"], reg["totals"]
    open_total = t["by_status"].get("unmitigated", 0) + t["by_status"].get("partially_mitigated", 0)

    def cell(s, n):
        return str(s)[:n].replace("|", "/")

    lines = [
        "# Fleet-wide Threat Register",
        "",
        f"Generated {m['generated']} from **{m['models']} threat models** "
        f"(**{m['threat_count']} threats**, {open_total} open); "
        f"{m['models_skipped_nonconforming']} nonconforming model(s) skipped.",
        "",
        "## How to read this",
        "",
        "- Statuses, impacts, and likelihoods are reported **exactly as the "
        "models state them** — mostly machine-derived at each model's "
        "emission date (bootstrap mode greps for controls; interview-mode "
        "rows carry owner answers). They decay until a `/threat-model "
        "review` pass re-scores them against current code.",
        "- The rank score is an ordinal ordering aid "
        "(impact weight × likelihood weight) — **not CVSS**, and it never "
        "feeds the ledger risk index.",
        "- Keys are `<product>/<model-slug>:<Tn>`, stable across model "
        "updates (threat IDs are never renumbered or reused).",
        "- Threats join the disposition ledger only via their `evidence` "
        "citations of canonical finding IDs.",
        "",
        "## Totals",
        "",
        "| status | count |",
        "|---|---|",
    ]
    for s in STATUS_ORDER:
        lines.append(f"| {s} | {t['by_status'].get(s, 0)} |")
    lines += ["", "| impact (open threats) | count |", "|---|---|"]
    for i in IMPACT_ORDER:
        lines.append(f"| {i} | {t['open_by_impact'].get(i, 0)} |")
    lines += [
        "",
        f"Evidence-backed threats: {t['evidence_backed']} of "
        f"{m['threat_count']} (the rest are STRIDE gap-fill); "
        f"LINDDUN privacy rows: {t['linddun']}.",
    ]
    cuts = reg.get("ownership_cuts") or {}
    if cuts:
        lines += [
            "",
            "## Ownership cuts",
            "",
            "Owned and upstream reported separately — upstream is never "
            "folded into the owned cut; the portfolio totals above are "
            "unchanged.",
            "",
            "| Cut | Models | Threats | Open | Open critical+existential |",
            "|---|---|---|---|---|",
        ]
        for c in cuts.values():
            lines.append(
                f"| {c['label']} | {c['models']} | {c['threats']} "
                f"| {c['open']} | {c['open_critical_plus']} |"
            )
    lines += [
        "",
        f"## Top 25 open threats (of {open_total})",
        "",
        "| key | product | threat | impact | likelihood | status |",
        "|---|---|---|---|---|---|",
    ]
    shown = 0
    for th in reg["threats"]:
        if th["status"] not in ("unmitigated", "partially_mitigated"):
            continue
        lines.append(
            f"| {th['key']} | {th['product']} | {cell(th['threat'], 110)} "
            f"| {th['impact']} | {th['likelihood']} | {th['status']} |"
        )
        shown += 1
        if shown >= 25:
            break
    lines += [
        "",
        f"## Top 25 quick wins (of {len(reg['quick_wins'])})",
        "",
        "Class-closing XS/S mitigations covering an open "
        "high/critical/existential threat — the highest-leverage "
        "engineering asks in the fleet:",
        "",
        "| product | mitigation | effort | covers |",
        "|---|---|---|---|",
    ]
    for w in reg["quick_wins"][:25]:
        lines.append(
            f"| {w['product']} | {cell(w['mitigation'], 100)} "
            f"| {w['effort']} | {', '.join(w['covers'][:4])} |"
        )
    tb = reg.get("tenant_boundaries") or []
    if tb:
        lines += [
            "",
            f"## Weakest tenant boundaries ({len(tb)} fleet-wide)",
            "",
            "Tenant-boundary rows from multi-tenant models' optional "
            "section 10, ordered weakest-first (failed then partial "
            "isolation-hardening dimensions, then complexity and tagged "
            "open threats). Dimension results are reported exactly as the "
            "models state them; a linked `/isolation-review` artifact "
            "carries the evidence:",
            "",
            "| boundary | interface | kind | exposure | complexity "
            "| failed dims | partial dims | open threats | review |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for b in tb[:25]:
            lines.append(
                f"| {b['key']} | {cell(b['interface'], 60)} | {b['kind']} "
                f"| {b['exposure']} | {b['complexity']} "
                f"| {', '.join(b['weak_dimensions']) or '—'} "
                f"| {', '.join(b['partial_dimensions']) or '—'} "
                f"| {len(b['open_threats'])} "
                f"| {cell(b.get('isolation_review_ref', '—'), 60)} |"
            )
    accepted = [th for th in reg["threats"] if th["status"] == "risk_accepted"]
    by_p = Counter(th["product"] for th in accepted)
    lines += [
        "",
        f"## Risk acceptances ({len(accepted)} fleet-wide)",
        "",
        "Owner- or model-recorded acceptances, aggregated here for "
        "the first time — worth a periodic human review. "
        "Top products:",
        "",
        "| product | risk_accepted threats |",
        "|---|---|",
    ]
    for p, n in by_p.most_common(15):
        lines.append(f"| {p} | {n} |")
    lines += [
        "",
        f"## Top 25 products by open-threat score (of {len(reg['by_product'])})",
        "",
        "| product | models | threats | open | open high+ |",
        "|---|---|---|---|---|",
    ]
    for p, v in list(reg["by_product"].items())[:25]:
        lines.append(
            f"| {p} | {v['models']} | {v['threats']} | {v['open']} | {v['open_high_plus']} |"
        )
    lines += [
        "",
        "---",
        "",
        f"Full register: `threat-register.json` (every threat with "
        f"actors, surface, asset, controls, evidence); dashboard: "
        f"`threat-register.html`. Scoring: {m['scoring']} "
        f"Rebuild with `/threat-register` after any batch of "
        f"threat-model runs, reviews, or updates.",
        "",
    ]
    lines += _doc_variance_md(reg)

    return "\n".join(lines)


def render_html(reg):
    m, t = reg["meta"], reg["totals"]

    def esc(s):
        return html.escape(str(s))

    def bar(n, mx):
        pct = 0 if not mx else int(100 * n / mx)
        return f"<div class='bar'><span style='width:{pct}%'></span><b>{n}</b></div>"

    mx_open = max([v["open"] for v in reg["by_product"].values()] or [1])
    rows_products = "\n".join(
        f"<tr><td>{esc(p)}</td><td>{v['models']}</td><td>{v['threats']}</td>"
        f"<td>{bar(v['open'], mx_open)}</td><td>{v['open_high_plus']}</td></tr>"
        for p, v in list(reg["by_product"].items())[:40]
    )
    rows_threats = "\n".join(
        f"<tr><td><code>{esc(th['key'])}</code></td><td>{esc(th['product'])}</td>"
        f"<td>{esc(th['threat'][:160])}</td><td class='{esc(th['impact'])}'>"
        f"{esc(th['impact'])}</td><td>{esc(th['likelihood'])}</td>"
        f"<td>{esc(th['status'])}</td></tr>"
        for th in [
            x for x in reg["threats"] if x["status"] in ("unmitigated", "partially_mitigated")
        ][:50]
    )
    rows_wins = "\n".join(
        f"<tr><td>{esc(w['product'])}</td><td>{esc(w['mitigation'][:140])}</td>"
        f"<td>{esc(w['effort'])}</td><td>{esc(', '.join(w['covers'][:4]))}</td></tr>"
        for w in reg["quick_wins"][:40]
    )
    status_cells = "".join(
        f"<div class='kpi'><div class='num'>{t['by_status'].get(s, 0)}</div>"
        f"<div class='lbl'>{s}</div></div>"
        for s in STATUS_ORDER
    )
    cuts = reg.get("ownership_cuts") or {}
    rows_cuts = "\n".join(
        f"<tr><td>{esc(c['label'])}</td><td>{c['models']}</td>"
        f"<td>{c['threats']}</td><td>{c['open']}</td>"
        f"<td>{c['open_critical_plus']}</td></tr>"
        for c in cuts.values()
    )
    cuts_panel = (
        ""
        if not rows_cuts
        else "<h2>Ownership cuts</h2>\n"
        "<p class='meta'>Owned and upstream reported separately — "
        "upstream is never folded into the owned cut; portfolio "
        "totals above are unchanged.</p>\n"
        "<table><tr><th>cut</th><th>models</th><th>threats</th>"
        "<th>open</th><th>open critical+existential</th></tr>\n"
        f"{rows_cuts}</table>"
    )
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Fleet-wide Threat Register</title><style>
body{{font:14px/1.5 -apple-system,Segoe UI,sans-serif;margin:2rem;color:#1a1a1a;max-width:1200px}}
h1{{font-size:1.5rem}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}} code{{font-size:12px}}
.kpis{{display:flex;gap:1rem;margin:1rem 0}}
.kpi{{border:1px solid #ddd;border-radius:8px;padding:.8rem 1.2rem;text-align:center}}
.kpi .num{{font-size:1.6rem;font-weight:700}} .kpi .lbl{{color:#666;font-size:12px}}
.bar{{position:relative;background:#f0f0f0;border-radius:4px;min-width:120px;height:18px}}
.bar span{{position:absolute;left:0;top:0;bottom:0;background:#c9302c55;border-radius:4px}}
.bar b{{position:relative;padding-left:6px;font-size:12px}}
td.critical,td.existential{{color:#c9302c;font-weight:700}} td.high{{color:#d9534f}}
.meta{{color:#666;font-size:12px}}</style></head><body>
<h1>Fleet-wide Threat Register</h1>
<p class='meta'>Generated {esc(m["generated"])} · {m["models"]} threat models ·
{m["threat_count"]} threats · key = model-slug:Tn (stable; IDs never reused) ·
rank score is ordinal, not CVSS · statuses as the models state them</p>
<div class='kpis'>{status_cells}</div>
{cuts_panel}
<h2>Top open threats</h2>
<table><tr><th>key</th><th>product</th><th>threat</th><th>impact</th>
<th>likelihood</th><th>status</th></tr>{rows_threats}</table>
<h2>Quick wins — class-closing XS/S mitigations over open high+ threats</h2>
<table><tr><th>product</th><th>mitigation</th><th>effort</th><th>covers</th></tr>
{rows_wins}</table>
<h2>Products by open threats</h2>
<table><tr><th>product</th><th>models</th><th>threats</th><th>open</th>
<th>open high+</th></tr>{rows_products}</table>
</body></html>"""


# --- standard population block (traust.cli.groups.corpus; best-effort) -----------


def _population_lines(trees, reg, engine=None):
    """Standard population block for cross-dashboard reconciliation.
    Reports only what this run already did; omitted (never fatal) when
    corpus.py or its config is unavailable."""
    try:
        from traust_engine.corpus import resolver as corpus

        cfg = engine.corpus.config() if engine is not None else corpus.load_config()
        m, bs = reg["meta"], reg["totals"]["by_status"]
        return corpus.population_block_lines(
            tool="threat-register",
            roots=corpus.roots_description(cfg, trees),
            unit="threats (rows in threat-model table), keyed <model-slug>:<Tn> — NOT findings",
            filters="nonconforming models skipped (lint gate); artifacts/ "
            "scratch and symlinks skipped",
            denominator="directory walk for *-threat-model.md (and legacy THREAT_MODEL.md)",
            counts={
                "Threat models parsed": m["models"],
                "Models skipped nonconforming": m["models_skipped_nonconforming"],
                "Threats total": m["threat_count"],
                "Threats open": bs.get("unmitigated", 0) + bs.get("partially_mitigated", 0),
            },
        )
    except Exception as exc:
        print(f"population block omitted: {exc}", file=sys.stderr)
        return None


def _population_html(lines):
    """Same content as the markdown block, as a final html-escaped panel."""
    items = []
    for ln in lines:
        if ln.startswith("- **"):
            label, _, val = ln[4:].partition(":**")
            items.append(f"<li><b>{html.escape(label)}:</b>{html.escape(val)}</li>")
        elif ln.startswith("- "):
            items.append(f"<li>{html.escape(ln[2:])}</li>")
    return "<h2>Population</h2><ul class='meta'>" + "".join(items) + "</ul>"


def _dashboards_home(engine):
    """Dashboards live with the metrics, separate from findings data:
    progress-tracker/metrics/dashboards/ when configured; None -> caller
    falls back to the legacy results-root location."""
    try:
        pt = locations.require(
            locations.progress_tracker_dir(engine.ctx.locations),
            "progress_tracker",
        )
        out = pt / "metrics" / "dashboards"
        out.mkdir(parents=True, exist_ok=True)
        return out
    except Exception:
        return None


def _inject_trend(path, text):
    try:
        import re as _re

        p = Path(path)
        s = p.read_text(encoding="utf-8")
        if p.suffix == ".md":
            head, _, rest = s.partition("\n")
            s = head + f"\n\n\U0001f4c8 *{text}*\n" + rest
        else:
            s = _re.sub(
                r"(<body[^>]*>)",
                lambda m: (
                    m.group(1) + "<div style='max-width:1280px;margin:10px auto 0;"
                    "padding:0 28px;font-size:13px;color:#6a6e73'>"
                    "\U0001f4c8 " + text + "</div>"
                ),
                s,
                count=1,
            )
        p.write_text(s, encoding="utf-8")
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results checkout (default: configured)",
    )
    ap.add_argument(
        "--out", default=None, help="output dir (default: <results-root>/threat-register)"
    )
    args = ap.parse_args()

    engine = load_engine(args.config_home)
    root = resolve_results_root(args)
    out = args.out or str((_dashboards_home(engine) or root) / "threat-register")
    reg = build(root, out, engine)
    m, t = reg["meta"], reg["totals"]
    print(
        f"{m['models']} models, {m['threat_count']} threats "
        f"({m['models_skipped_nonconforming']} nonconforming models skipped)"
    )
    print(
        f"open: {t['by_status'].get('unmitigated', 0)} unmitigated, "
        f"{t['by_status'].get('partially_mitigated', 0)} partial; "
        f"quick wins: {len(reg['quick_wins'])}"
    )
    try:
        from traust_engine.metrics import history as metrics_history

        bs = t["by_status"]
        headline = {
            "threat_models": m["models"],
            "threats_total": m["threat_count"],
            "threats_unmitigated": bs.get("unmitigated", 0),
            "threats_partial": bs.get("partially_mitigated", 0),
            "threats_open": bs.get("unmitigated", 0) + bs.get("partially_mitigated", 0),
            "quick_wins": len(reg["quick_wins"]),
        }
        prev = engine.metrics.previous("threat-register")
        tline = metrics_history.trend_line(
            headline,
            prev,
            [
                "threats_open",
                "threats_unmitigated",
                "threats_partial",
                "threat_models",
                "quick_wins",
            ],
        )
        if tline:
            _inject_trend(Path(out) / "threat-register.md", tline)
            _inject_trend(Path(out) / "threat-register.html", tline)
        if engine.metrics.append_if_changed("threat-register", headline):
            print("metrics snapshot appended (threat-register)")
    except Exception:
        pass
    print(f"wrote {out}/threat-register.{{json,md,html}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
