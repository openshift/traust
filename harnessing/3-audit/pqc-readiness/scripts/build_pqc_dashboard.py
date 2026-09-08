#!/usr/bin/env python3
"""build_pqc_dashboard.py — live PQC status dashboard for Hybrid Platforms.

Deterministic roll-up of the Phase-1 sweep, regenerated after every batch:

  sweep progress   analysis-results/pqc/_manifest/sweep-state.json +
                   _manifest/status/*.json (per-repo agent results)
  posture          analysis-results/pqc/**/*-pqc-readiness.json
                   (buckets, clock items, effort classes, HNDL, FIPS,
                   provider census from the sibling facts files)
  workflow         pqc_classification-tagged findings emitted by the
                   GENERAL skills since v0.87.0 (secure-code-audit PQC
                   tagging + verify-remediation don't-regress) — walked
                   from findings/ + oss-findings/ audit and verification
                   reports, so everyday-audit PQC signal is tracked in
                   the same dashboard as the dedicated sweep

Outputs (progress-tracker/metrics/dashboards/pqc/):
  pqc-dashboard.md     leadership one-pager: coverage, bucket distribution,
                       2030-clock burndown list, HNDL priorities, effort mix
  pqc-dashboard.json   machine-readable sidecar (dashboards consume this)

Appends `pqc-readiness` metrics to the shared hash-chained ledger
(append_if_changed — idempotent re-runs never spam history).

Usage: build_pqc_dashboard.py [--results-root PATH] [--config-home PATH]
"""

import argparse
import collections
import datetime
import json
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

BUCKETS = ["ready", "partial", "not-ready", "blocked-external", "not-applicable"]
EFFORTS = ["trivial", "moderate", "significant", "blocked-external"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()

    results = resolve_results_root(args)
    engine = load_engine(args.config_home)
    pqc = results / "pqc"
    pt = progress_tracker_dir(engine)
    out_dir = args.out_dir.resolve() if args.out_dir else pt / "metrics" / "dashboards" / "pqc"
    out_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.date.today().isoformat()

    # --- sweep progress ---
    state = {}
    sp = pqc / "_manifest" / "sweep-state.json"
    if sp.exists():
        state = json.loads(sp.read_text())
    total = state.get("total") or 0
    statuses = []
    for p in sorted((pqc / "_manifest" / "status").glob("*.json")):
        try:
            statuses.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    done = [s for s in statuses if s.get("status") == "done"]
    unreachable = [s for s in statuses if s.get("status") == "unreachable"]

    # --- per-repo readiness reports (sweep + pilot-superseded skipped) ---
    repos = []
    for rp in sorted(pqc.glob("*/*-pqc-readiness.json")):
        if rp.parts[-3] == "pilot":
            continue
        try:
            d = json.loads(rp.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        eff = collections.Counter(
            (ci.get("remediation_effort") or "unclassified") for ci in d.get("clock_items") or []
        )
        rem = d.get("remediations") or []
        rem_by_cat = collections.Counter((e.get("category") or "unclassified") for e in rem)
        repos.append(
            {
                "slug": rp.parent.name,
                "repository": (d.get("metadata") or {}).get("repository"),
                "overall": (d.get("scores") or {}).get("overall"),
                "domains": {
                    k: ((d.get("scores") or {}).get(k) or {}).get("score")
                    for k in ("VULN", "AGIL", "PQCA", "HNDL")
                },
                "bucket": d.get("readiness_bucket") or "unclassified",
                "clock_items": len(d.get("clock_items") or []),
                "effort": dict(eff),
                "hndl": bool((d.get("flags") or {}).get("hndl_priority")),
                "clock_2030": bool((d.get("flags") or {}).get("has_2030_clock_items")),
                "fips": (d.get("fips_interaction") or {}).get("verdict"),
                "dominant_provenance": (d.get("provenance_summary") or {}).get("dominant"),
                "remediations": len(rem),
                "remediations_by_category": dict(rem_by_cat),
            }
        )

    # --- PQC-tagged findings from the GENERAL skills (v0.87.0 wiring) ---
    tagged = collections.Counter()
    tagged_effort = collections.Counter()
    tagged_repos = set()
    tagged_reg = 0
    for root in (results / "findings", results / "oss-findings"):
        if not root.is_dir():
            continue
        for rp in root.rglob("*.json"):
            n = rp.name
            if (
                not (
                    n.endswith("security-audit.json") or n.endswith("remediation-verification.json")
                )
                or "_manifest" in rp.parts
            ):
                continue
            try:
                doc = json.loads(rp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for f in (doc.get("findings") or []) + (doc.get("regressions") or []):
                pc = f.get("pqc_classification")
                if not pc:
                    continue
                tagged[pc] += 1
                tagged_effort[f.get("remediation_effort") or "unclassified"] += 1
                tagged_repos.add(rp.parent.name)
                if "REG" in str(f.get("id", "")):
                    tagged_reg += 1

    buckets = collections.Counter(r["bucket"] for r in repos)
    efforts = collections.Counter()
    for r in repos:
        efforts.update(r["effort"])
    n_clock = sum(r["clock_items"] for r in repos)
    hndl = [r for r in repos if r["hndl"]]
    clock2030 = [r for r in repos if r["clock_2030"]]
    prov = collections.Counter(r["dominant_provenance"] for r in repos if r["dominant_provenance"])
    rem_total = sum(r["remediations"] for r in repos)
    rem_by_cat = collections.Counter()
    for r in repos:
        rem_by_cat.update(r["remediations_by_category"])
    rem_repos = sum(1 for r in repos if r["remediations"])
    pct = round(100 * len(done) / total, 1) if total else 0.0

    def _org(r):
        repo_url = r.get("repository") or ""
        if "github.com/" in repo_url:
            parts = repo_url.split("github.com/")[1].split("/")
            return parts[0] if parts else "unknown"
        slug = r.get("slug", "")
        if "--" in slug:
            return slug.split("--")[0]
        return "unknown"

    side = {
        "generated": today,
        "campaign": "pqc-phase1-sweep",
        "sweep": {
            "total": total,
            "done": len(done),
            "unreachable": len(unreachable),
            "coverage_pct": pct,
            "batches_done": state.get("batches_done"),
        },
        "buckets": {b: buckets.get(b, 0) for b in BUCKETS},
        "clock_items_total": n_clock,
        "repos_with_2030_clock": len(clock2030),
        "hndl_priority_repos": len(hndl),
        "effort_distribution": {e: efforts.get(e, 0) for e in EFFORTS},
        "remediations": {
            "total": rem_total,
            "repos_with_remediations": rem_repos,
            "by_category": {
                c: rem_by_cat.get(c, 0)
                for c in ("fix-now", "upgrade", "waiting-on-upstream", "deadline")
            },
        },
        "dominant_provenance": dict(prov.most_common()),
        "workflow_findings": {
            "total": sum(tagged.values()),
            "by_classification": dict(tagged.most_common()),
            "by_effort": dict(tagged_effort.most_common()),
            "repos": len(tagged_repos),
            "pqc_regressions": tagged_reg,
        },
        "repos": sorted(repos, key=lambda r: (r["overall"] is None, r["overall"] or 0)),
        "repos_by_org": {
            org: sorted(
                [r for r in repos if _org(r) == org],
                key=lambda r: (r["overall"] is None, r["overall"] or 0),
            )
            for org in sorted({_org(r) for r in repos})
        },
    }
    (out_dir / "pqc-dashboard.json").write_text(
        json.dumps(side, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    L = [
        "# PQC Readiness — Hybrid Platforms Status",
        "",
        f"**Generated:** {today} · Phase 1 sweep: "
        f"**{len(done)}/{total} repos assessed ({pct}%)**, "
        f"{len(unreachable)} unreachable",
        "",
        "## Executive Summary",
        "",
        f"We assessed {len(done)} repositories for post-quantum cryptography "
        f"readiness. "
        f"**{buckets.get('ready', 0)}** are ready today, "
        f"**{buckets.get('partial', 0)}** need minor work, "
        f"**{buckets.get('not-ready', 0)}** need significant changes, and "
        f"**{buckets.get('blocked-external', 0)}** are waiting on upstream "
        f"vendors.",
        "",
        f"The most urgent items: **{len(clock2030)} repos** have crypto that "
        f"NIST plans to deprecate by 2030, and **{len(hndl)} repos** handle "
        f"data that could be harvested now and decrypted by a future quantum "
        f"computer.",
        "",
        "**What the scores mean:**",
        "",
        "| Domain | Plain English | Score |",
        "|---|---|---|",
        "| **VULN** | Is this repo using crypto vulnerable to quantum attacks? | 0 = fully exposed, 100 = no quantum-vulnerable crypto |",
        "| **AGIL** | How easy is it to swap the crypto when needed? | 0 = hardcoded everywhere, 100 = fully configurable |",
        "| **PQCA** | Has this repo already adopted post-quantum crypto? | 0 = no PQC, 100 = fully adopted |",
        "| **HNDL** | Is there a harvest-now-decrypt-later risk? | 0 = high-value long-lived data exposed, 100 = no risk |",
        "",
        "**Overall** combines these (VULN 40%, AGIL 25%, PQCA 20%, HNDL 15%) "
        "into a 0–100 score. Higher = more ready.",
        "",
        "**Buckets:** "
        "**ready** (≥80, no urgent items) · "
        "**partial** (50–79, minor work) · "
        "**not-ready** (<50 or has significant-effort items) · "
        "**blocked-external** (waiting on vendor/upstream) · "
        "**not-applicable** (no crypto in the repo)",
        "",
        "| Bucket | Repos |",
        "|---|---:|",
    ]
    _bucket_labels = {
        "ready": "Ready",
        "partial": "Almost ready",
        "not-ready": "Needs work",
        "blocked-external": "Blocked on upstream",
        "not-applicable": "No crypto",
    }
    L += [f"| {_bucket_labels.get(b, b)} | {buckets.get(b, 0)} |" for b in BUCKETS]
    L += [""]
    L += [
        "",
        "## Action items",
        "",
        f"- **{len(clock2030)} repos** have crypto due for replacement before "
        f"2030 ({n_clock} total items to fix)",
        f"- **{len(hndl)} repos** have harvest-now-decrypt-later exposure "
        f"(sensitive long-lived data under classical encryption)",
        "- Fix effort breakdown: "
        + " / ".join(
            f"**{efforts.get(e, 0)}** "
            + {
                "trivial": "quick config fix",
                "moderate": "moderate refactor",
                "significant": "major rework",
                "blocked-external": "blocked on vendor",
            }.get(e, e)
            for e in EFFORTS
        ),
        f"- **{rem_total} remediation actions** across {rem_repos} repos "
        f"(structured `remediations` sections, harness ≥ 0.153.0): "
        f"**{rem_by_cat.get('fix-now', 0)}** fix now · "
        f"**{rem_by_cat.get('upgrade', 0)}** upgrades · "
        f"**{rem_by_cat.get('waiting-on-upstream', 0)}** waiting on "
        f"upstream · **{rem_by_cat.get('deadline', 0)}** deadline-bound "
        f"(NIST IR 8547)",
        "",
        "## Repos by org (worst-first)",
        "",
        "Each org's repos sorted by score (lowest = needs most work). "
        "Column guide: **Clock items** = crypto primitives on the NIST "
        "deprecation timeline (2030/2035); **Actions** = entries in the "
        "report's structured `remediations` section (fix-now / upgrade / "
        "waiting-on-upstream / deadline).",
        "",
    ]

    scored_repos = [r for r in side["repos"] if r["bucket"] not in ("not-applicable",)]
    orgs = collections.defaultdict(list)
    for r in scored_repos:
        orgs[_org(r)].append(r)

    for org_name in sorted(
        orgs, key=lambda o: -len([r for r in orgs[o] if r["bucket"] == "not-ready"])
    ):
        org_repos = orgs[org_name]
        org_nr = sum(1 for r in org_repos if r["bucket"] == "not-ready")
        org_ready = sum(1 for r in org_repos if r["bucket"] == "ready")
        L += [
            f"### {org_name} ({len(org_repos)} repos — {org_ready} ready, {org_nr} need work)",
            "",
            "| Repo | Score | Vulnerable? | Agile? | PQC adopted? | Harvest risk? | Clock items | Actions | FIPS? |",
            "|---|---|---:|---:|---:|---|---:|---:|---|",
        ]
        for r in org_repos[:15]:
            dom = r.get("domains") or {}

            def _fmt_domain(k, d=dom):
                v = d.get(k)
                return "—" if v is None else f"{v:g}"

            hndl_cell = _fmt_domain("HNDL") + (" ⚠" if r["hndl"] else "")
            fips_raw = r["fips"] or ""
            fips_display = {
                "no-penalty": "OK",
                "blocked-by-provider-version": "Blocked",
                "fips-validation-gap": "Gap",
                "pqc-blocked-by-fips-mode": "Blocked",
            }.get(fips_raw, fips_raw or "—")
            bucket_display = _bucket_labels.get(r["bucket"], r["bucket"])
            rem_cell = str(r["remediations"]) if r.get("remediations") else "—"
            L.append(
                f"| {r['slug']} | **{r['overall']}** ({bucket_display}) "
                f"| {_fmt_domain('VULN')} | {_fmt_domain('AGIL')} | {_fmt_domain('PQCA')} "
                f"| {hndl_cell} "
                f"| {r['clock_items']} | {rem_cell} | {fips_display} |"
            )
        if len(org_repos) > 15:
            L.append(f"| *… {len(org_repos) - 15} more* | | | | | | | | |")
        L += [""]
    if hndl:
        hndl_by_org = collections.defaultdict(list)
        for r in hndl:
            hndl_by_org[_org(r)].append(r)
        L += [
            "",
            "## Harvest risk — prioritize these repos",
            "",
            "These repos protect long-lived sensitive data with crypto that "
            "a quantum computer could break. An attacker recording this "
            "traffic today could decrypt it later. Prioritize PQC migration "
            "here.",
            "",
        ]
        for org_name in sorted(hndl_by_org):
            L.append(
                f"**{org_name}:** " + ", ".join(f"`{r['slug']}`" for r in hndl_by_org[org_name])
            )
    if prov:
        _prov_labels = {
            "inherited-platform": "platform (cluster/OS)",
            "inherited-constrained": "constrained config",
            "delegated-dependency": "upstream library",
            "native-first-party": "this repo's own code",
            "vendored": "vendored dependency",
            "externalized": "external service",
            "not-assessable-from-source": "unclear from source",
            "none": "none detected",
        }
        L += [
            "",
            "## Who controls the fix?",
            "",
            "Where the crypto decisions live across assessed repos: ",
            " · ".join(f"**{_prov_labels.get(k, k)}**: {v}" for k, v in prov.most_common()),
        ]
    _class_labels = {
        "pqc-blocker-config": "config blocking PQC",
        "shor-key-establishment": "vulnerable key exchange",
        "shor-signature": "vulnerable signatures",
        "clock-2030-parameter": "deprecated by 2030",
    }
    L += [
        "",
        "## PQC blockers from ongoing security audits",
        "",
        (
            f"**{sum(tagged.values())} PQC-relevant findings** across "
            f"{len(tagged_repos)} repos from routine security audits "
            f"({tagged_reg} regressions caught): "
            + (
                ", ".join(f"{_class_labels.get(k, k)} ×{v}" for k, v in tagged.most_common())
                or "none yet"
            )
            + ". Effort to fix: "
            + (", ".join(f"{k} ×{v}" for k, v in tagged_effort.most_common()) or "—")
            + "."
        )
        if tagged
        else "No PQC-relevant findings from routine audits yet — this section "
        "fills as security audits run on each repo.",
    ]
    L += [
        "",
        "*Deterministic roll-up of `analysis-results/pqc/**` — "
        "rebuilt per sweep batch. Sidecar: `pqc-dashboard.json`.*",
        "",
    ]
    (out_dir / "pqc-dashboard.md").write_text("\n".join(L), encoding="utf-8")

    # --- shared metrics ledger (best-effort) ---
    try:
        engine.metrics.append_if_changed(
            "pqc-readiness",
            {
                "pqc_repos_assessed": len(done),
                "pqc_sweep_coverage_pct": pct,
                "pqc_ready": buckets.get("ready", 0),
                "pqc_partial": buckets.get("partial", 0),
                "pqc_not_ready": buckets.get("not-ready", 0),
                "pqc_clock_items": n_clock,
                "pqc_hndl_repos": len(hndl),
                "pqc_remediations_total": rem_total,
                "pqc_remediations_fix_now": rem_by_cat.get("fix-now", 0),
                "pqc_tagged_findings": sum(tagged.values()),
                "pqc_regressions": tagged_reg,
            },
        )
    except Exception as e:
        print(f"[!] ledger append skipped: {e}", file=sys.stderr)

    print(f"[+] wrote {out_dir / 'pqc-dashboard.md'}")
    print(
        f"[+] {len(done)}/{total} assessed ({pct}%) · buckets "
        f"{ {b: buckets.get(b, 0) for b in BUCKETS} } · "
        f"{n_clock} clock items · {len(hndl)} HNDL repos"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
