#!/usr/bin/env python3
"""Coverage-gap rollup — the enumerator-expansion backlog, aggregated.

Every deterministic pre-scan self-reports what it could NOT cover: the
config-matrix expander emits `coverage_gaps` for TOML/INI files and
render-gated charts, the route×guard enumerator for unenumerated web
frameworks, the audit protocol records skipped pre-scans in
`metadata.additional.deterministic_steps`, and language holes surface in
`negative_results` prose ("opengrep hps pack has 0 Rust rules"). Those
statements persist per-report — but until this roll-up nothing aggregated
them, so prioritizing the next enumerator family or rule-pack language
was anecdote (deep-fn-technique-plan Phase-B residue, 2026-07-29).

This script walks the corpus via traust.cli.groups.corpus (the shared resolver —
never a hand-rolled walker; harness-qa/benchmark trees are centrally
excluded) and aggregates three signal tiers per HEAD code-audit report:

  structured   metadata.additional.coverage_gaps — the recording
               convention the enumerator pre-scan sections require
               (secure-code-audit SKILL.md); highest confidence
  steps        metadata.additional.deterministic_steps values starting
               "skipped:" — a pre-scan that did not run at all
  text         negative_results entries matching known gap signatures
               (lowest confidence; each match carries its source quote)

Output: coverage-gap-rollup.{json,md} — gap families ranked by distinct
repos affected, each row carrying tool, system, repo count, summed item
counts where recorded, signal-tier breakdown, and example repos. The MD
leads with the standard population block (census doctrine: state what was
counted and what was excluded).

Consumers: the deep-fn plan's Phase-B family-prioritization decision
(which enumerator/expander to build next) and the mine-ledger
rule-authoring backlog review; terminal otherwise.

Usage:
    python3 build_coverage_gap_rollup.py [--results-root DIR]
        [--config PATH] [--out-dir DIR] [--include-branch-audits]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from traust_engine.corpus import report_store
from traust_engine.corpus.resolver import load_config

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)
from traust.paths import HARNESS_ROOT

# negative_results prose signatures -> (tool, system) normalization.
# Deliberately narrow: each regex is a known emitter phrasing, not a
# guess; unrecognized prose never fabricates a gap row.
TEXT_SIGNATURES = [
    (
        re.compile(r"toml/ini/properties config file — no v1 expander"),
        ("config-matrix", "toml-ini-properties"),
    ),
    (
        re.compile(r"\b(express|fastapi|flask|spring)\b[^.]*UNENUMERATED"),
        ("route-guards", None),
    ),  # system = the captured framework
    (re.compile(r"defaults resolve only at render time"), ("config-matrix", "helm-render-gated")),
    (re.compile(r"CRD-shaped config"), ("config-matrix", "crd-operator-config")),
    (
        re.compile(
            r"opengrep\b[^.]{0,80}\b(?:has\s+)?(?:0|~?no)\s+"
            r"(\w+)\s+rules",
            re.I,
        ),
        ("opengrep", None),
    ),  # system = the captured language
    (
        re.compile(r"sanitizer[- ]probes?[^.]{0,60}Python-only", re.I),
        ("sanitizer-probes", "non-python"),
    ),
]


def _gap_rows_from_report(report: dict) -> list[dict]:
    rows = []
    additional = (report.get("metadata") or {}).get("additional") or {}

    for g in additional.get("coverage_gaps") or []:
        if not isinstance(g, dict):
            continue
        rows.append(
            {
                "tool": str(g.get("tool") or "unknown"),
                "system": str(g.get("system") or "unknown"),
                "count": g.get("count"),
                "signal": "structured",
            }
        )

    for step, status in (additional.get("deterministic_steps") or {}).items():
        if isinstance(status, str) and status.startswith("skipped"):
            rows.append(
                {
                    "tool": str(step),
                    "system": "pre-scan-skipped",
                    "count": None,
                    "signal": "steps",
                    "reason": status[:160],
                }
            )

    for nr in report.get("negative_results") or []:
        text = (
            " ".join(str(nr.get(k) or "") for k in ("area", "result", "files"))
            if isinstance(nr, dict)
            else str(nr)
        )
        for rx, (tool, system) in TEXT_SIGNATURES:
            m = rx.search(text)
            if not m:
                continue
            sysname = system or (m.group(1).lower() if m.groups() and m.group(1) else "unknown")
            # language aliases collapse into one family
            sysname = {
                "js": "javascript",
                "ts": "javascript",
                "typescript": "javascript",
                "golang": "go",
                "py": "python",
            }.get(sysname, sysname)
            rows.append(
                {
                    "tool": tool,
                    "system": sysname,
                    "count": None,
                    "signal": "text",
                    "quote": m.group(0)[:160],
                }
            )
    return rows


def build_rollup(
    results_root: Path,
    cfg: dict,
    include_branch_audits: bool = False,
    engine=None,
    use_engine_resolve: bool = False,
) -> dict:
    if use_engine_resolve and engine is not None:
        res = engine.corpus.load_resolution()
    else:
        res = report_store.load_resolution(results_root, cfg)
    store = report_store.ReportStore(report_store.LocalBackend(results_root))
    families: dict[tuple, dict] = defaultdict(
        lambda: {
            "repos": set(),
            "items": 0,
            "items_reported": False,
            "signals": defaultdict(int),
            "examples": [],
        }
    )
    population = {"records": 0, "scored": 0, "no_json": 0, "branch_skipped": 0, "unreadable": 0}

    for rec in res.records:
        population["records"] += 1
        if rec.report_kind != "code-audit":
            continue
        if rec.is_branch_audit and not include_branch_audits:
            population["branch_skipped"] += 1
            continue
        if not rec.audit_json:
            population["no_json"] += 1
            continue
        try:
            report = store.get_json(report_store.to_ref(rec.audit_json, results_root))
        except (OSError, json.JSONDecodeError):
            population["unreadable"] += 1
            continue
        population["scored"] += 1
        repo_key = f"{rec.tree}/{rec.repo_dir}"
        seen_here = set()
        for row in _gap_rows_from_report(report):
            key = (row["tool"], row["system"])
            fam = families[key]
            fam["repos"].add(repo_key)
            fam["signals"][row["signal"]] += 1
            if isinstance(row.get("count"), int):
                fam["items"] += row["count"]
                fam["items_reported"] = True
            if key not in seen_here and len(fam["examples"]) < 8:
                fam["examples"].append(repo_key)
            seen_here.add(key)

    ranked = sorted(
        (
            {
                "tool": k[0],
                "system": k[1],
                "repos_affected": len(v["repos"]),
                "items_recorded": v["items"] if v["items_reported"] else None,
                "signals": dict(v["signals"]),
                "example_repos": v["examples"],
            }
            for k, v in families.items()
        ),
        key=lambda r: (-r["repos_affected"], r["tool"], r["system"]),
    )

    return {
        "artifact": "coverage-gap-rollup",
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "population": {
            **population,
            "note": (
                "HEAD code-audit reports resolved via corpus.py "
                "(harness-qa/benchmark trees centrally excluded; "
                "branch re-audits skipped"
                + ("" if not include_branch_audits else " OFF")
                + "). 'scored' = reports actually parsed."
            ),
        },
        "gap_families": ranked,
        "warnings": res.warnings[:20],
    }


def render_md(data: dict) -> str:
    p = data["population"]
    lines = [
        "# Coverage-Gap Rollup — enumerator-expansion backlog",
        "",
        f"Generated {data['generated_at']} · harness {data['harness_version']}",
        "",
        "**Population:** "
        f"{p['scored']} HEAD code-audit reports parsed "
        f"(of {p['records']} corpus records; {p['branch_skipped']} branch "
        f"re-audits skipped, {p['no_json']} md-only, "
        f"{p['unreadable']} unreadable). {p['note']}",
        "",
        "Signal tiers: `structured` = metadata.additional.coverage_gaps "
        "(recording convention, highest confidence) · `steps` = skipped "
        "pre-scans in deterministic_steps · `text` = negative_results "
        "prose signatures (lowest confidence).",
        "",
        "| # | Tool | System / family | Repos affected | Items recorded "
        "| Signals | Example repos |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, g in enumerate(data["gap_families"], 1):
        sig = ", ".join(f"{k}:{v}" for k, v in sorted(g["signals"].items()))
        items = g["items_recorded"] if g["items_recorded"] is not None else "—"
        lines.append(
            f"| {i} | {g['tool']} | {g['system']} | "
            f"{g['repos_affected']} | {items} | {sig} | "
            f"{', '.join(g['example_repos'][:3])} |"
        )
    if not data["gap_families"]:
        lines.append(
            "| — | (no gap statements found in the corpus yet — "
            "the structured convention ships with the v0.204+ "
            "enumerators; coverage grows as repos are re-audited)"
            " | | | | | |"
        )
    lines += [
        "",
        "Reading the table: 'repos affected' ranks which enumerator "
        "family or rule-pack language to build next (deep-fn plan "
        "Phase-B prioritization). Rows sourced only from `text` "
        "signals deserve a skim of the quoted prose before acting.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=None)
    ap.add_argument(
        "--progress-tracker",
        type=Path,
        default=None,
        help="progress-tracker root (default: configured)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output directory (default: <progress-tracker>/metrics/coverage-gaps)",
    )
    ap.add_argument("--include-branch-audits", action="store_true")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = resolve_results_root(args)
    tracker = args.progress_tracker or progress_tracker_dir(engine)
    args.out_dir = args.out_dir or tracker / "metrics" / "coverage-gaps"

    cfg = load_config(args.config) if args.config else engine.corpus.config()
    data = build_rollup(
        results_root,
        cfg,
        args.include_branch_audits,
        engine=engine,
        use_engine_resolve=args.config is None,
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "coverage-gap-rollup.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.out_dir / "coverage-gap-rollup.md").write_text(render_md(data), encoding="utf-8")
    print(
        f"{len(data['gap_families'])} gap families over "
        f"{data['population']['scored']} reports -> {args.out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
