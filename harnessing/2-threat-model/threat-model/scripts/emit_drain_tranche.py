#!/usr/bin/env python3
"""Emit this week's trickle-drain tranche — the orchestrator's one
deterministic entry point for scheduling diff scans.

Reads the daily router's worklist (build_rescan_worklist.py) and writes
a dated tranche manifest: the quarterly-pool rows inside the weekly
drain rate (`drain_order < summary.drain.weekly_rate`, already
risk-ordered: exposure → tier → S_lines → C) plus, with
--include-immediate, the immediate diff-scan rows (rule-3 P2 /
tripwire escalations). Selection only — this script never scans,
never spends, and never authors a verdict.

Fail-closed guards:
  - refuses when the worklist is older than --max-age-hours (default
    48; a drain dispatched from a stale pool re-livess the pilot's
    clone-then-refuse waste)
  - refuses when the worklist predates the refusal pre-route
    (no `summary.preroute` block)
  - refuses to overwrite an existing tranche manifest for the same
    ISO week unless --force (idempotence: one tranche per week)

The orchestrator contract around this script is documented in
docs/continuous-operations.md ("Standing weekly drain — orchestrator
contract"). Downstream: each row is one headless `/vuln-scan
<clone> --diff` run (packet path; repo-config isolation rule S9 —
agent cwd NEVER inside the clone), results beside the row's baseline
report for /triage.

Usage:
    python3 scripts/emit_drain_tranche.py \
        [--worklist FILE] [--out-dir DIR] [--week YYYY-Www] \
        [--include-immediate] [--max-age-hours N] [--force]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
    workspace_dir,
)
from traust.paths import optional_config_path

ROW_FIELDS = (
    "repo_url",
    "repo_key",
    "lane",
    "tier",
    "exposure",
    "C",
    "S_lines",
    "drain_order",
    "rule",
    "reason",
    "audit_age_days",
    "changed_days",
    # threat-model cadence (plan Phases 1-3): the pr stamp
    # rides its diff row; review/quarterly rows are their own
    # lanes. `lane` joined this list at the same time — with
    # more than one dispatchable lane in a tranche, the
    # dispatcher can no longer assume every row is a diff.
    "threat_model",
    "threat_model_pr",
    "threat_model_age_days",
    "release_version",
    "release_change",
)

# Lanes a tranche may dispatch, and what each one runs.
_DISPATCH = {
    "diff-scan-quarterly": "/vuln-scan <clone> --diff",
    "diff-scan": "/vuln-scan <clone> --diff",
    "threat-model-quarterly": "/threat-model review <clone> --auto",
    "threat-model-review": "/threat-model review <clone> --auto",
}


def parse_generated_at(doc: dict) -> _dt.datetime | None:
    raw = doc.get("generated_at") or ""
    try:
        return _dt.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)
    except ValueError:
        return None


def select_rows(doc: dict, include_immediate: bool) -> list[dict]:
    """Both trickle pools drain by their OWN weekly rate — the diff pool
    spreads over a quarter of change, the threat-model pool over a
    quarter of calendar. A `threat-model-review` row is release-
    triggered and low-volume, so it dispatches immediately like an
    event row rather than queueing behind a drain order."""
    smry = doc.get("summary") or {}
    rate = (smry.get("drain") or {}).get("weekly_rate")
    tm_rate = (smry.get("threat_model") or {}).get("quarterly_weekly_rate")
    rows = []
    for d in doc.get("decisions") or []:
        lane = d.get("lane")
        order = d.get("drain_order")
        diff_q = (
            lane == "diff-scan-quarterly"
            and order is not None
            and rate is not None
            and order < rate
        )
        tm_q = (
            lane == "threat-model-quarterly"
            and order is not None
            and tm_rate is not None
            and order < tm_rate
        )
        imm = include_immediate and lane == "diff-scan"
        if diff_q or tm_q or lane == "threat-model-review" or imm:
            rows.append(d)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--worklist", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument(
        "--week",
        default=None,
        help="ISO week label (default: the worklist's generation week, e.g. 2026-W31)",
    )
    ap.add_argument(
        "--include-immediate",
        action="store_true",
        help="also include the immediate diff-scan lane (rule-3 P2 / tripwire rows)",
    )
    ap.add_argument("--no-shadow", action="store_true", help="skip observe-mode budget accounting")
    ap.add_argument(
        "--append-shadow",
        action="store_true",
        help="record this tranche's shadow verdict to the "
        "metrics ledger (budget-shadow) so 'how often "
        "would the cap bind' is answered by counting",
    )
    ap.add_argument("--max-age-hours", type=int, default=48)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = analysis_results_dir(engine)
    manifest = results_root / "findings" / "_manifest"
    args.worklist = args.worklist or manifest / "rescan-worklist.json"
    args.out_dir = args.out_dir or manifest

    try:
        doc = json.loads(args.worklist.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"REFUSED: cannot read worklist: {e}", file=sys.stderr)
        return 3

    gen = parse_generated_at(doc)
    if gen is None:
        print("REFUSED: worklist has no parseable generated_at", file=sys.stderr)
        return 3
    age_h = (_dt.datetime.now(_dt.UTC) - gen).total_seconds() / 3600
    if age_h > args.max_age_hours:
        print(
            f"REFUSED: worklist is {age_h:.0f}h old (max "
            f"{args.max_age_hours}h) — re-run "
            f"`traust build rescan-worklist` first (a stale pool "
            f"re-lives the clone-then-refuse waste)",
            file=sys.stderr,
        )
        return 3
    if not (doc.get("summary") or {}).get("preroute"):
        print(
            "REFUSED: worklist predates the refusal pre-route "
            "(no summary.preroute) — rebuild with harness >= 0.190.0",
            file=sys.stderr,
        )
        return 3

    week = args.week or f"{gen.isocalendar()[0]}-W{gen.isocalendar()[1]:02d}"
    out = args.out_dir / f"drain-tranche-{week}.json"
    if out.exists() and not args.force:
        print(
            f"REFUSED: {out} already exists — one tranche per week (--force to overwrite)",
            file=sys.stderr,
        )
        return 3

    rows = select_rows(doc, args.include_immediate)
    manifest = {
        "artifact": "drain-tranche",
        "week": week,
        "worklist_generated_at": doc.get("generated_at"),
        "harness_version": doc.get("harness_version"),
        "drain_rate": ((doc.get("summary") or {}).get("drain") or {}).get("weekly_rate"),
        "include_immediate": args.include_immediate,
        "dispatch_contract": (
            "one headless run per row, BY LANE (see dispatch_by_lane); "
            "agent cwd outside the clone (rule S9); output written "
            "beside the row's baseline report; spend declared via "
            "model_registry.py spend --batch drain-tranche-"
            + week
            + ". A row carrying `threat_model_pr` additionally runs "
            "`/threat-model pr <clone> --base <resolved anchor>` on "
            "the SAME clone after its diff scan — report-only, it "
            "writes no model and re-stamps no SHA."
        ),
        "dispatch_by_lane": dict(sorted(_DISPATCH.items())),
        "rows": [{k: r.get(k) for k in ROW_FIELDS} for r in rows],
    }

    # Observe-mode budget accounting. Computes a verdict and records it;
    # `rows` above is ALREADY built and is never filtered by this block.
    shadow = None
    if not args.no_shadow:
        try:
            import budget_shadow
            import build_rescan_worklist as brw

            ceiling, why = brw.read_policy_shadow_ceiling(
                optional_config_path("budget-policy.yaml")
            )
            ws = workspace_dir(engine)
            backlog = [d for d in (doc.get("decisions") or []) if d.get("lane") in brw._FULL_LANES]
            shadow = budget_shadow.shadow_verdict(ws, rows, ceiling, why, backlog_rows=backlog)
            manifest["budget_shadow"] = shadow
            if args.append_shadow:
                shadow["recorded"] = budget_shadow.append_verdict(ws, week, shadow)
        except Exception as e:
            manifest["budget_shadow"] = {
                "mode": "observe",
                "verdict": "unavailable",
                "error": str(e)[:200],
                "note": "shadow accounting failed; the tranche is "
                "unaffected (observe mode never withholds)",
            }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    by_lane: dict = {}
    for r in rows:
        by_lane[r.get("lane")] = by_lane.get(r.get("lane"), 0) + 1
    pr = sum(1 for r in rows if r.get("threat_model_pr"))
    print(
        f"tranche {week}: {len(rows)} row(s) ("
        + ", ".join(f"{k}={v}" for k, v in sorted(by_lane.items()))
        + f"){f'; {pr} with a threat-model pr companion' if pr else ''}"
        + f" → {out}"
    )
    if shadow:
        v = shadow.get("verdict")
        if v == "would_exceed":
            print(
                f"  budget shadow: WOULD EXCEED — MTD lane "
                f"${shadow['month_to_date_lane_usd']:,.2f} + tranche "
                f"${shadow['tranche_estimate_usd']:,.2f} vs ceiling "
                f"${shadow['ceiling_usd']:,.2f}; would withhold "
                f"{len(shadow.get('would_withhold') or [])} row(s). "
                f"NOTHING withheld (observe mode)."
            )
            if shadow.get("ceiling_unmeetable"):
                print(f"  {shadow['ceiling_unmeetable_note']}")
        elif v == "within":
            print(
                f"  budget shadow: within ceiling "
                f"(${shadow['projected_with_tranche_usd']:,.2f} of "
                f"${shadow['ceiling_usd']:,.2f}, headroom "
                f"${shadow['headroom_usd']:,.2f})"
            )
        else:
            print(f"  budget shadow: {v} — {shadow.get('ceiling_source')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
