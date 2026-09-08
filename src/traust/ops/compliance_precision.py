#!/usr/bin/env python3
"""Per-check field precision for compliance checks (Phase 4).

The fixture calibration gate proves a check CAN fire correctly; field
precision measures whether it fires correctly IN PRACTICE. The signal
is the attributed-override trail: every human override that reverses a
check-computed `not_satisfied` (override.overridden_check_verdict =
not_satisfied) is a recorded dismissal — the compliance analog of the
opengrep pack's promote/dismiss `scanner_correlation` ledger.

    precision(check) = confirmed_firings / (confirmed + dismissed)

Checks at or below the gate (default 0.5, the opengrep-pack precedent)
are FLAGGED with the recommendation from the plan's FP hard
requirement 4: demote to evidence_review until tightened. This script
routes attention, never demotes — registry changes are reviewed config
changes.

Usage:
    python3 -m traust.cli.compliance_precision \
        [--assessments <dir>] [--out-dir <dir>] [--gate 0.5]

Walks <dir> recursively for compliance-assessment artifacts (default:
analysis-results/compliance/ — the assessment tree of record) and writes
compliance-precision.{json,md} to --out-dir (default:
progress-tracker/metrics/compliance/).
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
    progress_tracker_dir,
)


def aggregate(root: Path, gate: float = 0.5) -> dict:
    stats: dict[str, dict] = {}
    n_files = 0
    for p in sorted(root.rglob("*.json")) if root.is_dir() else []:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (doc.get("metadata") or {}).get("artifact") != "compliance-assessment":
            continue
        n_files += 1
        for r in doc.get("results") or []:
            cid = r.get("check_id")
            if not cid:
                continue
            fired = dismissed = 0
            if r.get("verdict") == "not_satisfied" and r.get("verdict_source") == "check":
                fired = 1
            ov = r.get("override") or {}
            if (
                r.get("verdict_source") == "human_override"
                and ov.get("overridden_check_verdict") == "not_satisfied"
            ):
                fired = dismissed = 1
            if not fired:
                continue
            s = stats.setdefault(cid, {"fired": 0, "dismissed": 0})
            s["fired"] += fired
            s["dismissed"] += dismissed
    checks = []
    for cid, s in sorted(stats.items()):
        confirmed = s["fired"] - s["dismissed"]
        precision = confirmed / s["fired"] if s["fired"] else None
        checks.append(
            {
                "check_id": cid,
                "fired": s["fired"],
                "dismissed": s["dismissed"],
                "precision": (round(precision, 3) if precision is not None else None),
                "flagged": (precision is not None and precision <= gate),
            }
        )
    return {
        "metadata": {
            "artifact": "compliance-precision",
            "role": (
                "field-precision from attributed overrides — "
                "routes attention; demotion to evidence_review is "
                "a reviewed registry change, never automatic"
            ),
            "gate": gate,
            "assessments_scanned": n_files,
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "checks": checks,
        "note": (
            ""
            if n_files
            else "no assessment artifacts found — precision machinery "
            "in place, field data accrues as assessments run"
        ),
    }


def render_md(report: dict) -> str:
    m = report["metadata"]
    L = [
        "# Compliance Check Precision",
        "",
        f"_Generated {m['generated_at']} over "
        f"{m['assessments_scanned']} assessment artifact(s); gate "
        f"{m['gate']} (flagged ⇒ candidate for demotion to "
        f"evidence_review — a reviewed registry change)._",
        "",
    ]
    if not report["checks"]:
        L += [report["note"], ""]
    else:
        L += ["| Check | Fired | Dismissed | Precision | Flagged |", "|---|---:|---:|---:|---|"]
        for c in report["checks"]:
            L.append(
                f"| {c['check_id']} | {c['fired']} | "
                f"{c['dismissed']} | {c['precision']} | "
                f"{'⚠ YES' if c['flagged'] else ''} |"
            )
        L.append("")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--assessments", type=Path, default=None)
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output directory (default: <progress-tracker>/metrics/compliance)",
    )
    ap.add_argument("--gate", type=float, default=0.5)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    assessments = args.assessments or (analysis_results_dir(engine) / "compliance")
    out_dir = args.out_dir or (progress_tracker_dir(engine) / "metrics" / "compliance")
    report = aggregate(assessments, args.gate)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "compliance-precision.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "compliance-precision.md").write_text(render_md(report), encoding="utf-8")
    flagged = [c["check_id"] for c in report["checks"] if c["flagged"]]
    print(
        f"wrote {out_dir}/compliance-precision.{{json,md}} — "
        f"{len(report['checks'])} check(s) with field data"
        + (f"; FLAGGED: {', '.join(flagged)}" if flagged else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
