#!/usr/bin/env python3
"""
Emit track-findings disposition-ledger events from a *-remediation-verification.json
report (verify-remediation engine output).

Deterministic transform, sibling of emit_validation_ledger_events.py and
emit_triage_ledger_events.py. Verdict -> ledger mapping:

  resolved            -> resolution `resolved`
  new_approach        -> resolution `resolved`
  partially_resolved  -> resolution `partially_resolved`
                        (cross_repo.propagation == pending -> fix_in_progress)
  unresolved          -> resolution `open`
  regression          -> resolution `regression_introduced`
  risk_accepted       -> resolution `risk_accepted`
  false_positive      -> validity `false_positive` (resolution axis unused)

Never combine validity and resolution on one event. Regressions in
regressions[] are skipped here — route_regressions handles them separately.

One verification report covers one repo audit (metadata.original_report).
Event ids use the layer schema's canonical sha256, so re-emitting the
same report is idempotent.

Usage (from the workspace root):
  python3 -m traust.cli.emit_verification_ledger_events \\
      analysis-results/findings/<org>/<repo>/<repo>-remediation-verification.json \\
      [--results-root analysis-results]
      [--recorded-at ISO8601]
      [--dry-run]
      [--build-cumulative]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.ledger import LedgerService, compute_event_id

from traust.cli.emit_validation_ledger_events import (
    layer_path_for,
    sanitize_harness_version,
)
from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.lib.event_time import recorded_at_arg, report_occurred_at

RATIONALE_CAP = 500

VERDICT_RESOLUTION: dict[str, str] = {
    "resolved": "resolved",
    "new_approach": "resolved",
    "partially_resolved": "partially_resolved",
    "unresolved": "open",
    "regression": "regression_introduced",
    "risk_accepted": "risk_accepted",
}


def _squash(text: str, cap: int = RATIONALE_CAP) -> str:
    return " ".join(str(text or "").split())[:cap]


def _localize(foreign: str, marker: str, root: Path) -> Path | None:
    i = foreign.find(marker)
    return root / foreign[i + len(marker) :] if i >= 0 else None


def resolve_audit_path(report: dict, results_root: Path) -> Path:
    original = str((report.get("metadata") or {}).get("original_report") or "")
    if not original:
        raise ValueError("metadata.original_report is missing")
    local = _localize(original, "analysis-results/", results_root)
    if local is None:
        local = Path(original)
    if not local.is_file():
        raise FileNotFoundError(f"audit report not found: {local}")
    return local.resolve()


def map_disposition(finding: dict) -> tuple[dict, str | None, str | None]:
    """Return (disposition, validity_for_event_id, resolution_for_event_id)."""
    verdict = str(finding.get("verdict") or "")
    if verdict == "false_positive":
        return {"validity": "false_positive"}, "false_positive", None

    resolution = VERDICT_RESOLUTION.get(verdict)
    if resolution is None:
        raise ValueError(f"unsupported verdict: {verdict!r}")

    cross = finding.get("cross_repo") or {}
    if (
        verdict == "partially_resolved"
        and isinstance(cross, dict)
        and cross.get("propagation") == "pending"
    ):
        resolution = "fix_in_progress"

    return {"resolution": resolution}, None, resolution


def build_events(
    report: dict,
    source_ref: str,
    audit: dict,
    recorded_at: str,
) -> dict:
    """Return {events, skipped, counts}."""
    meta = report.get("metadata") or {}
    hv = str(meta.get("harness_version") or "0.0.0")
    occurred_at = report_occurred_at(meta.get("date"), recorded_at)
    actor = {
        "kind": "machine",
        "identity": f"verify-remediation/{hv}",
        "ldap_verified": False,
    }
    source = {"type": "verification_report", "ref": source_ref, "actor": actor}
    audit_ids = {str(f.get("id")) for f in audit.get("findings") or []}

    events: list[dict] = []
    skipped: list[dict] = []
    counts: dict[str, int] = {}

    for finding in report.get("verified_findings") or []:
        finding_ref = str(finding.get("original_id") or "")
        verdict = str(finding.get("verdict") or "")
        if not finding_ref:
            skipped.append({"original_id": "", "verdict": verdict, "reason": "missing original_id"})
            continue
        if finding_ref not in audit_ids:
            skipped.append(
                {
                    "original_id": finding_ref,
                    "verdict": verdict,
                    "reason": "original_id not in audit findings",
                }
            )
            continue
        try:
            disposition, validity, resolution = map_disposition(finding)
        except ValueError as e:
            skipped.append({"original_id": finding_ref, "verdict": verdict, "reason": str(e)})
            continue

        evidence = finding.get("evidence") or {}
        explanation = evidence.get("explanation") if isinstance(evidence, dict) else ""
        event: dict = {
            "event_id": compute_event_id(source_ref, finding_ref, validity, resolution),
            "finding_ref": finding_ref,
            "recorded_at": recorded_at,
            "occurred_at": occurred_at,
            "source": source,
            "disposition": disposition,
            "rationale": _squash(explanation),
            "evidence_refs": [],
        }
        if (clean_hv := sanitize_harness_version(hv)) is not None:
            event["harness_version"] = clean_hv
        events.append(event)
        key = verdict or "unknown"
        counts[key] = counts.get(key, 0) + 1

    return {"events": events, "skipped": skipped, "counts": counts}


def append_to_layer(
    layer_path: Path,
    audit_path: Path,
    audit: dict,
    events: list[dict],
    recorded_at: str,
    hv: str,
    *,
    engine=None,
) -> dict:
    shell = {
        "metadata": {
            "audit_report": audit_path.name,
            "repository": str(
                (audit.get("metadata") or {}).get("repository") or "https://unknown.invalid/"
            ),
            "created": recorded_at,
            "harness_version": sanitize_harness_version(hv) or "0.0.0",
        },
        "events": [],
        "needs_review": [],
    }
    commit = str((audit.get("metadata") or {}).get("commit") or "")
    if re.match(r"^[0-9a-f]{7,40}$", commit):
        shell["metadata"]["audit_commit"] = commit

    ledger = (
        engine.ledger.service(data_dir=layer_path.parent)
        if engine is not None
        else LedgerService(data_dir=layer_path.parent)
    )
    layer = ledger.ensure_layer_file(layer_path, shell=shell)
    last = max((e.get("recorded_at", "") for e in layer.get("events", [])), default="")
    stamp = max(recorded_at, last)
    stamped = [{**e, "recorded_at": stamp} for e in events]

    submitted = len(stamped)
    result = ledger.submit_events(layer_path, stamped, report_path=audit_path)
    appended = len(result.event_ids) if result.event_ids is not None else submitted
    return {
        "appended": appended,
        "duplicates_skipped": submitted - appended,
        "queued": result.queue_added,
    }


def process_report(
    report_path: Path,
    results_root: Path,
    recorded_at: str,
    *,
    dry_run: bool,
    build_cumulative: bool,
    engine=None,
) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    try:
        report_rel = str(report_path.resolve().relative_to(results_root.resolve()))
        source_ref = f"analysis-results/{report_rel}"
    except ValueError:
        report_rel = report_path.name
        source_ref = report_rel

    audit_path = resolve_audit_path(report, results_root)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    out = build_events(report, source_ref, audit, recorded_at)
    layer_path = layer_path_for(audit_path)
    hv = str((report.get("metadata") or {}).get("harness_version") or "0.0.0")

    if dry_run:
        totals = {
            "appended": len(out["events"]),
            "duplicates_skipped": 0,
            "queued": 0,
        }
    else:
        totals = append_to_layer(
            layer_path,
            audit_path,
            audit,
            out["events"],
            recorded_at,
            hv,
            engine=engine,
        )
        if build_cumulative and totals["appended"]:
            res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "traust.cli.build_cumulative",
                    str(audit_path),
                    str(layer_path),
                    "--generated-at",
                    recorded_at,
                ],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                print(
                    f"WARN: build_cumulative failed for {audit_path}: {res.stderr.strip()}",
                    file=sys.stderr,
                )

    mode = "DRY RUN — would append" if dry_run else "appended"
    counts = out["counts"]
    by_verdict = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(
        f"{report_rel}: {by_verdict or 'no events'} — {mode} "
        f"{totals['appended']} event(s), "
        f"{totals['duplicates_skipped']} already present (idempotent)"
    )
    for s in out["skipped"]:
        print(
            f"  skipped {s['original_id']} ({s['verdict']}): {s['reason']}",
            file=sys.stderr,
        )
    totals["skipped"] = len(out["skipped"])
    totals.update(counts)
    return totals


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_config_home_arg(parser)
    parser.add_argument("report", help="a *-remediation-verification.json report")
    parser.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="the analysis-results checkout (default: configured analysis-results)",
    )
    parser.add_argument(
        "--recorded-at",
        type=recorded_at_arg,
        help="override the append timestamp (RFC 3339)",
    )
    parser.add_argument("--dry-run", action="store_true", help="resolve and report; write nothing")
    parser.add_argument(
        "--build-cumulative",
        action="store_true",
        help="rebuild <repo>-findings-current.{json,md}",
    )
    args = parser.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()
    if not results_root.is_dir():
        print(f"ERROR: results root {results_root} not found", file=sys.stderr)
        return 2

    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"ERROR: report {report_path} not found", file=sys.stderr)
        return 2

    recorded_at = args.recorded_at or datetime.now(UTC).isoformat(timespec="seconds")
    try:
        process_report(
            report_path,
            results_root,
            recorded_at,
            dry_run=args.dry_run,
            build_cumulative=args.build_cumulative,
            engine=engine,
        )
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"ERROR: {report_path}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["ledger", "emit-verification", *sys.argv[1:]]))
