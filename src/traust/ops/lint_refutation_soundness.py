#!/usr/bin/env python3
"""
Retroactive refutation-soundness linter.

Walks every validation run (a `validation-audit.jsonl` under
`analysis-results/**/validations/`), re-examines each `refuted` verdict
with the deterministic soundness gate
(harnessing/5-validate/validate-findings/soundness.py), and writes a
re-adjudication worklist for every refutation that the gate would have
blocked:

  error-signature:<name>     probe transcript is an error transcript
                             (Forbidden, command not found, jsonpath
                             error, NotFound, does not exist, could not
                             connect, unsubstituted template)
  rbac-zero-subjects         RBAC probe enumerated zero concrete
                             subjects (empty `vf-rbac-tried:` list)
  rbac-template-placeholder  literal `system:serviceaccount:{ns}:{sa}`
  target-not-deployed        the run directory contains
                             install-failure.yaml (whole run)

READ-ONLY over the corpus: no ledger, findings-current, or report is
modified — the output is a worklist JSON only (Phase 1 of the
scanning-skill error-correction plan; re-validation itself is Phase 0c).

Usage (from the workspace root):
  python traust/scripts/lint_refutation_soundness.py \\
      [--results-root analysis-results] \\
      [--out analysis-results/scan-testing/sxs-2026-07/refutation-soundness-worklist.json]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root
from traust.paths import skill_dir

# Load the gate by file path (the validate-findings dir has generically
# named modules — plan, report, scope — that must not enter sys.path).
_SOUNDNESS_PATH = skill_dir("validate-findings") / "soundness.py"
_spec = importlib.util.spec_from_file_location("vf_soundness", _SOUNDNESS_PATH)
soundness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(soundness)

DEFAULT_OUT_REL = Path("scan-testing/sxs-2026-07/refutation-soundness-worklist.json")
EXCERPT_CAP = 400


def _squash(text, cap=EXCERPT_CAP):
    return " ".join(str(text or "").split())[:cap]


def discover_runs(results_root: Path) -> list[Path]:
    """Every validation run directory (contains validation-audit.jsonl)
    under a `validations/` tree — hidden/scratch dirs and symlinked
    duplicates excluded, deduped by resolved path."""
    seen = set()
    runs = []
    for p in sorted(results_root.rglob("validation-audit.jsonl")):
        rel_parts = p.relative_to(results_root).parts
        if "validations" not in rel_parts:
            continue
        if any(part.startswith(".") for part in rel_parts):
            continue
        run_dir = p.parent
        key = run_dir.resolve()
        if key in seen:
            continue
        seen.add(key)
        runs.append(run_dir)
    return runs


def _refuted_steps_from_audit(audit_path: Path) -> list[dict]:
    steps = []
    try:
        with audit_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("verdict") == "refuted":
                    steps.append(rec)
    except OSError:
        pass
    return steps


def _observed_from_artifacts(run_dir: Path, rec: dict) -> str:
    """Fallback observed text for an audit-jsonl step: its evidence
    artifacts (audit lines do not carry `observed` themselves)."""
    chunks = []
    for ev in rec.get("evidence") or []:
        p = run_dir / str(ev)
        if p.is_file():
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(chunks)


def lint_run(run_dir: Path, results_root: Path) -> tuple[list[dict], dict]:
    """(worklist entries, run stats) for one validation run."""
    rel_run = str(run_dir.relative_to(results_root))
    install_failure = soundness.run_install_failed(run_dir)
    entries: list[dict] = []
    stats = {
        "reports": 0,
        "refuted_findings": 0,
        "refuted_steps": 0,
        "install_failure": install_failure,
    }

    reports = [p for p in sorted(run_dir.glob("*-validation.json")) if not p.is_symlink()]
    covered_step_ids: set[str] = set()

    for rp in reports:
        try:
            doc = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, MemoryError):
            continue
        stats["reports"] += 1
        for vf in doc.get("validated_findings") or []:
            for step in vf.get("steps") or []:
                if step.get("step_id"):
                    covered_step_ids.add(str(step["step_id"]))
            if vf.get("verdict") != "refuted":
                continue
            stats["refuted_findings"] += 1
            flag = soundness.flag_validated_finding(vf, install_failure=install_failure)
            if not flag:
                continue
            entries.append(
                {
                    "level": "finding",
                    "run": rel_run,
                    "report": str(rp.relative_to(results_root)),
                    "source_id": vf.get("source_id"),
                    "finding_ref": str(vf.get("source_id") or "").rsplit("/", 1)[-1],
                    "source_report": vf.get("source_report"),
                    "title": vf.get("title"),
                    "claimed_severity": vf.get("claimed_severity"),
                    "verdict": "refuted",
                    "soundness_flag": flag,
                    "observed_excerpt": _squash(vf.get("observed_impact")),
                    "refuted_step_ids": [
                        s.get("step_id")
                        for s in vf.get("steps") or []
                        if s.get("verdict") == "refuted"
                    ],
                }
            )

    # Steps the reports do not cover (no sibling report, or refuted steps
    # outside any validated finding, e.g. recon): lint from the audit
    # log + evidence artifacts.
    for rec in _refuted_steps_from_audit(run_dir / "validation-audit.jsonl"):
        stats["refuted_steps"] += 1
        if str(rec.get("step_id")) in covered_step_ids:
            continue
        observed = _observed_from_artifacts(run_dir, rec)
        flag = soundness.soundness_flag(
            str(rec.get("verb") or ""), observed, install_failure=install_failure
        )
        if not flag:
            continue
        entries.append(
            {
                "level": "step",
                "run": rel_run,
                "report": None,
                "source_id": None,
                "finding_ref": rec.get("finding_ref"),
                "source_report": None,
                "title": None,
                "claimed_severity": None,
                "verdict": "refuted",
                "soundness_flag": flag,
                "observed_excerpt": _squash(observed),
                "refuted_step_ids": [rec.get("step_id")],
            }
        )
    return entries, stats


def _condition(flag: str) -> str:
    """Bucket a flag into the three gate conditions (a/b/c)."""
    if flag.startswith("error-signature:"):
        return "error-signature"
    if flag in ("rbac-zero-subjects", "rbac-template-placeholder"):
        return "rbac-unsound-probe"
    return "target-not-deployed"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results root (default: configured analysis-results)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"worklist output path (default: <results-root>/{DEFAULT_OUT_REL})",
    )
    args = ap.parse_args()

    results_root = resolve_results_root(args)
    out = args.out or (results_root / DEFAULT_OUT_REL)
    if not results_root.is_dir():
        print(f"ERROR: results root {results_root} not found", file=sys.stderr)
        return 2

    runs = discover_runs(results_root)
    all_entries: list[dict] = []
    totals = Counter()
    install_failure_runs = []
    for run_dir in runs:
        entries, stats = lint_run(run_dir, results_root)
        all_entries.extend(entries)
        totals["reports"] += stats["reports"]
        totals["refuted_findings"] += stats["refuted_findings"]
        totals["refuted_steps"] += stats["refuted_steps"]
        if stats["install_failure"]:
            install_failure_runs.append(str(run_dir.relative_to(results_root)))

    finding_entries = [e for e in all_entries if e["level"] == "finding"]
    by_flag = Counter(e["soundness_flag"] for e in all_entries)
    by_condition = Counter(_condition(e["soundness_flag"]) for e in all_entries)
    by_severity = Counter(str(e["claimed_severity"]) for e in finding_entries)
    criticals = [e for e in finding_entries if e["claimed_severity"] == "critical"]

    doc = {
        "title": "Refutation-soundness re-adjudication worklist",
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "generator": "traust/scripts/lint_refutation_soundness.py",
        "plan_ref": "progress-tracker/plans/scanning-skill-error-correction-plan.md (Phase 1)",
        "note": "Worklist only — no ledger, findings-current, or report "
        "was modified. Each entry is a refuted verdict the "
        "soundness gate would have blocked; re-validate (Phase "
        "0c) or human-review before trusting the refutation.",
        "census": {
            "runs_scanned": len(runs),
            "reports_scanned": totals["reports"],
            "refuted_findings_total": totals["refuted_findings"],
            "refuted_steps_total": totals["refuted_steps"],
            "flagged_total": len(all_entries),
            "flagged_findings": len(finding_entries),
            "flagged_steps": len(all_entries) - len(finding_entries),
            "by_condition": dict(by_condition),
            "by_flag": dict(by_flag),
            "flagged_findings_by_severity": dict(by_severity),
            "flagged_criticals": len(criticals),
            "install_failure_runs": install_failure_runs,
        },
        "worklist": all_entries,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    c = doc["census"]
    print(
        f"Scanned {c['runs_scanned']} run(s) / {c['reports_scanned']} "
        f"report(s): {c['refuted_findings_total']} refuted finding(s), "
        f"{c['flagged_findings']} flagged "
        f"({c['flagged_criticals']} critical) + {c['flagged_steps']} "
        f"uncovered step(s); {len(install_failure_runs)} run(s) with "
        f"install-failure.yaml"
    )
    print("By condition: " + ", ".join(f"{k}={v}" for k, v in sorted(by_condition.items())))
    print("By flag: " + ", ".join(f"{k}={v}" for k, v in sorted(by_flag.items())))
    print(
        "Flagged findings by severity: "
        + ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items()))
    )
    print(f"Worklist: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
