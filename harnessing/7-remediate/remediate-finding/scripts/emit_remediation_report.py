#!/usr/bin/env python3
"""
Assemble a ``*-remediation.json`` report from a prepared worktree.

Inputs:
  --rem-id ID            manifest row to report on (required)
  --worktree DIR         git worktree containing the fix branch (required)
  --checks FILE          JSON array of check objects (from run_checks.sh)
  --strategy S           patch.strategy enum value
  --rationale TEXT       patch.rationale (>= 50 chars)
  --behaviour TEXT       patch.behaviour_change
  --residual TEXT        patch.residual_risk
  --tests-added T[,T…]   regression tests added
  --status S             override summary.status (default derived from checks)
  --out FILE             write JSON here (default: manifest report_path)

The script computes the diff, diffstat, files_changed, fix_commit, and
populates source_findings[] from the triage + audit reports referenced
by the manifest row.  The result is validated by the caller via
``traust reporting validate --schema remediation.schema.json``.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    resolve_results_root,
    workspace_dir,
)

HERE = Path(__file__).resolve().parent
# Harness root: the directory holding VERSION, walked rather than counted.
# This was `HERE.parents[1]`, which resolved to `harnessing/` and so pointed one
# level too shallow — the C8 script-placement migration moved this file
# into scripts/ and the count was never updated.
HARNESS = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())
VERSION_FILE = HARNESS / "VERSION"


def sh(cwd: Path, *cmd: str) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def sh_ok(cwd: Path, *cmd: str) -> str:
    r = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    return r.stdout.strip()


def harness_version() -> str:
    ver = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.is_file() else "0.0.0"
    sha = sh_ok(HARNESS, "git", "rev-parse", "--short", "HEAD")
    return f"{ver}-{sha}" if sha else ver


def load_row(rem_id: str, manifest: Path) -> dict:
    with manifest.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["rem_id"] == rem_id:
                return r
    raise KeyError(f"rem_id {rem_id!r} not in manifest")


def load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except json.JSONDecodeError:
        # External findings (e.g. security-tracker advisories) may reference a
        # Markdown file instead of a JSON report; fall back to manifest fields.
        return {}


def build_source_findings(row: dict, workspace: Path) -> list[dict]:
    triage = load_json(workspace / row["triage_path"]) if row.get("triage_path") else {}
    audit = load_json(workspace / row["audit_path"]) if row.get("audit_path") else {}

    tf = next((f for f in triage.get("findings", []) if str(f.get("id")) == row["finding_id"]), {})
    af = next(
        (f for f in audit.get("findings", []) if str(f.get("id")) == row.get("audit_finding_id")),
        {},
    )

    cwes = af.get("cwes") or [c for c in (row.get("cwes") or "").split(";") if c]
    if not cwes:
        cwes = ["CWE-0"]  # schema requires ≥1; flag for human review

    locs = af.get("locations") or []
    if not locs and row.get("file"):
        locs = [{"path": row["file"], "lines": str(row.get("line") or "")}]
    if not locs:
        locs = [{"path": "(unknown)", "lines": ""}]

    sev = (row.get("severity") or af.get("severity") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "informational"):
        sev = "medium"

    ref = (
        f"{Path(row['triage_path']).name}#{row['finding_id']}"
        if row.get("triage_path")
        else row["finding_id"]
    )

    out = {
        "finding_ref": ref,
        "title": row.get("title") or tf.get("title") or af.get("title") or row["rem_id"],
        "severity": sev,
        "cwes": cwes,
        "locations": locs,
    }
    if row.get("confidence"):
        with contextlib.suppress(ValueError):
            out["triage_confidence"] = float(row["confidence"])
    vv = row.get("validation_verdict") or "not_validated"
    out["validation_verdict"] = vv if vv else "not_validated"
    if row.get("audit_path"):
        out["audit_report_path"] = row["audit_path"]
    if row.get("triage_path"):
        out["triage_report_path"] = row["triage_path"]
    if row.get("validation_report"):
        out["validation_report_path"] = row["validation_report"]
    return [out]


def compute_patch(work: Path, base: str, out_dir: Path, rem_id: str) -> tuple[dict, str]:
    """Return (patch_block_without_strategy_rationale, fix_commit)."""
    fix_commit = sh_ok(work, "git", "rev-parse", "HEAD")
    diff = sh_ok(work, "git", "diff", base, "HEAD")
    if not diff:
        # include unstaged changes if nothing committed yet
        diff = sh_ok(work, "git", "diff")

    diff_path = out_dir / f"{rem_id}-patch.diff"
    diff_path.write_text(
        diff + ("\n" if diff and not diff.endswith("\n") else ""), encoding="utf-8"
    )
    diff_sha = hashlib.sha256(diff_path.read_bytes()).hexdigest()

    numstat = sh_ok(work, "git", "diff", "--numstat", base, "HEAD") or sh_ok(
        work, "git", "diff", "--numstat"
    )
    namestatus = sh_ok(work, "git", "diff", "--name-status", base, "HEAD") or sh_ok(
        work, "git", "diff", "--name-status"
    )

    status_map = {}
    for line in namestatus.splitlines():
        parts = line.split("\t")
        st = parts[0][:1]
        path = parts[-1]
        status_map[path] = {"A": "added", "D": "deleted", "R": "renamed"}.get(st, "modified")

    files_changed = []
    add_total = del_total = 0
    for line in numstat.splitlines():
        a, d, p = line.split("\t")
        a_i = int(a) if a.isdigit() else 0
        d_i = int(d) if d.isdigit() else 0
        add_total += a_i
        del_total += d_i
        files_changed.append(
            {
                "path": p,
                "change_type": status_map.get(p, "modified"),
                "additions": a_i,
                "deletions": d_i,
            }
        )
    if not files_changed:
        files_changed = [
            {"path": "(no changes)", "change_type": "modified", "additions": 0, "deletions": 0}
        ]

    patch = {
        "files_changed": files_changed,
        "diffstat": {
            "files": len(files_changed),
            "additions": add_total,
            "deletions": del_total,
        },
        "diff_path": diff_path.name,
        "diff_sha256": diff_sha,
    }
    return patch, fix_commit


def derive_status(checks: list[dict]) -> str:
    if not checks:
        return "patched"
    outcomes = {c.get("outcome") for c in checks}
    if "fail" in outcomes or "error" in outcomes:
        return "checks_failed"
    return "checks_passed"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--rem-id", required=True)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--checks", type=Path)
    ap.add_argument("--strategy", default="other")
    ap.add_argument("--rationale", required=True)
    ap.add_argument("--behaviour", default="none")
    ap.add_argument("--residual", default="")
    ap.add_argument("--tests-added", default="")
    ap.add_argument("--status")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    workspace = workspace_dir(engine)
    analysis = resolve_results_root(args)
    manifest = analysis / "remediations" / "_manifest" / "remediation-manifest.csv"

    row = load_row(args.rem_id, manifest)
    # containment: report_path is manifest-derived (ultimately from
    # report-influenced ids) — resolved target must stay under the
    # remediations tree (audit B1, plan P0.2)
    dest = (workspace / row["report_path"]).resolve()
    allowed = (analysis / "remediations").resolve()
    if not dest.is_relative_to(allowed):
        raise SystemExit(f"refusing to write outside {allowed}: {row['report_path']!r}")
    out_dir = dest.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or dest

    base = row.get("audited_commit") or "HEAD~1"
    if base == "HEAD":
        base = sh_ok(args.worktree, "git", "rev-parse", "origin/HEAD") or "HEAD~1"

    patch_block, fix_commit = compute_patch(args.worktree, base, out_dir, args.rem_id)
    patch_block["strategy"] = args.strategy
    patch_block["rationale"] = args.rationale
    patch_block["behaviour_change"] = args.behaviour
    if args.residual:
        patch_block["residual_risk"] = args.residual
    if args.tests_added:
        patch_block["tests_added"] = [t.strip() for t in args.tests_added.split(",") if t.strip()]

    checks = json.loads(args.checks.read_text(encoding="utf-8")) if args.checks else []
    if not checks:
        checks = [{"name": "none", "command": "(no checks run)", "outcome": "skip"}]

    status = args.status or derive_status(checks)
    passed = sum(1 for c in checks if c.get("outcome") == "pass")

    fork_block = {
        "url": row["fork_url"],
        "host": "github" if "github.com" in row["fork_url"] else "other",
        "visibility": "private",
        "upstream_remote": row["upstream_url"],
        "base_ref": row.get("audited_commit") or "HEAD",
        "fix_branch": row["fix_branch"],
    }
    if re.fullmatch(r"[0-9a-f]{7,40}", row.get("audited_commit") or ""):
        fork_block["base_commit"] = row["audited_commit"]
    if re.fullmatch(r"[0-9a-f]{7,40}", fix_commit or ""):
        fork_block["fix_commit"] = fix_commit

    meta = {
        "date": dt.date.today().isoformat(),
        "harness_version": harness_version(),
        "logical_product": row["logical_product"],
        "repository": row["upstream_url"],
    }
    if re.fullmatch(r"[0-9a-f]{7,40}", row.get("audited_commit") or ""):
        meta["audited_commit"] = row["audited_commit"]
    if row.get("jira_key"):
        meta["jira_keys"] = [row["jira_key"]]

    report = {
        "title": f"{row['repo_name']} — automated remediation for {row['finding_id']}",
        "metadata": meta,
        "source_findings": build_source_findings(row, workspace),
        "fork": fork_block,
        "patch": patch_block,
        "checks": checks,
        "summary": {
            "status": status,
            "checks_passed": passed,
            "checks_total": len(checks),
            "findings_addressed": 1,
            "ready_for_review": status in ("checks_passed", "revalidated_fixed", "pr_opened"),
        },
    }

    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(str(out_path.relative_to(workspace)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
