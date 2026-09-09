#!/usr/bin/env python3
# Migration utility archived 2026-08-11
"""Export a harness report to the GitLab security-report (SAST) format.

GitLab's Vulnerability Report / security dashboards do not ingest SARIF
natively — they want the GitLab security-report JSON schema
(https://gitlab.com/gitlab-org/security-products/security-report-schemas,
targeted major: v15). This is the GitLab counterpart of
`export_sarif.py` (SARIF plan P2,;
progress-tracker/plans/sarif-integration-plan.md), and the same
invariants hold:

- One-way, read-only projection: the harness report + disposition
  ledger stay authoritative. Nothing round-trips.
- Findings dispositioned false_positive are EXCLUDED by default (the
  GitLab schema has no suppression concept — an excluded-count is
  printed and recorded in scan metadata; `--include-false-positives`
  keeps them). risk_accepted stays included (it is real, accepted risk).
- Vulnerability `id` is a deterministic UUIDv5 of the campaign finding
  ID, so re-uploads dedup stably.
- Severity maps critical/high/medium/low/informational →
  Critical/High/Medium/Low/Info.

Attach in CI as a `sast` report artifact:

    artifacts:
      reports:
        sast: <repo>-gl-sast.json

Stdlib only. Usage:

    python3 -m traust.cli.export_gitlab_sast <report.json> [-o out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from pathlib import Path

SCHEMA_VERSION = "15.2.1"
# deterministic namespace for uuid5 vulnerability ids (random-generated
# once, fixed forever — NOT per-run)
NAMESPACE = uuid.UUID("6fb9a1f2-3c44-4c1d-9a75-2f1e0c7a58d1")
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
}
_CWE_NUM_RX = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)
_LINES_RX = re.compile(r"^\s*(\d+)\s*(?:[-–]\s*(\d+))?\s*$")


def _identifiers(finding: dict) -> list[dict]:
    fid = finding.get("id", "")
    out = [{"type": "harness_finding_id", "name": fid, "value": fid}]
    for cwe in finding.get("cwes") or []:
        m = _CWE_NUM_RX.match(str(cwe))
        if m:
            out.append(
                {
                    "type": "cwe",
                    "name": f"CWE-{m.group(1)}",
                    "value": m.group(1),
                    "url": f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html",
                }
            )
    return out


def _location(finding: dict) -> dict:
    for loc in finding.get("locations") or []:
        path = loc.get("path", "")
        if not path or ":" in path.split("/")[0]:
            continue  # pseudo-paths (pkg:, oci-config:) don't map
        out = {"file": path}
        m = _LINES_RX.match(loc.get("lines") or "")
        if m:
            out["start_line"] = int(m.group(1))
            if m.group(2):
                out["end_line"] = int(m.group(2))
        return out
    return {}


def export(report: dict, include_fps: bool = False) -> tuple[dict, int]:
    metadata = report.get("metadata") or {}
    additional = metadata.get("additional") or {}
    version = str(additional.get("harness_version") or metadata.get("harness_version") or "0.0.0")
    semantic = version.split("-")[0]
    date = metadata.get("date") or "1970-01-01"
    stamp = f"{date}T00:00:00"

    vulnerabilities, excluded = [], 0
    for f in report.get("findings") or []:
        disp = f.get("disposition") or {}
        if not include_fps and (
            disp.get("validity") == "false_positive"
            or f.get("validation_status") == "false_positive"
        ):
            excluded += 1
            continue
        severity = f.get("effective_severity") or f.get("severity") or "informational"
        description = f.get("description", "")
        disp_bits = [f"{k}={disp[k]}" for k in ("validity", "resolution") if disp.get(k)]
        if disp_bits:
            description += (
                "\n\nHarness disposition: "
                + ", ".join(disp_bits)
                + " (authoritative state lives in the "
                "disposition ledger)"
            )
        vuln = {
            "id": str(uuid.uuid5(NAMESPACE, f.get("id", ""))),
            "name": f.get("title", f.get("id", "(untitled)")),
            "description": description,
            "severity": SEVERITY_MAP.get(severity, "Unknown"),
            "identifiers": _identifiers(f),
            "location": _location(f),
        }
        if f.get("remediation"):
            vuln["solution"] = f["remediation"]
        vulnerabilities.append(vuln)

    component = {
        "id": "traust",
        "name": "traust",
        "version": semantic,
        # Stamped into every exported SAST report, so a campaign
        # codename here travels to every downstream consumer —
        # same defect class as the SARIF informationUri.
        "vendor": {"name": os.environ.get("SAST_VENDOR_NAME", "traust")},
    }
    doc = {
        "version": SCHEMA_VERSION,
        "schema": "https://gitlab.com/gitlab-org/security-products/"
        "security-report-schemas/-/raw/master/dist/"
        "sast-report-format.json",
        "scan": {
            "analyzer": component,
            "scanner": component,
            "type": "sast",
            "start_time": stamp,
            "end_time": stamp,
            "status": "success",
            "messages": [
                {
                    "level": "info",
                    "value": (
                        "one-way projection of "
                        f"{report.get('title', 'a harness report')}; "
                        "the harness report + disposition ledger are "
                        f"authoritative; {excluded} false-positive "
                        "finding(s) excluded"
                    ),
                }
            ],
        },
        "vulnerabilities": vulnerabilities,
    }
    return doc, excluded


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "reports", nargs="+", type=Path, help="report.schema.json-conformant report(s)"
    )
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        help="output path (single input only; default: <input stem>-gl-sast.json)",
    )
    parser.add_argument(
        "--include-false-positives",
        action="store_true",
        help="keep findings dispositioned false_positive (default: exclude and count)",
    )
    args = parser.parse_args(argv)

    if args.out and len(args.reports) > 1:
        print("ERROR: -o/--out requires exactly one input report", file=sys.stderr)
        return 2

    rc = 0
    for report_path in args.reports:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {report_path}: {e}", file=sys.stderr)
            rc = 1
            continue
        if not isinstance(report, dict) or "findings" not in report:
            print(f"ERROR: {report_path}: not a harness report", file=sys.stderr)
            rc = 1
            continue
        doc, excluded = export(report, args.include_false_positives)
        stem = (
            report_path.name[: -len(".json")]
            if report_path.name.endswith(".json")
            else report_path.name
        )
        out = args.out or report_path.with_name(f"{stem}-gl-sast.json")
        out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        n = len(doc["vulnerabilities"])
        note = f", {excluded} FP(s) excluded" if excluded else ""
        print(f"wrote {out} ({n} vulnerabilit{'ies' if n != 1 else 'y'}{note})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
