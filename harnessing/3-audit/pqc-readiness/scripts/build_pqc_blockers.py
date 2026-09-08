#!/usr/bin/env python3
"""build_pqc_blockers.py — project PQC remediations into a findings-shaped artifact.

Deterministically converts a `<slug>-pqc-readiness.json` report's
`remediations[]` into `<slug>-pqc-blockers.json`: an artifact that mirrors
the security-audit findings vocabulary (id / title / severity / cwes /
locations / description / remediation / category / validation_status) so
consumers like /patch normalize it the same way they normalize audit
findings — WITHOUT claiming contracts/schemas/report.schema.json conformance. It is
its own artifact (`"artifact": "pqc-blockers"`, shape contract
contracts/schemas/pqc-blockers.schema.json); converging the two shapes into one
contracts data model is deliberately deferred.

Mapping (all deterministic, no agent):
  remediation.category  -> severity   (fix-now: high, deadline 2030: medium,
                                       deadline 2035: low, upgrade: low,
                                       waiting-on-upstream: informational)
  remediation.locations -> finding.locations (file:line anchors)
  remediation.id        -> finding.id (stable across re-emission)
  category/deadline     -> pqc_classification (report.schema.json's shared
                           vocabulary, reused not extended)

Remediations without locations[] are not patchable and are excluded, with
the exclusion recorded in metadata.additional.excluded_remediations —
never silently dropped. Zero eligible remediations -> no file written.

Usage:
  build_pqc_blockers.py --readiness <slug>-pqc-readiness.json [--out PATH]
  build_pqc_blockers.py --results-root analysis-results/pqc   # batch backfill
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from traust_contracts.paths import schema_path

from traust.context import add_config_home_arg, resolve_results_root

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
FINDINGS_SCHEMA = schema_path("pqc-blockers")

_SEVERITY: dict[str, str] = {
    "fix-now": "high",
    "upgrade": "low",
    "waiting-on-upstream": "informational",
}
# category=deadline severity is clock-dependent
_DEADLINE_SEVERITY = {2030: "medium", 2035: "low"}

# remediation category -> pqc_classification (report.schema.json's shared
# vocabulary — reused, not extended, so /patch recipe routing keyed on
# these values works unchanged)
_PQC_CLASS = {
    "fix-now": "pqc-blocker-config",
    "upgrade": "pqc-adoption",
    "waiting-on-upstream": "pqc-blocker-config",
}
_DEADLINE_CLASS = {2030: "clock-2030-parameter", 2035: "pqc-blocker-config"}

_SEVERITY_CRITERIA = [
    {
        "level": "critical",
        "definition": "Not used by this projection — PQC "
        "transition items are schedule risks, not live exploits.",
    },
    {
        "level": "high",
        "definition": "fix-now: quantum-vulnerable crypto the "
        "repo owner can remove today (pin, kill-switch, or hardcoded "
        "algorithm blocking PQC negotiation).",
    },
    {
        "level": "medium",
        "definition": "NIST IR 8547 deprecated-after-2030 "
        "clock item in first-party code or config.",
    },
    {
        "level": "low",
        "definition": "Disallowed-after-2035 clock item, or an "
        "upgrade that unlocks PQC when the toolchain allows.",
    },
    {
        "level": "informational",
        "definition": "Waiting on an upstream provider/vendor; no repo-local action yet.",
    },
]

_ROADMAP_PRIORITY = {
    "fix-now": "immediate",
    "deadline": "scheduled (NIST IR 8547 clock)",
    "upgrade": "next toolchain bump",
    "waiting-on-upstream": "track upstream",
}


def _severity(rem: dict) -> str:
    if rem.get("category") == "deadline":
        return _DEADLINE_SEVERITY.get(rem.get("deadline"), "medium")
    return _SEVERITY.get(rem.get("category", ""), "low")


def _pqc_classification(rem: dict) -> str:
    if rem.get("category") == "deadline":
        return _DEADLINE_CLASS.get(rem.get("deadline"), "pqc-blocker-config")
    return _PQC_CLASS.get(rem.get("category", ""), "pqc-blocker-config")


def _title(rem: dict) -> str:
    action = (rem.get("action") or "").strip()
    head = re.split(r"\s+[—–]\s+|(?<=[.;])\s", action, maxsplit=1)[0]
    if len(head) > 90:
        head = head[:87].rsplit(" ", 1)[0] + "…"
    return f"PQC finding: {head}"


def _locations(rem: dict) -> list[dict[str, str]]:
    locs = []
    for loc in rem.get("locations") or []:
        path, _, line = str(loc).rpartition(":")
        if path and line.isdigit():
            locs.append({"path": path, "lines": line})
        else:
            locs.append({"path": str(loc)})
    return locs


def _finding(rem: dict, who_sets_tls: str) -> dict[str, Any]:
    desc_parts = [rem.get("action") or ""]
    if rem.get("deadline"):
        desc_parts.append(f"NIST IR 8547 clock: disallowed/deprecated after {rem['deadline']}.")
    if rem.get("blast_radius"):
        desc_parts.append(f"Blast radius: {rem['blast_radius']}.")
    desc_parts.append(f"TLS decision owner (who_sets_tls): {who_sets_tls}.")

    finding: dict[str, Any] = {
        "id": rem["id"],
        "title": _title(rem),
        "severity": _severity(rem),
        "cwes": ["CWE-327"],
        "locations": _locations(rem),
        "description": " ".join(p for p in desc_parts if p),
        "remediation": rem.get("target") or rem.get("action") or "",
        "category": "cryptography",
        "validation_status": "not_verified",
        "pqc_classification": _pqc_classification(rem),
    }
    if rem.get("remediation_effort"):
        finding["remediation_effort"] = rem["remediation_effort"]
    if rem.get("blocked_on"):
        finding["remediation"] += f" (blocked on: {rem['blocked_on']})"
    return finding


def _summary_counts(findings: list[dict]) -> list[dict[str, Any]]:
    by_sev: dict[str, list[str]] = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f["id"])
    return [
        {
            "severity": lvl,
            "count": len(by_sev.get(lvl, [])),
            "finding_ids": by_sev.get(lvl, []),
        }
        for lvl in ("critical", "high", "medium", "low", "informational")
    ]


def _roadmap(remediations: list[dict]) -> list[dict[str, Any]]:
    by_cat: dict[str, list[str]] = {}
    for rem in remediations:
        by_cat.setdefault(rem.get("category", "unclassified"), []).append(rem["id"])
    return [
        {
            "priority": _ROADMAP_PRIORITY.get(cat, cat),
            "action": f"Work the {len(ids)} `{cat}` PQC remediation(s) — details per finding.",
            "addresses": ids,
        }
        for cat, ids in sorted(by_cat.items())
    ]


def build_findings_doc(readiness: dict, source_name: str) -> dict[str, Any] | None:
    """Project one readiness report into the findings-shaped artifact.

    Returns None when there is nothing patchable to emit.
    """
    meta = readiness.get("metadata") or {}
    who = readiness.get("who_sets_tls", "unknown")
    rems = readiness.get("remediations") or []
    eligible = [r for r in rems if r.get("locations")]
    excluded = [r["id"] for r in rems if not r.get("locations")]
    if not eligible:
        return None

    findings = [_finding(r, who) for r in eligible]
    repo = meta.get("repository") or readiness.get("repository") or "unknown"
    counts = {c["severity"]: c["count"] for c in _summary_counts(findings)}

    return {
        "artifact": "pqc-blockers",
        "title": f"PQC readiness findings — {repo.rstrip('/').rsplit('/', 1)[-1]}",
        "metadata": {
            "date": meta.get("assessed_at") or "",
            "scope": (
                "Post-quantum readiness remediations projected from "
                f"{source_name} (deterministic, no new analysis)"
            ),
            "repository": repo,
            "commit": meta.get("commit"),
            "framework": "NIST IR 8547",
            "methodology": (
                "Deterministic projection of pqc-readiness "
                "remediations[] into the findings vocabulary "
                "by build_pqc_blockers.py"
            ),
            "additional": {
                "harness_version": meta.get("harness_version", ""),
                "source_artifact": source_name,
                "adapter_version": (meta.get("tool") or {}).get("adapter_version", ""),
                "who_sets_tls": who,
                "readiness_status": readiness.get("status", ""),
                "excluded_remediations": excluded,
            },
        },
        "executive_summary": {
            "prose": (
                f"{len(findings)} PQC transition finding(s) projected "
                f"from the readiness report (status: "
                f"{readiness.get('status', 'unknown')}, TLS decision "
                f"owner: {who}). These are schedule-risk items on the "
                "NIST IR 8547 clock, not live exploits."
            ),
            "severity_counts": counts,
        },
        "severity_criteria": _SEVERITY_CRITERIA,
        "findings": findings,
        "findings_summary": _summary_counts(findings),
        "remediation_roadmap": _roadmap(eligible),
    }


def validate_doc(doc: dict, source: str) -> int:
    try:
        import jsonschema
    except ImportError:
        print(
            "build_pqc_blockers: jsonschema not installed — cannot gate output",
            file=sys.stderr,
        )
        return 1
    schema = json.loads(FINDINGS_SCHEMA.read_text())
    errs = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(doc),
        key=lambda e: list(e.path),
    )
    for e in errs:
        loc = ".".join(str(p) for p in e.path) or "<root>"
        print(f"{source}: {loc}: {e.message}", file=sys.stderr)
    return len(errs)


def emit(readiness_path: Path, out: Path | None) -> Path | None:
    readiness = json.loads(readiness_path.read_text())
    doc = build_findings_doc(readiness, readiness_path.name)
    if doc is None:
        print(f"{readiness_path.name}: no location-anchored remediations — nothing to emit")
        return None
    target = out or readiness_path.with_name(
        readiness_path.name.replace("-pqc-readiness.json", "-pqc-blockers.json")
    )
    if validate_doc(doc, str(target)):
        raise SystemExit(f"refusing to write {target}: output violates pqc-blockers.schema.json")
    target.write_text(json.dumps(doc, indent=1))
    print(f"wrote {target}: {len(doc['findings'])} finding(s)")
    return target


def main() -> None:
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--readiness", help="one <slug>-pqc-readiness.json")
    ap.add_argument("--out", help="output path (default: alongside input)")
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="batch: walk <results-root>/pqc/*/*-pqc-readiness.json",
    )
    args = ap.parse_args()

    if args.readiness:
        emit(Path(args.readiness), Path(args.out) if args.out else None)
        return

    root = resolve_results_root(args) / "pqc"
    reports = sorted(root.glob("*/*-pqc-readiness.json"))
    written = sum(1 for p in reports if emit(p, None) is not None)
    print(f"batch: {written}/{len(reports)} reports emitted findings")


if __name__ == "__main__":
    main()
