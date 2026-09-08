#!/usr/bin/env python3
"""Validation gate for tenant-isolation review reports (isolation-review).

Stdlib-only mirror of contracts/schemas/isolation-review.schema.json, in the style of
pqc-readiness's ``pqc_facts.py --validate-readiness``. The two must stay in
sync; tests/test_isolation_review.py exercises both against shared fixtures.

Usage:
    python3 validate_isolation_review.py REPORT.json   # exit 0 == valid
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED_TOP = ["title", "metadata", "interfaces", "gaps", "posture"]
REQUIRED_META = ["service", "repos", "graph_ref", "harness_version", "reviewed_at"]
REQUIRED_IFACE = ["id", "name", "kind", "exposure", "complexity", "dimensions"]
REQUIRED_GAP = ["severity", "interface_id", "description", "remediation"]

DIMENSIONS = ("privilege", "encryption", "authentication", "connectivity", "hygiene")
KINDS = ("api", "data-store", "queue", "ingress", "webhook", "cli", "other")
EXPOSURES = ("public", "tenant", "partner", "internal")
COMPLEXITIES = ("low", "medium", "high")
RESULTS = ("yes", "partial", "no", "na")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
POSTURES = ("strong", "adequate", "weak", "critical-gap")


def _check_interface(idx: int, iface: dict, errs: list[str]) -> None:
    label = f"interfaces[{idx}]"
    for k in REQUIRED_IFACE:
        if k not in iface:
            errs.append(f"{label}: missing key: {k}")
    iid = iface.get("id")
    if iid is not None and not (
        isinstance(iid, str) and iid.startswith("IF-") and iid[3:].isdigit()
    ):
        errs.append(f"{label}: bad id {iid!r} (expected IF-<n>)")
    if "kind" in iface and iface["kind"] not in KINDS:
        errs.append(f"{label}: bad kind {iface['kind']!r}")
    if "exposure" in iface and iface["exposure"] not in EXPOSURES:
        errs.append(f"{label}: bad exposure {iface['exposure']!r}")
    if "complexity" in iface and iface["complexity"] not in COMPLEXITIES:
        errs.append(f"{label}: bad complexity {iface['complexity']!r}")

    dims = iface.get("dimensions")
    if not isinstance(dims, dict):
        if "dimensions" in iface:
            errs.append(f"{label}: dimensions must be an object")
        return
    for dim in DIMENSIONS:
        d = dims.get(dim)
        if d is None:
            errs.append(f"{label}: missing dimensions.{dim}")
            continue
        result = d.get("result")
        if result not in RESULTS:
            errs.append(f"{label}.{dim}: bad result {result!r}")
        if result in ("partial", "no") and not d.get("evidence"):
            errs.append(
                f"{label}.{dim}: result {result!r} requires "
                "evidence citations (file:line or finding IDs)"
            )


def validate(doc: dict) -> list[str]:
    errs: list[str] = []
    for k in REQUIRED_TOP:
        if k not in doc:
            errs.append(f"missing top-level key: {k}")

    meta = doc.get("metadata") or {}
    for k in REQUIRED_META:
        if k not in meta:
            errs.append(f"missing metadata.{k}")
    repos = meta.get("repos")
    if repos is not None and (not isinstance(repos, list) or not repos):
        errs.append("metadata.repos must be a non-empty array")

    interfaces = doc.get("interfaces")
    known_ids: set[str] = set()
    if interfaces is not None and not isinstance(interfaces, list):
        errs.append("interfaces must be an array")
    else:
        for i, iface in enumerate(interfaces or []):
            _check_interface(i, iface, errs)
            if isinstance(iface.get("id"), str):
                known_ids.add(iface["id"])

    gaps = doc.get("gaps")
    if gaps is not None and not isinstance(gaps, list):
        errs.append("gaps must be an array")
    else:
        for i, gap in enumerate(gaps or []):
            for k in REQUIRED_GAP:
                if k not in gap:
                    errs.append(f"gaps[{i}]: missing key: {k}")
            if "severity" in gap and gap["severity"] not in SEVERITIES:
                errs.append(f"gaps[{i}]: bad severity {gap['severity']!r}")
            ref = gap.get("interface_id")
            if ref is not None and known_ids and ref not in known_ids:
                errs.append(f"gaps[{i}]: interface_id {ref!r} does not match any interfaces[].id")

    posture = doc.get("posture") or {}
    if "posture" in doc:
        if "overall" not in posture:
            errs.append("missing posture.overall")
        elif posture["overall"] not in POSTURES:
            errs.append(f"bad posture.overall {posture['overall']!r}")
        if "summary" not in posture:
            errs.append("missing posture.summary")
    return errs


def validate_file(path: Path) -> int:
    doc = json.loads(path.read_text(encoding="utf-8"))
    errs = validate(doc)
    if errs:
        print("INVALID:", file=sys.stderr)
        for e in errs:
            print("  -", e, file=sys.stderr)
        return 1
    print("isolation review valid: 0 errors")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Validate an isolation-review report (isolation-review.schema.json mirror)."
    )
    ap.add_argument("report", help="path to <slug>-isolation-review.json")
    args = ap.parse_args(argv)
    return validate_file(Path(args.report))


if __name__ == "__main__":
    raise SystemExit(main())
