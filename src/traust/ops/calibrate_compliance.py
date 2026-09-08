#!/usr/bin/env python3
"""Run-idempotence gate for compliance assessments (Phase 4,
determinism amendment 5).

Same pinned inputs ⇒ byte-identical verdicts, or the pipeline has
nondeterminism to hunt. This gate runs the deterministic runner TWICE
with identical arguments into separate directories, canonicalizes both
artifacts (volatile fields stripped — generated_at and the differing
out-dir paths), and compares:

  - the full result sets (verdict, evidence hashes, reasons — everything)
  - the coverage blocks
  - the OSCAL exports when requested (uuid5 identifiers must match)

Any divergence prints a unified summary of the differing controls and
exits 1. This is a CALIBRATION gate: run it after engine/registry
changes and in CI over the committed calibration snapshot
(progress-tracker/configs/compliance/calibration/) — a real
iac_declared snapshot from the deployment's public IaC mirror at a
pinned commit, so the gate exercises real-shaped data offline.

Usage:
    python3 -m traust.cli.calibrate_compliance \
        --snapshot <cloud-inventory.json> [--khs <khs.json>]
        [--frameworks all] [--work-dir <dir>]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from traust_engine._util.script_loader import load_script

from traust.paths import HARNESS_ROOT


def _load(name: str):
    return load_script(name, HARNESS_ROOT)


ca = _load("compliance_assert")
rcc = _load("run_compliance_check")


def run_once(out_dir: Path, snapshot: Path, khs: Path | None, frameworks: str) -> dict:
    argv = [
        "--frameworks",
        frameworks,
        "--target-kind",
        "environment",
        "--environment",
        "calibration",
        "--collector",
        f"cloud_inventory={snapshot}",
        "--findings-db",
        str(out_dir / "absent.db"),
        "--trust-categories",
        "security",
        "--out-dir",
        str(out_dir),
        "--oscal",
    ]
    if khs:
        argv += ["--collector", f"scan_k8s_hardening={khs}"]
    rc = rcc.main(argv)
    base = rcc.artifact_base("calibration", frameworks)
    doc = json.loads((out_dir / f"{base}.json").read_text(encoding="utf-8"))
    doc["_rc"] = rc
    doc["_oscal"] = json.loads((out_dir / f"{base}.oscal.json").read_text(encoding="utf-8"))
    return doc


def comparable(doc: dict) -> str:
    """Canonical form with run-local volatility removed."""
    d = json.loads(json.dumps(doc))  # deep copy
    d["metadata"].pop("generated_at", None)
    d["_oscal"]["assessment-results"]["metadata"].pop("last-modified", None)
    for res in d["_oscal"]["assessment-results"]["results"]:
        res.pop("start", None)
    return ca.canonical_json(d)


def diff_summary(a: dict, b: dict) -> list[str]:
    out = []
    ra = {(r["framework"], r["control_id"]): r for r in a["results"]}
    rb = {(r["framework"], r["control_id"]): r for r in b["results"]}
    for key in sorted(set(ra) | set(rb)):
        va, vb = ra.get(key), rb.get(key)
        if va is None or vb is None:
            out.append(f"{key[0]}:{key[1]} present in only one run")
        elif ca.canonical_json(va) != ca.canonical_json(vb):
            out.append(
                f"{key[0]}:{key[1]} differs — "
                f"run1={va.get('verdict')} run2={vb.get('verdict')}"
                + (
                    ""
                    if va.get("verdict") != vb.get("verdict")
                    else " (same verdict, differing evidence/fields)"
                )
            )
    if a.get("coverage") != b.get("coverage"):
        out.append("coverage blocks differ")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshot", required=True, type=Path)
    ap.add_argument("--khs", type=Path, default=None)
    ap.add_argument("--frameworks", default="all")
    ap.add_argument("--work-dir", type=Path, default=None)
    args = ap.parse_args(argv)

    work = args.work_dir or Path(tempfile.mkdtemp(prefix="cc-idem-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        one = run_once(work / "run1", args.snapshot, args.khs, args.frameworks)
        two = run_once(work / "run2", args.snapshot, args.khs, args.frameworks)
        if one["_rc"] != two["_rc"]:
            print(f"✗ exit codes differ: {one['_rc']} vs {two['_rc']}")
            return 1
        if comparable(one) == comparable(two):
            n = len(one["results"])
            print(
                f"✓ idempotent: {n} control results byte-identical "
                f"across runs (incl. evidence hashes, coverage, OSCAL "
                f"uuids)"
            )
            return 0
        print("✗ NONDETERMINISM DETECTED:")
        for line in diff_summary(one, two) or ["(difference outside the result set)"]:
            print(f"  - {line}")
        return 1
    finally:
        if args.work_dir is None:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
