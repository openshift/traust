#!/usr/bin/env python3
"""
Print the next N pending remediation candidates from remediation-manifest.csv.

A row is pending when status == "candidate" AND its report_path does not
exist as a real file (mirrors next_pending_validation.py).

Usage:
  next_pending_remediation.py [N]                   # default N=1
  next_pending_remediation.py [N] --json
  next_pending_remediation.py [N] --product <p>
  next_pending_remediation.py --rem-id <id> --json  # one specific row
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    resolve_results_root,
    workspace_dir,
)

HERE = Path(__file__).resolve().parent


def load(manifest: Path) -> list[dict]:
    with manifest.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def is_done(workspace: Path, r: dict) -> bool:
    rp = workspace / r["report_path"]
    return rp.is_file() and not rp.is_symlink()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("n", nargs="?", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--product")
    ap.add_argument("--rem-id")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    workspace = workspace_dir(engine)
    manifest = (
        resolve_results_root(args) / "remediations" / "_manifest" / "remediation-manifest.csv"
    )

    rows = load(manifest)
    if args.rem_id:
        rows = [r for r in rows if r["rem_id"] == args.rem_id]
        for r in rows:
            print(json.dumps(r) if args.json else r["rem_id"])
        return 0 if rows else 1

    out = []
    for r in rows:
        if args.product and r["logical_product"] != args.product:
            continue
        if r.get("status", "candidate") != "candidate":
            continue
        if is_done(workspace, r):
            continue
        out.append(r)
        if len(out) >= args.n:
            break

    for r in out:
        print(json.dumps(r) if args.json else r["rem_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
