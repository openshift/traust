#!/usr/bin/env python3
"""
Atomically update one row of remediation-manifest.csv.

Same fcntl-locked rewrite pattern as update_validation_progress.py so
multiple remediation workers can run concurrently.

Usage:
  update_remediation_progress.py <rem_id> <status>
      [--fix-commit SHA] [--pr-url URL]
      [--started ISO] [--completed ISO]
      [--report PATH]

  status ∈ { candidate, forked, patching, patched,
             checks_passed, checks_failed,
             revalidated_fixed, revalidated_still_vulnerable,
             pr_opened, merged, abandoned }
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import sys
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root

HERE = Path(__file__).resolve().parent

VALID_STATUS = {
    "candidate",
    "forked",
    "patching",
    "patched",
    "checks_passed",
    "checks_failed",
    "revalidated_fixed",
    "revalidated_still_vulnerable",
    "pr_opened",
    "merged",
    "abandoned",
}
TERMINAL = {
    "checks_failed",
    "revalidated_fixed",
    "revalidated_still_vulnerable",
    "pr_opened",
    "merged",
    "abandoned",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("rem_id")
    ap.add_argument("status", choices=sorted(VALID_STATUS))
    ap.add_argument("--fix-commit")
    ap.add_argument("--pr-url")
    ap.add_argument("--started")
    ap.add_argument("--completed")
    ap.add_argument("--report")
    args = ap.parse_args(argv)

    manifest = (
        resolve_results_root(args) / "remediations" / "_manifest" / "remediation-manifest.csv"
    )
    lock = manifest.parent / ".remediation-manifest.lock"

    now = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch(exist_ok=True)
    with Path.open(lock, "w") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            with Path.open(manifest, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                rows = list(reader)

            hit = False
            for r in rows:
                if r["rem_id"] == args.rem_id:
                    hit = True
                    r["status"] = args.status
                    if args.status == "patching" and not r.get("started"):
                        r["started"] = args.started or now
                    if args.started:
                        r["started"] = args.started
                    if args.fix_commit:
                        r["fix_commit"] = args.fix_commit
                    if args.pr_url:
                        r["pr_url"] = args.pr_url
                    if args.report:
                        r["report_path"] = args.report
                    if args.status in TERMINAL:
                        r["completed"] = args.completed or now
                    break
            if not hit:
                print(f"ERROR: no manifest row for {args.rem_id!r}", file=sys.stderr)
                return 1

            tmp = manifest.with_suffix(".csv.tmp")
            with Path.open(tmp, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                w.writerows(rows)
            tmp.replace(manifest)
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)

    print(f"updated {args.rem_id!r} → {args.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
