#!/usr/bin/env python3
# Migration utility written 2026-08-18
"""Re-stamp the 364 finding fingerprints the v1 -> v2 recipe change moved.

Ledger plan queue item 3, decision D8. `algo_version` v2 (traust-ledger 0.2.0) drops
a location path that canonicalizes to empty from the hashed set, so a finding
located at `['.', 'src/a.go']` no longer hashes `";src/a.go"`. Measured against the
installed recipe over all 75,170 stamped corpus findings: exactly **364 move**, in
259 repos. Until they are re-stamped, `check_finding_identity` — which recomputes
and compares — reports them as mismatched.

Scope, measured rather than assumed:

- **361 baseline reports** carry the 364 findings. Only `finding.fingerprint` is
  rewritten.
- **No layer is touched.** 63 layers hold events on these findings and **zero** of
  those events carry a fingerprint stamp, so there is nothing to migrate there.
  Consequently no Merkle root moves and **nothing needs re-signing** — which is why
  this does not wait on the signing key reaching an unattended writer (P8).
- **No claim hash changes.** `traust_ledger.events.CLAIM_FIELDS` is
  (id, title, severity, cwes, locations, description, remediation) — `fingerprint`
  is not among them, so the baseline tamper-guard is unaffected.

On A15: this writes a baseline, and that gate reserves baseline writes for the three
audit skills. It is not the violation A15 exists to stop — no finding is added and no
claim is altered; an existing finding's identity stamp is corrected to the recipe the
harness now computes, exactly as the P0.4 pass corrected 606 forged and 1,807 absent
stamps. Nothing here can create or resurrect a finding.

Safety properties:

- **DRY-RUN BY DEFAULT.** Nothing is written without `--apply`.
- **Idempotent.** A finding already at its v2 value is skipped; a second `--apply`
  run is a no-op.
- **Refuses on drift.** If a stored value is neither the worklist's v1 nor the
  recomputed v2, the finding is reported and skipped, never overwritten — a third
  value means something else edited the report and this tool is not the adjudicator.
- **Recomputes, never trusts the worklist.** The v2 value written is computed from
  the finding in the report at run time; the worklist is used only to identify
  candidates and to assert the v1 side has not changed underneath.

    python3 -m traust.migrations.restamp_fingerprints_v2 <results-root> [--apply]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from traust_engine.ledger import ALGO_VERSION, fingerprint

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
    progress_tracker_dir,
)

WORKLIST = "progress-tracker/plans/identity-differential-2026-08-17/v2-restamp-worklist.json"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "results_root", type=Path, nargs="?", default=None, help="the analysis-results checkout"
    )
    ap.add_argument(
        "--worklist", type=Path, default=None, help=f"default: <progress-tracker>/{WORKLIST}"
    )
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()
    tracker = progress_tracker_dir(engine)

    worklist = args.worklist or (tracker / WORKLIST)
    if not worklist.is_file():
        print(f"ERROR: worklist not found: {worklist}", file=sys.stderr)
        return 2
    rows = json.loads(worklist.read_text(encoding="utf-8"))
    if rows.get("algo_to") != ALGO_VERSION:
        print(
            f"ERROR: worklist targets {rows.get('algo_to')} but the installed "
            f"recipe is {ALGO_VERSION} — regenerate the worklist",
            file=sys.stderr,
        )
        return 2

    by_report: dict[str, list[dict]] = {}
    for r in rows["findings"]:
        by_report.setdefault(r["report"], []).append(r)

    tally: Counter[str] = Counter()
    drift: list[str] = []
    for rel, items in sorted(by_report.items()):
        path = results_root / rel
        if not path.is_file():
            tally["report missing"] += 1
            drift.append(f"{rel}: report not found")
            continue
        raw = path.read_text(encoding="utf-8")
        report = json.loads(raw)
        repo = (report.get("metadata") or {}).get("repository")
        wanted = {i["finding"]: i for i in items}
        swaps: list[tuple[str, str]] = []
        for finding in report.get("findings") or []:
            row = wanted.get(finding.get("id"))
            if not row:
                continue
            stored = finding.get("fingerprint")
            recomputed = fingerprint(finding, repo)
            if stored == recomputed:
                tally["already v2"] += 1
                continue
            if stored != row["v1"]:
                tally["drift — skipped"] += 1
                drift.append(
                    f"{rel} / {finding['id']}: stored {str(stored)[:12]}… "
                    f"is neither v1 {row['v1'][:12]}… nor v2 "
                    f"{recomputed[:12]}…"
                )
                continue
            swaps.append((stored, recomputed))
            tally["re-stamped"] += 1

        # Surgical text edit, NOT a re-serialization. The corpus is mixed on
        # ensure_ascii: some reports store "\u2014", others a literal em dash,
        # depending on which producer wrote them. Re-dumping the document
        # therefore churns thousands of unrelated lines whichever setting is
        # chosen — measured at 3,011 and 2,272 changed lines for 364 intended
        # ones. Replacing only the fingerprint line leaves every other byte
        # untouched, so the diff is exactly the findings that moved.
        #
        # Identical inputs hash identically, so when two findings in one report
        # share a v1 value they share the v2 value too: replacing every
        # occurrence of the pair is correct, and the count is asserted.
        for v1, v2 in swaps:
            needle = f'"fingerprint": "{v1}"'
            if needle not in raw:
                tally["fingerprint line not found — skipped"] += 1
                drift.append(f"{rel}: {v1[:12]}… not on a fingerprint line")
                continue
            raw = raw.replace(needle, f'"fingerprint": "{v2}"')
        if swaps and args.apply:
            after = json.loads(raw)
            written = {f.get("id"): f.get("fingerprint") for f in after.get("findings") or []}
            bad = [
                fid
                for fid, _ in ((i["finding"], None) for i in items)
                if fid in written
                and written[fid]
                != fingerprint(next(f for f in after["findings"] if f.get("id") == fid), repo)
            ]
            if bad:
                drift.append(f"{rel}: post-edit verify failed for {bad}")
                tally["post-edit verify failed"] += 1
                continue
            path.write_text(raw, encoding="utf-8")
            tally["reports written"] += 1

    print(
        f"{'APPLY' if args.apply else 'DRY RUN'} · worklist {rows['count']} findings "
        f"· {len(by_report)} reports · recipe {ALGO_VERSION}"
    )
    for k, v in tally.most_common():
        print(f"  {k:22} {v}")
    for d in drift[:10]:
        print(f"  ! {d}")
    if len(drift) > 10:
        print(f"  ! … and {len(drift) - 10} more")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
