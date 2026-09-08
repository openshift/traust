#!/usr/bin/env python3
"""Bulk-close the `needs_review` backlog as `rejected` (Michele, 2026-08-25).

`needs_review` is the "noticed but not recorded" lane: a statement someone was
meant to look at, holding no state until they do. It had an append and no exit —
nothing anywhere could move an item out of `pending` until
`LedgerWriter.resolve_needs_review` landed in traust-ledger 0.13.1 — so the queue
filled for months. Measured 2026-08-25 across the corpus: **16,706 of 16,740 items
pending, across 3,466 layers**, dominated by `undetermined_finding` (8,860),
`stale_baseline` (2,992), `needs_manual_test` (1,937) and `unsound_refutation`
(1,548). It is past any plausible review capacity, and a worklist nobody can work
is not a worklist.

**`rejected`, never `confirmed`, and the distinction is the whole safety argument.**
`confirmed` asserts that a corresponding event was appended — a determination the
ledger actually holds. For most of this backlog there deliberately is none:
`undetermined_finding` means triage could not decide *so no validity event was
emitted*. Confirming would record decisions nobody made.
`resolve_needs_review` refuses it anyway.

**Nothing is dismissed and no disposition moves.** Every current state derives from
`events`; a review item sets none. Closing one changes what a human is asked to
look at, not what the ledger believes:

  * `undetermined_finding`, `needs_manual_test` — the finding stays `not_verified`
  * `unsound_refutation`  — the refutation stays blocked, so the finding stays OPEN
  * `stale_baseline`      — the event was already emitted; it stands
  * `rebaseline_*`        — orphaned history stays orphaned, as it already was

**`severity_proposal` is skipped by default.** Those 63 are the one class where
closing forfeits something concrete: a proposed re-rating that is simply lost.
`--include-severity-proposals` opts in.

**What the note buys.** Every closure records why, so the corpus never claims these
were reviewed:

    bulk-closed 2026-08-25: queue exceeded review capacity; not individually reviewed

Anyone auditing later can filter on it and re-open by queueing fresh items.

**No signing.** `needs_review` is not an event: it sits outside the Merkle tree and
outside `merkle_signature_payload`, so closing an item cannot move a root or
invalidate a signature. Verified by test in traust-ledger.

    python3 -m traust.migrations.bulk_close_needs_review <root> \
        [--apply] [--include-severity-proposals] [--reason R] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from traust_engine.ledger import LedgerError, LedgerService

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

NOTE = "bulk-closed 2026-08-25: queue exceeded review capacity; not individually reviewed"

#: Closing one of these throws away a proposal rather than a non-decision, so it
#: stays out unless asked for explicitly.
PROTECTED_REASONS = frozenset({"severity_proposal"})

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}


def _layers(root: Path):
    for path in sorted(root.rglob("*-findings-layer.json")):
        if STATE_DIRS & set(path.relative_to(root).parts):
            continue
        yield path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_config_home_arg(ap)
    ap.add_argument(
        "root",
        type=Path,
        nargs="?",
        default=None,
        help="findings root (default: configured analysis-results)",
    )
    ap.add_argument("--apply", action="store_true", help="write; without it this only reports")
    ap.add_argument(
        "--include-severity-proposals",
        action="store_true",
        help=f"also close {sorted(PROTECTED_REASONS)} (default: skip)",
    )
    ap.add_argument(
        "--reason",
        action="append",
        default=None,
        help="close only these queue_reasons (repeatable)",
    )
    ap.add_argument(
        "--note",
        default=NOTE,
        help="resolution note recorded on each closure. Defaults to the "
        "2026-08-25 wording; override it for a LATER pass, because "
        "reusing that date stamps items with a closure that did not "
        "happen then and an auditor filtering on the note cannot "
        "tell the two passes apart.",
    )
    ap.add_argument("--limit", type=int, default=0, help="stop after N layers")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    root = (args.root or analysis_results_dir(engine)).resolve()

    if not root.is_dir():
        print(f"error: no such directory: {root}", file=sys.stderr)
        return 2

    protected = set() if args.include_severity_proposals else PROTECTED_REASONS
    wanted = set(args.reason) if args.reason else None

    closed = Counter()
    skipped = Counter()
    failed: list[str] = []
    layers_touched = 0
    layers_seen = 0

    for path in _layers(root):
        if args.limit and layers_seen >= args.limit:
            break
        try:
            layer = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failed.append(f"{path}: unreadable ({exc})")
            continue
        layers_seen += 1

        targets = []
        for item in layer.get("needs_review") or []:
            if not isinstance(item, dict) or item.get("status") != "pending":
                continue
            reason = item.get("queue_reason") or "(none)"
            if reason in protected or (wanted and reason not in wanted):
                skipped[reason] += 1
                continue
            targets.append((LedgerService.review_item_key(item), reason))

        if not targets:
            continue
        layers_touched += 1

        if not args.apply:
            for _key, reason in targets:
                closed[reason] += 1
            continue

        ledger = engine.ledger.service(data_dir=path.parent)
        for key, reason in targets:
            try:
                ledger.resolve_review_item(path, key, "rejected", note=args.note)
                closed[reason] += 1
            except LedgerError:
                skipped["(already resolved)"] += 1
            except Exception as exc:
                failed.append(f"{path}: {reason}: {exc}")

    verb = "closed" if args.apply else "would close"
    total = sum(closed.values())
    print(f"{verb} {total} item(s) across {layers_touched} layer(s) ({layers_seen} scanned)")
    for reason, n in closed.most_common():
        print(f"   {n:6}  {reason}")
    if skipped:
        print("skipped:")
        for reason, n in skipped.most_common():
            print(f"   {n:6}  {reason}")
    if failed:
        print(f"\n{len(failed)} failure(s):", file=sys.stderr)
        for line in failed[:20]:
            print(f"   {line}", file=sys.stderr)
    if not args.apply:
        print("\n(dry run — re-run with --apply to write)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
