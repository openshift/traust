#!/usr/bin/env python3
# Migration utility written 2026-08-18
"""Backfill `metadata.audit_report_sha256` onto every layer (plan §4.4.0 step 1).

A layer names its baseline by relative path, which is only meaningful while the two
share a directory. §4.4.0 moves reports to object storage and keeps the ledger in
git, so the link has to become content-addressed first: this records the sha256 of
the exact bytes each layer currently annotates.

Why this is cheap and safe:

- **No re-stamp. Re-signature: SOMETIMES, and this was wrong until 2026-08-21.**
  Under format 2 `merkle_signature_payload` covered the Merkle root, leaf_format,
  epoch, size, the pre-epoch checkpoint and a digest of `claim_hashes` — not the
  report — so the original claim here ("no re-signature") held. **Format 3 added
  `audit_report_sha256` to the payload**, and this file kept the old claim, so
  backfilling a digest onto a format-3 layer left a signature that no longer
  verified. Writes now go through `stamp_report_reference`, which drops the stale
  signature (D4b); the run reports how many need re-signing. The Merkle root itself
  still covers events only, so no root moves.
  Adding a metadata field therefore moves no root and invalidates no signature, so
  this needs no Vault key.
- **Idempotent.** A layer already carrying the digest of its current report is
  skipped; a second `--apply` run is a no-op.
- **Never overwrites a differing digest.** If a layer already records a digest that
  does NOT match the report's bytes, that is the signal the report was rewritten
  since — reported and skipped, not healed. `baseline_claims.py record` is the
  deliberate re-record path.
- **Skips layers whose report is missing**, rather than inventing a reference.

    python3 -m traust.migrations.backfill_report_digest <results-root> [--apply]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from traust_engine.ledger import report_sha256, stamp_report_reference

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    ap.add_argument(
        "--refresh-changed",
        action="store_true",
        help="UPDATE a digest that differs, instead of reporting it. Off by default "
        "because a differing digest is indistinguishable from tampering: the "
        "layer says one thing, the bytes say another. Use it only when you know "
        "why the report changed — e.g. straight after the item 4b re-path, which "
        "rewrites locations and therefore fingerprints. It drops the now-stale "
        "signature (D4b via stamp_report_reference), so re-sign afterwards.",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()

    tally: Counter[str] = Counter()
    conflicts: list[str] = []
    seen: set[str] = set()

    for layer_path in sorted(results_root.rglob("*-findings-layer.json")):
        real = str(layer_path.resolve())
        if real in seen:  # the findings tree carries gap-plan symlinks
            continue
        seen.add(real)
        tally["layers"] += 1
        try:
            layer = json.loads(layer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable layer"] += 1
            continue
        meta = layer.get("metadata") or {}
        name = meta.get("audit_report")
        if not name:
            tally["no audit_report named"] += 1
            continue
        report = layer_path.parent / name
        if not report.is_file():
            tally["report not found beside layer"] += 1
            continue

        digest = report_sha256(report)
        current = meta.get("audit_report_sha256")
        if current == digest:
            tally["already recorded"] += 1
            continue
        if current and not args.refresh_changed:
            tally["differing digest — skipped"] += 1
            conflicts.append(
                f"{layer_path.relative_to(results_root)}: records "
                f"{current[:12]}…, report hashes {digest[:12]}…"
            )
            continue

        # Through stamp_report_reference, never by assignment: it is the one place
        # that enforces D4b. Writing the field directly is what produced a layer
        # claiming signature format 3 whose signature no longer verified — format 3
        # signs the digest, so adding one invalidates the signature without moving
        # the Merkle root, and nothing downstream was checking for that.
        layer["metadata"] = meta
        stamp_report_reference(layer, report)
        if not (layer.get("metadata") or {}).get("merkle_root_signature"):
            tally["signature dropped — re-sign required"] += 1
        tally["backfilled"] += 1
        if args.apply:
            svc = engine.ledger.service(data_dir=layer_path.parent)
            svc.stamp_report_file(layer_path, Path(report))

    print(f"{'APPLY' if args.apply else 'DRY RUN'} · {tally['layers']} layers")
    for k, v in tally.most_common():
        if k != "layers":
            print(f"  {k:34} {v}")
    for c in conflicts[:10]:
        print(f"  ! {c}")
    if len(conflicts) > 10:
        print(f"  ! … and {len(conflicts) - 10} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
