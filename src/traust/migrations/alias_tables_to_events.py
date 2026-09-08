#!/usr/bin/env python3
"""Convert legacy `metadata.finding_aliases` tables into alias EVENTS (item 10 / P2).

An alias records that a finding was renamed by a re-baseline: `old-report:FIND-010`
became `ARGO_ROLLOUTS-22276e3-010`. Today that lives in a mutable metadata dict, so a
rename is a fact nothing signs the history of — it can be edited or dropped and the
Merkle root will not notice, because the root covers `events`, not `metadata`.

As an event it is append-only, inside the tree, and carries who said so and when.
`make_alias_event` has been valid since contracts v0.4.4.

Measured 2026-08-21: **413 layers, 12,405 alias entries, 3,316 of them confirmed.**

**The table is NOT deleted.** `_resolve_layer_findings` still reads
`metadata.finding_aliases` when resolving a ref, so removing it in the same pass would
change resolution while the events are still unproven. Migration first, readers second,
deletion last — the table becomes redundant, then dead, then gone.

**This re-signs**: new events move the Merkle root. Needs a signing identity.

    python3 -m traust.migrations.alias_tables_to_events <root> \
        [--apply] [--pubkey PATH] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from traust_engine.ledger import (
    LedgerError,
    make_alias_event,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
ACTOR = {"kind": "machine", "identity": "migration/alias_tables_to_events", "ldap_verified": False}


def existing_alias_pairs(layer: dict) -> set[tuple[str, str]]:
    """(old_ref, new_ref) already recorded as an event — so re-runs add nothing."""
    out = set()
    for e in layer.get("events") or []:
        al = e.get("alias")
        if al and e.get("finding_ref"):
            out.add((e["finding_ref"], al.get("new_finding_ref")))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--pubkey", type=Path, default=None)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()

    tally: Counter[str] = Counter()
    problems: list[str] = []
    started = time.monotonic()

    for layer_path in sorted(results_root.rglob("*-findings-layer.json")):
        if args.limit and tally["layers touched"] >= args.limit:
            break
        if STATE_DIRS.intersection(layer_path.relative_to(results_root).parts):
            continue
        try:
            layer = json.loads(layer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable"] += 1
            continue
        meta = layer.get("metadata") or {}
        table = meta.get("finding_aliases") or {}
        if not table:
            continue
        tally["layers with a table"] += 1

        already = existing_alias_pairs(layer)
        new_events = []
        for old_ref, entry in sorted(table.items()):
            new_ref = entry.get("new_id")
            if not new_ref:
                tally["entry without new_id — skipped"] += 1
                continue
            if (old_ref, new_ref) in already:
                tally["already an event"] += 1
                continue
            # `mapped_at` is when the rename was decided; keep it as the event's own
            # time rather than stamping "now", or the ledger records the migration
            # date as the date the finding was renamed.
            when = entry.get("mapped_at") or meta.get("updated") or meta.get("created")
            if not when:
                tally["entry without a timestamp — skipped"] += 1
                problems.append(f"{layer_path.name}: {old_ref} has no mapped_at")
                continue
            new_events.append(
                make_alias_event(
                    old_ref,
                    new_ref,
                    entry.get("matched_by") or "unknown",
                    recorded_at=when,
                    source_ref=entry.get("from_report") or meta.get("audit_report") or "",
                    actor=ACTOR,
                    rationale=(
                        "Migrated from metadata.finding_aliases (item 10 / P2): the rename "
                        "was recorded in mutable metadata, which the Merkle root does not "
                        "cover. Values are carried over unchanged."
                    ),
                    confirmed=entry.get("confirmed"),
                    rejected=entry.get("rejected"),
                    similarity=entry.get("similarity"),
                    path_overlap=entry.get("path_overlap"),
                    from_report=entry.get("from_report"),
                )
            )
        if not new_events:
            continue
        tally["alias events to add"] += len(new_events)
        tally["layers touched"] += 1
        if not args.apply:
            continue

        layer.setdefault("events", []).extend(new_events)
        layer["events"].sort(key=lambda e: e.get("recorded_at") or "")
        svc = engine.ledger.service(data_dir=layer_path.parent)
        svc.store_layer(layer_path, layer)
        try:
            svc.sign(layer_path)
        except LedgerError as exc:
            tally["sign failed — NOT written"] += 1
            problems.append(f"{layer_path.name}: {exc}")
            continue
        if args.pubkey:
            layer = engine.ledger.service(data_dir=layer_path.parent).read_layer_file(layer_path)
            bad = [
                f
                for f in verify_merkle_signature(layer, str(args.pubkey))
                if f.severity.name == "ERROR"
            ]
            if bad:
                tally["fresh signature failed to verify — NOT written"] += 1
                continue
        tally["layers written"] += 1

    print(f"{'APPLY' if args.apply else 'DRY RUN'} · {time.monotonic() - started:.0f}s")
    for k, v in tally.most_common():
        print(f"  {k:44} {v:,}")
    for p in problems[:15]:
        print(f"    ! {p}")
    if len(problems) > 15:
        print(f"    … {len(problems) - 15} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
