#!/usr/bin/env python3
"""Bring ledger event timestamps up to the RFC 3339 contract.

Uses the contract's own `to_rfc3339`, so "repaired" means exactly "what the
model now enforces". Both timestamp fields take the same path: a convertible
value (a bare date) is padded to midnight UTC.

They differ only where the schema forces it. `occurred_at` is optional, so an
unconvertible value is dropped. `recorded_at` is required, so it can only be
reported for a human — rewriting it would mean inventing a timestamp.

Converting is safe for both. Every consumer slices `recorded_at[:10]`, and
padding preserves that prefix, so the interactive `source.ref` day-key and
the `event_id` derived from it do not move.

Changing a field re-roots the layer under `leaf_format 2`, so a layer that
arrives signed must leave signed; without a signing identity such a layer is
restored and reported instead of written unsigned.

Run this BEFORE the gated contracts release ships — the model validates on
read as well as write.

    python3 -m traust.migrations.fix_event_timestamps <results-root> \\
        [--apply] [--pubkey PATH] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from traust_contracts.v1.timestamps import TimestampError, is_rfc3339, to_rfc3339
from traust_engine.ledger import LedgerError, verify_merkle_signature

from traust.context import add_config_home_arg, analysis_results_dir, load_engine

LAYER_SUFFIX = "-findings-layer.json"
STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
PROGRESS_EVERY = 250


class TimestampField(NamedTuple):
    name: str
    droppable: bool


# Required vs optional is the only difference, and the schema dictates it.
TIMESTAMP_FIELDS = (
    TimestampField("recorded_at", droppable=False),
    TimestampField("occurred_at", droppable=True),
)


def converted(field_name: str) -> str:
    return f"{field_name} converted"


def dropped(field_name: str) -> str:
    return f"{field_name} dropped (unconvertible)"


def unrepairable(field_name: str) -> str:
    return f"{field_name} unconvertible — LEFT FOR A HUMAN"


class WriteRefused(Exception):
    """The layer was restored rather than written. Carries (reason, detail)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass
class Repair:
    """Outcome of repairing events. `changed` counts writes needing a re-root."""

    counts: Counter[str] = field(default_factory=Counter)
    problems: list[str] = field(default_factory=list)
    changed: int = 0

    def merge(self, other: Repair) -> None:
        self.counts += other.counts
        self.problems += other.problems
        self.changed += other.changed


def _repair_field(event: dict, spec: TimestampField) -> Repair:
    result = Repair()
    if spec.name not in event:
        return result

    value = event[spec.name]
    if is_rfc3339(value):
        return result

    try:
        event[spec.name] = to_rfc3339(value)
    except TimestampError:
        if not spec.droppable:
            ref = str(event.get("event_id", "?"))[:12]
            result.problems.append(f"{ref}: {spec.name}={value!r} is unconvertible and required")
            result.counts[unrepairable(spec.name)] += 1
            return result
        del event[spec.name]
        result.counts[dropped(spec.name)] += 1
    else:
        result.counts[converted(spec.name)] += 1

    result.changed += 1
    return result


def repair_events(events: list[dict]) -> Repair:
    """Bring event timestamps to RFC 3339 in place.

    Pure apart from mutating the dicts, so the decision logic is testable
    without a ledger or a signing key.
    """
    result = Repair()
    for event in events:
        if not isinstance(event, dict):
            continue
        for spec in TIMESTAMP_FIELDS:
            result.merge(_repair_field(event, spec))
    return result


class TimestampMigration:
    def __init__(
        self,
        engine,
        results_root: Path,
        *,
        apply: bool = False,
        limit: int | None = None,
        pubkey: Path | None = None,
    ) -> None:
        self.engine = engine
        self.results_root = results_root
        self.apply = apply
        self.limit = limit
        self.pubkey = pubkey
        self.tally: Counter[str] = Counter()
        self.problems: list[str] = []
        self._started = 0.0

    def run(self) -> int:
        self._started = time.monotonic()
        layers = sorted(self.results_root.rglob(f"*{LAYER_SUFFIX}"))

        for path in layers:
            if self.limit and self.tally["layers touched"] >= self.limit:
                break
            self._process(path)

        self._report(len(layers))
        return 1 if self.problems else 0

    def _process(self, path: Path) -> None:
        if STATE_DIRS.intersection(path.relative_to(self.results_root).parts):
            return
        try:
            layer = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.tally["unreadable"] += 1
            return

        events = layer.get("events") or []
        review = layer.get("needs_review") or []
        if not events and not review:
            return
        self.tally["layers considered"] += 1

        repair = repair_events(events)
        repair.merge(repair_events(review))
        self.tally += repair.counts
        self.problems += [f"{path.name}: {p}" for p in repair.problems]

        if not repair.changed:
            return
        self.tally["layers touched"] += 1
        if not self.apply:
            return

        try:
            self._persist(path, layer)
        except WriteRefused as refused:
            self.tally[refused.reason] += 1
            self.problems.append(f"{path.name}: {refused.detail}")
            return

        self.tally["layers written"] += 1
        self._progress()

    def _persist(self, path: Path, layer: dict) -> None:
        """Write, re-stamp, and re-sign — or restore and raise WriteRefused."""
        original = path.read_bytes()
        was_signed = self._is_signed(original)

        service = self.engine.ledger.service(data_dir=path.parent)
        service.store_layer(path, layer)

        # sign() stamps the Merkle root and signs only if a key is configured;
        # the stamp is needed either way because the events changed.
        try:
            service.sign(path)
        except LedgerError as exc:
            path.write_bytes(original)
            raise WriteRefused("sign failed — NOT written", str(exc)) from None

        fresh = service.read_layer_file(path)

        # verify_merkle_signature reports nothing on an unsigned layer, so
        # assert the signature exists rather than that none failed.
        if was_signed and not (fresh.get("metadata") or {}).get("merkle_root_signature"):
            path.write_bytes(original)
            raise WriteRefused(
                "signature LOST during re-sign — NOT written",
                "signed on entry, unsigned after sign(); is LAAS_SIGNING_KEY_PATH "
                "readable and COSIGN_PASSWORD set?",
            )

        if self.pubkey:
            errors = [
                finding
                for finding in verify_merkle_signature(fresh, str(self.pubkey))
                if finding.severity.name == "ERROR"
            ]
            if errors:
                path.write_bytes(original)
                raise WriteRefused(
                    "fresh signature failed to verify — NOT written",
                    errors[0].message[:90],
                )

    @staticmethod
    def _is_signed(raw: bytes) -> bool:
        try:
            metadata = json.loads(raw).get("metadata") or {}
        except json.JSONDecodeError:
            return False
        return bool(metadata.get("merkle_root_signature"))

    def _progress(self) -> None:
        written = self.tally["layers written"]
        if written % PROGRESS_EVERY:
            return
        rate = written / max(time.monotonic() - self._started, 1e-9)
        print(f"  … {written} written ({rate:.1f}/s)", flush=True)

    def _report(self, scanned: int) -> None:
        mode = "APPLY" if self.apply else "DRY RUN"
        elapsed = time.monotonic() - self._started
        print(f"{mode} · {scanned:,} layer files · {elapsed:.0f}s")
        for name, count in self.tally.most_common():
            print(f"  {name:44} {count:,}")
        for problem in self.problems[:20]:
            print(f"    ! {problem}")
        if len(self.problems) > 20:
            print(f"    … {len(self.problems) - 20} more")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(parser)
    parser.add_argument("results_root", type=Path, nargs="?", default=None)
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--pubkey",
        type=Path,
        default=None,
        help="verify each fresh signature before writing",
    )
    args = parser.parse_args(argv)

    engine = load_engine(args.config_home)
    return TimestampMigration(
        engine,
        (args.results_root or analysis_results_dir(engine)).resolve(),
        apply=args.apply,
        limit=args.limit,
        pubkey=args.pubkey,
    ).run()


if __name__ == "__main__":
    sys.exit(main())
