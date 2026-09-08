#!/usr/bin/env python3
"""Record baseline-appended findings as EVENTS (item 9 / B7).

Gate A15 stopped producers writing findings straight into a baseline on 2026-08-17,
because a baseline append records a finding against a commit it was not found at and
bypasses the rescan router's re-baseline decision. The findings that entered that way
before the gate are still there, and the ledger has no event for them: their
provenance lives only in the report's `origin` field, which nothing signs.

This emits one event per such finding, from the producer that claimed it, so the
provenance is inside the Merkle tree. Measured 2026-08-21: **1,761 findings** —
impact-analysis 1,007, verify-remediation 686, vuln-scan 68.

**Non-destructive: the baseline is not modified.** "Extract into events" could mean
removing them from the report, and that would change 8,235 reports and every metric
derived from them. Recording provenance is the part that is unambiguously correct;
whether the finding should also leave the baseline is a separate decision that needs a
human, and this migration does not pre-empt it.

**This re-signs**: new events move the Merkle root. Needs a signing identity.

    python3 -m traust.migrations.baseline_findings_to_events <root> \
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
    compute_event_id,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
# origin -> the source type that producer's report is
ORIGIN_SOURCE = {
    "impact-analysis": "impact_report",
    "verify-remediation": "verification_report",
    "vuln-scan": "vuln_scan_report",
}


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
            tally["unreadable layer"] += 1
            continue
        meta = layer.get("metadata") or {}
        name = meta.get("audit_report")
        report = layer_path.parent / Path(name).name if name else None
        if not report or not report.is_file():
            continue
        try:
            findings = json.loads(report.read_text(encoding="utf-8")).get("findings") or []
        except (OSError, json.JSONDecodeError):
            tally["unreadable report"] += 1
            continue

        have = {
            (e.get("finding_ref"), (e.get("source") or {}).get("type"))
            for e in (layer.get("events") or [])
        }
        new_events = []
        for f in findings:
            origin = f.get("origin")
            if not origin:
                continue
            tally[f"origin: {origin}"] += 1
            stype = ORIGIN_SOURCE.get(origin)
            if not stype:
                tally["unmapped origin — skipped"] += 1
                problems.append(f"{report.name}: unknown origin {origin!r}")
                continue
            ref = f.get("id")
            if not ref or (ref, stype) in have:
                tally["already evidenced"] += 1
                continue
            when = (
                f.get("discovered_at")
                or f.get("date")
                or (json.loads(report.read_text(encoding="utf-8")).get("metadata") or {}).get(
                    "date"
                )
            )
            if not when:
                tally["no timestamp — skipped"] += 1
                continue
            ev = {
                "finding_ref": ref,
                "recorded_at": when if "T" in str(when) else f"{when}T00:00:00+00:00",
                "source": {
                    "type": stype,
                    "ref": name,
                    "actor": {
                        "kind": "machine",
                        "identity": f"{origin}/pre-A15",
                        "ldap_verified": False,
                    },
                },
                "disposition": {"validity": "confirmed"},
                "rationale": (
                    f"Provenance migration (item 9 / B7): this finding was appended "
                    f"directly to the baseline by {origin} before gate A15 closed that "
                    f"path on 2026-08-17. The event records who claimed it; the "
                    f"baseline entry is unchanged."
                ),
            }
            if f.get("fingerprint"):
                ev["fingerprint"] = f["fingerprint"]
            ev["event_id"] = compute_event_id(name, ref, "confirmed", None)
            new_events.append(ev)

        if not new_events:
            continue
        tally["events to add"] += len(new_events)
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
            if [
                x
                for x in verify_merkle_signature(layer, str(args.pubkey))
                if x.severity.name == "ERROR"
            ]:
                tally["fresh signature failed to verify — NOT written"] += 1
                continue
        tally["layers written"] += 1

    print(f"{'APPLY' if args.apply else 'DRY RUN'} · {time.monotonic() - started:.0f}s")
    for k, v in tally.most_common():
        print(f"  {k:44} {v:,}")
    for p in problems[:10]:
        print(f"    ! {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
