#!/usr/bin/env python3
"""Backfill `fingerprint` onto ledger events (ledger plan item 6d).

Events carry the finding's identity so a disposition survives a re-baseline: a
`finding_ref` is `FIND-NNN` or `REPO-<commit>-NNN`, both of which move, while a
fingerprint does not. `attach_identity` stamps it on write, but almost nothing did
historically — measured 2026-08-21: **198 of 56,963 events (0.35%)**.

Ceiling, measured before writing this (§4.3.1d): **96.22%** of events resolve to a
stamped baseline finding directly, **97.87%** if the git-history pass is added for the
1,902 legacy `FIND-NNN` refs whose baseline was regenerated under the canonical scheme.
The residual ~2.1% are dispositions on findings no current baseline holds; they stay
unstamped, which is honest.

**This re-signs.** Adding a field to an event changes the event, which changes the
Merkle root under `leaf_format 2`, which invalidates the signature. So a signing
identity is required (`vault login`, then `LAAS_SIGNING_KEY_PATH` +
`COSIGN_PASSWORD`); without one, layers are counted and left untouched rather than
written unsigned.

**D9 applies:** the fingerprint identifies the FINDING. It is being added as an
attribute of the event, never as its key — `event_id` is untouched.

    python3 -m traust.migrations.backfill_event_fingerprints <root> \
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
    attach_identity,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

LAYER_SUFFIX = "-findings-layer.json"
STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}


def build_index(layer_path: Path, meta: dict) -> dict[str, str]:
    """finding_ref -> fingerprint, from the baseline this layer annotates.

    Confirmed aliases are applied, because a re-baseline that renamed a finding
    recorded the mapping there; ignoring it would leave those events unstamped for no
    reason.
    """
    name = meta.get("audit_report")
    if not name:
        return {}
    report = layer_path.parent / Path(name).name
    if not report.is_file():
        return {}
    try:
        findings = json.loads(report.read_text(encoding="utf-8")).get("findings") or []
    except (OSError, json.JSONDecodeError):
        return {}
    idx = {f.get("id"): f.get("fingerprint") for f in findings if f.get("fingerprint")}
    for old, alias in (meta.get("finding_aliases") or {}).items():
        if alias.get("confirmed"):
            fp = idx.get(alias.get("new_id"))
            if fp:
                idx[old] = fp
    return idx


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument(
        "--pubkey",
        type=Path,
        default=None,
        help="verify each fresh signature before writing; without it a "
        "layer is written on the signer's word alone",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()

    tally: Counter[str] = Counter()
    problems: list[str] = []
    started = time.monotonic()

    layers = sorted(results_root.rglob(f"*{LAYER_SUFFIX}"))
    for _n, layer_path in enumerate(layers):
        if args.limit and tally["layers touched"] >= args.limit:
            break
        rel = layer_path.relative_to(results_root)
        if STATE_DIRS.intersection(rel.parts):
            continue
        try:
            layer = json.loads(layer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable"] += 1
            continue
        events = layer.get("events") or []
        if not events:
            continue
        tally["layers considered"] += 1

        meta = layer.get("metadata") or {}
        idx = build_index(layer_path, meta)
        if not idx:
            tally["no resolvable baseline — skipped"] += 1
            tally["events left unstamped"] += sum(1 for e in events if not e.get("fingerprint"))
            continue

        stamped = sum(1 for e in events if attach_identity(e, idx))
        tally["events already stamped"] += sum(1 for e in events if e.get("fingerprint")) - stamped
        if not stamped:
            tally["events left unstamped"] += sum(1 for e in events if not e.get("fingerprint"))
            continue
        tally["events stamped"] += stamped
        tally["events left unstamped"] += sum(1 for e in events if not e.get("fingerprint"))
        tally["layers touched"] += 1

        if not args.apply:
            continue

        # **Capture the on-disk state BEFORE stamping.** `stamp_merkle_metadata`
        # correctly drops the now-void signature when the root moves (D8), so a
        # `was_signed` read from the in-memory layer afterwards is always False in
        # exactly the case that matters — which made the guard below dead code on
        # its first attempt. The question is what the FILE carried on entry.
        original = layer_path.read_bytes()
        try:
            was_signed = bool(
                (json.loads(original).get("metadata") or {}).get("merkle_root_signature")
            )
        except json.JSONDecodeError:
            was_signed = False

        def _restore(reason: str, detail: str, _lp=layer_path, _orig=original) -> None:
            _lp.write_bytes(_orig)
            tally[reason] += 1
            problems.append(f"{_lp.name}: {detail}")

        svc = engine.ledger.service(data_dir=layer_path.parent)
        svc.store_layer(layer_path, layer)
        try:
            svc.sign(layer_path)
        except LedgerError as exc:
            _restore("sign failed — NOT written", str(exc))
            continue

        fresh = engine.ledger.service(data_dir=layer_path.parent).read_layer_file(layer_path)
        # **Assert the signature EXISTS, not merely that none failed to verify.**
        # `verify_merkle_signature` reports nothing on an unsigned layer — there is
        # no signature to fail — so a pubkey check alone calls an unsigned layer
        # clean. That is precisely how the 112 went unnoticed. A layer that
        # arrived signed must leave signed.
        if was_signed and not (fresh.get("metadata") or {}).get("merkle_root_signature"):
            _restore(
                "signature LOST during re-sign — NOT written",
                "layer was signed on entry and is unsigned after sign(); "
                "is LAAS_SIGNING_KEY_PATH readable and COSIGN_PASSWORD set?",
            )
            continue
        if args.pubkey:
            bad = [
                f
                for f in verify_merkle_signature(fresh, str(args.pubkey))
                if f.severity.name == "ERROR"
            ]
            if bad:
                _restore("fresh signature failed to verify — NOT written", bad[0].message[:90])
                continue
        tally["layers written"] += 1
        if tally["layers written"] % 250 == 0:
            rate = tally["layers written"] / max(time.monotonic() - started, 1e-9)
            print(f"  … {tally['layers written']} written ({rate:.1f}/s)", flush=True)

    print(
        f"{'APPLY' if args.apply else 'DRY RUN'} · {len(layers):,} layer files · "
        f"{time.monotonic() - started:.0f}s"
    )
    for k, v in tally.most_common():
        print(f"  {k:44} {v:,}")
    for p in problems[:20]:
        print(f"    ! {p}")
    if len(problems) > 20:
        print(f"    … {len(problems) - 20} more")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
