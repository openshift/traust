#!/usr/bin/env python3
"""Record every artifact's digest in its layer — plan R1.

**Why this is the gate on deleting reports from git.** `audit_report_sha256` binds the
ONE report each layer annotates: 8,109 of 54,126 artifacts, **15%**. Every sibling —
triage, threat model, findings-current, verification, privilege profile — has no digest
anywhere, so once git no longer holds the original there is nothing to check a copied
file against. That is fine for a copy and disqualifying for a deletion.

After this pass, an artifact can be fetched from object storage and proven to be the
bytes the ledger recorded, using a map that is inside the layer's signature under
format 4.

**This re-signs**, twice over: the map is signed, and writing it bumps the layer from
format 3 to 4. Needs a signing identity.

    python3 -m traust.migrations.backfill_artifact_digests <root> \
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
    stamp_artifact_digests,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}


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
        if args.limit and tally["layers written"] >= args.limit:
            break
        if STATE_DIRS.intersection(layer_path.relative_to(results_root).parts):
            continue
        try:
            layer = json.loads(layer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable"] += 1
            continue
        tally["layers considered"] += 1
        if not stamp_artifact_digests(layer, layer_path):
            tally["already current"] += 1
            continue
        n = len((layer.get("metadata") or {}).get("artifact_digests") or {})
        tally["artifacts newly covered"] += n
        tally["layers to update"] += 1
        if n == 0:
            tally["layer with no sibling artifacts"] += 1
        if not args.apply:
            continue

        # **Capture the on-disk state BEFORE stamping, and restore on failure.**
        # This migration is the highest-risk one to get wrong: populating
        # `artifact_digests` CHANGES the format-4 signed payload (verified — at
        # format 4 the payload differs with the map populated; at format 3 the
        # field is ignored), so every layer it touches *must* be re-signed. Its
        # sibling `backfill_event_fingerprints` had this identical shape — write
        # first, `continue` on failure with the file already on disk while the
        # tally said "NOT written" — and it silently unsigned 112 corpus layers on
        # 2026-08-31. Keeping the original bytes makes "NOT written" true.
        original = layer_path.read_bytes()
        try:
            prior_sig = (json.loads(original).get("metadata") or {}).get("merkle_root_signature")
        except json.JSONDecodeError:
            prior_sig = None
        was_signed = bool(prior_sig)

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
        # **Assert the signature EXISTS.** `verify_merkle_signature` reports nothing
        # on an unsigned layer — there is no signature to fail — so a pubkey check
        # alone calls an unsigned layer clean. A layer that arrived signed must
        # leave signed, or the digests it now carries are vouched for by nobody.
        fresh_sig = (fresh.get("metadata") or {}).get("merkle_root_signature")
        if was_signed and not fresh_sig:
            _restore(
                "signature LOST during re-sign — NOT written",
                "layer was signed on entry and is unsigned after sign(); "
                "is LAAS_SIGNING_KEY_PATH readable and COSIGN_PASSWORD set?",
            )
            continue
        # **An UNCHANGED signature is the real hazard here, not a missing one.**
        # `artifact_digests` lives in metadata, not events, so populating it does
        # not move the Merkle root — nothing drops the old signature, and `sign()`
        # without a key leaves it in place. But at format 4 the signed payload
        # covers a digest over that map, so the surviving signature no longer
        # verifies: present-but-invalid, which D8 calls indistinguishable from
        # tampering and which is strictly worse than unsigned. Since populating the
        # map always changes the payload, a re-sign MUST change the signature bytes.
        if was_signed and fresh_sig == prior_sig:
            _restore(
                "signature STALE — NOT written",
                "artifact_digests changed the format-4 signed payload but the "
                "signature is byte-identical, so it no longer verifies; "
                "is LAAS_SIGNING_KEY_PATH readable and COSIGN_PASSWORD set?",
            )
            continue
        if args.pubkey and [
            x
            for x in verify_merkle_signature(fresh, str(args.pubkey))
            if x.severity.name == "ERROR"
        ]:
            _restore(
                "fresh signature failed to verify — NOT written", "fresh signature failed to verify"
            )
            continue
        tally["layers written"] += 1
        if tally["layers written"] % 500 == 0:
            rate = tally["layers written"] / max(time.monotonic() - started, 1e-9)
            print(f"  … {tally['layers written']} written ({rate:.1f}/s)", flush=True)

    print(f"{'APPLY' if args.apply else 'DRY RUN'} · {time.monotonic() - started:.0f}s")
    for k, v in tally.most_common():
        print(f"  {k:44} {v:,}")
    for p in problems[:10]:
        print(f"    ! {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
