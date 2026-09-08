#!/usr/bin/env python3
# Migration utility written 2026-08-18
"""Re-sign every layer under signature format 3 (plan §4.4.0a).

Format 2 signed the Merkle root, its interpretation and a digest of
`claim_hashes` — but not `audit_report_sha256`. So the field recording *which
bytes a layer annotates* sat outside the signature, and anyone able to write the
layer could repoint it at a substituted report by rewriting the digest to match.
Format 3 binds it. Every existing signature has to be re-made to gain that.

The corpus is NOT invalidated meanwhile: verification reconstructs the payload for
whichever format a layer records, and format 2 verifies without complaint until its
layer is re-signed. This pass is an upgrade, not a repair.

Requires the signing key: `LAAS_SIGNING_KEY_PATH` and `COSIGN_PASSWORD`, read
once at start (so a 30-minute Vault token expiring mid-run is harmless — the key
file is already on disk).

Safety properties:

- **DRY-RUN BY DEFAULT.** Nothing is written without `--apply`.
- **Idempotent and resumable.** A layer already at format 3 is skipped, so an
  interrupted run is resumed by re-running it.
- **Verifies each signature before writing.** A layer whose fresh signature does
  not verify against the public half is reported and left untouched, never written
  half-signed.
- **Skips unsigned layers** unless `--sign-unsigned`. This upgrades existing
  signatures; signing a layer for the first time is P8's write-path question.
- **Does not trust the recorded format number.** With `--pubkey` a layer already at
  format 3 is *verified* before being skipped, and re-signed if the signature does not
  verify. Trusting the number is what let a layer through whose digest was backfilled
  after signing: format 3 covers `audit_report_sha256`, so adding one invalidates the
  signature without moving the root (measured 2026-08-20).
- **Refuses to sign a stale root.** If the layer's recorded root does not match its
  events, it is reported and skipped — re-stamping is `build_cumulative`'s job, and
  silently fixing it here would sign over a discrepancy someone should see.

    python3 -m traust.migrations.resign_layers_format3 <results-root> [--apply] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from traust_engine.ledger import (
    LedgerError,
    verify_merkle_integrity,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.paths import optional_config_path

SIGNATURE_FORMAT_CURRENT = 4


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    ap.add_argument("--limit", type=int, default=None, help="stop after N layers")
    ap.add_argument(
        "--sign-unsigned",
        action="store_true",
        help="also sign layers that were never signed (default: skip — "
        "this migration upgrades signatures; signing a layer for the "
        "first time is the write-path question, P8)",
    )
    ap.add_argument(
        "--pubkey", type=Path, default=None, help="public half, for verifying each fresh signature"
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()
    pubkey = args.pubkey or optional_config_path("ledger-signing-key.pub")

    # signing_env resolves LAAS_SIGNING_KEY_PATH first, then the legacy
    # HARNESS_SIGNING_KEY_PATH. Checking one name directly is how this gate would
    # refuse an operator who exported the canonical one.
    if args.apply and not (
        os.environ.get("LAAS_SIGNING_KEY_PATH") or os.environ.get("HARNESS_SIGNING_KEY_PATH")
    ):
        print(
            "ERROR: LAAS_SIGNING_KEY_PATH is unset — read the ledger signing "
            "key from your secret store into a 0700 dir and point this at it, "
            "with COSIGN_PASSWORD from the same secret. See "
            "docs/signing.md for where the key lives.",
            file=sys.stderr,
        )
        return 2

    tally: Counter[str] = Counter()
    problems: list[str] = []
    seen: set[str] = set()
    started = time.monotonic()

    for layer_path in sorted(results_root.rglob("*-findings-layer.json")):
        real = str(layer_path.resolve())
        if real in seen:  # gap-plan symlinks
            continue
        seen.add(real)
        if args.limit and tally["considered"] >= args.limit:
            break
        tally["considered"] += 1
        try:
            layer = json.loads(layer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable"] += 1
            continue
        meta = layer.get("metadata") or {}
        if not meta.get("merkle_root_signature"):
            if not args.sign_unsigned:
                tally["unsigned — skipped"] += 1
                continue
            tally["unsigned — signing (opt-in)"] += 1
        elif int(meta.get("merkle_signature_format", 1)) >= SIGNATURE_FORMAT_CURRENT:
            # Trusting the format NUMBER is what let a broken layer through: a
            # digest backfilled onto a format-3 layer invalidates the signature
            # without moving the root, so the layer still claims 3 while failing
            # verification, and this branch skipped it forever (measured
            # 2026-08-20, feast__release-rhoai-2.25). Verify before believing it.
            if args.pubkey:
                if not verify_merkle_signature(layer, str(pubkey)):
                    tally["already format 3 — verified"] += 1
                    continue
                tally["format 3 but signature INVALID — re-signing"] += 1
            else:
                tally["already format 3 — unverified (no --pubkey)"] += 1
                continue
        if [f for f in verify_merkle_integrity(layer) if f.severity.name == "ERROR"]:
            tally["stale root — skipped"] += 1
            problems.append(f"{layer_path.name}: merkle integrity ERROR, not re-signed")
            continue

        tally["to re-sign"] += 1
        if not args.apply:
            continue

        svc = engine.ledger.service(data_dir=layer_path.parent)
        svc.store_layer(layer_path, layer)
        try:
            svc.sign(layer_path)
        except LedgerError as exc:
            tally["sign failed"] += 1
            problems.append(f"{layer_path.name}: {exc}")
            continue
        layer = engine.ledger.service(data_dir=layer_path.parent).read_layer_file(layer_path)
        bad = [f for f in verify_merkle_signature(layer, str(pubkey)) if f.severity.name == "ERROR"]
        if bad:
            tally["fresh signature failed to verify — NOT written"] += 1
            problems.append(f"{layer_path.name}: {bad[0].message[:90]}")
            continue
        tally["re-signed"] += 1
        if tally["re-signed"] % 250 == 0:
            rate = tally["re-signed"] / max(time.monotonic() - started, 1e-9)
            print(f"  … {tally['re-signed']} re-signed ({rate:.1f}/s)", flush=True)

    print(
        f"{'APPLY' if args.apply else 'DRY RUN'} · {tally['considered']} layers · "
        f"{time.monotonic() - started:.0f}s"
    )
    for k, v in tally.most_common():
        if k != "considered":
            print(f"  {k:38} {v}")
    for p in problems[:10]:
        print(f"  ! {p}")
    if len(problems) > 10:
        print(f"  ! … and {len(problems) - 10} more")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
