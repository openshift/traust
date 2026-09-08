#!/usr/bin/env python3
"""Create the ledger for audits that have none (drift row ledger:audits-without-a-layer).

A findings-layer is where a disposition is written. **116 security audits have no layer
beside them**, so their **873 findings cannot be confirmed, refuted or resolved** — they
are invisible to triage, to the SLA view and to every metric that counts adjudicated
work. Measured 2026-08-21; all 116 are dated June/July, so the producer path was fixed
in August and nobody swept the residue. Nothing reported it because until 0.313.0 no
check asserted the invariant.

Only `*-security-audit.json` gets a layer. A layer records dispositions on findings, so
an artifact that asserts no findings needs none — threat models, privilege profiles,
patch diffs, fuzz corpora and per-CVE evidence are correctly ledger-free.

The layer is created **empty of events** and that is the point: it establishes the
place a disposition can be written, and pins what the findings currently claim
(`claim_hashes`) and which report bytes they came from (`audit_report_sha256`), both
inside the signed payload. It asserts nothing about the findings themselves.

    python3 -m traust.migrations.create_missing_layers <root> \
        [--apply] [--pubkey PATH]
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
    compute_claim_hash,
    stamp_report_reference,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
SPECIAL = {"_manifest", "_index", "_orgs"}


def _fill_claims(layer_path: Path, report_path: Path, args, tally, problems, engine) -> None:
    """Add claim_hashes for findings the layer does not yet cover. Never overwrites an
    existing hash: a changed claim is a signal, and silently re-hashing would erase it.
    """
    try:
        layer = json.loads(layer_path.read_text(encoding="utf-8"))
        findings = json.loads(report_path.read_text(encoding="utf-8")).get("findings") or []
    except (OSError, json.JSONDecodeError):
        return
    meta = layer.setdefault("metadata", {})
    ch = meta.setdefault("claim_hashes", {})
    added = 0
    for f in findings:
        fid = f.get("id")
        if fid and fid not in ch:
            ch[fid] = compute_claim_hash(f)
            added += 1
    if not added:
        return
    tally["claim hashes added"] += added
    tally["layers gaining claim hashes"] += 1
    if not args.apply:
        return
    svc = engine.ledger.service(data_dir=layer_path.parent)
    svc.store_layer(layer_path, layer)
    try:
        svc.sign(layer_path)
    except LedgerError as exc:
        tally["claims: sign failed — NOT written"] += 1
        problems.append(f"{layer_path.name}: {exc}")
        return
    if args.pubkey:
        layer = engine.ledger.service(data_dir=layer_path.parent).read_layer_file(layer_path)
        if [
            x
            for x in verify_merkle_signature(layer, str(args.pubkey))
            if x.severity.name == "ERROR"
        ]:
            tally["claims: fresh signature failed — NOT written"] += 1
            return
    tally["layers re-signed for claims"] += 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--pubkey", type=Path, default=None)
    ap.add_argument(
        "--fill-claims",
        action="store_true",
        help="also backfill claim_hashes on layers that already exist but "
        "record none, or cover only some of their report's findings. "
        "claim_hashes is the baseline's tamper-evidence and sits "
        "inside the signed payload, so a layer missing it cannot "
        "detect a finding's claim being edited.",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()

    tally: Counter[str] = Counter()
    problems: list[str] = []
    started = time.monotonic()

    for dirpath, _dirnames, filenames in os.walk(results_root):
        parts = list(Path(dirpath).relative_to(results_root).parts)
        if set(parts) & STATE_DIRS or (parts and parts[0] in SPECIAL):
            continue
        present = set(filenames)
        for fname in sorted(f for f in filenames if f.endswith("-security-audit.json")):
            base_ = fname[: -len("-security-audit.json")]
            if f"{base_}-findings-layer.json" in present:
                if args.fill_claims:
                    _fill_claims(
                        Path(dirpath) / f"{base_}-findings-layer.json",
                        Path(dirpath) / fname,
                        args,
                        tally,
                        problems,
                        engine,
                    )
                continue
            report_path = Path(dirpath) / fname
            base = fname[: -len("-security-audit.json")]
            layer_path = Path(dirpath) / f"{base}-findings-layer.json"
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                tally["unreadable report"] += 1
                continue
            rmeta = report.get("metadata") or {}
            findings = report.get("findings") or []
            tally["audits without a layer"] += 1
            tally["findings gaining a ledger"] += len(findings)
            if not args.apply:
                continue

            layer = {
                "metadata": {
                    "audit_report": fname,
                    "repository": rmeta.get("repository"),
                    "created": rmeta.get("date") or rmeta.get("generated"),
                    "harness_version": rmeta.get("harness_version"),
                    "audit_commit": rmeta.get("commit"),
                    # What each finding currently claims. Pinning it here is the whole
                    # tamper-evidence story for a baseline; it is inside the signature.
                    "claim_hashes": {
                        f["id"]: compute_claim_hash(f) for f in findings if f.get("id")
                    },
                },
                "events": [],
            }
            layer["metadata"] = {k: v for k, v in layer["metadata"].items() if v is not None}
            stamp_report_reference(layer, report_path)
            svc = engine.ledger.service(data_dir=layer_path.parent)
            svc.store_layer(layer_path, layer)
            try:
                svc.sign(layer_path)
            except LedgerError as exc:
                tally["sign failed — NOT written"] += 1
                problems.append(f"{layer_path.name}: {exc}")
                continue
            if args.pubkey:
                svc = engine.ledger.service(data_dir=layer_path.parent)
                layer = svc.read_layer_file(layer_path)
                if [
                    x
                    for x in verify_merkle_signature(layer, str(args.pubkey))
                    if x.severity.name == "ERROR"
                ]:
                    tally["fresh signature failed to verify — NOT written"] += 1
                    continue
            tally["layers created"] += 1

    print(f"{'APPLY' if args.apply else 'DRY RUN'} · {time.monotonic() - started:.0f}s")
    for k, v in tally.most_common():
        print(f"  {k:44} {v:,}")
    for p in problems[:10]:
        print(f"    ! {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
