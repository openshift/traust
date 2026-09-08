#!/usr/bin/env python3
"""Baseline claim hashes — tamper-evidence for *-security-audit.json reports.

The disposition ledger is append-only and hash-chained, but the audit report
it annotates was historically protected only by convention ("never hand-edit
validation_status") and git history. This tool closes that gap: it records a
sha256 of each finding's canonical claim fields (id, title, severity, cwes,
locations, description, remediation — validation_status deliberately excluded)
into the layer's `metadata.claim_hashes`, and verifies the audit report
against them. `validate_report.py` re-verifies on every layer validation and
`build_cumulative.py` refuses to rebuild the cumulative report from a
tampered baseline.

Rules:
  - `record` only ADDS hashes for findings not yet baselined (sanctioned
    appends — create-fuzzing / vuln-scan follow-ups, validate-findings
    novel findings, verify-remediation routed regressions — get pinned on
    the next track-findings run). It never overwrites an existing hash,
    except for findings explicitly named with --rebaseline whose
    validation_status is 'corrected' (the sanctioned in-place revision path).
  - `verify` exits 1 on any mismatch or baselined-finding deletion;
    'corrected' drift is a warning with a --rebaseline hint.

Usage:
    python3 harnessing/4-triage/track-findings/scripts/baseline_claims.py \
        record <audit.json> <layer.json> [--rebaseline ID ...]
    python3 harnessing/4-triage/track-findings/scripts/baseline_claims.py \
        verify <audit.json> <layer.json>
    python3 harnessing/4-triage/track-findings/scripts/baseline_claims.py sweep <findings-root>

`sweep` walks a findings tree, and for every canonical (non-symlink)
`*-security-audit.json` creates a minimal disposition layer if none exists
(track-findings Phase 1 shape) and pins all claim hashes. Idempotent:
re-running only adds hashes for newly appended findings.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine import HarnessEngine
from traust_engine.assets import harness_version as _engine_harness_version
from traust_engine.reporting.validate import compute_claim_hash

from traust.context import add_config_home_arg, load_engine


def _load(path: Path, what: str) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"error: cannot read {what} at {path}: {e}")


def _record_into(audit: dict, layer: dict, rebaseline: set[str]):
    """Shared add-only recording core. Mutates layer; returns
    (added_ids, rebaselined_ids, refused_[(id, why)])."""
    findings = {f.get("id"): f for f in audit.get("findings", [])}
    hashes = layer.setdefault("metadata", {}).setdefault("claim_hashes", {})
    added, rebaselined, refused = [], [], []
    for fid, f in findings.items():
        current = compute_claim_hash(f)
        recorded = hashes.get(fid)
        if recorded is None:
            hashes[fid] = current
            added.append(fid)
        elif recorded != current:
            if fid in rebaseline:
                if f.get("validation_status") != "corrected":
                    refused.append((fid, "not marked 'corrected'"))
                else:
                    hashes[fid] = current
                    rebaselined.append(fid)
            else:
                refused.append((fid, "hash mismatch without --rebaseline"))
    for fid in sorted(rebaseline - set(findings)):
        refused.append((fid, "--rebaseline id not in the audit report"))
    return added, rebaselined, refused


def record(
    audit_path: Path, layer_path: Path, rebaseline: set[str], engine: HarnessEngine | None = None
) -> int:
    audit = _load(audit_path, "audit report")
    layer = _load(layer_path, "layer")
    added, rebaselined, refused = _record_into(audit, layer, rebaseline)
    hashes = layer["metadata"]["claim_hashes"]

    if refused:
        for fid, why in refused:
            print(f"REFUSED {fid}: {why}", file=sys.stderr)
        print(
            "record aborted — the layer was NOT modified. In-place edits to "
            "baselined claims require validation_status 'corrected' plus an "
            "explicit --rebaseline; everything else flows through the ledger.",
            file=sys.stderr,
        )
        return 1

    ledger = (engine or load_engine()).ledger.service(data_dir=layer_path.parent)

    if added or rebaselined:
        ledger.patch_layer_file(layer_path, {"claim_hashes": hashes}, sign=False)

    digest_changed = ledger.stamp_report_file(layer_path, audit_path, sign=False)
    print(
        f"baselined {len(added)} new finding(s), re-baselined "
        f"{len(rebaselined)}, {len(hashes)} total pinned "
        f"({', '.join(sorted(added)[:5])}{'…' if len(added) > 5 else ''})"
        if added or rebaselined
        else f"nothing to do — all {len(hashes)} baselined finding(s) unchanged"
    )
    if digest_changed:
        print("recorded metadata.audit_report_sha256 for the current report bytes")
    return 0


def verify(audit_path: Path, layer_path: Path) -> int:
    audit = _load(audit_path, "audit report")
    layer = _load(layer_path, "layer")
    findings = {f.get("id"): f for f in audit.get("findings", [])}
    hashes = (layer.get("metadata") or {}).get("claim_hashes") or {}
    if not hashes:
        print("no claim_hashes recorded in the layer — run 'record' first")
        return 0

    errors = warnings = 0
    for fid, recorded in sorted(hashes.items()):
        f = findings.get(fid)
        if f is None:
            print(
                f"ERROR {fid}: baselined finding missing from the audit "
                f"report (deleted or re-id'd)",
                file=sys.stderr,
            )
            errors += 1
        elif compute_claim_hash(f) != recorded:
            if f.get("validation_status") == "corrected":
                print(
                    f"WARN  {fid}: claim drifted but finding is 'corrected' "
                    f"— re-baseline with: record --rebaseline {fid}"
                )
                warnings += 1
            else:
                print(
                    f"ERROR {fid}: claim hash mismatch — edited in place "
                    f"without a 'corrected' revision",
                    file=sys.stderr,
                )
                errors += 1
    unbaselined = sorted(set(findings) - set(hashes))
    if unbaselined:
        print(
            f"WARN  {len(unbaselined)} finding(s) not yet baselined "
            f"(new appends?): {', '.join(unbaselined[:5])}" + ("…" if len(unbaselined) > 5 else "")
        )
        warnings += 1

    ok = len(hashes) - errors
    print(
        f"verified {ok}/{len(hashes)} baselined claim(s), {errors} error(s), {warnings} warning(s)"
    )
    return 1 if errors else 0


_HEX_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


def _harness_version() -> str:
    return _engine_harness_version()


def _minimal_layer(audit: dict, audit_name: str, harness_version: str) -> dict:
    """track-findings Phase 1 initialization shape."""
    ameta = audit.get("metadata") or {}
    now = datetime.now(UTC).isoformat(timespec="seconds")
    meta = {
        "audit_report": audit_name,
        "repository": (
            ameta.get("repository")
            if isinstance(ameta.get("repository"), str)
            and ameta.get("repository", "").startswith("http")
            else f"unknown://{audit_name.removesuffix('-security-audit.json')}"
        ),
        "created": now,
        "harness_version": harness_version,
    }
    commit = str(ameta.get("commit") or "")
    if _HEX_COMMIT.match(commit):
        meta["audit_commit"] = commit
    return {"metadata": meta, "events": [], "needs_review": []}


def sweep(root: Path, engine: HarnessEngine | None = None) -> int:
    """Create-and-pin across a findings tree. Canonical reports only
    (symlinked duplicates share their canonical's ledger)."""
    if not root.is_dir():
        sys.exit(f"error: {root} is not a directory")
    harness_version = _harness_version()
    seen = created = updated = unchanged = 0
    failures: list[str] = []
    refused_total: list[str] = []

    for audit_path in sorted(root.rglob("*-security-audit.json")):
        if audit_path.is_symlink():
            continue
        seen += 1
        try:
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            failures.append(f"{audit_path}: unreadable ({e})")
            continue
        layer_path = audit_path.with_name(
            audit_path.name.removesuffix("-security-audit.json") + "-findings-layer.json"
        )
        try:
            ledger = (engine or load_engine()).ledger.service(data_dir=layer_path.parent)
            is_new = not layer_path.exists()
            shell = _minimal_layer(audit, audit_path.name, harness_version)
            layer = ledger.ensure_layer_file(layer_path, shell=shell)
            added, _, refused = _record_into(audit, layer, set())
            if refused:
                refused_total.extend(
                    f"{audit_path.parent.name}/{fid}: {why}" for fid, why in refused
                )
                continue
            if is_new or added:
                hashes = layer["metadata"].get("claim_hashes") or {}
                if hashes:
                    ledger.patch_layer_file(layer_path, {"claim_hashes": hashes}, sign=False)
                created += is_new
                updated += not is_new
            else:
                unchanged += 1
        except OSError as e:
            failures.append(f"{layer_path}: {e}")

    print(
        f"sweep: {seen} canonical audit report(s) — "
        f"{created} layer(s) created, {updated} existing layer(s) pinned, "
        f"{unchanged} already current, {len(failures)} unreadable, "
        f"{len(refused_total)} refused"
    )
    for f in failures[:10]:
        print(f"  unreadable: {f}", file=sys.stderr)
    if len(failures) > 10:
        print(f"  … and {len(failures) - 10} more", file=sys.stderr)
    for r in refused_total[:10]:
        print(f"  REFUSED {r}", file=sys.stderr)
    return 1 if refused_total else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Record/verify tamper-evidence claim hashes for an audit "
        "report in its disposition layer."
    )
    add_config_home_arg(ap)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("record", "verify"):
        sp = sub.add_parser(name)
        sp.add_argument("audit", help="Path to the *-security-audit.json")
        sp.add_argument("layer", help="Path to the *-findings-layer.json")
        if name == "record":
            sp.add_argument(
                "--rebaseline",
                action="append",
                default=[],
                metavar="ID",
                help="Finding id whose 'corrected' revision may "
                "overwrite its recorded hash (repeatable).",
            )
    sp = sub.add_parser("sweep")
    sp.add_argument("root", help="Findings tree to walk (e.g. analysis-results/findings)")
    args = ap.parse_args(argv)
    engine = load_engine(args.config_home)
    if args.cmd == "sweep":
        return sweep(Path(args.root), engine=engine)
    audit, layer = Path(args.audit), Path(args.layer)
    if args.cmd == "record":
        return record(audit, layer, set(args.rebaseline), engine=engine)
    return verify(audit, layer)


if __name__ == "__main__":
    sys.exit(main())
