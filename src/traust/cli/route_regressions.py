#!/usr/bin/env python3
"""Route verify-remediation Phase-5 regressions into the findings ledger.

A `*-remediation-verification.json` report's `regressions[]` are
audit-grade new findings (same evidence standards as secure-code-audit),
but their `{SLUG}-{sha7}-REG-{NNN}` IDs fail the campaign finding-ID
convention and — before harness 0.196.0 — routed nowhere: no baseline
entry, no ledger event, no cumulative visibility. Per the user directive
of 2026-07-27, regressions become first-class ledger findings DIRECTLY,
with no /triage precondition — parity with the full scanning skills,
whose findings enter reports/ledger at birth with
`validation_status: not_verified` while triage adjudicates downstream.

For each regression this tool:

  1. Mints a campaign-compliant finding ID at the patched sha —
     `{REPO_SLUG}-{PATCHED_SHA7}-{NNN}`, numbering continuing where the
     baseline's existing findings at that sha leave off (001 for a new
     sha; IDs are sha-scoped so collisions cannot occur).
  2. Appends the transcribed finding to the repo's baseline
     `*-security-audit.json` (the same sanctioned-append flow as
     /vuln-scan and /create-fuzzing follow-ups), with
     `validation_status: not_verified`, `origin: "verify-remediation"`,
     the REG id + verification report in `source_findings`, and a
     script-computed fingerprint (traust_engine.ledger). The
     report's findings_summary and executive_summary counts are kept
     consistent (validator-enforced).
  3. Pins the new finding's claim hash into the disposition layer
     (add-only, never overwriting — baseline_claims semantics).
  4. Appends one ledger birth event per routed finding: source type
     `verification_report`, machine actor `verify-remediation`,
     `disposition: {resolution: "open"}` (validity stays the
     `not_verified` default — an event never sets it), the verification
     report as evidence_ref. Idempotent via the canonical event_id.
  5. Writes `routed_id` back onto the verification report's regression
     entry (provenance both ways), and rebuilds the cumulative
     `*-findings-current.{json,md}` via build_cumulative.py.

Re-running on the same report is a no-op: already-routed regressions are
detected via `routed_id` / `source_findings` back-references and via the
deterministic event_id.

This tool routes and records; it never authors a verdict — the routed
findings await triage/validation adjudication like any other claimed
finding (docs/findings-routing.md).

Usage (from the workspace root):
    python3 traust/scripts/route_regressions.py \
        <path>/<repo>-remediation-verification.json \
        [--audit <audit.json>] [--layer <layer.json>] \
        [--recorded-at ISO8601] [--no-rebuild] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.ledger import (
    LedgerService,
    compute_claim_hash,
    compute_event_id,
    findings_from_events,
    fingerprint,
)

from traust.context import add_config_home_arg, load_engine
from traust.lib.event_time import recorded_at_arg, report_occurred_at
from traust.paths import HARNESS_ROOT

VERIFICATION_SUFFIX = "-remediation-verification.json"
REG_ID_RE = re.compile(r"^([A-Z][A-Z0-9_]{0,23})-([a-f0-9]{7})-REG-(\d{3})$")
CAMPAIGN_ID_RE = re.compile(r"^([A-Z][A-Z0-9_]{0,23})-([a-f0-9]{7})-(\d{3})$")

# Finding claim fields transcribed verbatim from the regression entry
# (regression shape is a subset of report.schema.json#/$defs/finding).
_TRANSCRIBE_OPTIONAL = ("cvss", "evidence", "attack_pattern", "category")


def harness_version() -> str:
    try:
        return (HARNESS_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"


def _load(path: Path, what: str) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"error: cannot read {what} at {path}: {e}")


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def stable_ref(path: Path) -> str:
    """Deterministic source.ref for ledger events: path relative to the
    parent of the git repo that contains it (matching the existing
    verification-event convention, e.g.
    'analysis-results/<product>/<repo>/<repo>-remediation-verification.json');
    falls back to the basename when no repo root is found."""
    p = path.resolve()
    for anc in p.parents:
        if (anc / ".git").exists():
            return p.relative_to(anc.parent).as_posix()
    return p.name


def next_sequence(audit: dict, slug: str, sha7: str, layer: dict | None = None) -> int:
    """First free NNN for campaign IDs at (slug, sha7).

    Scans the baseline AND, when a layer is supplied, its event-carried
    findings (plan B2). Since non-audit producers no longer append to the
    baseline (gate A15), ids they minted live only on events — so ignoring the
    layer would re-issue the same NNN on the next run and collide.
    """
    top = 0
    ids = [f.get("id") for f in audit.get("findings", [])]
    if layer is not None:
        ids += list(findings_from_events(layer.get("events")))
    for fid in ids:
        m = CAMPAIGN_ID_RE.match(str(fid or ""))
        if m and m.group(1) == slug and m.group(2) == sha7:
            top = max(top, int(m.group(3)))
    return top + 1


def transcribe(reg: dict, new_id: str, repo_url: str | None, verification_ref: str) -> dict:
    """Regression entry -> report.schema.json finding (sanctioned append)."""
    finding = {
        "id": new_id,
        "title": reg["title"],
        "severity": reg["severity"],
        "cwes": list(reg["cwes"]),
        "locations": [dict(loc) for loc in reg["locations"]],
        "description": reg["description"],
        "remediation": reg["remediation"],
    }
    for key in _TRANSCRIBE_OPTIONAL:
        if reg.get(key) is not None:
            finding[key] = reg[key]
    finding["validation_status"] = "not_verified"
    finding["origin"] = "verify-remediation"
    # Provenance both ways: the REG id lives here; routed_id lives on the
    # verification report's regression entry.
    finding["source_findings"] = [reg["id"], verification_ref]
    finding["fingerprint"] = fingerprint(finding, repo_url)
    return finding


def update_summaries(audit: dict, finding: dict) -> None:
    """Keep findings_summary / executive_summary.severity_counts
    consistent with the appended finding (validator cross-checks 3/4/6)."""
    sev = finding["severity"]
    for entry in audit.get("findings_summary", []):
        if entry.get("severity") == sev:
            entry["count"] = int(entry.get("count", 0)) + 1
            entry.setdefault("finding_ids", []).append(finding["id"])
            break
    else:
        audit.setdefault("findings_summary", []).append(
            {"severity": sev, "count": 1, "finding_ids": [finding["id"]]}
        )
    counts = (audit.get("executive_summary") or {}).get("severity_counts")
    if isinstance(counts, dict):
        counts[sev] = int(counts.get(sev, 0)) + 1


def build_event(
    new_id: str,
    reg: dict,
    source_ref: str,
    patched7: str,
    occurred_at: str,
    recorded_at: str,
    hv: str,
) -> dict:
    rationale = (
        f"Phase-5 regression {reg['id']} ({reg['severity']}) routed as new "
        f"campaign finding {new_id} at patched commit {patched7} "
        f"(introduced by {reg.get('introduced_by', 'unknown')}). Enters the "
        f"ledger at validation_status: not_verified with resolution open — "
        f"no triage precondition; triage/validation adjudicate downstream "
        f"(user directive 2026-07-27)."
    )
    return {
        "event_id": compute_event_id(source_ref, new_id, None, "open"),
        "finding_ref": new_id,
        "recorded_at": recorded_at,
        "occurred_at": occurred_at,
        "source": {
            "type": "verification_report",
            "ref": source_ref,
            "actor": {"kind": "machine", "identity": "verify-remediation"},
        },
        "disposition": {"resolution": "open"},
        "rationale": rationale,
        "evidence_refs": [source_ref],
        "harness_version": hv,
    }


def route(
    verification_path: Path,
    audit_path: Path,
    layer_path: Path,
    recorded_at: str | None,
    dry_run: bool,
    *,
    engine=None,
) -> dict:
    verification = _load(verification_path, "verification report")
    regressions = verification.get("regressions") or []
    if not regressions:
        return {"routed": [], "skipped": [], "regressions": 0}

    audit = _load(audit_path, "baseline audit report")
    meta = verification.get("metadata") or {}
    patched7 = str(meta.get("patched_commit", ""))[:7]
    if not re.match(r"^[0-9a-f]{7}$", patched7):
        sys.exit(f"error: metadata.patched_commit missing/malformed in {verification_path}")
    repo_url = (audit.get("metadata") or {}).get("repository") or meta.get("repository")
    hv = harness_version()
    now = recorded_at or datetime.now(UTC).isoformat(timespec="seconds")
    occurred_at = report_occurred_at(meta.get("date"), now)

    shell = {
        "metadata": {
            "audit_report": audit_path.name,
            "repository": str(repo_url or "https://unknown.invalid/"),
            "created": now,
            "harness_version": hv,
        },
        "events": [],
        "needs_review": [],
    }
    commit = str((audit.get("metadata") or {}).get("commit") or "")
    if re.match(r"^[0-9a-f]{7,40}$", commit):
        shell["metadata"]["audit_commit"] = commit
    ledger = (
        engine.ledger.service(data_dir=layer_path.parent)
        if engine is not None
        else LedgerService(data_dir=layer_path.parent)
    )
    layer = ledger.ensure_layer_file(layer_path, shell=shell)

    source_ref = stable_ref(verification_path)
    verification_rel = os.path.relpath(verification_path.resolve(), audit_path.resolve().parent)

    # B4 — the baseline and the layer's event-carried findings are BOTH
    # searched. This router no longer appends to the baseline (gate A15), so
    # its own prior routes live only on events; scanning the baseline alone
    # would re-route every regression on the next run.
    event_carried = findings_from_events(layer.get("events"))
    findings_by_id = {f.get("id"): f for f in audit.get("findings", [])}
    findings_by_id.update(event_carried)
    already_routed = {}  # REG id -> existing campaign finding id
    for f in list(audit.get("findings", [])) + list(event_carried.values()):
        for src in f.get("source_findings") or []:
            if REG_ID_RE.match(str(src)):
                already_routed[src] = f["id"]

    existing_event_ids = {e.get("event_id") for e in layer["events"]}
    last_recorded = max((e.get("recorded_at", "") for e in layer["events"]), default="")
    stamp = max(now, last_recorded)

    routed, skipped, new_events = [], [], []
    for reg in regressions:
        fresh_finding = None
        reg_id = reg.get("id", "")
        m = REG_ID_RE.match(reg_id)
        if not m:
            sys.exit(f"error: regression id '{reg_id}' does not match the canonical REG format")
        slug, sha7 = m.group(1), m.group(2)
        if sha7 != patched7:
            print(
                f"WARN: {reg_id}: sha segment differs from "
                f"metadata.patched_commit ({patched7}); keeping the id's "
                f"own sha for the routed finding",
                file=sys.stderr,
            )

        prior = already_routed.get(reg_id) or (
            reg.get("routed_id") if reg.get("routed_id") in findings_by_id else None
        )
        if prior:
            if reg.get("routed_id") != prior:
                reg["routed_id"] = prior  # heal the back-reference
            skipped.append({"regression": reg_id, "routed_id": prior, "reason": "already_routed"})
        else:
            new_id = f"{slug}-{sha7}-{next_sequence(audit, slug, sha7, layer):03d}"
            finding = transcribe(reg, new_id, repo_url, verification_rel)
            # Decision 2026-08-17: a regression stays a NEW finding at the
            # patched sha — the id records when it came back and against which
            # commit — but the link to the original is recorded explicitly
            # instead of left merely inferable. Fingerprint equality
            # (repo | sorted locations | primary CWE) is the deterministic test.
            # Resolution state is deliberately not consulted: a fingerprint
            # match is the same vulnerability either way, and the ledger already
            # records whether the original was resolved.
            for _prior in audit.get("findings", []):
                if (
                    _prior.get("fingerprint")
                    and _prior.get("fingerprint") == finding.get("fingerprint")
                    and _prior.get("id") != new_id
                ):
                    if _prior["id"] not in finding["source_findings"]:
                        finding["source_findings"].append(_prior["id"])
                    break
            # B4 — the claim rides on the event, NOT the baseline. This router
            # appended 664 findings into *-security-audit.json until
            # 2026-08-17, mutating the claim set with no event recording it.
            fresh_finding = finding
            findings_by_id[new_id] = finding
            reg["routed_id"] = new_id
            already_routed[reg_id] = new_id
            # Claim hash: add-only, never overwrite (baseline_claims rule).
            hashes = layer["metadata"].setdefault("claim_hashes", {})
            hashes.setdefault(new_id, compute_claim_hash(finding))
            routed.append({"regression": reg_id, "routed_id": new_id, "severity": reg["severity"]})

        # Birth event — emitted for fresh routes AND healed for prior
        # routes whose event is missing (deterministic event_id dedupes).
        event = build_event(
            already_routed[reg_id], reg, source_ref, patched7, occurred_at, stamp, hv
        )
        if fresh_finding is not None:
            # Only the birth event carries the claim; a healed event for a
            # prior route does not re-state it (the original event already has
            # it, and later events supersede — findings_from_events).
            event["finding"] = fresh_finding
        if event["event_id"] not in existing_event_ids:
            existing_event_ids.add(event["event_id"])
            new_events.append(event)
            # Append IN-LOOP, not after: next_sequence() reads event-carried
            # ids off the layer, so a second regression in the same run would
            # otherwise be minted the same NNN as the first. The baseline
            # append used to provide this accumulation.
            layer["events"].append(event)

    if not dry_run and (routed or new_events):
        pending_hashes = layer["metadata"].get("claim_hashes") or {}
        if pending_hashes:
            ledger.patch_layer_file(layer_path, {"claim_hashes": pending_hashes}, sign=False)
        ledger.submit_events(
            layer_path,
            new_events,
            report_path=audit_path,
        )
        _write(verification_path, verification)

    return {
        "routed": routed,
        "skipped": skipped,
        "events": len(new_events),
        "regressions": len(regressions),
    }


def rebuild_cumulative(audit_path: Path, layer_path: Path) -> int:
    return subprocess.call(
        [sys.executable, "-m", "traust.cli.build_cumulative", str(audit_path), str(layer_path)]
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("verification", type=Path, help=f"path to the *{VERIFICATION_SUFFIX} report")
    ap.add_argument(
        "--audit",
        type=Path,
        help="baseline *-security-audit.json (default: sibling "
        "derived from the verification filename)",
    )
    ap.add_argument(
        "--layer",
        type=Path,
        help="*-findings-layer.json ledger (default: sibling; created if absent)",
    )
    ap.add_argument(
        "--recorded-at",
        type=recorded_at_arg,
        help="override the ledger append timestamp (RFC 3339, for reproducible runs)",
    )
    ap.add_argument(
        "--no-rebuild",
        action="store_true",
        help="skip the cumulative rebuild (build_cumulative.py)",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    vpath = args.verification
    if not vpath.name.endswith(VERIFICATION_SUFFIX):
        sys.exit(f"error: expected a *{VERIFICATION_SUFFIX} file, got {vpath.name}")
    if not vpath.is_file():
        sys.exit(f"error: {vpath} not found")
    stem = vpath.name[: -len(VERIFICATION_SUFFIX)]
    audit_path = args.audit or vpath.parent / f"{stem}-security-audit.json"
    layer_path = args.layer or vpath.parent / f"{stem}-findings-layer.json"
    if not audit_path.is_file():
        sys.exit(f"error: baseline audit report {audit_path} not found (pass --audit)")

    engine = load_engine(args.config_home)
    result = route(vpath, audit_path, layer_path, args.recorded_at, args.dry_run, engine=engine)
    tag = " [dry-run]" if args.dry_run else ""
    if not result["regressions"]:
        print(f"{vpath.name}: no regressions to route{tag}")
        return 0
    for r in result["routed"]:
        print(f"routed {r['regression']} -> {r['routed_id']} ({r['severity']}){tag}")
    for s in result["skipped"]:
        print(f"skipped {s['regression']} -> {s['routed_id']} ({s['reason']}){tag}")
    print(
        f"{vpath.name}: {len(result['routed'])} routed, "
        f"{len(result['skipped'])} already routed, "
        f"{result['events']} ledger event(s) appended{tag}"
    )
    if not args.dry_run and not args.no_rebuild and (result["routed"] or result["events"]):
        return rebuild_cumulative(audit_path, layer_path)
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["route", "regressions", *sys.argv[1:]]))
