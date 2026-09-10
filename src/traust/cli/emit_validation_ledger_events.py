#!/usr/bin/env python3
"""
Emit track-findings disposition-ledger events from a *-validation.json
live-validation report (validate-findings engine output).

Deterministic transform, sibling of emit_triage_ledger_events.py.
Verdict -> ledger mapping (track-findings SKILL.md source table):

  confirmed        -> validity `confirmed` event. source.type is
                      validation_report, so the merge engine treats it as
                      class-1 execution-verified evidence — it outranks
                      every static determination.
  refuted          -> machine false_positive event. Execution evidence or
                      not, a dismissal still requires an LDAP-verified
                      human countersignature (asymmetric caution) — the
                      event pends as refuted_awaiting_signoff until
                      /countersign clears it. Every refutation is also
                      merge-appended into the repo's refuted register.
                      EXCEPTION — soundness gate: a refutation that is
                      unsound (soundness_flag stamped by the engine, or
                      retroactively detected: error-signature transcript,
                      zero-subject RBAC probe, install-failure.yaml
                      beside the report) queues an `unsound_refutation`
                      needs_review item instead — never an FP event,
                      never a register entry.
  inconclusive     -> nothing (nothing was proven or refuted); if it
                      carries a soundness_flag it queues the same
                      `unsound_refutation` needs_review item
  blocked_by_scope -> nothing
  not_attempted    -> nothing

One validation report covers one logical product and fans out across many
repos' audit reports. Each validated finding names its baseline via
`source_report` (an absolute path from the validation runner's machine)
and `source_id` (`<package>:<subpath>/<finding-id>`). Resolution to the
canonical audit in the local findings store:

  1. Suffix-localize the path on `analysis-results/` under --results-root;
     symlinked duplicates resolve (realpath) to their canonical, whose
     ledger they share.
  2. Otherwise (e.g. `progress-tracker/processed-results/...` mirror
     paths) match by content: the canonical audit with the same basename
     whose sha256 equals the local mirror copy's.
  3. Otherwise match by CLAIM: every same-basename canonical whose
     finding with the same id has an identical claim hash (the
     baseline_claims.py canonical fields). A claim-hash-identical finding
     IS the same claim, so when several alias product trees carry it
     (e.g. mce/ and multicluster-engine/), the event lands in EVERY
     replica's ledger — their dispositions stay in sync rather than one
     going stale. Refutations remain countersign-gated in each.

The finding id (the tail of `source_id`) must exist in the resolved
audit's findings, or the verdict is skipped with a warning.

Baseline staleness: the validation report records the sha256 of every
baseline it read (`source_reports[]`). When a DIRECTLY-resolved audit's
current content no longer matches, the event is still emitted (the proof
stands against the claim it tested — recorded in evidence_refs) but a
`stale_baseline` needs_review item is queued so a human confirms the
claim survived the baseline revision. Content- and claim-matched targets
are never stale by construction — the match itself proves the claim is
current.

Event ids use the layer schema's canonical sha256, so re-emitting the
same report is idempotent (existing events are never duplicated on
append). This tool routes and records; it never decides state — the
track-findings merge engine (evidence-class precedence, countersign
rules) does.

Usage (from the workspace root):
  python traust/scripts/emit_validation_ledger_events.py \\
      analysis-results/validations/<product>/<product>-validation.json \\
      [--results-root analysis-results]
      [--workspace-root .]              # for progress-tracker mirror paths
      [--recorded-at ISO8601]           # reproducible runs
      [--dry-run]                       # report, write nothing
      [--build-cumulative]              # rebuild findings-current per repo

Batch mode (the campaign backfill):
  python traust/scripts/emit_validation_ledger_events.py \\
      --manifest analysis-results/validations/_manifest/validation-manifest.csv \\
      [same options]
"""

import argparse
import csv
import hashlib

# Refutation-soundness gate — loaded by file path so the generically
# named sibling modules (plan, report, scope, …) never enter sys.path.
import importlib.util
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.ledger import (
    LedgerService,
    compute_claim_hash,  # canonical impl
    compute_event_id,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
    workspace_dir,
)
from traust.lib.event_time import recorded_at_arg, report_occurred_at
from traust.paths import skill_dir

_SOUNDNESS_PATH = skill_dir("validate-findings") / "soundness.py"
_spec = importlib.util.spec_from_file_location("vf_soundness", _SOUNDNESS_PATH)
soundness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(soundness)

RATIONALE_CAP = 500
EVENT_VERDICTS = ("confirmed", "refuted")
HARNESS_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(-[0-9a-f]{7,40})?")


def sanitize_harness_version(raw: str) -> str | None:
    """Layer events require `^\\d+\\.\\d+\\.\\d+(-sha)?$`, but some
    validation reports carry annotated versions (e.g.
    '0.6.4-37419f1+recompute' from recompute_verdicts.py). Keep the
    conforming prefix; the raw string stays in the actor identity."""
    m = HARNESS_VERSION_RE.match(str(raw or ""))
    return m.group(0) if m else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _localize(foreign: str, marker: str, root: Path) -> Path | None:
    """Map a foreign absolute path onto the local tree via a suffix marker."""
    i = foreign.find(marker)
    return root / foreign[i + len(marker) :] if i >= 0 else None


def _squash(text: str, cap: int = RATIONALE_CAP) -> str:
    return " ".join(str(text or "").split())[:cap]


class AuditResolver:
    """Resolve a validated finding's source_report to its canonical audit.

    Caches parsed audits and (lazily) a basename index of every canonical
    (non-symlink) *-security-audit.json under the results root.
    """

    def __init__(self, results_root: Path, workspace_root: Path):
        self.results_root = results_root
        self.workspace_root = workspace_root
        self._audits: dict[Path, dict] = {}
        self._by_basename: dict[str, list[Path]] | None = None

    def load_audit(self, path: Path) -> dict:
        if path not in self._audits:
            self._audits[path] = json.loads(path.read_text(encoding="utf-8"))
        return self._audits[path]

    def _basename_index(self) -> dict[str, list[Path]]:
        if self._by_basename is None:
            self._by_basename = {}
            # Container-image audits are ledger baselines too (their
            # validations reference *-container-audit.json baselines).
            for pattern in ("*-security-audit.json", "*-container-audit.json"):
                for p in self.results_root.rglob(pattern):
                    rel_parts = p.relative_to(self.results_root).parts
                    # Hidden dirs (.verify-tmp, .git) are scratch, never
                    # targets.
                    if not p.is_symlink() and not any(part.startswith(".") for part in rel_parts):
                        self._by_basename.setdefault(p.name, []).append(p)
        return self._by_basename

    def _finding(self, audit_path: Path, finding_id: str) -> dict | None:
        for f in self.load_audit(audit_path).get("findings", []):
            if f.get("id") == finding_id:
                return f
        return None

    def resolve(self, source_report: str, finding_id: str) -> tuple[list[Path], str]:
        """Return (canonical audit paths, note). Empty when unresolvable.

        Multiple paths only from a claim-hash match: alias trees carrying
        the byte-identical claim all receive the event.
        """
        # 1. Direct: the analysis-results suffix exists locally.
        local = _localize(source_report, "analysis-results/", self.results_root)
        if local is not None and local.exists():
            return [local.resolve()], "direct"

        # 2. Content match: a local mirror copy (e.g. progress-tracker's
        #    processed-results) identifies its canonical by sha256.
        candidates = self._basename_index().get(Path(source_report).name, [])
        mirror = _localize(
            source_report, "progress-tracker/", self.workspace_root / "progress-tracker"
        )
        if mirror is not None and mirror.exists():
            want = _sha256(mirror)
            hits = [c for c in candidates if _sha256(c) == want]
            if len(hits) == 1:
                return [hits[0].resolve()], "content-match"

            # 3. Claim match: the mirror IS the baseline that was tested;
            #    any canonical carrying the identical claim is the same
            #    claim and receives the event.
            claim = None
            try:
                mf = json.loads(mirror.read_text(encoding="utf-8"))
                claim = next((f for f in mf.get("findings", []) if f.get("id") == finding_id), None)
            except (OSError, json.JSONDecodeError):
                pass
            if claim is not None:
                want_claim = compute_claim_hash(claim)
                hits = [
                    c
                    for c in candidates
                    if (cf := self._finding(c, finding_id)) is not None
                    and compute_claim_hash(cf) == want_claim
                ]
                if hits:
                    return sorted(set(c.resolve() for c in hits)), "claim-match"
                return [], "claim not found in any canonical audit"
            return [], f"finding id absent from mirror baseline {mirror}"

        return [], (
            "no local mirror and no analysis-results suffix"
            if not candidates
            else "no local copy of the baseline"
        )


def _rationale(f: dict) -> str:
    verdict = f["verdict"]
    technique = f.get("technique") or "replay"
    if verdict == "confirmed":
        detail = _squash(
            f.get("observed_impact") or f.get("deviation_from_claim") or "see evidence artifacts",
            400,
        )
        return _squash(f"live validation ({technique}): confirmed — {detail}")
    detail = _squash(
        f.get("deviation_from_claim")
        or f.get("observed_impact")
        or "claim did not reproduce against the live target",
        400,
    )
    return _squash(f"live validation ({technique}): refuted — {detail}")


def _evidence_refs(f: dict, report_rel_dir: str, validated_sha: str | None) -> list[str]:
    refs = []
    for ev in f.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        path = ev.get("path")
        if path:
            ref = f"{report_rel_dir}/{path}"
            if ev.get("sha256"):
                ref += f"#sha256:{ev['sha256']}"
            refs.append(ref)
    if validated_sha:
        refs.append(f"validated-baseline-sha256:{validated_sha}")
    return refs


ATTESTATION_SINCE = (0, 176, 0)
CONTROLS_SINCE = (0, 177, 0)
DIFFERENTIAL_SINCE = (0, 178, 0)
GRADES_SINCE = (0, 179, 0)


def _report_version_at_least(report: dict, threshold: tuple) -> bool:
    hv = str((report.get("metadata") or {}).get("harness_version") or "0")
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", hv)
    return bool(m) and tuple(int(x) for x in m.groups()) >= threshold


def load_attestation(run_dir: Path) -> dict | None:
    """P2: target-attestation.json beside the report (attest_target.py)."""
    f = run_dir / "target-attestation.json"
    if not f.is_file():
        return None
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"attested": False, "checks": [], "error": "unparseable target-attestation.json"}
    return doc


def _attestation_required(report: dict) -> bool:
    """Reports at/after ATTESTATION_SINCE must carry an attestation;
    older reports are grandfathered (attack_refs-gate discipline)."""
    return _report_version_at_least(report, ATTESTATION_SINCE)


def build_events(
    report: dict,
    report_rel: str,
    resolver: AuditResolver,
    recorded_at: str,
    *,
    install_failure: bool = False,
    attestation: dict | None = None,
    attestation_required: bool = False,
    controls_required: bool = False,
    differential_required: bool = False,
    grades_required: bool = False,
) -> dict:
    """Group the report's decided verdicts by canonical audit.

    Returns {per_audit: {audit_path: {events, needs_review, register}},
             skipped: [...], counts: {...}}.

    Soundness gate (harnessing/5-validate/validate-findings/soundness.py): a
    `refuted` verdict that rests on an unsound probe — error-signature
    transcript, zero-subject RBAC probe, or a target-not-deployed run
    (`install_failure=True`) — NEVER becomes a false_positive event or a
    refuted-register entry. It queues an `unsound_refutation`
    needs_review item instead, as does any finding the engine already
    stamped with a `soundness_flag`.
    """
    meta = report.get("metadata") or {}
    hv = str(meta.get("harness_version") or "0.0.0")
    occurred_at = report_occurred_at(meta.get("date"), recorded_at)
    actor = {"kind": "machine", "identity": f"validate-findings/{hv}", "ldap_verified": False}
    source = {"type": "validation_report", "ref": report_rel, "actor": actor}
    report_rel_dir = str(Path(report_rel).parent)
    recorded_shas = {
        s.get("path"): s.get("sha256")
        for s in report.get("source_reports") or []
        if s.get("kind") == "security-audit"
    }

    per_audit: dict[Path, dict] = {}
    skipped: list[dict] = []
    counts = {"confirmed": 0, "refuted": 0, "unsound": 0, "no_event": 0}

    for f in report.get("validated_findings") or []:
        verdict = f.get("verdict")
        # Soundness gate: flagged refutations (stamped by the engine or
        # detected retroactively on ungated legacy reports) route to
        # needs_review below, never to the FP/countersign path.
        flag = None
        # P2 attestation gate: an unattested (or, for new reports,
        # missing-attestation) environment structurally invalidates
        # EVERY verdict — confirmed and refuted alike — because nothing
        # was proven testable. environment_invalid routes to
        # needs_review; no ledger event, no register entry.
        if attestation is not None and not attestation.get("attested"):
            flag = "environment_invalid"
        elif attestation is None and attestation_required:
            flag = "attestation_missing"
        elif verdict == "refuted":
            flag = soundness.flag_validated_finding(
                f,
                install_failure=install_failure,
                controls_required=controls_required,
                differential_required=differential_required,
            )
        elif verdict == "inconclusive" and f.get("soundness_flag"):
            flag = str(f["soundness_flag"])
        if verdict not in EVENT_VERDICTS and not flag:
            counts["no_event"] += 1
            continue
        sid = str(f.get("source_id") or "")
        finding_id = sid.rsplit("/", 1)[-1]
        src = str(f.get("source_report") or "")
        if not finding_id or not src:
            skipped.append(
                {"source_id": sid, "verdict": verdict, "reason": "missing source_id/source_report"}
            )
            continue
        targets, note = resolver.resolve(src, finding_id)
        targets = [t for t in targets if resolver._finding(t, finding_id) is not None]
        if not targets:
            skipped.append(
                {
                    "source_id": sid,
                    "verdict": verdict,
                    "reason": f"unresolvable baseline ({note}): {src}",
                }
            )
            continue

        validated_sha = recorded_shas.get(src)

        if flag:
            counts["unsound"] += 1
            for audit_path in targets:
                bucket = per_audit.setdefault(
                    audit_path, {"events": [], "needs_review": [], "register": []}
                )
                bucket["needs_review"].append(
                    {
                        "queued_at": recorded_at,
                        "source_ref": report_rel,
                        "quote": _squash(
                            f"machine refutation blocked by the soundness gate "
                            f"({flag}) — the probe never soundly tested the "
                            f"claim; observed: "
                            f"{f.get('observed_impact') or '(no output)'}"
                        ),
                        "author": actor["identity"],
                        "suggested_finding_ref": finding_id,
                        "queue_reason": "unsound_refutation",
                        "status": "pending",
                    }
                )
            continue

        # P4 grade gate on confirmations: E3 (inference-only) never
        # auto-confirms at any report age; ungraded confirmations from
        # reports at/after GRADES_SINCE quarantine until graded. E0/E1
        # keep class-1 (override) power; E2 events demote to machine
        # static in build_cumulative.event_class.
        grade = f.get("evidence_grade")
        if verdict == "confirmed" and (grade == "E3" or (grade is None and grades_required)):
            counts["unsound"] += 1
            for audit_path in targets:
                bucket = per_audit.setdefault(
                    audit_path, {"events": [], "needs_review": [], "register": []}
                )
                bucket["needs_review"].append(
                    {
                        "queued_at": recorded_at,
                        "source_ref": report_rel,
                        "quote": _squash(
                            (
                                "E3 inference-only confirmation — grade the "
                                "evidence or re-probe for an observed effect: "
                                if grade == "E3"
                                else "ungraded confirmation (post-0.179.0 reports "
                                "must grade evidence E0-E3): "
                            )
                            + str(f.get("observed_impact") or "(no output)"),
                            500,
                        ),
                        "author": actor["identity"],
                        "suggested_finding_ref": finding_id,
                        "queue_reason": (
                            "weak_confirmation" if grade == "E3" else "ungraded_confirmation"
                        ),
                        "status": "pending",
                    }
                )
            continue

        validity = "confirmed" if verdict == "confirmed" else "false_positive"
        counts[verdict] += 1

        for audit_path in targets:
            # Staleness only means something for a direct hit: content- and
            # claim-matched targets are current by construction.
            stale = (
                note == "direct" and bool(validated_sha) and _sha256(audit_path) != validated_sha
            )

            bucket = per_audit.setdefault(
                audit_path, {"events": [], "needs_review": [], "register": []}
            )
            event = {
                "event_id": compute_event_id(report_rel, finding_id, validity, None),
                "finding_ref": finding_id,
                "recorded_at": recorded_at,
                "occurred_at": occurred_at,
                "source": source,
                "disposition": {"validity": validity},
                "rationale": _rationale(f),
                "evidence_refs": _evidence_refs(f, report_rel_dir, validated_sha),
            }
            if grade:
                event["evidence_grade"] = grade

            # P9: machine severity-adjustment PROPOSAL — never an event
            # carrying disposition.severity (the layer validator rejects
            # machine severity); it queues for the human countersign
            # severity decision. E3-graded evidence never proposes.
            sv = f.get("severity_validation") or {}
            proposal = sv.get("proposal")
            if proposal and grade != "E3":
                chain = f.get("chain_context") or {}
                bucket["needs_review"].append(
                    {
                        "queued_at": recorded_at,
                        "source_ref": report_rel,
                        "quote": _squash(
                            f"severity proposal: {proposal.get('severity')} "
                            f"(claimed {f.get('claimed_severity') or '?'}, "
                            f"delta {sv.get('delta')}) — "
                            f"{proposal.get('rationale')}"
                            + (
                                f" [chain {chain.get('chain_id')}: "
                                f"{chain.get('chain_severity')} — "
                                f"{chain.get('role')}]"
                                if chain
                                else ""
                            ),
                            500,
                        ),
                        "author": actor["identity"],
                        "suggested_finding_ref": finding_id,
                        "queue_reason": "severity_proposal",
                        "status": "pending",
                    }
                )
            if (clean_hv := sanitize_harness_version(hv)) is not None:
                event["harness_version"] = clean_hv
            bucket["events"].append(event)

            if stale:
                bucket["needs_review"].append(
                    {
                        "queued_at": recorded_at,
                        "source_ref": report_rel,
                        "quote": _squash(
                            f"validated against baseline sha256 {validated_sha}, "
                            f"but {audit_path.name} has since changed — confirm "
                            f"the {verdict} verdict still applies to the current "
                            f"claim"
                        ),
                        "author": actor["identity"],
                        "suggested_finding_ref": finding_id,
                        "queue_reason": "stale_baseline",
                        "status": "pending",
                    }
                )

            if verdict == "refuted":
                bucket["register"].append(
                    {
                        "finding_ref": finding_id,
                        "title": f.get("title"),
                        "claimed_severity": f.get("claimed_severity"),
                        "refute_reasons": [
                            _squash(
                                f.get("deviation_from_claim")
                                or "not reproduced in live validation",
                                200,
                            )
                        ],
                        "tier": "countersign",
                        "evidence_refs": _evidence_refs(f, report_rel_dir, validated_sha),
                        "asserted_at": recorded_at,
                        "asserted_by": actor["identity"],
                        "note": "Falsifiable claim: remains in fuzzing and "
                        "live-validation scope; execution evidence "
                        "overrides (evidence-class precedence).",
                    }
                )

    return {"per_audit": per_audit, "skipped": skipped, "counts": counts}


def append_to_layer(
    layer_path: Path,
    audit_path: Path,
    audit: dict,
    bucket: dict,
    recorded_at: str,
    hv: str,
    *,
    engine=None,
) -> dict:
    """Create or idempotently append to the layer file. Returns counts."""
    shell = {
        "metadata": {
            "audit_report": audit_path.name,
            "repository": str(
                (audit.get("metadata") or {}).get("repository") or "https://unknown.invalid/"
            ),
            "created": recorded_at,
            "harness_version": sanitize_harness_version(hv) or "0.0.0",
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

    # Monotonic timestamp: events array must stay chronological.
    last = max((e.get("recorded_at", "") for e in layer.get("events", [])), default="")
    stamp = max(recorded_at, last)
    events = [{**e, "recorded_at": stamp} for e in bucket["events"]]

    submitted = len(events)
    # RESOLVED by LedgerService.submit_events: report-reference stamping
    # (plan §4.4.0 step 1), dedup, Merkle finalization, and signing are
    # internal to the service. Stale-signature handling (configured-but-broken
    # signer, or signature dropped because root moved) raises LedgerError
    # when signing is required, and silently proceeds otherwise.
    result = ledger.submit_events(
        layer_path,
        events,
        report_path=audit_path,
        queue_items=bucket.get("needs_review"),
    )
    appended = len(result.event_ids) if result.event_ids is not None else submitted
    return {
        "appended": appended,
        "duplicates_skipped": submitted - appended,
        "queued": result.queue_added,
    }


def merge_register(
    register_path: Path, source_ref: str, entries: list[dict], recorded_at: str
) -> int:
    """Merge-append refuted-register entries; never clobber another
    source's (e.g. the triage emitter's) entries."""
    if register_path.is_file():
        doc = json.loads(register_path.read_text(encoding="utf-8"))
    else:
        doc = {"source": source_ref, "entries": []}
    sources = set(doc.get("sources") or ([doc["source"]] if doc.get("source") else []))
    sources.add(source_ref)
    doc["sources"] = sorted(sources)
    seen = {(e.get("finding_ref"), e.get("asserted_by")) for e in doc.get("entries", [])}
    fresh = []
    for e in entries:
        key = (e["finding_ref"], e["asserted_by"])
        if key in seen:
            continue
        seen.add(key)
        fresh.append(e)
    doc.setdefault("entries", []).extend(fresh)
    doc["generated_at"] = recorded_at
    if fresh:
        register_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return len(fresh)


def layer_path_for(audit_path: Path) -> Path:
    stem = audit_path.name
    # Naming rules (docs-verification 2026-07-31 P0-4, emitter leg):
    # - code audits strip their suffix (<repo>-findings-layer.json);
    # - cloud-config audits strip THEIR suffix too — the production
    #   cloud-config tree ledgers all use the short name — UNLESS a
    #   code audit shares the directory (companion IaC baseline under
    #   findings/), where the short name would clobber the code
    #   audit's ledger;
    # - container reports always share the code audit's directory, so
    #   their ledger artifacts keep the full stem (".json" fallback).
    if stem.endswith("-cloud-config-audit.json"):
        short = stem[: -len("-cloud-config-audit.json")]
        if not (audit_path.parent / f"{short}-security-audit.json").is_file():
            return audit_path.parent / f"{short}-findings-layer.json"
        # companion baseline beside a code audit -> keep full stem
        return audit_path.parent / (stem[: -len(".json")] + "-findings-layer.json")
    for suffix in ("-security-audit.json", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return audit_path.parent / f"{stem}-findings-layer.json"


def process_report(
    report_path: Path,
    resolver: AuditResolver,
    recorded_at: str,
    dry_run: bool,
    build_cumulative: bool,
    *,
    engine=None,
) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    try:
        report_rel = str(report_path.resolve().relative_to(resolver.results_root.resolve()))
    except ValueError:
        report_rel = report_path.name
    # Run-level deployment gate: an install-failure.yaml beside the
    # report means the operand never deployed — nothing in the run may
    # ledger as refuted.
    install_failure = soundness.run_install_failed(report_path.parent)
    attestation = load_attestation(report_path.parent)
    attestation_required = _attestation_required(report)
    out = build_events(
        report,
        report_rel,
        resolver,
        recorded_at,
        install_failure=install_failure,
        attestation=attestation,
        attestation_required=attestation_required,
        controls_required=_report_version_at_least(report, CONTROLS_SINCE),
        differential_required=_report_version_at_least(report, DIFFERENTIAL_SINCE),
        grades_required=_report_version_at_least(report, GRADES_SINCE),
    )

    hv = str((report.get("metadata") or {}).get("harness_version") or "0.0.0")
    totals = {"appended": 0, "duplicates_skipped": 0, "queued": 0, "registered": 0, "layers": 0}
    for audit_path, bucket in sorted(out["per_audit"].items()):
        layer_path = layer_path_for(audit_path)
        totals["layers"] += 1
        if dry_run:
            totals["appended"] += len(bucket["events"])
            totals["queued"] += len(bucket["needs_review"])
            totals["registered"] += len(bucket["register"])
            continue
        counts = append_to_layer(
            layer_path,
            audit_path,
            resolver.load_audit(audit_path),
            bucket,
            recorded_at,
            hv,
            engine=engine,
        )
        for k in ("appended", "duplicates_skipped", "queued"):
            totals[k] += counts[k]
        if bucket["register"]:
            register_path = layer_path.with_name(
                layer_path.name.replace("-findings-layer.json", "-refuted-register.json")
            )
            totals["registered"] += merge_register(
                register_path, report_rel, bucket["register"], recorded_at
            )
        if build_cumulative and counts["appended"]:
            # H12: the merge engine runs with this tool's authority over the
            # ledger, so it must be the one shipped with the package. Invoking
            # it as a module (-m) resolves it from the installed distribution
            # rather than a filesystem path, so there is no planted-script
            # surface to guard against.
            res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "traust.cli.build_cumulative",
                    str(audit_path),
                    str(layer_path),
                    "--generated-at",
                    recorded_at,
                ],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                print(
                    f"WARN: build_cumulative failed for {audit_path}: {res.stderr.strip()}",
                    file=sys.stderr,
                )

    mode = "DRY RUN — would append" if dry_run else "appended"
    c = out["counts"]
    print(
        f"{report_rel}: {c['confirmed']} confirmed, {c['refuted']} refuted "
        f"(countersign-gated), {c.get('unsound', 0)} unsound refutation(s) "
        f"(→ needs_review, no FP event), {c['no_event']} verdicts with no "
        f"event — {mode} {totals['appended']} event(s) across "
        f"{totals['layers']} ledger(s), {totals['duplicates_skipped']} "
        f"already present (idempotent), {totals['queued']} review item(s), "
        f"{totals['registered']} register entr(ies)"
    )
    for s in out["skipped"]:
        print(f"  skipped {s['source_id']} ({s['verdict']}): {s['reason']}", file=sys.stderr)
    totals["skipped"] = len(out["skipped"])
    totals.update(c)
    return totals


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_config_home_arg(parser)
    parser.add_argument("report", nargs="?", help="a *-validation.json live-validation report")
    parser.add_argument(
        "--manifest",
        help="validation-manifest.csv — batch-process every row whose report_path resolves locally",
    )
    parser.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="the analysis-results checkout (default: configured analysis-results)",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="parent workspace containing progress-tracker (default: configured workspace)",
    )
    parser.add_argument(
        "--recorded-at",
        type=recorded_at_arg,
        help="override the append timestamp (RFC 3339)",
    )
    parser.add_argument("--dry-run", action="store_true", help="resolve and report; write nothing")
    parser.add_argument(
        "--build-cumulative",
        action="store_true",
        help="rebuild <repo>-findings-current.{json,md} for every ledger that gained events",
    )
    args = parser.parse_args(argv)
    if bool(args.report) == bool(args.manifest):
        parser.error("provide exactly one of <report> or --manifest")

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()
    if not results_root.is_dir():
        print(f"ERROR: results root {results_root} not found", file=sys.stderr)
        return 2
    workspace_root = (args.workspace_root or workspace_dir(engine)).resolve()
    resolver = AuditResolver(results_root, workspace_root)
    recorded_at = args.recorded_at or datetime.now(UTC).isoformat(timespec="seconds")

    reports: list[Path] = []
    if args.manifest:
        for row in csv.DictReader(Path.open(args.manifest, encoding="utf-8")):
            rp = row.get("report_path") or ""
            local = _localize(rp, "analysis-results/", results_root)
            if local is not None and local.exists():
                reports.append(local)
            elif rp or row.get("status") not in ("", None):
                print(
                    f"  manifest: no local report for {row.get('slug')} "
                    f"(status={row.get('status')}) — skipped",
                    file=sys.stderr,
                )
    else:
        reports.append(Path(args.report))

    grand = {}
    failures = 0
    for rp in reports:
        try:
            totals = process_report(
                rp, resolver, recorded_at, args.dry_run, args.build_cumulative, engine=engine
            )
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"ERROR: {rp}: {e}", file=sys.stderr)
            failures += 1
            continue
        for k, v in totals.items():
            grand[k] = grand.get(k, 0) + v

    if len(reports) > 1:
        print(
            f"\nTOTAL: {grand.get('appended', 0)} event(s) "
            f"({grand.get('confirmed', 0)} confirmed, "
            f"{grand.get('refuted', 0)} refuted) across "
            f"{grand.get('layers', 0)} ledger(s), "
            f"{grand.get('duplicates_skipped', 0)} already present, "
            f"{grand.get('queued', 0)} stale-baseline review item(s), "
            f"{grand.get('skipped', 0)} skipped, {failures} report "
            f"failure(s)"
        )
    if not args.dry_run and grand.get("refuted", 0):
        print(
            "NEXT: refutations await LDAP-verified sign-off — run "
            "/countersign (`traust admin countersign queue`)"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["ledger", "emit-validation", *sys.argv[1:]]))
