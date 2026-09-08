#!/usr/bin/env python3
"""
Deterministic merge engine for the track-findings skill.

Replays a findings-disposition layer (layer.schema.json) over its
security-audit report (report.schema.json) and emits the cumulative
report pair:

    <base>-findings-current.json   (report.schema.json + disposition blocks)
    <base>-findings-current.md     (human-readable rendering)

The merge is pure code so ten reruns give ten identical outputs: the model
gathers and interprets disposition sources; this script decides state.

Usage (from the workspace root):
  python3 -m traust.cli.build_cumulative \
      <audit.json> <layer.json> [--out <basepath>] [--generated-at ISO8601]

Merge rules (keep in sync with harnessing/4-triage/track-findings/SKILL.md):
  validity   — EVIDENCE-CLASS precedence (harness >= 0.27.0): class 1
               execution-verified sources (validation_report,
               verification_report) > class 2 human static determinations >
               class 3 machine static (triage_report and other machine
               events). Latest wins within the deciding class. A machine
               false_positive NEVER sets validity on its own — it raises
               refuted_awaiting_signoff until an LDAP-verified human
               countersigns — EXCEPT auto_accept_tier events (unanimous,
               lint-clean, high-confidence, low/informational-claimed
               triage FPs), which may set validity directly.
               A class-1 'confirmed' overrides any human false_positive
               (fp_overridden — loud, attributed). After execution-verified
               confirmation, re-asserting false_positive requires TWO
               distinct LDAP-verified humans post-dating the proof
               (two-person rule; a single attempt sets
               fp_reassertion_blocked).
  assurance  — highest evidence class that has spoken on validity:
               execution_proven > human_reviewed > machine_verified >
               claimed.
  resolution — verification_report events > jira events > everything else;
               latest wins within the highest populated tier.
  conflict   — both 'confirmed' and 'false_positive' appear anywhere in the
               finding's events. Surfaced, never silently resolved.
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_contracts.enums import DispositionResolution, Validity
from traust_engine._util.layer_paths import (
    LayerPathOutsideRoot,
    confine_layer_path,
)
from traust_engine.ledger import (
    FINGERPRINT_ALGO_CURRENT,
    aliases_from_events,
    attach_identity,
    check_report_digest,
    compute_claim_hash,
    findings_from_events,
    fingerprint_index,
)
from traust_engine.ledger import (
    is_actor_verified as _actor_is_verified,
)

from traust.context import (
    add_config_home_arg,
    default_findings_roots,
    load_engine,
)

# Derived from the shared contract, never retyped: these drive the summary
# blocks, so a hand-maintained copy silently omits any value added upstream —
# no error, just a missing column. Enum order is the contract's order.
RESOLUTION_KEYS = [e.value for e in DispositionResolution]
VALIDITY_KEYS = [e.value for e in Validity]

# Lower number = higher authority for the resolution axis.
RESOLUTION_TIERS = {"verification_report": 0, "jira": 1}
DEFAULT_RESOLUTION_TIER = 2

# Evidence classes for the validity axis: an executed proof beats a human
# static opinion beats a machine static verdict.
EXEC_SOURCE_TYPES = {"validation_report", "verification_report"}


def event_class(event):
    """1 = execution-verified, 2 = human static, 3 = machine static.

    P4 evidence grades narrow class 1: only E0 (observed effect) and E1
    (authenticated success on the exploit action) keep execution-class
    status — and with it, override power over human FP signatures
    (decision 2026-07-25: E0/E1 only). An E2/E3-graded event from an
    execution source is machine static evidence with a grade annotation.
    Ungraded events from execution sources keep class 1 (pre-0.179.0
    reports are grandfathered; the emitter quarantines ungraded
    confirmations from newer reports before they ever become events)."""
    if event.get("evidence_grade") in ("E2", "E3"):
        return 3
    if event["source"]["actor"].get("kind") == "human":
        # Actor beats source here: every pipeline emitter stamps
        # kind=machine, so a human-actored event citing an execution
        # report is a human determination recorded against that report
        # (SKILL.md verification mapping: false_positive → "human event
        # if it names a verified human"), not executed proof. Classing
        # it 1 made exec_decisive discard human FPs recorded on
        # verification_report events — the finding pended forever.
        return 2
    if event["source"]["type"] in EXEC_SOURCE_TYPES:
        return 1
    return 3


def verify_claim_hashes(audit, layer):
    """Refuse to build from a tampered baseline.

    Returns (errors, warnings): errors are silent in-place edits or deleted
    baselined findings; 'corrected' drift and not-yet-baselined appends are
    warnings (the cumulative build proceeds, the next `baseline_claims.py
    record` pins them)."""
    hashes = (layer.get("metadata") or {}).get("claim_hashes") or {}
    if not hashes:
        return [], []  # pre-claim-hash layer — nothing to verify against
    findings = {f.get("id"): f for f in audit.get("findings", [])}
    # B2 — an event-carried claim is pinnable on the same terms as a baselined
    # one (the required keys are identical by construction, asserted in the
    # contracts tests). Without this the verifier would report every pinned
    # event-carried finding as "missing from the audit report", which is the
    # opposite of the truth: it is present, just not in the baseline.
    for _fid, _f in findings_from_events(layer.get("events")).items():
        findings.setdefault(_fid, _f)
    errors, warnings = [], []
    for fid, recorded in sorted(hashes.items()):
        f = findings.get(fid)
        if f is None:
            errors.append(f"{fid}: baselined finding missing from the audit report")
        elif compute_claim_hash(f) != recorded:
            if f.get("validation_status") == "corrected":
                warnings.append(f"{fid}: 'corrected' claim drift — re-baseline it")
            else:
                errors.append(f"{fid}: claim hash mismatch — edited in place")
    unbaselined = sorted(set(findings) - set(hashes))
    if unbaselined:
        warnings.append(f"{len(unbaselined)} finding(s) not yet baselined")
    return errors, warnings


def _event_dt(event):
    return datetime.fromisoformat(event["recorded_at"])


def derive_disposition(finding, events, generated_at):
    """Derive the current two-axis disposition for one finding."""
    events = sorted(events, key=_event_dt)
    base_validity = finding.get("validation_status", "not_verified")

    validity_events = [e for e in events if e["disposition"].get("validity")]
    exec_v = [e for e in validity_events if event_class(e) == 1]
    human_v = [e for e in validity_events if event_class(e) == 2]
    machine_v = [e for e in validity_events if event_class(e) == 3]

    fp_overridden = False
    fp_reassertion_blocked = False

    # Class 2: human static determinations (latest wins).
    if human_v:
        class2_validity = human_v[-1]["disposition"]["validity"]
    elif machine_v:
        last_e = machine_v[-1]
        last = last_e["disposition"]["validity"]
        # Machine refutation evidence cannot set false_positive on its own —
        # unless it met the auto-accept bar (layer.schema.json
        # auto_accept_tier); a 10% audit-valve sample is queued regardless.
        if last == "false_positive" and not last_e.get("auto_accept_tier"):
            class2_validity = base_validity
        else:
            class2_validity = last
    else:
        class2_validity = base_validity

    # Class 1: execution-verified evidence outranks static opinions.
    # An FP verdict from a machine report still needs countersign, so only
    # non-FP class-1 validities (confirmed/corrected) decide directly.
    exec_decisive = [e for e in exec_v if e["disposition"]["validity"] != "false_positive"]
    if exec_decisive:
        proof = exec_decisive[-1]
        validity = proof["disposition"]["validity"]
        if validity == "confirmed":
            human_fp = [e for e in human_v if e["disposition"]["validity"] == "false_positive"]
            if any(_event_dt(e) <= _event_dt(proof) for e in human_fp):
                # Executed proof overturns the earlier human dismissal.
                fp_overridden = True
            post = [e for e in human_fp if _event_dt(e) > _event_dt(proof)]
            post_ids = {
                e["source"]["actor"].get("identity")
                for e in post
                if _actor_is_verified(e["source"]["actor"])
            }
            if len(post_ids) >= 2:
                # Two-person rule satisfied: independent re-assertion wins.
                validity = "false_positive"
                fp_overridden = False
            elif post:
                fp_reassertion_blocked = True
    else:
        validity = class2_validity

    # Machine FP evidence (any class — a validation_report refutation is
    # still machine evidence) pends until a human weighs in, unless it met
    # the auto-accept bar. ANY human validity determination clears the
    # flag: countersigning resolves it as FP, keep-open (confirmed)
    # resolves it as reviewed-and-rejected.
    refuted_awaiting_signoff = (
        any(
            e["disposition"].get("validity") == "false_positive"
            and e["source"]["actor"].get("kind") == "machine"
            and not e.get("auto_accept_tier")
            for e in validity_events
        )
        and validity != "false_positive"
        and not human_v
    )

    # P6: lanes disagreeing (confirmed + false_positive both in evidence)
    # must adjudicate as a CONFLICT card with both transcripts — never as
    # an unopposed FP countersign. Conflict routing wins over the
    # awaiting-signoff queue (countersign renders kind=conflict with
    # DECISION markers).
    _seen = {e["disposition"].get("validity") for e in validity_events}
    if {"confirmed", "false_positive"} <= _seen:
        refuted_awaiting_signoff = False

    if exec_v:
        assurance = "execution_proven"
    elif human_v:
        assurance = "human_reviewed"
    elif machine_v:
        assurance = "machine_verified"
    else:
        assurance = "claimed"

    seen_validities = {e["disposition"]["validity"] for e in validity_events}
    conflict = {"confirmed", "false_positive"} <= seen_validities

    resolution_events = [e for e in events if e["disposition"].get("resolution")]
    resolution = "open"
    if resolution_events:
        best_tier = min(
            RESOLUTION_TIERS.get(e["source"]["type"], DEFAULT_RESOLUTION_TIER)
            for e in resolution_events
        )
        tier_events = [
            e
            for e in resolution_events
            if RESOLUTION_TIERS.get(e["source"]["type"], DEFAULT_RESOLUTION_TIER) == best_tier
        ]
        resolution = tier_events[-1]["disposition"]["resolution"]

    # Severity override: HUMAN-only (class 2, LDAP-verified — the layer
    # validator rejects machine actors carrying disposition.severity), and
    # the latest human severity event wins. The audit's original severity
    # field is never rewritten — callers surface this as effective_severity.
    severity_events = [
        e for e in events if e["disposition"].get("severity") and event_class(e) == 2
    ]

    disposition = {
        "validity": validity,
        "resolution": resolution,
        "assurance": assurance,
        "last_updated": events[-1]["recorded_at"] if events else generated_at,
        "events": [e["event_id"] for e in events],
    }
    if severity_events:
        last_sev = severity_events[-1]
        disposition["severity_override"] = {
            "severity": last_sev["disposition"]["severity"],
            "by": last_sev["source"]["actor"].get("identity", "?"),
            "at": last_sev.get("occurred_at", last_sev["recorded_at"]),
            **({"rationale": last_sev["rationale"]} if last_sev.get("rationale") else {}),
        }
    if conflict:
        disposition["conflict"] = True
    if refuted_awaiting_signoff:
        disposition["refuted_awaiting_signoff"] = True
    if fp_overridden:
        disposition["fp_overridden"] = True
    if fp_reassertion_blocked:
        disposition["fp_reassertion_blocked"] = True
    return disposition


def build_cumulative(audit, layer, layer_ref, generated_at):
    """Return the cumulative report dict, or raise ValueError on bad refs."""
    findings = {f["id"]: f for f in audit.get("findings", [])}

    # B2 — union event-carried findings with the baseline's own.
    #
    # Only /secure-code-audit, /secure-rpm-audit and /secure-container-audit may
    # write an audit baseline (gate A15). A finding discovered BETWEEN audits
    # therefore rides on its event in an `event.finding` block, because there is
    # no baseline id for finding_ref to join to. Without this union those
    # findings would be recorded, signed and invisible — the failure mode the
    # ledger's tenet 5 exists to prevent (wrongly dismissing silently deletes
    # real risk).
    #
    # setdefault, not update: the BASELINE WINS. Once a re-audit baselines the
    # same id, the baseline's claim is authoritative and the event-carried copy
    # is a stale duplicate. This is also what lets a supplement be absorbed at
    # re-audit without a migration — the event stays in history, the baseline
    # simply takes precedence from then on.
    event_carried = findings_from_events(layer.get("events"))
    for _fid, _f in event_carried.items():
        findings.setdefault(_fid, _f)

    # Rebaseline aliases (traust_engine.ledger): a superseded scan's
    # finding ids map to their successors. Events are immutable — refs are
    # resolved here at replay time, and only CONFIRMED mappings transfer
    # history (fingerprint tier auto-confirms; path/title tiers pend in
    # needs_review until a human confirms). Unconfirmed-alias refs are
    # tolerated (their history stays parked, not lost), as are refs whose
    # rebaseline left them unmatched with a pending needs_review decision
    # ("history stays under the old id until a human maps or closes it");
    # refs with no alias and no queued decision still fail loudly — that
    # remains the tamper guard.
    # P2: alias events are AUTHORITATIVE; metadata.finding_aliases is a legacy
    # projection kept readable while the corpus still carries it. Events win on
    # conflict, because the table sits outside the Merkle tree with no verifier —
    # anyone able to edit it could re-point a false_positive or accepted_risk
    # verdict at a different finding and the root would still verify. Reading
    # both means no data migration is forced: layers convert as they are
    # rewritten, exactly as leaf_format 2 rolled out.
    raw_aliases = dict((layer.get("metadata") or {}).get("finding_aliases") or {})
    raw_aliases.update(aliases_from_events(layer.get("events")))

    # finding_identity.py namespaces non-canonical old ids with their
    # source-report slug ("<slug>:FIND-NNN") so branch variants sharing a
    # layer cannot collide. Events keep the bare id, so an event ref is
    # looked up bare first, then via namespaced keys — a namespaced match
    # only RESOLVES when it is unambiguous (exactly one entry); ambiguous
    # matches park rather than guess.
    ns_aliases = {}
    for k, v in raw_aliases.items():
        if ":" in k:
            ns_aliases.setdefault(k.split(":", 1)[1], []).append(v)

    def _alias_for(ref):
        a = raw_aliases.get(ref)
        if a is not None:
            return a
        cands = ns_aliases.get(ref) or []
        return cands[0] if len(cands) == 1 else None

    def _has_alias(ref):
        return ref in raw_aliases or ref in ns_aliases

    queued_unmatched = {
        i.get("suggested_finding_ref")
        for i in layer.get("needs_review", [])
        if i.get("queue_reason") == "rebaseline_unmatched" and i.get("status") == "pending"
    }

    def resolve(ref, _seen=None):
        _seen = _seen or set()
        a = _alias_for(ref)
        if not a or not a.get("confirmed") or ref in _seen:
            return ref
        _seen.add(ref)
        return resolve(a["new_id"], _seen)

    by_finding = {}
    unknown = []
    parked = []
    for e in layer.get("events", []):
        ref = resolve(e["finding_ref"])
        if ref not in findings:
            if (
                _has_alias(e["finding_ref"])
                or _has_alias(ref)
                or e["finding_ref"] in queued_unmatched
            ):
                parked.append(ref)  # pending/unconfirmed rebaseline mapping
                continue
            unknown.append(ref)
        by_finding.setdefault(ref, []).append(e)
    if unknown:
        raise ValueError(
            "layer references finding IDs not in the audit report: "
            + ", ".join(sorted(set(unknown)))
        )
    if parked:
        print(
            f"WARN: {len(set(parked))} superseded finding id(s) have "
            f"unconfirmed or unmatched rebaseline dispositions — their "
            f"events are parked until the mapping is confirmed or closed "
            f"via countersign/needs_review",
            file=sys.stderr,
        )

    report = json.loads(json.dumps(audit))  # deep copy

    # B2 — event-carried findings join the PROJECTION too. The `findings` dict
    # above only satisfies ref validation; the report itself is a deep copy of
    # the audit, so without this an arrival event would resolve cleanly and
    # still never appear in any output. Appended only when the id is absent
    # from the baseline, which is the same baseline-wins rule as the union.
    _present = {f["id"] for f in report.get("findings", [])}
    for _fid, _f in event_carried.items():
        if _fid not in _present:
            report.setdefault("findings", []).append(json.loads(json.dumps(_f)))

    for f in report.get("findings", []):
        disp = derive_disposition(f, by_finding.get(f["id"], []), generated_at)
        f["disposition"] = disp
        f["validation_status"] = disp["validity"]
        ov = disp.get("severity_override")
        f["effective_severity"] = ov["severity"] if ov else f.get("severity")

    all_disp = [f["disposition"] for f in report.get("findings", [])]
    pending = [i for i in layer.get("needs_review", []) if i.get("status") == "pending"]
    report["disposition_summary"] = {
        "layer_ref": layer_ref,
        "generated_at": generated_at,
        "by_resolution": {
            k: sum(1 for d in all_disp if d["resolution"] == k) for k in RESOLUTION_KEYS
        },
        "by_validity": {k: sum(1 for d in all_disp if d["validity"] == k) for k in VALIDITY_KEYS},
        "severity_overrides": [
            {"finding": f["id"], "from": f.get("severity"), **f["disposition"]["severity_override"]}
            for f in report.get("findings", [])
            if f["disposition"].get("severity_override")
        ],
        "conflicts": [
            f["id"] for f in report.get("findings", []) if f["disposition"].get("conflict")
        ],
        "needs_review_count": len(pending),
    }

    if not report["title"].endswith("— Cumulative Findings Status"):
        report["title"] = report["title"] + " — Cumulative Findings Status"
    meta = report.setdefault("metadata", {})
    additional = meta.setdefault("additional", {})
    additional["cumulative"] = {
        "source_audit": layer["metadata"]["audit_report"],
        "layer": layer_ref,
        "original_report_date": meta.get("date"),
        "generated_at": generated_at,
    }
    meta["date"] = generated_at[:10]
    return report


VALIDITY_LABEL = {
    "confirmed": "✅ confirmed",
    "corrected": "✏️ corrected",
    "false_positive": "🚫 false positive",
    "not_verified": "⬜ not verified",
    "hardening": "🛡️ hardening",
}
RESOLUTION_LABEL = {
    "open": "❌ open",
    "fix_in_progress": "🔧 fix in progress",
    "resolved": "✅ resolved",
    "partially_resolved": "⚠️ partially resolved",
    "risk_accepted": "📋 risk accepted",
    "regression_introduced": "🆕 regression introduced",
}


def render_markdown(report, layer):
    """Render the cumulative report to Markdown."""
    meta = report["metadata"]
    ds = report["disposition_summary"]
    cumulative = meta.get("additional", {}).get("cumulative", {})
    lines = []
    add = lines.append

    add(f"# {report['title']}")
    add("")
    add("| Field | Value |")
    add("|-------|-------|")
    add(f"| **Generated** | {ds['generated_at']} |")
    add(
        f"| **Original Report** | {cumulative.get('source_audit', '?')} "
        f"({cumulative.get('original_report_date', '?')}) |"
    )
    add(f"| **Disposition Layer** | {ds['layer_ref']} |")
    if meta.get("repository"):
        add(f"| **Repository** | {meta['repository']} |")
    if meta.get("commit"):
        add(f"| **Audited Commit** | `{meta['commit']}` |")
    add("")

    add("## Disposition Summary")
    add("")
    add("| Resolution | Count | | Validity | Count |")
    add("|---|---|---|---|---|")
    rows = max(len(RESOLUTION_KEYS), len(VALIDITY_KEYS))
    for i in range(rows):
        rk = RESOLUTION_KEYS[i] if i < len(RESOLUTION_KEYS) else None
        vk = VALIDITY_KEYS[i] if i < len(VALIDITY_KEYS) else None
        left = f"{RESOLUTION_LABEL[rk]} | {ds['by_resolution'][rk]}" if rk else " | "
        right = f"{VALIDITY_LABEL[vk]} | {ds['by_validity'][vk]}" if vk else " | "
        add(f"| {left} | | {right} |")
    add("")

    if ds.get("severity_overrides"):
        add("## Severity overrides (human, LDAP-verified)")
        add("")
        add(
            "Original severities are preserved on each finding; the "
            "effective severity below is what current prioritization "
            "should use."
        )
        add("")
        add("| Finding | Original | Effective | By | When |")
        add("|---|---|---|---|---|")
        for ov in ds["severity_overrides"]:
            add(
                f"| `{ov['finding']}` | {ov.get('from', '?')} | "
                f"**{ov['severity']}** | {ov['by']} | {ov['at'][:10]} |"
            )
        add("")

    if ds.get("conflicts"):
        add("## ⚠️ Conflicts — needs human re-review")
        add("")
        add(
            "These findings carry both 'confirmed' and 'false positive' "
            "determinations. The ledger keeps both; a human must adjudicate."
        )
        add("")
        for fid in ds["conflicts"]:
            add(f"- `{fid}`")
        add("")

    awaiting = [
        f for f in report.get("findings", []) if f["disposition"].get("refuted_awaiting_signoff")
    ]
    if awaiting:
        add("## ⏳ Refuted by machine validation — awaiting human sign-off")
        add("")
        add(
            "Machine evidence refuted these findings, but a false-positive "
            "determination requires an LDAP-verified human countersignature. "
            "Build the decision-card inbox with "
            "`traust admin countersign queue` "
            "(or run `/track-findings <report> --interactive`)."
        )
        add("")
        for f in awaiting:
            add(f"- `{f['id']}` — {f['title']}")
        add("")

    overridden = [f for f in report.get("findings", []) if f["disposition"].get("fp_overridden")]
    if overridden:
        add("## ⚡ False-positive assertions overridden by execution evidence")
        add("")
        add(
            "A reproducing exploit/crash confirmed these findings over a "
            "prior human false-positive determination. Both events remain "
            "in the ledger with attribution. Re-asserting false positive "
            "now requires two independent LDAP-verified humans "
            "(two-person rule)."
        )
        add("")
        for f in overridden:
            add(f"- `{f['id']}` — {f['title']}")
        add("")

    blocked = [
        f for f in report.get("findings", []) if f["disposition"].get("fp_reassertion_blocked")
    ]
    if blocked:
        add("## 🔒 FP re-assertion blocked (two-person rule)")
        add("")
        add(
            "A single human re-asserted false positive against an "
            "execution-verified confirmation. A second independent "
            "LDAP-verified human must concur before validity changes."
        )
        add("")
        for f in blocked:
            add(f"- `{f['id']}` — {f['title']}")
        add("")

    pending = [i for i in layer.get("needs_review", []) if i.get("status") == "pending"]
    if pending:
        add(f"## 📋 Needs review — {len(pending)} pending statement(s)")
        add("")
        for item in pending:
            add(f"- **{item['author']}** at {item['source_ref']}:")
            # Legacy layers written by the pre-0.200 emit_validation bug
            # carry "note" instead of the schema-required "quote"; render
            # whichever is present rather than crashing the whole rebuild.
            quote = item.get("quote") or item.get("note") or "(no statement text)"
            add(f"  > {quote}")
            if item.get("suggested_finding_ref"):
                sugg = item.get("suggested_disposition") or {}
                axis = sugg.get("validity") or sugg.get("resolution") or "?"
                add(
                    f"  - suggested: `{item['suggested_finding_ref']}` → {axis} "
                    f"({item.get('queue_reason', 'unclassified')})"
                )
        add("")

    add("## Findings")
    add("")
    add("| ID | Severity | Title | Validity | Resolution | Last Updated |")
    add("|---|---|---|---|---|---|")
    for f in report.get("findings", []):
        d = f["disposition"]
        add(
            f"| `{f['id']}` | {f['severity']} | {f['title']} "
            f"| {VALIDITY_LABEL[d['validity']]} "
            f"| {RESOLUTION_LABEL[d['resolution']]} "
            f"| {d['last_updated'][:10]} |"
        )
    add("")

    events_by_id = {e["event_id"]: e for e in layer.get("events", [])}
    detailed = [f for f in report.get("findings", []) if f["disposition"]["events"]]
    if detailed:
        add("## Event History")
        add("")
        for f in detailed:
            add(f"### {f['id']}: {f['title']}")
            add("")
            for eid in f["disposition"]["events"]:
                e = events_by_id[eid]
                actor = e["source"]["actor"]
                who = actor.get("display_name") or actor.get("identity") or actor["kind"]
                disp = e["disposition"]
                axis = ", ".join(f"{k}: {v}" for k, v in disp.items())
                add(f"- **{e['recorded_at'][:10]}** — [{e['source']['type']}] {who} → {axis}")
                add(f"  > {e['rationale']}")
                add(f"  - source: {e['source']['ref']}")
            add("")

    add("---")
    add(
        "*Generated by the track-findings skill. The disposition layer is "
        "append-only; corrections are new events, never edits.*"
    )
    add("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a cumulative findings report from an audit report "
        "and its disposition layer."
    )
    add_config_home_arg(parser)
    parser.add_argument(
        "audit",
        help="Path to the baseline report: a *-security-audit.json, a "
        "*-cloud-config-audit.json (declared-layer IaC audit), or a "
        "*-container-audit.json (container-image audit)",
    )
    parser.add_argument("layer", help="Path to the *-findings-layer.json ledger")
    parser.add_argument(
        "--out",
        help="Output basepath (default: alongside the audit report, <repo>-findings-current)",
    )
    parser.add_argument(
        "--generated-at", help="Override the generation timestamp (ISO 8601, for reproducible runs)"
    )
    parser.add_argument(
        "--findings-root",
        help="Confine the layer path to this tree (default: configured analysis-results/findings)",
    )
    args = parser.parse_args(argv)

    engine = load_engine(args.config_home)
    audit_path = Path(args.audit)
    # P9b: this took a bare path and wrote a ledger wherever it was told,
    # including outside analysis-results/ and through a symlink, while three of
    # the five writers already refused that. Same helper as rebaseline().
    roots = (
        [Path(args.findings_root)]
        if args.findings_root
        else default_findings_roots(engine, audit_path)
    )
    try:
        layer_path = confine_layer_path(args.layer, roots, what="layer")
    except LayerPathOutsideRoot as e:
        print(
            f"ERROR: {e} (pass --findings-root if your results tree lives elsewhere)",
            file=sys.stderr,
        )
        return 2
    try:
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        layer = json.loads(layer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read inputs: {e}", file=sys.stderr)
        return 2

    claim_errors, claim_warnings = verify_claim_hashes(audit, layer)

    # The content-addressed half (plan §4.4.0 step 1). A digest mismatch means the
    # annotated BYTES were rewritten — legitimate after a re-audit or a corpus
    # migration, and not by itself a tampered claim, which is why it warns here
    # rather than refusing: verify_claim_hashes above is what refuses. Surfaced,
    # never healed — re-record deliberately with baseline_claims.py record.
    if digest_msg := check_report_digest(layer, audit_path):
        claim_warnings = [*claim_warnings, digest_msg]

    for w in claim_warnings:
        print(f"WARN: {w}", file=sys.stderr)
    if claim_errors:
        for e in claim_errors:
            print(f"ERROR: {e}", file=sys.stderr)
        print(
            "ERROR: refusing to build the cumulative report from a tampered "
            "baseline — the audit report's claims no longer match the "
            "layer's claim_hashes. Restore the report (or re-baseline "
            "'corrected' findings via"
            "harnessing/4-triage/track-findings/scripts/baseline_claims.py).",
            file=sys.stderr,
        )
        return 2

    # P1: carry cross-scan identity ON the event, before stamping the Merkle
    # root, so the fingerprint is inside the tree rather than reachable only
    # through metadata.finding_aliases (a mutable table, outside the tree, with
    # no verifier). Backfills historical events too — they are observations, and
    # the identity they observed is whatever the audit report records for that
    # finding. Existing values are never overwritten.
    _idx = fingerprint_index(audit)
    _stamped = sum(1 for e in layer.get("events") or [] if attach_identity(e, _idx))
    if _stamped:
        print(
            f"identity: stamped {_stamped} event(s) with fingerprint ({FINGERPRINT_ALGO_CURRENT})",
            file=sys.stderr,
        )

    ledger = engine.ledger.service(data_dir=layer_path.parent)
    layer_path.parent.mkdir(parents=True, exist_ok=True)
    ledger.store_layer(layer_path, layer)
    ledger.sign(layer_path)

    generated_at = args.generated_at or datetime.now(UTC).isoformat(timespec="seconds")

    if args.out:
        base = Path(args.out)
    else:
        stem = audit_path.name
        # "-container-audit.json" is deliberately absent: container
        # reports share the code audit's directory, so their cumulative
        # keeps the full stem (<image>-container-audit-findings-current,
        # via the ".json" fallback) to avoid clobbering the code audit's
        # <repo>-findings-current.
        for suffix in ("-security-audit.json", "-cloud-config-audit.json", ".json"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        base = audit_path.parent / f"{stem}-findings-current"

    layer_ref = os.path.relpath(layer_path, base.parent)
    try:
        report = build_cumulative(audit, layer, layer_ref, generated_at)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    # NOT with_suffix(): a dotted repo slug (3scale.github.io) makes the
    # basepath's "extension" .io-findings-current, which with_suffix would
    # replace — silently misnaming the outputs (3scale.github.json).
    json_path = base.parent / (base.name + ".json")
    md_path = base.parent / (base.name + ".md")
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report, layer), encoding="utf-8")

    ds = report["disposition_summary"]
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(
        f"Findings: {len(report.get('findings', []))} | "
        f"resolution: {ds['by_resolution']} | "
        f"validity: {ds['by_validity']} | "
        f"conflicts: {len(ds['conflicts'])} | "
        f"needs_review pending: {ds['needs_review_count']}"
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["build", "cumulative", *sys.argv[1:]]))
