#!/usr/bin/env python3
"""Unit tests for the track-findings merge engine (build_cumulative.py)."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

import pytest
from traust_engine.ledger import compute_event_id

from traust.cli.build_cumulative import (
    build_cumulative,
    render_markdown,
)

GENERATED_AT = "2026-07-10T12:00:00+00:00"
F1 = "TEST_WIDGET-abcdef0-001"
F2 = "TEST_WIDGET-abcdef0-002"


def _audit():
    return {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-05-21",
            "scope": "First-party Go source, Kubernetes manifests",
            "commit": "abcdef0123456789abcdef0123456789abcdef01",
            "additional": {"harness_version": "0.18.0-1234567"},
        },
        "findings": [
            {
                "id": F1,
                "title": "SSRF via Webhook Annotation",
                "severity": "high",
                "validation_status": "not_verified",
            },
            {
                "id": F2,
                "title": "Unbounded Request Body Read",
                "severity": "medium",
                "validation_status": "not_verified",
            },
        ],
    }


def _event(
    finding_ref,
    validity=None,
    resolution=None,
    *,
    kind="human",
    source_type="mr_comment",
    ref="https://example.com/mr/17#note_1",
    at="2026-07-01T10:00:00+00:00",
    identity="jdoe@example.com",
    ldap=True,
):
    actor = {"kind": kind}
    if identity:
        actor["identity"] = identity
    if kind == "human":
        actor["ldap_verified"] = ldap
    disposition = {}
    if validity:
        disposition["validity"] = validity
    if resolution:
        disposition["resolution"] = resolution
    return {
        "event_id": compute_event_id(ref, finding_ref, validity, resolution),
        "finding_ref": finding_ref,
        "recorded_at": at,
        "source": {"type": source_type, "ref": ref, "actor": actor},
        "disposition": disposition,
        "rationale": "Because the input is validated upstream in the webhook.",
    }


def _layer(events=(), needs_review=()):
    return {
        "metadata": {
            "audit_report": "test-widget-security-audit.json",
            "audit_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "repository": "https://github.com/example/test-widget",
            "created": "2026-06-01T00:00:00+00:00",
            "harness_version": "0.18.0-1234567",
        },
        "events": list(events),
        "needs_review": list(needs_review),
    }


def _build(events=(), needs_review=()):
    return build_cumulative(
        _audit(),
        _layer(events, needs_review),
        "test-widget-findings-layer.json",
        GENERATED_AT,
    )


def _finding(report, fid):
    return next(f for f in report["findings"] if f["id"] == fid)


class TestDeriveDisposition(unittest.TestCase):
    def test_no_events_defaults(self):
        report = _build()
        d = _finding(report, F1)["disposition"]
        self.assertEqual(d["validity"], "not_verified")
        self.assertEqual(d["resolution"], "open")
        self.assertEqual(d["events"], [])
        self.assertEqual(d["last_updated"], GENERATED_AT)
        self.assertNotIn("conflict", d)

    def test_human_confirmed_sets_validity(self):
        report = _build([_event(F1, validity="confirmed")])
        f = _finding(report, F1)
        self.assertEqual(f["disposition"]["validity"], "confirmed")
        self.assertEqual(f["validation_status"], "confirmed")

    def test_machine_confirmed_sets_validity(self):
        report = _build(
            [
                _event(
                    F1,
                    validity="confirmed",
                    kind="machine",
                    source_type="validation_report",
                    ref="v.json",
                    identity="validate-findings",
                )
            ]
        )
        self.assertEqual(_finding(report, F1)["validation_status"], "confirmed")

    def test_machine_refuted_awaits_signoff(self):
        report = _build(
            [
                _event(
                    F1,
                    validity="false_positive",
                    kind="machine",
                    source_type="validation_report",
                    ref="v.json",
                    identity="validate-findings",
                )
            ]
        )
        f = _finding(report, F1)
        self.assertEqual(f["validation_status"], "not_verified")
        self.assertTrue(f["disposition"]["refuted_awaiting_signoff"])

    def test_human_countersign_clears_awaiting(self):
        report = _build(
            [
                _event(
                    F1,
                    validity="false_positive",
                    kind="machine",
                    source_type="validation_report",
                    ref="v.json",
                    identity="validate-findings",
                    at="2026-07-01T10:00:00+00:00",
                ),
                _event(
                    F1,
                    validity="false_positive",
                    source_type="interactive",
                    ref="interactive:2026-07-02",
                    at="2026-07-02T10:00:00+00:00",
                ),
            ]
        )
        f = _finding(report, F1)
        self.assertEqual(f["validation_status"], "false_positive")
        self.assertNotIn("refuted_awaiting_signoff", f["disposition"])

    def test_human_fp_on_verification_report_sets_validity(self):
        # Regression (pre-0.200): event_class keyed on source.type before
        # actor.kind, so a human false_positive recorded on a
        # verification_report event — the exact shape SKILL.md prescribes
        # for verification FP verdicts naming a verified human — was
        # class 1, filtered out of exec_decisive (FPs never decide there),
        # absent from human_v, and the finding pended forever.
        report = _build(
            [
                _event(
                    F1,
                    validity="false_positive",
                    source_type="verification_report",
                    ref="rv.json",
                    at="2026-07-02T10:00:00+00:00",
                ),
            ]
        )
        f = _finding(report, F1)
        self.assertEqual(f["validation_status"], "false_positive")
        self.assertNotIn("refuted_awaiting_signoff", f["disposition"])
        self.assertEqual(f["disposition"]["assurance"], "human_reviewed")

    def test_execution_proof_overrides_human_fp(self):
        # Evidence-class precedence (harness >= 0.27.0): an execution-
        # verified confirmation (class 1) overturns a human static
        # false-positive assertion (class 2) — loudly, via fp_overridden.
        report = _build(
            [
                _event(
                    F1,
                    validity="false_positive",
                    source_type="interactive",
                    ref="interactive:2026-07-01",
                    at="2026-07-01T10:00:00+00:00",
                ),
                _event(
                    F1,
                    validity="confirmed",
                    kind="machine",
                    source_type="validation_report",
                    ref="v.json",
                    identity="validate-findings",
                    at="2026-07-05T10:00:00+00:00",
                ),
            ]
        )
        f = _finding(report, F1)
        self.assertEqual(f["validation_status"], "confirmed")
        self.assertTrue(f["disposition"]["fp_overridden"])
        self.assertEqual(f["disposition"]["assurance"], "execution_proven")
        self.assertTrue(f["disposition"]["conflict"])

    def test_human_outranks_later_machine_static(self):
        # Within static evidence the old rule stands: a human determination
        # outranks a later machine static (triage_report) verdict.
        report = _build(
            [
                _event(
                    F1,
                    validity="false_positive",
                    source_type="interactive",
                    ref="interactive:2026-07-01",
                    at="2026-07-01T10:00:00+00:00",
                ),
                _event(
                    F1,
                    validity="confirmed",
                    kind="machine",
                    source_type="triage_report",
                    ref="t.json",
                    identity="triage/0.27.0",
                    at="2026-07-05T10:00:00+00:00",
                ),
            ]
        )
        f = _finding(report, F1)
        self.assertEqual(f["validation_status"], "false_positive")
        self.assertTrue(f["disposition"]["conflict"])
        self.assertEqual(f["disposition"]["assurance"], "human_reviewed")

    def test_conflict_detected_and_summarized(self):
        report = _build(
            [
                _event(F1, validity="confirmed", ref="mr#1", at="2026-07-01T10:00:00+00:00"),
                _event(F1, validity="false_positive", ref="mr#2", at="2026-07-02T10:00:00+00:00"),
            ]
        )
        self.assertTrue(_finding(report, F1)["disposition"]["conflict"])
        self.assertEqual(report["disposition_summary"]["conflicts"], [F1])

    def test_verification_report_outranks_later_comment(self):
        report = _build(
            [
                _event(
                    F1,
                    resolution="resolved",
                    kind="machine",
                    source_type="verification_report",
                    ref="rv.json",
                    identity="verify-remediation",
                    at="2026-07-01T10:00:00+00:00",
                ),
                _event(
                    F1, resolution="fix_in_progress", ref="mr#9", at="2026-07-05T10:00:00+00:00"
                ),
            ]
        )
        self.assertEqual(_finding(report, F1)["disposition"]["resolution"], "resolved")

    def test_latest_wins_within_tier(self):
        report = _build(
            [
                _event(
                    F1,
                    resolution="partially_resolved",
                    kind="machine",
                    source_type="verification_report",
                    ref="rv1.json",
                    identity="verify-remediation",
                    at="2026-07-01T10:00:00+00:00",
                ),
                _event(
                    F1,
                    resolution="resolved",
                    kind="machine",
                    source_type="verification_report",
                    ref="rv2.json",
                    identity="verify-remediation",
                    at="2026-07-05T10:00:00+00:00",
                ),
            ]
        )
        self.assertEqual(_finding(report, F1)["disposition"]["resolution"], "resolved")

    def test_jira_outranks_comment_but_not_verification(self):
        report = _build(
            [
                _event(
                    F1,
                    resolution="risk_accepted",
                    source_type="jira",
                    ref="OSPRH-1",
                    at="2026-07-01T10:00:00+00:00",
                ),
                _event(
                    F1, resolution="fix_in_progress", ref="mr#9", at="2026-07-05T10:00:00+00:00"
                ),
            ]
        )
        self.assertEqual(_finding(report, F1)["disposition"]["resolution"], "risk_accepted")


class TestBuildCumulative(unittest.TestCase):
    def test_unknown_finding_ref_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _build([_event("GHOST-abcdef0-001", validity="confirmed")])
        self.assertIn("GHOST-abcdef0-001", str(ctx.exception))

    def test_summary_counts(self):
        report = _build(
            [
                _event(F1, validity="confirmed", resolution="resolved"),
            ]
        )
        ds = report["disposition_summary"]
        self.assertEqual(ds["by_resolution"]["resolved"], 1)
        self.assertEqual(ds["by_resolution"]["open"], 1)
        self.assertEqual(ds["by_validity"]["confirmed"], 1)
        self.assertEqual(ds["by_validity"]["not_verified"], 1)

    def test_needs_review_count_pending_only(self):
        items = [
            {
                "queued_at": "2026-07-01T00:00:00+00:00",
                "source_ref": "mr#3",
                "quote": "maybe fp?",
                "author": "guest",
                "status": "pending",
            },
            {
                "queued_at": "2026-07-01T00:00:00+00:00",
                "source_ref": "mr#4",
                "quote": "resolved I think",
                "author": "guest",
                "status": "rejected",
            },
        ]
        report = _build(needs_review=items)
        self.assertEqual(report["disposition_summary"]["needs_review_count"], 1)

    def test_title_and_metadata_stamped(self):
        report = _build()
        self.assertTrue(report["title"].endswith("Cumulative Findings Status"))
        cumulative = report["metadata"]["additional"]["cumulative"]
        self.assertEqual(cumulative["original_report_date"], "2026-05-21")
        self.assertEqual(report["metadata"]["date"], "2026-07-10")

    def test_original_audit_not_mutated(self):
        audit = _audit()
        snapshot = copy.deepcopy(audit)
        build_cumulative(
            audit, _layer([_event(F1, validity="confirmed")]), "layer.json", GENERATED_AT
        )
        self.assertEqual(audit, snapshot)

    def test_deterministic_output(self):
        events = [_event(F1, validity="confirmed", resolution="resolved")]
        a = build_cumulative(_audit(), _layer(events), "l.json", GENERATED_AT)
        b = build_cumulative(_audit(), _layer(events), "l.json", GENERATED_AT)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_namespaced_confirmed_alias_transfers_history(self):
        # finding_identity.py rebaseline namespaces legacy old ids with
        # their source-report slug ("<slug>:FIND-NNN"); events keep the
        # bare id. A confirmed namespaced mapping must transfer history.
        layer = _layer([_event("FIND-001", validity="confirmed", resolution="resolved")])
        layer["metadata"]["finding_aliases"] = {
            "test-widget:FIND-001": {
                "new_id": F1,
                "matched_by": "fingerprint",
                "confirmed": True,
                "from_report": "test-widget-security-audit.json",
            },
        }
        report = build_cumulative(_audit(), layer, "l.json", GENERATED_AT)
        self.assertEqual(_finding(report, F1)["validation_status"], "confirmed")

    def test_ambiguous_namespaced_alias_parks_not_guesses(self):
        # Two branch variants alias the same bare legacy id to different
        # successors: the event must park (not transfer to either).
        layer = _layer([_event("FIND-001", validity="confirmed")])
        layer["metadata"]["finding_aliases"] = {
            "variant-a:FIND-001": {
                "new_id": F1,
                "matched_by": "fingerprint",
                "confirmed": True,
                "from_report": "a.json",
            },
            "variant-b:FIND-001": {
                "new_id": F2,
                "matched_by": "fingerprint",
                "confirmed": True,
                "from_report": "b.json",
            },
        }
        report = build_cumulative(_audit(), layer, "l.json", GENERATED_AT)
        self.assertEqual(_finding(report, F1)["validation_status"], "not_verified")
        self.assertEqual(_finding(report, F2)["validation_status"], "not_verified")

    def test_unmatched_old_with_pending_review_parks(self):
        # rebaseline queues unmatched old ids in needs_review ("history
        # stays under the old id until a human maps or closes it") — the
        # build must park those events, not refuse the rebuild.
        items = [
            {
                "queued_at": "2026-07-01T00:00:00+00:00",
                "source_ref": "rebaseline:test-widget-security-audit.json",
                "quote": "FIND-009 has no match — fixed, moved, or dropped?",
                "author": "finding_identity/rebaseline",
                "suggested_finding_ref": "FIND-009",
                "queue_reason": "rebaseline_unmatched",
                "status": "pending",
            }
        ]
        report = _build([_event("FIND-009", validity="confirmed")], needs_review=items)
        self.assertEqual(report["disposition_summary"]["by_validity"]["not_verified"], 2)

    def test_unmatched_old_without_review_still_raises(self):
        # The tamper guard: an unknown ref with neither an alias nor a
        # queued rebaseline decision must still fail loudly.
        with self.assertRaises(ValueError):
            _build([_event("FIND-009", validity="confirmed")])

    def test_merkle_metadata_on_layer(self):
        from traust_ledger.client import LedgerClient

        layer = _layer([_event(F1, validity="confirmed")])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test-findings-layer.json"
            p.write_text(json.dumps(layer), encoding="utf-8")
            client = LedgerClient(token="test-token", data_dir=td)
            client.sign("test-findings-layer")
            meta = json.loads(p.read_text())["metadata"]
        self.assertEqual(meta["merkle_epoch"], 0)
        self.assertEqual(meta["merkle_algorithm"], "sha256")
        self.assertEqual(meta["merkle_size"], 1)
        self.assertRegex(meta["merkle_root"], r"^[0-9a-f]{64}$")


class TestRenderMarkdown(unittest.TestCase):
    def test_sections_present(self):
        events = [
            _event(F1, validity="confirmed", ref="mr#1", at="2026-07-01T10:00:00+00:00"),
            _event(F1, validity="false_positive", ref="mr#2", at="2026-07-02T10:00:00+00:00"),
            _event(
                F2,
                validity="false_positive",
                kind="machine",
                source_type="validation_report",
                ref="v.json",
                identity="validate-findings",
                at="2026-07-03T10:00:00+00:00",
            ),
        ]
        review = [
            {
                "queued_at": "2026-07-01T00:00:00+00:00",
                "source_ref": "mr#5",
                "quote": "isn't 001 maybe a false positive?",
                "author": "guest",
                "status": "pending",
                "queue_reason": "ambiguous_statement",
            }
        ]
        layer = _layer(events, review)
        report = build_cumulative(_audit(), layer, "l.json", GENERATED_AT)
        md = render_markdown(report, layer)

        self.assertIn("## Disposition Summary", md)
        self.assertIn("Conflicts — needs human re-review", md)
        self.assertIn("awaiting human sign-off", md)
        self.assertIn("Needs review — 1 pending", md)
        self.assertIn("isn't 001 maybe a false positive?", md)
        self.assertIn("## Event History", md)
        self.assertIn(F1, md)
        self.assertIn(F2, md)

    def test_quiet_report_has_no_alert_sections(self):
        layer = _layer()
        report = build_cumulative(_audit(), layer, "l.json", GENERATED_AT)
        md = render_markdown(report, layer)
        self.assertNotIn("Conflicts", md)
        self.assertNotIn("awaiting human sign-off", md)
        self.assertNotIn("Needs review", md)
        self.assertNotIn("## Event History", md)


@pytest.mark.requires_ledger
class TestContainerBaselineCli(unittest.TestCase):
    """Container-audit baselines keep their full stem in the CLI's
    default output naming: the report shares a directory with the code
    audit, so <image>-container-audit-findings-current must never
    collapse to <image>-findings-current (which belongs to the code
    audit)."""

    def test_container_stem_not_stripped(self):
        import tempfile
        from pathlib import Path

        import traust.cli.build_cumulative as bc

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            audit_p = base / "widget-container-audit.json"
            layer_p = base / "widget-container-audit-findings-layer.json"
            audit_p.write_text(json.dumps(_audit()), encoding="utf-8")
            layer = _layer()
            layer["metadata"]["audit_report"] = audit_p.name
            layer_p.write_text(json.dumps(layer), encoding="utf-8")

            argv = sys.argv
            sys.argv = [
                "build_cumulative.py",
                str(audit_p),
                str(layer_p),
                "--generated-at",
                GENERATED_AT,
            ]
            try:
                rc = bc.main()
            finally:
                sys.argv = argv
            self.assertEqual(rc, 0)
            self.assertTrue((base / "widget-container-audit-findings-current.json").is_file())
            self.assertFalse((base / "widget-findings-current.json").exists())


if __name__ == "__main__":
    unittest.main()
