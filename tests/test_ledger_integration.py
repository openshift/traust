#!/usr/bin/env python3
"""Unit tests for traust.cli.emit_triage_ledger_events and the
evidence-class merge rules it feeds (build_cumulative.py)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

from traust.cli.build_cumulative import derive_disposition
from traust.cli.emit_triage_ledger_events import (
    build_events,
    is_auto_accept,
    resolve_lambda,
    resolve_tenancy_profile,
)

WEIGHTS = {
    "version": "1",
    "default": 0.3,
    "single_tenant_dampening": 0.5,
    "weights": {"tenant-isolation": 1.0, "network-exposure": 0.9, "supply-chain": 0.5},
}

RECORDED = "2026-07-11T12:00:00+00:00"


def _tfinding(**kw):
    base = {
        "id": "f001",
        "orig_id": "TEST_REPO-abc1234-001",
        "title": "Cross-tenant token theft",
        "file": "pkg/scope.go",
        "line": 37,
        "category": "authorization",
        "claimed_severity": "critical",
        "verdict": "true_positive",
        "verify_verdict": "exploitable",
        "confidence": 9.0,
        "severity": "critical",
        "rationale": "reachable at handler.go:73",
        "vote_breakdown": {
            "true_positive": 3,
            "hardening": 0,
            "false_positive": 0,
            "cannot_verify": 0,
        },
        "refute_reasons": [],
        "exclusion_rule": None,
        "first_links": ["plugins/plugin.go:73"],
    }
    base.update(kw)
    return base


def _triage(findings):
    return {
        "triage_completed": "2026-07-09",
        "triage_context": {
            "environment": "multi-tenant platform",
            "votes_per_finding": 3,
            "repo": "/tmp/x",
            "harness_version": "0.27.0-abc1234",
        },
        "summary": {},
        "findings": findings,
    }


AUDIT_MT = {
    "metadata": {"commit": "abc1234def", "repository": "https://example.invalid/repo"},
    "peach_isolation_review": {"applicable": True},
}
AUDIT_ST = {"metadata": {}, "peach_isolation_review": {"applicable": False}}

LINT_CLEAN = {
    "f001": {"status": "ok"},
    "f002": {"status": "ok"},
    "f003": {"status": "ok"},
}


def _emit(findings, audit=AUDIT_MT, lint=LINT_CLEAN, override=None):
    return build_events(_triage(findings), audit, WEIGHTS, lint, "TRIAGE.json", RECORDED, override)


class TestWeights(unittest.TestCase):
    def test_category_lookup_multi_tenant(self):
        self.assertEqual(resolve_lambda(WEIGHTS, "tenant-isolation", "multi_tenant"), 1.0)
        self.assertEqual(resolve_lambda(WEIGHTS, "logging-monitoring", "multi_tenant"), 0.3)

    def test_single_tenant_dampening(self):
        self.assertEqual(resolve_lambda(WEIGHTS, "tenant-isolation", "single_tenant"), 0.5)

    def test_profile_from_peach(self):
        self.assertEqual(
            resolve_tenancy_profile(AUDIT_MT, None),
            ("multi_tenant", "peach_isolation_review.applicable"),
        )
        self.assertEqual(resolve_tenancy_profile(AUDIT_ST, None)[0], "single_tenant")
        self.assertEqual(
            resolve_tenancy_profile(AUDIT_ST, "multi_tenant"),
            ("multi_tenant", "override"),
        )


class TestEmitter(unittest.TestCase):
    def test_true_positive_emits_confirmed(self):
        out = _emit([_tfinding()])
        self.assertEqual(len(out["events"]), 1)
        e = out["events"][0]
        self.assertEqual(e["disposition"]["validity"], "confirmed")
        self.assertEqual(e["source"]["type"], "triage_report")
        self.assertEqual(e["source"]["actor"]["kind"], "machine")

    def test_needs_manual_test_tp_queues_instead_of_event(self):
        out = _emit([_tfinding(verify_verdict="needs_manual_test")])
        self.assertEqual(out["events"], [])
        self.assertEqual(len(out["needs_review"]), 1)
        item = out["needs_review"][0]
        self.assertEqual(item["queue_reason"], "needs_manual_test")
        self.assertEqual(item["suggested_disposition"], {"validity": "confirmed"})

    def test_hardening_records_emission_time_lambda(self):
        out = _emit(
            [
                _tfinding(
                    verdict="hardening",
                    verify_verdict="hardening",
                    category="tenant-isolation",
                    severity=None,
                    exclusion_rule="13",
                )
            ]
        )
        e = out["events"][0]
        self.assertEqual(e["disposition"]["validity"], "hardening")
        rw = e["risk_weight"]
        self.assertEqual(rw["lambda"], 1.0)
        self.assertEqual(rw["tenancy_profile"], "multi_tenant")
        self.assertEqual(rw["profile_source"], "peach_isolation_review.applicable")
        self.assertEqual(rw["weights_version"], "1")

    def test_undetermined_emits_queue_item_not_event(self):
        out = _emit(
            [
                _tfinding(
                    verdict="undetermined",
                    severity=None,
                    verify_verdict="needs_manual_test",
                    confidence=0,
                )
            ]
        )
        self.assertEqual(out["events"], [])
        self.assertEqual(len(out["needs_review"]), 1)
        self.assertEqual(out["needs_review"][0]["queue_reason"], "undetermined_finding")

    def test_duplicate_emits_nothing(self):
        out = _emit([_tfinding(verdict="duplicate", duplicate_of="f009")])
        self.assertEqual(out["events"], [])
        self.assertEqual(out["skipped"], [])

    def test_non_canonical_orig_id_skipped(self):
        out = _emit([_tfinding(orig_id="weird-id-7")])
        self.assertEqual(out["events"], [])
        self.assertTrue(out["skipped"])


def _fp(**kw):
    base = _tfinding(
        verdict="false_positive",
        verify_verdict="refuted",
        severity=None,
        claimed_severity="low",
        confidence=8.5,
        exclusion_rule="2",
        refute_reasons=["already_handled"],
        vote_breakdown={
            "true_positive": 0,
            "hardening": 0,
            "false_positive": 3,
            "cannot_verify": 0,
        },
    )
    base.update(kw)
    return base


class TestFalsePositiveTiers(unittest.TestCase):
    def test_auto_accept_bar(self):
        self.assertTrue(is_auto_accept(_fp(), LINT_CLEAN))
        # medium+ claimed severity -> countersign
        self.assertFalse(is_auto_accept(_fp(claimed_severity="medium"), LINT_CLEAN))
        # dissenting TP vote -> countersign
        self.assertFalse(
            is_auto_accept(
                _fp(
                    vote_breakdown={
                        "true_positive": 1,
                        "hardening": 0,
                        "false_positive": 2,
                        "cannot_verify": 0,
                    }
                ),
                LINT_CLEAN,
            )
        )
        # low confidence -> countersign
        self.assertFalse(is_auto_accept(_fp(confidence=7.0), LINT_CLEAN))

    def test_auto_accept_requires_two_concurring_fp_votes(self):
        # P0-2 (docs-verification 2026-07-31): a lone FP vote — the
        # anchor_absent reduced-tier shape — is not corroboration
        self.assertFalse(
            is_auto_accept(
                _fp(
                    vote_breakdown={
                        "true_positive": 0,
                        "hardening": 0,
                        "false_positive": 1,
                        "cannot_verify": 2,
                    }
                ),
                LINT_CLEAN,
            )
        )
        self.assertTrue(
            is_auto_accept(
                _fp(
                    vote_breakdown={
                        "true_positive": 0,
                        "hardening": 0,
                        "false_positive": 2,
                        "cannot_verify": 1,
                    }
                ),
                LINT_CLEAN,
            )
        )
        # lint flagged -> countersign
        self.assertFalse(is_auto_accept(_fp(), {"f001": {"status": "broken_citations"}}))
        # no lint results supplied -> conservative countersign
        self.assertFalse(is_auto_accept(_fp(), None))

    def test_auto_accept_marks_event_and_register_tier(self):
        out = _emit([_fp()])
        e = out["events"][0]
        self.assertTrue(e.get("auto_accept_tier"))
        self.assertEqual(out["register"][0]["tier"], "auto_accept")

    def test_countersign_fp_unmarked_and_registered(self):
        out = _emit([_fp(claimed_severity="high")])
        self.assertNotIn("auto_accept_tier", out["events"][0])
        self.assertEqual(out["register"][0]["tier"], "countersign")

    def test_every_fp_lands_in_refuted_register(self):
        out = _emit(
            [
                _fp(),
                _fp(id="f002", orig_id="TEST_REPO-abc1234-002", claimed_severity="high"),
            ]
        )
        self.assertEqual(len(out["register"]), 2)
        self.assertIn("Falsifiable", out["register"][0]["note"])


def _levent(
    validity,
    kind="machine",
    source_type="triage_report",
    at=RECORDED,
    identity="triage/0.27.0",
    ldap=False,
    **extra,
):
    e = {
        "event_id": "0" * 64,
        "finding_ref": "TEST_REPO-abc1234-001",
        "recorded_at": at,
        "occurred_at": at,
        "source": {
            "type": source_type,
            "ref": "x",
            "actor": {"kind": kind, "identity": identity, "ldap_verified": ldap},
        },
        "disposition": {"validity": validity},
        "rationale": "ten characters at least",
    }
    e.update(extra)
    return e


class TestMergePrecedence(unittest.TestCase):
    FINDING = {"id": "TEST_REPO-abc1234-001", "validation_status": "not_verified"}

    def _derive(self, events):
        return derive_disposition(self.FINDING, events, RECORDED)

    def test_triage_confirmed_sets_validity(self):
        d = self._derive([_levent("confirmed")])
        self.assertEqual(d["validity"], "confirmed")
        self.assertEqual(d["assurance"], "machine_verified")

    def test_triage_hardening_sets_validity(self):
        d = self._derive([_levent("hardening")])
        self.assertEqual(d["validity"], "hardening")

    def test_countersign_fp_pends(self):
        d = self._derive([_levent("false_positive")])
        self.assertEqual(d["validity"], "not_verified")
        self.assertTrue(d["refuted_awaiting_signoff"])

    def test_auto_accept_fp_sets_validity(self):
        d = self._derive([_levent("false_positive", auto_accept_tier=True)])
        self.assertEqual(d["validity"], "false_positive")
        self.assertNotIn("refuted_awaiting_signoff", d)

    def test_two_person_rule_blocks_single_reassertion(self):
        events = [
            _levent(
                "confirmed",
                source_type="validation_report",
                at="2026-07-05T10:00:00+00:00",
                identity="validate-findings",
            ),
            _levent(
                "false_positive",
                kind="human",
                source_type="interactive",
                ldap=True,
                at="2026-07-06T10:00:00+00:00",
                identity="alice",
            ),
        ]
        d = self._derive(events)
        self.assertEqual(d["validity"], "confirmed")
        self.assertTrue(d["fp_reassertion_blocked"])

    def test_two_person_rule_allows_dual_reassertion(self):
        events = [
            _levent(
                "confirmed",
                source_type="validation_report",
                at="2026-07-05T10:00:00+00:00",
                identity="validate-findings",
            ),
            _levent(
                "false_positive",
                kind="human",
                source_type="interactive",
                ldap=True,
                at="2026-07-06T10:00:00+00:00",
                identity="alice",
            ),
            _levent(
                "false_positive",
                kind="human",
                source_type="interactive",
                ldap=True,
                at="2026-07-07T10:00:00+00:00",
                identity="bob",
            ),
        ]
        d = self._derive(events)
        self.assertEqual(d["validity"], "false_positive")
        self.assertNotIn("fp_overridden", d)


@pytest.mark.requires_ledger
class TestCLIEndToEnd(unittest.TestCase):
    def test_emit_append_idempotent_and_layer_valid(self):
        import subprocess

        weights_path = (
            Path(__file__).parent.parent / "config" / "hardening-risk-weights.example.json"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            triage = _triage(
                [
                    _tfinding(),
                    _tfinding(
                        id="f002",
                        orig_id="TEST_REPO-abc1234-002",
                        verdict="hardening",
                        verify_verdict="hardening",
                        severity=None,
                        exclusion_rule="13",
                        category="network-exposure",
                    ),
                    _fp(id="f003", orig_id="TEST_REPO-abc1234-003"),
                ]
            )
            (tmp / "TRIAGE.json").write_text(json.dumps(triage))
            (tmp / "audit-security-audit.json").write_text(json.dumps(AUDIT_MT))
            lint = {"results": [{"id": i, "status": "ok"} for i in ("f001", "f002", "f003")]}
            (tmp / "lint.json").write_text(json.dumps(lint))

            cmd = [
                sys.executable,
                "-m",
                "traust.cli.emit_triage_ledger_events",
                str(tmp / "TRIAGE.json"),
                "--audit",
                str(tmp / "audit-security-audit.json"),
                "--weights",
                str(weights_path),
                "--lint",
                str(tmp / "lint.json"),
                "--recorded-at",
                RECORDED,
            ]
            r1 = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(r1.returncode, 0, r1.stderr)
            layer_path = tmp / "audit-findings-layer.json"
            layer1 = json.loads(layer_path.read_text())
            self.assertEqual(len(layer1["events"]), 3)

            # second run appends nothing (idempotent)
            r2 = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            layer2 = json.loads(layer_path.read_text())
            self.assertEqual(len(layer2["events"]), 3)
            self.assertIn("merkle_root", layer2["metadata"])
            self.assertEqual(layer2["metadata"]["merkle_size"], 3)
            self.assertIn("3 already present", r2.stdout)

            register = json.loads((tmp / "audit-refuted-register.json").read_text())
            self.assertEqual(len(register["entries"]), 1)


if __name__ == "__main__":
    unittest.main()
