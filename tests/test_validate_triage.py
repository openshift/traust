#!/usr/bin/env python3
"""Unit tests for schema/triage.schema.json and cross_validate_triage."""

import unittest
from pathlib import Path

import jsonschema
from traust_contracts.paths import schema_path as _schema_path
from traust_engine.reporting.validate import (
    ValidationResult,
    build_registry,
    cross_validate_triage,
    detect_schema_path,
    load_schema,
)

SCHEMA = load_schema(_schema_path("triage"))
REGISTRY = build_registry()


def _finding(**kw):
    base = {
        "id": "f001",
        "orig_id": "TEST_REPO-abc1234-001",
        "title": "Cross-tenant token theft via scope gap",
        "file": "pkg/rbac/scope.go",
        "line": 37,
        "category": "authorization",
        "claimed_severity": "critical",
        "verdict": "true_positive",
        "verify_verdict": "exploitable",
        "confidence": 9.0,
        "severity": "critical",
        "rationale": "reachable at handler.go:73; no ownership check",
        "vote_breakdown": {
            "true_positive": 3,
            "hardening": 0,
            "false_positive": 0,
            "cannot_verify": 0,
        },
        "refute_reasons": [],
        "exclusion_rule": None,
        "first_links": ["plugins/credentials/plugin.go:73"],
        "duplicate_of": None,
        "owner_hint": "@maintainers (CODEOWNERS)",
    }
    base.update(kw)
    return base


def _valid_triage():
    return {
        "triage_completed": "2026-07-09",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant internet-facing platform",
            "votes_per_finding": 3,
            "repo": "/tmp/clone",
            "harness_version": "0.24.0-e240e87",
        },
        "summary": {
            "input_count": 3,
            "true_positives": 1,
            "hardening": 1,
            "false_positives": 1,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            _finding(),
            _finding(
                id="f002",
                orig_id="TEST_REPO-abc1234-002",
                title="CORS wildcard on public API",
                verdict="hardening",
                verify_verdict="hardening",
                severity=None,
                exclusion_rule="13",
                confidence=8.0,
                vote_breakdown={
                    "true_positive": 0,
                    "hardening": 3,
                    "false_positive": 0,
                    "cannot_verify": 0,
                },
            ),
            _finding(
                id="f003",
                orig_id="TEST_REPO-abc1234-003",
                title="Dev-overlay default credentials",
                verdict="false_positive",
                verify_verdict="refuted",
                severity=None,
                exclusion_rule="2",
                confidence=8.0,
                refute_reasons=["intentional_behavior"],
                vote_breakdown={
                    "true_positive": 0,
                    "hardening": 0,
                    "false_positive": 3,
                    "cannot_verify": 0,
                },
                owner_hint=None,
            ),
        ],
    }


def _schema_errors(doc):
    v = jsonschema.Draft202012Validator(
        SCHEMA, registry=REGISTRY, format_checker=jsonschema.FormatChecker()
    )
    return [e.message for e in v.iter_errors(doc)]


def _cross(doc):
    result = ValidationResult(file_path="TRIAGE.json")
    cross_validate_triage(doc, result)
    return result


class TestTriageSchema(unittest.TestCase):
    def test_valid_document_passes(self):
        self.assertEqual(_schema_errors(_valid_triage()), [])

    def test_verdict_enum_rejects_unknown(self):
        doc = _valid_triage()
        doc["findings"][0]["verdict"] = "probably_fine"
        self.assertTrue(_schema_errors(doc))

    def test_harness_version_required(self):
        doc = _valid_triage()
        del doc["triage_context"]["harness_version"]
        self.assertTrue(any("harness_version" in e for e in _schema_errors(doc)))

    def test_severity_vocabulary_matches_report_schema(self):
        doc = _valid_triage()
        doc["findings"][0]["severity"] = "HIGH"  # uppercase rejected
        self.assertTrue(_schema_errors(doc))

    def test_vote_breakdown_requires_hardening_key(self):
        doc = _valid_triage()
        del doc["findings"][0]["vote_breakdown"]["hardening"]
        # rejected via the anyOf wrapper, so assert rejection rather than
        # a specific message
        self.assertTrue(_schema_errors(doc))

    def test_unknown_finding_field_rejected(self):
        doc = _valid_triage()
        doc["findings"][0]["novel_field"] = 1
        self.assertTrue(_schema_errors(doc))

    def test_recommendation_carried_through_accepted(self):
        doc = _valid_triage()
        doc["findings"][0]["recommendation"] = "Add an ownership check before issuing the token."
        self.assertEqual(_schema_errors(doc), [])

    def test_recommendation_null_accepted(self):
        doc = _valid_triage()
        doc["findings"][0]["recommendation"] = None
        self.assertEqual(_schema_errors(doc), [])


class TestTriageCrossValidation(unittest.TestCase):
    def test_valid_document_no_errors(self):
        r = _cross(_valid_triage())
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])

    def test_rule13_false_positive_rejected(self):
        doc = _valid_triage()
        doc["findings"][2]["exclusion_rule"] = "13"
        r = _cross(doc)
        self.assertTrue(any("never false positives" in e for e in r.errors))

    def test_hardening_without_rule13_rejected(self):
        doc = _valid_triage()
        doc["findings"][1]["exclusion_rule"] = "3"
        r = _cross(doc)
        self.assertTrue(any("requires exclusion_rule 13" in e for e in r.errors))

    def test_false_positive_needs_refute_reasons(self):
        doc = _valid_triage()
        doc["findings"][2]["refute_reasons"] = []
        r = _cross(doc)
        self.assertTrue(any("empty refute_reasons" in e for e in r.errors))

    def test_summary_count_mismatch(self):
        doc = _valid_triage()
        doc["summary"]["hardening"] = 2
        r = _cross(doc)
        self.assertTrue(any("summary.hardening" in e for e in r.errors))

    def test_by_severity_mismatch(self):
        doc = _valid_triage()
        doc["summary"]["by_severity"]["critical"] = 0
        r = _cross(doc)
        self.assertTrue(any("by_severity[critical]" in e for e in r.errors))

    def test_severity_on_non_tp_rejected(self):
        doc = _valid_triage()
        doc["findings"][1]["severity"] = "low"
        r = _cross(doc)
        self.assertTrue(any("true positives only" in e for e in r.errors))

    def test_undetermined_with_confidence_rejected(self):
        doc = _valid_triage()
        doc["findings"][2].update(
            verdict="undetermined", exclusion_rule=None, confidence=7.0, verify_verdict=None
        )
        doc["summary"].update(false_positives=0, undetermined=1)
        r = _cross(doc)
        self.assertTrue(any("undetermined" in e for e in r.errors))

    def test_undetermined_needs_manual_test_ok(self):
        doc = _valid_triage()
        doc["findings"][2].update(
            verdict="undetermined",
            exclusion_rule=None,
            confidence=0,
            refute_reasons=["unlocatable"],
            verify_verdict="needs_manual_test",
        )
        doc["summary"].update(false_positives=0, undetermined=1)
        r = _cross(doc)
        self.assertEqual(r.errors, [])

    def test_duplicate_must_reference_known_canonical(self):
        doc = _valid_triage()
        doc["findings"][2].update(verdict="duplicate", duplicate_of="f999", exclusion_rule=None)
        doc["summary"].update(false_positives=0, duplicates=1)
        r = _cross(doc)
        self.assertTrue(any("not a known finding id" in e for e in r.errors))

    def test_majority_contradiction_warns(self):
        doc = _valid_triage()
        doc["findings"][0]["vote_breakdown"] = {
            "true_positive": 1,
            "hardening": 0,
            "false_positive": 2,
            "cannot_verify": 0,
        }
        r = _cross(doc)
        self.assertTrue(any("contradicts strict vote majority" in w for w in r.warnings))

    def test_noncanonical_orig_id_in_canonical_batch_warns(self):
        doc = _valid_triage()
        doc["findings"][2]["orig_id"] = "SOME-weird-id"
        r = _cross(doc)
        self.assertTrue(any("not canonical" in w for w in r.warnings))

    def test_duplicate_ids_rejected(self):
        doc = _valid_triage()
        doc["findings"][1]["id"] = "f001"
        r = _cross(doc)
        self.assertTrue(any("Duplicate triage finding ID" in e for e in r.errors))


class TestSchemaAutoDetection(unittest.TestCase):
    def test_triage_filenames_detected(self):
        self.assertIsNotNone(detect_schema_path(Path("TRIAGE.json")))
        self.assertIsNotNone(detect_schema_path(Path("acp-triage.json")))

    def test_other_filenames_fall_through(self):
        self.assertIsNone(detect_schema_path(Path("x-security-audit.json")))
        self.assertIsNone(detect_schema_path(Path("x-findings-current.json")))


if __name__ == "__main__":
    unittest.main()
