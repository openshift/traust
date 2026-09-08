#!/usr/bin/env python3
"""Unit tests for schema/vuln-findings.schema.json and cross_validate_vuln_findings."""

import copy
import unittest
from pathlib import Path

import jsonschema
from traust_contracts.paths import schema_path as _schema_path
from traust_engine.reporting.validate import (
    ValidationResult,
    build_registry,
    cross_validate_vuln_findings,
    detect_schema_path,
    load_schema,
)

SCHEMA = load_schema(_schema_path("vuln-findings"))
REGISTRY = build_registry()


def _finding(**kw):
    base = {
        "id": "EXAMPLE_REPO-abc1234-001",
        "scanner_ref": "F-01-01",
        "file": "pkg/server/handler.go",
        "line": 73,
        "category": "command-injection",
        "cwe": "CWE-78",
        "severity": "high",
        "confidence": 0.9,
        "title": "Command injection via unsanitized template value",
        "description": (
            "The handler passes the request's template parameter into "
            "exec.Command without sanitization; untrusted input reaches the "
            "shell at handler.go:73."
        ),
        "exploit_scenario": "POST a template containing $(id) to /render.",
        "recommendation": "Use exec.Command with a fixed argv; never a shell string.",
        "confidence_reason": "Direct data flow from request to sink.",
    }
    base.update(kw)
    return base


def _valid_doc():
    return {
        "target": "targets/example-repo",
        "scanned_at": "2026-07-12T20:00:00Z",
        "focus_areas": ["HTTP handlers (pkg/server) — render, upload"],
        "metadata": {
            "repo": "example-repo",
            "repo_slug": "EXAMPLE_REPO",
            "scanned_ref": "abc1234",
            "harness_version": "0.38.0-de5a090",
            "baseline": "findings/example-repo/example-repo-security-audit.json",
            "baseline_findings": 12,
        },
        "findings": [_finding()],
        "known_findings": [
            {
                "title": "Path traversal in upload handler",
                "matches_baseline_id": "EXAMPLE_REPO-9cb7556-004",
            }
        ],
        "summary": {
            "total": 1,
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "known": 1,
            "low_confidence": 0,
        },
    }


def _schema_errors(doc):
    validator = jsonschema.Draft202012Validator(
        SCHEMA, registry=REGISTRY, format_checker=jsonschema.FormatChecker()
    )
    return list(validator.iter_errors(doc))


def _cross(doc):
    r = ValidationResult(file_path="example-repo-vuln-findings.json")
    cross_validate_vuln_findings(doc, r)
    return r


class TestVulnFindingsSchema(unittest.TestCase):
    def test_valid_document_passes(self):
        self.assertEqual(_schema_errors(_valid_doc()), [])

    def test_autodetect_by_filename(self):
        p = detect_schema_path(Path("x/example-repo-vuln-findings.json"))
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "vuln-findings.schema.json")

    def test_legacy_name_not_autodetected(self):
        self.assertIsNone(detect_schema_path(Path("x/VULN-FINDINGS.json")))

    def test_legacy_uppercase_severity_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["severity"] = "HIGH"
        self.assertTrue(_schema_errors(doc))

    def test_non_canonical_id_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["id"] = "F-001"
        self.assertTrue(_schema_errors(doc))

    def test_null_line_accepted(self):
        doc = _valid_doc()
        doc["findings"][0]["line"] = None
        self.assertEqual(_schema_errors(doc), [])

    def test_bad_cwe_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["cwe"] = "CWE78"
        self.assertTrue(_schema_errors(doc))

    def test_unknown_finding_field_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["novel_field"] = 1
        self.assertTrue(_schema_errors(doc))

    def test_empty_findings_valid(self):
        doc = _valid_doc()
        doc["findings"] = []
        doc["summary"].update(total=0, high=0)
        self.assertEqual(_schema_errors(doc), [])

    def test_non_git_scanned_ref_accepted(self):
        doc = _valid_doc()
        doc["metadata"]["scanned_ref"] = "0000000 (not a git checkout)"
        self.assertEqual(_schema_errors(doc), [])


class TestVulnFindingsCrossValidation(unittest.TestCase):
    def test_valid_document_no_errors(self):
        r = _cross(_valid_doc())
        self.assertEqual(r.errors, [])

    def test_duplicate_id_rejected(self):
        doc = _valid_doc()
        doc["findings"].append(copy.deepcopy(doc["findings"][0]))
        doc["summary"].update(total=2, high=2)
        r = _cross(doc)
        self.assertTrue(any("Duplicate finding ID" in e for e in r.errors))

    def test_id_prefix_must_match_metadata(self):
        doc = _valid_doc()
        doc["findings"][0]["id"] = "OTHER_REPO-abc1234-001"
        r = _cross(doc)
        self.assertTrue(any("must derive from" in e for e in r.errors))

    def test_summary_count_mismatch(self):
        doc = _valid_doc()
        doc["summary"]["high"] = 5
        r = _cross(doc)
        self.assertTrue(any("summary.high" in e for e in r.errors))

    def test_low_confidence_reconciles(self):
        doc = _valid_doc()
        doc["findings"][0]["confidence"] = 0.2
        r = _cross(doc)
        self.assertTrue(any("summary.low_confidence" in e for e in r.errors))

    def test_known_without_baseline_rejected(self):
        doc = _valid_doc()
        doc["metadata"]["baseline"] = None
        doc["metadata"]["baseline_findings"] = 0
        r = _cross(doc)
        self.assertTrue(any("baseline is null" in e for e in r.errors))


if __name__ == "__main__":
    unittest.main()
