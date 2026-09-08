#!/usr/bin/env python3
"""Tests for the cloud-config findings-current schema route in
validate_report.py.

Covers schema/cloud-config-findings-current.schema.json (the cumulative
shape build_cumulative.py derives from a *-cloud-config-audit.json
baseline), both auto-detection paths (metadata stamp, sibling-audit
fallback), the cloud-config cross-checks, and the negative direction:
code-audit / container-audit cumulative reports must keep their
pre-existing default report.schema.json route.
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema
from traust_engine.reporting.validate import (
    SCHEMA_DIR,
    ValidationResult,
    build_registry,
    cross_validate_cloud_config_current,
    detect_schema_path,
    load_schema,
    validate_report,
)

CLOUD_CONFIG_CURRENT_SCHEMA = load_schema(SCHEMA_DIR / "cloud-config-findings-current.schema.json")
REGISTRY = build_registry()

GENERATED_AT = "2026-07-28T23:19:00+00:00"


def _valid_current():
    """Minimal cloud-config findings-current that passes all validation.

    Mirrors what build_cumulative.py emits over a cloud-config-audit
    baseline: audit finding core + disposition/validation_status/
    effective_severity per finding, disposition_summary, cumulative
    metadata stamp, title suffix."""
    return {
        "title": "Cloud config audit — widget (declared layer) — Cumulative Findings Status",
        "metadata": {
            "target": "widget",
            "assessment_mode": "declared",
            "target_head": "6cb81ba1a4077a2b812d6c8403d9f4f871a3d9f3",
            "ref": "main",
            "ref_kind": "default",
            "repository": "https://github.com/example/widget",
            "harness_version": "0.202.0",
            "checkov_version": "3.3.6",
            "facts_ref": "analysis-results/cloud-config/widget/widget-cloud-facts.json",
            "facts_snapshot_id": "b50717124734aae7",
            "generated_at": "2026-07-28T20:52:36Z",
            "frameworks": ["terraform"],
            "deterministic_steps": [
                {
                    "tool": "checkov (via run_checkov.py)",
                    "invocation": "python3 run_checkov.py --target-dir .",
                    "version": "3.3.6",
                }
            ],
            "additional": {
                "cumulative": {
                    "source_audit": "widget-cloud-config-audit.json",
                    "layer": "widget-findings-layer.json",
                    "original_report_date": None,
                    "generated_at": GENERATED_AT,
                }
            },
            "date": "2026-07-28",
        },
        "summary": {
            "facts_total": 2,
            "confirmed": 1,
            "suppressed": 1,
            "needs_review": 0,
            "gaps": 0,
            "by_severity": {"low": 1, "informational": 1},
            "by_provider": {"aws": 2},
        },
        "findings": [
            {
                "id": "CCA-widget-001",
                "fact_ids": ["cca-d0055ddb7a4a"],
                "framework": "terraform",
                "provider": "aws",
                "check_id": "CKV_AWS_1",
                "title": "S3 bucket lacks server-side encryption",
                "severity": "low",
                "scanner_severity": "unrated",
                "status": "confirmed",
                "rationale": "Rubric row R4: hygiene gap on a non-sensitive artifact bucket.",
                "locations": [
                    {
                        "file_path": "/main.tf",
                        "resource": "aws_s3_bucket.artifacts",
                        "file_line_range": [10, 24],
                    }
                ],
                "cwe": "CWE-311",
                "control_refs": [],
                "remediation": "Enable SSE-S3 on the bucket.",
                "disposition": {
                    "validity": "not_verified",
                    "resolution": "open",
                    "assurance": "claimed",
                    "last_updated": GENERATED_AT,
                    "events": [],
                },
                "validation_status": "not_verified",
                "effective_severity": "low",
            },
            {
                "id": "CCA-widget-002",
                "fact_ids": ["cca-f049540e9baa"],
                "framework": "terraform",
                "provider": "aws",
                "check_id": "CKV_AWS_2",
                "title": "Bucket versioning disabled",
                "severity": "informational",
                "scanner_severity": "unrated",
                "status": "suppressed",
                "rationale": "Versioning is handled by the backup pipeline; "
                "cited in docs/backup.md.",
                "locations": [
                    {
                        "file_path": "/main.tf",
                        "resource": "aws_s3_bucket.artifacts",
                        "file_line_range": [10, 24],
                    }
                ],
                "cwe": None,
                "control_refs": [],
                "remediation": None,
                "disposition": {
                    "validity": "not_verified",
                    "resolution": "open",
                    "assurance": "claimed",
                    "last_updated": GENERATED_AT,
                    "events": [],
                },
                "validation_status": "not_verified",
                "effective_severity": "informational",
            },
        ],
        "gaps": [],
        "disposition_summary": {
            "layer_ref": "widget-findings-layer.json",
            "generated_at": GENERATED_AT,
            "by_resolution": {
                "open": 2,
                "fix_in_progress": 0,
                "resolved": 0,
                "partially_resolved": 0,
                "risk_accepted": 0,
                "regression_introduced": 0,
            },
            "by_validity": {
                "confirmed": 0,
                "corrected": 0,
                "false_positive": 0,
                "not_verified": 2,
                "hardening": 0,
            },
            "severity_overrides": [],
            "conflicts": [],
            "needs_review_count": 0,
        },
    }


def _schema_errors(report):
    validator = jsonschema.Draft202012Validator(
        CLOUD_CONFIG_CURRENT_SCHEMA,
        format_checker=jsonschema.FormatChecker(),
        registry=REGISTRY,
    )
    return [e.message for e in validator.iter_errors(report)]


def _cross(report):
    result = ValidationResult(file_path="<test>")
    cross_validate_cloud_config_current(report, result)
    return result


# ---------------------------------------------------------------------------
# Good report
# ---------------------------------------------------------------------------


class TestValidCloudConfigCurrent(unittest.TestCase):
    def test_valid_current_passes_schema(self):
        self.assertEqual(_schema_errors(_valid_current()), [])

    def test_valid_current_passes_cross_checks(self):
        result = _cross(_valid_current())
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_round_trip_via_file_with_detection(self):
        report = _valid_current()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-findings-current.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            detected = detect_schema_path(path)
            self.assertIsNotNone(detected)
            self.assertEqual(detected.name, "cloud-config-findings-current.schema.json")
            r = validate_report(str(path), load_schema(detected), registry=REGISTRY)
            self.assertTrue(r.passed, r.errors)

    def test_severity_override_shape_accepted(self):
        r = _valid_current()
        f = r["findings"][0]
        f["disposition"]["severity_override"] = {
            "severity": "high",
            "by": "jdoe@example.com",
            "at": GENERATED_AT,
            "rationale": "Bucket holds signed release artifacts.",
        }
        f["effective_severity"] = "high"
        r["disposition_summary"]["severity_overrides"] = [
            {
                "finding": f["id"],
                "from": "low",
                "severity": "high",
                "by": "jdoe@example.com",
                "at": GENERATED_AT,
                "rationale": "Bucket holds signed release artifacts.",
            }
        ]
        self.assertEqual(_schema_errors(r), [])
        self.assertEqual(_cross(r).errors, [])


# ---------------------------------------------------------------------------
# Schema violations
# ---------------------------------------------------------------------------


class TestCloudConfigCurrentSchemaViolations(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_current())
        fn(r)
        return _schema_errors(r)

    def test_missing_disposition_summary(self):
        errors = self._mutate(lambda r: r.pop("disposition_summary"))
        self.assertTrue(
            any("'disposition_summary' is a required property" in e for e in errors), errors
        )

    def test_missing_finding_disposition(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("disposition"))
        self.assertTrue(any("'disposition' is a required property" in e for e in errors), errors)

    def test_missing_effective_severity(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("effective_severity"))
        self.assertTrue(
            any("'effective_severity' is a required property" in e for e in errors), errors
        )

    def test_title_without_cumulative_suffix(self):
        errors = self._mutate(
            lambda r: r.__setitem__("title", "Cloud config audit — widget (declared layer)")
        )
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_bad_finding_id_pattern(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("id", "WIDGET-abc-001"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_observed_assessment_mode_unrepresentable(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("assessment_mode", "observed"))
        self.assertTrue(any("declared" in e for e in errors), errors)

    def test_source_audit_must_reference_cloud_config_baseline(self):
        errors = self._mutate(
            lambda r: r["metadata"]["additional"]["cumulative"].__setitem__(
                "source_audit", "widget-security-audit.json"
            )
        )
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_invalid_disposition_validity(self):
        errors = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "maybe")
        )
        self.assertTrue(any("'maybe' is not one of" in e for e in errors), errors)

    def test_vintage_extras_tolerated(self):
        # Real corpus vintages carry campaign annotations and free-form
        # summary notes — the contract stays open there.
        def mutate(r):
            r["metadata"]["tracking"] = "PROJ-3528"
            r["metadata"]["campaign"] = "iac-baseline-sweep"
            r["summary"]["note"] = "DECLARED CONFIGURATION ONLY."

        self.assertEqual(self._mutate(mutate), [])

    def test_unknown_top_level_key_rejected(self):
        errors = self._mutate(lambda r: r.__setitem__("bogus", 1))
        self.assertTrue(any("additional properties" in e.lower() for e in errors), errors)


# ---------------------------------------------------------------------------
# Cross-validation
# ---------------------------------------------------------------------------


class TestCloudConfigCurrentCrossChecks(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_current())
        fn(r)
        return _cross(r)

    def test_duplicate_finding_id(self):
        result = self._mutate(lambda r: r["findings"][1].__setitem__("id", "CCA-widget-001"))
        self.assertTrue(any("Duplicate finding ID" in e for e in result.errors), result.errors)

    def test_effective_severity_must_match_severity(self):
        result = self._mutate(
            lambda r: r["findings"][0].__setitem__("effective_severity", "critical")
        )
        self.assertTrue(any("effective_severity" in e for e in result.errors), result.errors)

    def test_effective_severity_must_match_override(self):
        def mutate(r):
            r["findings"][0]["disposition"]["severity_override"] = {
                "severity": "high",
                "by": "jdoe@example.com",
                "at": GENERATED_AT,
            }
            # effective_severity left at 'low' — contradicts the override

        result = self._mutate(mutate)
        self.assertTrue(any("severity_override" in e for e in result.errors), result.errors)

    def test_validation_status_disposition_mismatch(self):
        result = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "confirmed")
        )
        self.assertTrue(any("does not equal" in e for e in result.errors), result.errors)

    def test_by_validity_count_mismatch(self):
        result = self._mutate(
            lambda r: r["disposition_summary"]["by_validity"].__setitem__("confirmed", 2)
        )
        self.assertTrue(any("by_validity[confirmed]" in e for e in result.errors), result.errors)

    def test_summary_status_count_drift_warns_not_errors(self):
        # Vintage drift observed in the real corpus — must not fail files.
        result = self._mutate(lambda r: r["summary"].__setitem__("confirmed", 5))
        self.assertEqual(result.errors, [])
        self.assertTrue(any("summary.confirmed" in w for w in result.warnings), result.warnings)

    def test_summary_gaps_drift_warns_not_errors(self):
        result = self._mutate(lambda r: r["summary"].__setitem__("gaps", 7))
        self.assertEqual(result.errors, [])
        self.assertTrue(any("summary.gaps" in w for w in result.warnings), result.warnings)


# ---------------------------------------------------------------------------
# Auto-detection routing
# ---------------------------------------------------------------------------


def _code_audit_current():
    """A code-audit cumulative stub: report.schema.json-shaped stamp."""
    return {
        "title": "Security Assessment — Widget — Cumulative Findings Status",
        "metadata": {
            "date": "2026-07-28",
            "scope": "First-party Go source under cmd/ and pkg/.",
            "additional": {
                "cumulative": {
                    "source_audit": "widget-security-audit.json",
                    "layer": "widget-findings-layer.json",
                    "original_report_date": "2026-07-01",
                    "generated_at": GENERATED_AT,
                }
            },
        },
    }


class TestCloudConfigAuditReportDetection(unittest.TestCase):
    """The Layer-2 *-cloud-config-audit.json report itself must route to
    schema/cloud-config-audit.schema.json in sweeps — the default
    code-audit route produced 128 bogus errors (executive_summary,
    severity_criteria, findings_summary...) on a live report
    (rhoim-bootc-images re-baseline, 2026-07-29). run_checkov.py
    --validate-report stays the canonical content gate; validate_report
    applies only the schema (code-audit cross-checks are gated off)."""

    def test_audit_report_routes_to_cloud_config_audit_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-cloud-config-audit.json"
            path.write_text("{}", encoding="utf-8")
            detected = detect_schema_path(path)
            self.assertIsNotNone(detected)
            self.assertEqual(detected.name, "cloud-config-audit.schema.json")

    def test_live_report_shape_passes_without_code_audit_cross_checks(self):
        # A schema-valid cloud-config-audit report must not be failed by
        # the code-audit cross-checks (severity_criteria/findings_summary
        # are not part of this shape).
        current = _valid_current()
        finding = copy.deepcopy(current["findings"][0])
        for k in ("disposition", "validation_status", "effective_severity"):
            finding.pop(k, None)
        report = {
            "title": "Cloud Config Audit (Declared Layer) — widget",
            "metadata": {k: v for k, v in current["metadata"].items() if k != "additional"},
            "summary": {
                "facts_total": 1,
                "confirmed": 1,
                "suppressed": 0,
                "needs_review": 0,
                "gaps": 0,
                "by_severity": {finding["severity"]: 1},
                "by_provider": {finding["provider"]: 1},
            },
            "findings": [finding],
            "gaps": [],
        }
        schema = load_schema(SCHEMA_DIR / "cloud-config-audit.schema.json")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-cloud-config-audit.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            result = validate_report(str(path), schema, registry=REGISTRY)
        self.assertEqual(result.errors, [], f"unexpected errors: {result.errors}")


class TestFindingsCurrentDetection(unittest.TestCase):
    def test_metadata_stamp_routes_cloud_config(self):
        # Path 1: build_cumulative's source_audit stamp alone decides —
        # no sibling audit file present.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-findings-current.json"
            path.write_text(json.dumps(_valid_current()), encoding="utf-8")
            detected = detect_schema_path(path)
            self.assertIsNotNone(detected)
            self.assertEqual(detected.name, "cloud-config-findings-current.schema.json")

    def test_sibling_audit_fallback_routes_cloud_config(self):
        # Path 2: stamp stripped, but the *-cloud-config-audit.json baseline
        # sits next to the cumulative report.
        report = _valid_current()
        del report["metadata"]["additional"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-findings-current.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            (Path(tmpdir) / "widget-cloud-config-audit.json").write_text("{}", encoding="utf-8")
            detected = detect_schema_path(path)
            self.assertIsNotNone(detected)
            self.assertEqual(detected.name, "cloud-config-findings-current.schema.json")

    def test_no_stamp_no_sibling_keeps_default_route(self):
        report = _valid_current()
        del report["metadata"]["additional"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-findings-current.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            self.assertIsNone(detect_schema_path(path))

    def test_code_audit_current_keeps_default_route(self):
        # Negative: a code-audit cumulative must NOT match the new route,
        # even with a stray cloud-config audit for a DIFFERENT base name
        # in the same directory (the stamp is authoritative).
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-findings-current.json"
            path.write_text(json.dumps(_code_audit_current()), encoding="utf-8")
            (Path(tmpdir) / "other-cloud-config-audit.json").write_text("{}", encoding="utf-8")
            self.assertIsNone(detect_schema_path(path))

    def test_code_audit_stamp_beats_sibling_collision(self):
        # Stamp says security-audit: default route even if a same-base
        # cloud-config audit file exists.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "widget-findings-current.json"
            path.write_text(json.dumps(_code_audit_current()), encoding="utf-8")
            (Path(tmpdir) / "widget-cloud-config-audit.json").write_text("{}", encoding="utf-8")
            self.assertIsNone(detect_schema_path(path))

    def test_container_audit_current_keeps_default_route(self):
        report = _code_audit_current()
        report["metadata"]["additional"]["cumulative"]["source_audit"] = (
            "console-container-audit.json"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "console-container-audit-findings-current.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            self.assertIsNone(detect_schema_path(path))

    def test_nonexistent_file_keeps_default_route(self):
        # Guards the pre-existing contract asserted in test_validate_triage.
        self.assertIsNone(detect_schema_path(Path("x-findings-current.json")))

    def test_code_audit_current_fails_new_schema(self):
        # Negative: the code-audit cumulative shape is not valid under the
        # cloud-config-findings-current contract.
        self.assertTrue(_schema_errors(_code_audit_current()))


if __name__ == "__main__":
    unittest.main()
