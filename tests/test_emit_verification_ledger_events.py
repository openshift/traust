#!/usr/bin/env python3
"""Unit tests for emit_verification_ledger_events — pure transform helpers."""

from __future__ import annotations

import pytest
from traust_engine.ledger import compute_event_id

from traust.cli.emit_verification_ledger_events import (
    build_events,
    map_disposition,
    resolve_audit_path,
)

RECORDED_AT = "2026-07-15T12:00:00+00:00"
SOURCE_REF = "analysis-results/findings/org/repo/repo-remediation-verification.json"


def _audit(finding_ids):
    return {"findings": [{"id": fid} for fid in finding_ids], "metadata": {}}


def _report(verified_findings, *, date="2026-07-15", hv="0.45.1"):
    return {
        "metadata": {
            "date": date,
            "harness_version": hv,
            "original_report": "test.json",
        },
        "verified_findings": verified_findings,
    }


def _finding(original_id, verdict, **kwargs):
    finding = {
        "original_id": original_id,
        "verdict": verdict,
        "evidence": {"explanation": "test rationale"},
    }
    finding.update(kwargs)
    return finding


class TestMapDisposition:
    @pytest.mark.parametrize(
        "verdict, cross_repo, expected_disposition, expected_validity, expected_resolution",
        [
            ("resolved", None, {"resolution": "resolved"}, None, "resolved"),
            ("new_approach", None, {"resolution": "resolved"}, None, "resolved"),
            (
                "partially_resolved",
                None,
                {"resolution": "partially_resolved"},
                None,
                "partially_resolved",
            ),
            (
                "partially_resolved",
                {"propagation": "pending", "fix_repo": "x"},
                {"resolution": "fix_in_progress"},
                None,
                "fix_in_progress",
            ),
            (
                "partially_resolved",
                {"propagation": "consumed", "fix_repo": "x"},
                {"resolution": "partially_resolved"},
                None,
                "partially_resolved",
            ),
            ("unresolved", None, {"resolution": "open"}, None, "open"),
            (
                "regression",
                None,
                {"resolution": "regression_introduced"},
                None,
                "regression_introduced",
            ),
            (
                "risk_accepted",
                None,
                {"resolution": "risk_accepted"},
                None,
                "risk_accepted",
            ),
            (
                "false_positive",
                None,
                {"validity": "false_positive"},
                "false_positive",
                None,
            ),
        ],
    )
    def test_verdict_mapping(
        self,
        verdict,
        cross_repo,
        expected_disposition,
        expected_validity,
        expected_resolution,
    ):
        finding = {"verdict": verdict}
        if cross_repo is not None:
            finding["cross_repo"] = cross_repo
        disposition, validity, resolution = map_disposition(finding)
        assert disposition == expected_disposition
        assert validity == expected_validity
        assert resolution == expected_resolution

    def test_unknown_verdict_raises_value_error(self):
        with pytest.raises(ValueError, match="unsupported verdict"):
            map_disposition({"verdict": "banana"})


class TestBuildEvents:
    def test_resolved_finding_emits_resolution_resolved(self):
        out = build_events(
            _report([_finding("FIND-001", "resolved")]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert len(out["events"]) == 1
        assert out["events"][0]["disposition"] == {"resolution": "resolved"}

    def test_false_positive_emits_validity_false_positive(self):
        out = build_events(
            _report([_finding("FIND-001", "false_positive")]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert len(out["events"]) == 1
        assert out["events"][0]["disposition"] == {"validity": "false_positive"}

    def test_partially_resolved_with_pending_cross_repo_emits_fix_in_progress(self):
        out = build_events(
            _report(
                [
                    _finding(
                        "FIND-001",
                        "partially_resolved",
                        cross_repo={"propagation": "pending", "fix_repo": "x"},
                    )
                ]
            ),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert len(out["events"]) == 1
        assert out["events"][0]["disposition"] == {"resolution": "fix_in_progress"}

    def test_missing_original_id_is_skipped(self):
        out = build_events(
            _report([_finding("", "resolved")]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert out["events"] == []
        assert len(out["skipped"]) == 1
        assert out["skipped"][0]["reason"] == "missing original_id"

    def test_unknown_finding_ref_is_skipped(self):
        out = build_events(
            _report([_finding("FIND-999", "resolved")]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert out["events"] == []
        assert len(out["skipped"]) == 1
        assert out["skipped"][0]["reason"] == "original_id not in audit findings"

    def test_unknown_verdict_is_skipped(self):
        out = build_events(
            _report([_finding("FIND-001", "banana")]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert out["events"] == []
        assert len(out["skipped"]) == 1
        assert "unsupported verdict" in out["skipped"][0]["reason"]

    def test_all_verdicts_emit_expected_dispositions(self):
        findings = [
            _finding("FIND-001", "resolved"),
            _finding("FIND-002", "new_approach"),
            _finding("FIND-003", "partially_resolved"),
            _finding("FIND-004", "unresolved"),
            _finding("FIND-005", "regression"),
            _finding("FIND-006", "risk_accepted"),
            _finding("FIND-007", "false_positive"),
        ]
        out = build_events(
            _report(findings),
            SOURCE_REF,
            _audit([f"FIND-00{i}" for i in range(1, 8)]),
            RECORDED_AT,
        )
        assert len(out["events"]) == 7
        by_ref = {e["finding_ref"]: e["disposition"] for e in out["events"]}
        assert by_ref["FIND-001"] == {"resolution": "resolved"}
        assert by_ref["FIND-002"] == {"resolution": "resolved"}
        assert by_ref["FIND-003"] == {"resolution": "partially_resolved"}
        assert by_ref["FIND-004"] == {"resolution": "open"}
        assert by_ref["FIND-005"] == {"resolution": "regression_introduced"}
        assert by_ref["FIND-006"] == {"resolution": "risk_accepted"}
        assert by_ref["FIND-007"] == {"validity": "false_positive"}

    def test_event_ids_are_deterministic(self):
        report = _report([_finding("FIND-001", "resolved")])
        audit = _audit(["FIND-001"])
        out1 = build_events(report, SOURCE_REF, audit, RECORDED_AT)
        out2 = build_events(report, SOURCE_REF, audit, RECORDED_AT)
        assert out1["events"][0]["event_id"] == out2["events"][0]["event_id"]
        assert out1["events"][0]["event_id"] == compute_event_id(
            SOURCE_REF, "FIND-001", None, "resolved"
        )

    def test_rationale_comes_from_evidence_explanation(self):
        finding = _finding("FIND-001", "resolved")
        finding["evidence"]["explanation"] = "  multi   word   rationale  "
        out = build_events(
            _report([finding]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert out["events"][0]["rationale"] == "multi word rationale"

    def test_missing_evidence_yields_empty_rationale(self):
        finding = {"original_id": "FIND-001", "verdict": "resolved"}
        out = build_events(
            _report([finding]),
            SOURCE_REF,
            _audit(["FIND-001"]),
            RECORDED_AT,
        )
        assert out["events"][0]["rationale"] == ""


class TestResolveAuditPath:
    def test_localizes_analysis_results_suffix(self, tmp_path):
        results_root = tmp_path / "analysis-results"
        audit_rel = results_root / "findings" / "org" / "repo" / "repo-security-audit.json"
        audit_rel.parent.mkdir(parents=True)
        audit_rel.write_text("{}")
        foreign = f"/home/runner/ws/{audit_rel.relative_to(tmp_path)}"
        report = {"metadata": {"original_report": foreign}}
        resolved = resolve_audit_path(report, results_root)
        assert resolved == audit_rel.resolve()

    def test_missing_original_report_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match=r"metadata.original_report is missing"):
            resolve_audit_path({"metadata": {}}, tmp_path)

    def test_missing_audit_file_raises_file_not_found(self, tmp_path):
        results_root = tmp_path / "analysis-results"
        results_root.mkdir()
        report = {
            "metadata": {
                "original_report": str(results_root / "findings/org/repo/missing.json"),
            }
        }
        with pytest.raises(FileNotFoundError, match="audit report not found"):
            resolve_audit_path(report, results_root)
