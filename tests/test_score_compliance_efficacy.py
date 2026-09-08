#!/usr/bin/env python3
"""Tests for traust.ops.score_compliance_efficacy — the end-to-end
compliance efficacy benchmark (Phase 8). The unit tests prove the
scorer can FAIL (a benchmark that can't fail measures nothing); the
integration test runs the real seeded target via the configured progress-tracker."""

import subprocess
import sys

import pytest

from tests.compliance_paths import compliance_configs_dir, compliance_skip_reason

_SEEDED_TARGET = compliance_configs_dir() / "efficacy" / "seeded-target"

from traust.ops import score_compliance_efficacy as sce


def _key():
    return {
        "expected": {"fw-a": {"c1": "not_satisfied", "c2": "satisfied", "c3": "not_assessed"}},
        "honesty_probes": ["fw-a:c3"],
        "crosswalk_coherence": [["fw-a:c1", "fw-b:x1"]],
    }


def _artifact(c1="not_satisfied", c2="satisfied", c3="not_assessed", x1="not_satisfied"):
    return {
        "results": [
            {
                "framework": "fw-a",
                "controls": [
                    {"control_id": "c1", "verdict": c1},
                    {"control_id": "c2", "verdict": c2},
                    {"control_id": "c3", "verdict": c3},
                ],
            },
            {"framework": "fw-b", "controls": [{"control_id": "x1", "verdict": x1}]},
        ]
    }


def test_all_expectations_met_passes():
    rep = sce.score(_key(), _artifact())
    assert rep["verdict"] == "PASS"
    assert rep["controls_checked"] == 3
    assert rep["failures"] == []


def test_wrong_verdict_fails():
    rep = sce.score(_key(), _artifact(c2="not_satisfied"))
    assert rep["verdict"] == "FAIL"
    [f] = rep["failures"]
    assert f["class"] == "WRONG_VERDICT" and f["control"] == "fw-a:c2"


def test_guessing_on_honesty_probe_is_worst_class_and_sorts_first():
    rep = sce.score(_key(), _artifact(c3="satisfied", c2="not_satisfied"))
    assert rep["verdict"] == "FAIL"
    assert rep["failures"][0]["class"] == "GUESSING"
    assert rep["failures"][0]["control"] == "fw-a:c3"


def test_missing_result_fails():
    art = _artifact()
    art["results"][0]["controls"].pop(1)  # drop c2
    rep = sce.score(_key(), art)
    assert any(f["class"] == "MISSING" and f["control"] == "fw-a:c2" for f in rep["failures"])


def test_crosswalk_incoherence_fails():
    rep = sce.score(_key(), _artifact(x1="satisfied"))
    assert rep["verdict"] == "FAIL"
    [f] = rep["failures"]
    assert f["class"] == "INCOHERENCE"


def test_render_md_lists_failures():
    rep = sce.score(_key(), _artifact(c3="satisfied"))
    md = sce.render_md(rep)
    assert "GUESSING" in md and "FAIL" in md


@pytest.mark.skipif(not _SEEDED_TARGET.is_dir(), reason=compliance_skip_reason())
def test_seeded_target_end_to_end(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.ops.score_compliance_efficacy",
            "--fixture",
            str(_SEEDED_TARGET),
            "--out-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout
    assert (tmp_path / "compliance-efficacy.json").is_file()
