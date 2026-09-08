"""Phase 4 tests: idempotence gate, N-pass enforcement, precision."""

import json
import sys

import pytest

from traust.context import load_engine
from traust.paths import skill_dir

yaml = pytest.importorskip("yaml")
pytest.importorskip("jsonschema")

from tests.compliance_paths import (
    compliance_configs_available,
    compliance_configs_dir,
    compliance_skip_reason,
)

_CALIBRATION_SNAPSHOT = (
    compliance_configs_dir() / "calibration" / "iac-inventory-calibration.json"
)

pytestmark = pytest.mark.skipif(
    not compliance_configs_available() or not _CALIBRATION_SNAPSHOT.is_file(),
    reason=compliance_skip_reason(),
)


def _load(name):
    import importlib

    pkg_paths = {
        "calibrate_compliance": "traust.ops.calibrate_compliance",
        "compliance_precision": "traust.ops.compliance_precision",
        "build_compliance_dashboard": "traust_engine.compliance.dashboard",
    }
    if name in pkg_paths:
        return importlib.import_module(pkg_paths[name])
    path = skill_dir("compliance-check") / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cal = _load("calibrate_compliance")
vca = _load("validate_compliance_assessment")
prec = _load("compliance_precision")


# ---------------- idempotence (offline, real calibration snapshot) ----


def test_idempotence_over_calibration_snapshot(tmp_path):
    snap = _CALIBRATION_SNAPSHOT
    assert snap.is_file(), "calibration snapshot missing"
    rc = cal.main(["--snapshot", str(snap), "--work-dir", str(tmp_path / "w")])
    assert rc == 0


def test_idempotence_gate_detects_divergence(tmp_path, monkeypatch):
    snap = _CALIBRATION_SNAPSHOT
    calls = {"n": 0}
    real = cal.run_once

    def flaky(out_dir, snapshot, khs, frameworks):
        doc = real(out_dir, snapshot, khs, frameworks)
        calls["n"] += 1
        if calls["n"] == 2 and doc["results"]:
            doc["results"][0]["verdict"] = "not_assessed"
            doc["results"][0].pop("evidence", None)
            doc["results"][0]["reason"] = "injected divergence"
        return doc

    monkeypatch.setattr(cal, "run_once", flaky)
    rc = cal.main(["--snapshot", str(snap), "--work-dir", str(tmp_path / "w")])
    assert rc == 1


# ---------------- N-pass agreement enforcement ----------------


def _er_result(**over):
    r = {
        "framework": "soc2-tsc",
        "control_id": "A1.2",
        "classification": "evidence_review",
        "verdict": "satisfied",
        "verdict_source": "agent",
        "evidence": [
            {
                "sha256": "a" * 64,
                "kind": "human_artifact",
                "locator": "artifact:backup-evidence.pdf",
            }
        ],
    }
    r.update(over)
    return {"results": [r]}


def test_agent_verdict_requires_n_pass_agreement():
    failures = vca.n_pass_failures(_er_result())
    assert failures and "n_pass_agreement" in failures[0]


def test_agreed_two_passes_ok():
    doc = _er_result(n_pass_agreement={"passes": 2, "agreed": True})
    assert vca.n_pass_failures(doc) == []


def test_disagreement_cannot_carry_verdict():
    doc = _er_result(n_pass_agreement={"passes": 2, "agreed": False})
    failures = vca.n_pass_failures(doc)
    assert failures and "disagreement" in failures[0]


def test_not_assessed_needs_no_agreement():
    doc = _er_result(verdict="not_assessed", verdict_source="check", evidence=None)
    doc["results"][0].pop("evidence")
    doc["results"][0]["reason"] = "awaiting artifact"
    assert vca.n_pass_failures(doc) == []


# ---------------- precision tracker ----------------


def _assessment(tmp_path, name, results):
    p = tmp_path / name
    p.write_text(
        json.dumps({"metadata": {"artifact": "compliance-assessment"}, "results": results})
    )
    return p


def test_precision_aggregates_overrides(tmp_path):
    _assessment(
        tmp_path,
        "a1.json",
        [
            {
                "framework": "nist-800-53-rev5",
                "control_id": "sc-28",
                "classification": "deterministic",
                "verdict": "not_satisfied",
                "verdict_source": "check",
                "check_id": "chk-encryption-at-rest",
            },
            {
                "framework": "nist-800-53-rev5",
                "control_id": "ac-6",
                "classification": "deterministic",
                "verdict": "satisfied",
                "verdict_source": "human_override",
                "check_id": "chk-no-rbac-wildcards",
                "override": {
                    "by": "u",
                    "date": "2026-07-19",
                    "rationale": "fp — templated file",
                    "overridden_check_verdict": "not_satisfied",
                },
            },
        ],
    )
    _assessment(
        tmp_path,
        "a2.json",
        [
            {
                "framework": "pci-dss-v4",
                "control_id": "7.2.1",
                "classification": "deterministic",
                "verdict": "not_satisfied",
                "verdict_source": "check",
                "check_id": "chk-no-rbac-wildcards",
            },
        ],
    )
    report = prec.aggregate(tmp_path)
    by = {r["check_id"]: r for r in report["checks"]}
    enc = by["chk-encryption-at-rest"]
    assert enc["fired"] == 1 and enc["dismissed"] == 0
    assert enc["precision"] == 1.0
    rbac = by["chk-no-rbac-wildcards"]
    assert rbac["fired"] == 2 and rbac["dismissed"] == 1
    assert rbac["precision"] == 0.5
    assert rbac["flagged"] is True  # at the 0.5 gate boundary
    assert enc["flagged"] is False


def test_precision_empty_tree_is_honest(tmp_path):
    report = prec.aggregate(tmp_path)
    assert report["checks"] == []
    assert "no assessment artifacts" in report["note"]


# ---------------- Phase 5: dashboard builder ----------------

dash = _load("build_compliance_dashboard")


@pytest.fixture(scope="module")
def corpus_cfg():
    return load_engine().corpus.config()


def _mk_assessment_dir(tmp_path, target, generated_at, ns_count=1):
    d = tmp_path / "assessments" / target
    d.mkdir(parents=True)
    results = [
        {
            "framework": "nist-800-53-rev5",
            "control_id": "sc-28",
            "classification": "deterministic",
            "verdict": "not_satisfied",
            "verdict_source": "check",
            "check_id": "chk-encryption-at-rest",
            "evidence": [
                {"sha256": "a" * 64, "kind": "inventory_snapshot_excerpt", "locator": "x"}
            ],
        }
    ] * ns_count
    (d / "compliance-assessment.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "artifact": "compliance-assessment",
                    "harness_version": "t",
                    "registry_hash": "b" * 64,
                    "generated_at": generated_at,
                    "target": {"kind": "environment", "environment": target},
                    "frameworks": [{"id": "nist-800-53-rev5"}],
                    "skipped_frameworks": {"pci-dss-v4": "skipped: no CDE"},
                },
                "coverage": {
                    "nist-800-53-rev5": {
                        "total_in_scope": ns_count,
                        "deterministic": ns_count,
                        "evidence_review": 0,
                        "organizational": 0,
                        "satisfied": 0,
                        "not_satisfied": ns_count,
                        "not_applicable": 0,
                        "not_assessed": 0,
                    }
                },
                "results": results,
            }
        )
    )
    return d


def test_dashboard_latest_per_target_and_transparency(tmp_path, corpus_cfg):
    _mk_assessment_dir(tmp_path, "env-a", "2026-07-18T00:00:00Z", ns_count=3)
    _mk_assessment_dir(tmp_path, "env-a-old", "2026-07-01T00:00:00Z")
    # newer artifact for env-a in a sibling dir
    d = tmp_path / "assessments" / "env-a-new"
    d.mkdir()
    newer = json.loads((tmp_path / "assessments/env-a/compliance-assessment.json").read_text())
    newer["metadata"]["generated_at"] = "2026-07-19T00:00:00Z"
    newer["metadata"]["target"]["environment"] = "env-a"
    (d / "compliance-assessment.json").write_text(json.dumps(newer))

    doc = dash.build(
        tmp_path / "assessments", tmp_path / "absent.db", tmp_path / "absent", corpus_cfg
    )
    by_target = {t["target"]: t for t in doc["targets"]}
    assert by_target["env-a"]["generated_at"] == "2026-07-19T00:00:00Z"
    assert "pci-dss-v4" in by_target["env-a"]["skipped_frameworks"]
    md = dash.render_md(doc, [])
    assert "no CDE" in md  # skip reasons rendered
    assert "compliance percentage" not in md.lower().replace("no blended compliance percentage", "")
    assert "Trend renders once" in md  # single point = no trend


def test_dashboard_trend_needs_two_snapshots(tmp_path, corpus_cfg):
    _mk_assessment_dir(tmp_path, "e", "2026-07-19T00:00:00Z")
    doc = dash.build(
        tmp_path / "assessments", tmp_path / "absent.db", tmp_path / "absent", corpus_cfg
    )
    h1 = [
        {
            "generated_at": "2026-07-18T00:00:00Z",
            "targets": 1,
            "not_satisfied_total": 5,
            "not_assessed_total": 2,
        }
    ]
    assert "Trend renders once" in dash.render_md(doc, h1)
    h2 = [
        *h1,
        {
            "generated_at": "2026-07-19T00:00:00Z",
            "targets": 1,
            "not_satisfied_total": 4,
            "not_assessed_total": 2,
        },
    ]
    md = dash.render_md(doc, h2)
    assert "| 2026-07-18 | 1 | 5 | 2 |" in md


def test_single_framework_run_never_hides_other_coverage(tmp_path, corpus_cfg):
    """User requirement: per-framework runs must merge, not overwrite."""
    _mk_assessment_dir(tmp_path, "env-m", "2026-07-18T00:00:00Z")
    # newer SOC 2-only assessment of the SAME target
    d = tmp_path / "assessments" / "env-m-soc2"
    d.mkdir()
    (d / "env-m-soc2-tsc-compliance-assessment.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "artifact": "compliance-assessment",
                    "harness_version": "t",
                    "registry_hash": "b" * 64,
                    "generated_at": "2026-07-19T12:00:00Z",
                    "target": {"kind": "environment", "environment": "env-m"},
                    "frameworks": [{"id": "soc2-tsc", "caveat": "point-in-time"}],
                    "skipped_frameworks": {},
                },
                "coverage": {
                    "soc2-tsc": {
                        "total_in_scope": 2,
                        "deterministic": 2,
                        "evidence_review": 0,
                        "organizational": 0,
                        "satisfied": 2,
                        "not_satisfied": 0,
                        "not_applicable": 0,
                        "not_assessed": 0,
                    }
                },
                "results": [],
            }
        )
    )
    doc = dash.build(
        tmp_path / "assessments", tmp_path / "absent.db", tmp_path / "absent", corpus_cfg
    )
    t = {x["target"]: x for x in doc["targets"]}["env-m"]
    # BOTH frameworks present, each with its own assessment date
    assert set(t["coverage"]) == {"nist-800-53-rev5", "soc2-tsc"}
    assert t["assessed_at"]["soc2-tsc"].startswith("2026-07-19")
    assert t["assessed_at"]["nist-800-53-rev5"].startswith("2026-07-18")
    md = dash.render_md(doc, [])
    assert "2026-07-18" in md and "2026-07-19" in md


def test_artifact_base_naming():
    rcc2 = _load("run_compliance_check")
    assert rcc2.artifact_base("env a/b", "all") == "env-a-b-all-compliance-assessment"
    assert rcc2.artifact_base("x", "soc2-tsc") == "x-soc2-tsc-compliance-assessment"
    assert (
        rcc2.artifact_base("x", "pci-dss-v4, soc2-tsc")
        == "x-pci-dss-v4+soc2-tsc-compliance-assessment"
    )
