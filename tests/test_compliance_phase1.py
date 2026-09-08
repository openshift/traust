"""Phase 1 tests: assertion engine, citation gate, schemas, seed configs."""

import copy
import importlib.util
import json
import sys

import pytest

from traust.paths import skill_dir

jsonschema = pytest.importorskip("jsonschema")
yaml = pytest.importorskip("yaml")

from tests.compliance_paths import (
    compliance_configs_available,
    compliance_configs_dir,
    compliance_skip_reason,
)

_CONFIGS = compliance_configs_dir


def _load(name):
    _paths = {
        "compliance_assert": (skill_dir("compliance-check") / "scripts" / "compliance_assert.py"),
        "validate_compliance_assessment": (
            skill_dir("compliance-check") / "scripts" / "validate_compliance_assessment.py"
        ),
    }
    spec = importlib.util.spec_from_file_location(name, _paths.get(name, "traust.cli.{name}"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ca = _load("compliance_assert")
vca = _load("validate_compliance_assessment")


# ---------------- canonicalization + evidence ids ----------------


def test_canonicalize_strips_volatile_and_sorts():
    a = {
        "b": 1,
        "a": 2,
        "resourceVersion": "9",
        "creationTimestamp": "t",
        "nested": [{"uid": "x", "z": 1, "y": 2}],
    }
    b = {"nested": [{"y": 2, "z": 1, "uid": "DIFFERENT"}], "a": 2, "b": 1, "resourceVersion": "42"}
    assert ca.canonical_json(a) == ca.canonical_json(b)
    assert ca.evidence_id(a) == ca.evidence_id(b)


# ---------------- path selection ----------------

SNAP = {
    "resources": [
        {"region": "us-east-1", "encryption_at_rest": True, "rules": [{"verbs": ["get", "list"]}]},
        {"region": "eu-west-1", "encryption_at_rest": False, "rules": [{"verbs": ["*"]}]},
    ]
}


def test_select_fanout_and_nested():
    assert ca.select(SNAP, "resources[*].region") == ["us-east-1", "eu-west-1"]
    assert ca.select(SNAP, "resources[*].rules[*].verbs[*]") == ["get", "list", "*"]
    assert ca.select(SNAP, "resources[*].missing") == []
    assert ca.select(SNAP, "nope.deeper") == []


# ---------------- assertion evaluation ----------------


def test_all_values_semantics():
    ok = {"resources": [{"encryption_at_rest": True}, {"encryption_at_rest": True}]}
    outcome, _, _ = ca.eval_assertion(
        ok, {"path": "resources[*].encryption_at_rest", "operator": "equals", "expected": True}
    )
    assert outcome == "pass"
    outcome, _, _ = ca.eval_assertion(
        SNAP, {"path": "resources[*].encryption_at_rest", "operator": "equals", "expected": True}
    )
    assert outcome == "fail"  # one False ruins it — no sampling


def test_empty_selection_is_not_assessed_not_vacuous_pass():
    outcome, _, reason = ca.eval_assertion(
        {}, {"path": "resources[*].region", "operator": "equals", "expected": "x"}
    )
    assert outcome == "not_assessed" and "no values" in reason


def test_exists_absent():
    assert ca.eval_assertion(SNAP, {"path": "resources[*]", "operator": "exists"})[0] == "pass"
    assert ca.eval_assertion({}, {"path": "resources[*]", "operator": "absent"})[0] == "pass"
    assert ca.eval_assertion(SNAP, {"path": "resources[*]", "operator": "absent"})[0] == "fail"


def test_param_indirection_and_undeclared():
    params = {
        "parameters": {
            "allowed_data_regions": {"value": ["us-east-1", "eu-west-1"], "controls": ["x:y"]}
        }
    }
    outcome, _, _ = ca.eval_assertion(
        SNAP,
        {"path": "resources[*].region", "operator": "in", "expected": "param:allowed_data_regions"},
        params,
    )
    assert outcome == "pass"
    outcome, _, reason = ca.eval_assertion(
        SNAP,
        {"path": "resources[*].region", "operator": "in", "expected": "param:allowed_data_regions"},
        None,
    )
    assert outcome == "not_assessed" and "undeclared" in reason


def test_evaluate_check_applicability_and_verdicts():
    check = {
        "id": "chk-encryption-at-rest",
        "collector": "cloud_inventory",
        "assertion": {
            "path": "resources[*].encryption_at_rest",
            "operator": "equals",
            "expected": True,
        },
        "applies_when": {"path": "resources[*]", "operator": "exists"},
    }
    res = ca.evaluate_check(check, SNAP)
    assert res["verdict"] == "not_satisfied"
    assert res["evidence"] and all(len(e["sha256"]) == 64 for e in res["evidence"])
    res = ca.evaluate_check(check, {"resources": []})
    assert res["verdict"] == "not_applicable"
    assert "declared applicability" in res["reason"]


def test_sampling_rule_is_deterministic():
    snap = {"resources": [{"region": f"r{i}"} for i in range(20)]}
    check = {
        "id": "chk-x",
        "collector": "cloud_inventory",
        "sampling": "sorted_first_5",
        "assertion": {"path": "resources[*].region", "operator": "regex", "expected": "^r"},
    }
    a = ca.evaluate_check(check, snap)
    b = ca.evaluate_check(check, copy.deepcopy(snap))
    assert a == b and a["verdict"] == "satisfied"


# ---------------- seed configs validate against their schemas -------


def _schema(name):
    from traust_contracts.paths import schema_path as _sp

    return json.loads(_sp(name.removesuffix(".schema.json")).read_text())


@pytest.mark.skipif(not compliance_configs_available(), reason=compliance_skip_reason())
def test_seed_registry_validates():
    reg = yaml.safe_load((_CONFIGS() / "compliance-mapping.yaml").read_text())
    jsonschema.validate(reg, _schema("compliance-mapping.schema.json"))
    check_ids = {c["id"] for c in reg["checks"]}
    for ctl in reg["controls"]:
        for cid in ctl.get("checks") or []:
            assert cid in check_ids, f"{ctl['control_id']} references unknown check {cid}"


@pytest.mark.skipif(not compliance_configs_available(), reason=compliance_skip_reason())
def test_seed_org_parameters_validate_and_cover_registry_refs():
    params = yaml.safe_load((_CONFIGS() / "org-parameters.yaml").read_text())
    jsonschema.validate(params, _schema("org-parameters.schema.json"))
    reg = yaml.safe_load((_CONFIGS() / "compliance-mapping.yaml").read_text())
    declared = set(params["parameters"])
    for chk in reg["checks"]:
        exp = (chk.get("assertion") or {}).get("expected")
        if isinstance(exp, str) and exp.startswith("param:"):
            assert exp[6:] in declared, f"{chk['id']} needs {exp}"


# ---------------- the citation gate ----------------


def _minimal_assessment():
    return {
        "metadata": {
            "artifact": "compliance-assessment",
            "harness_version": "0.99.0-test",
            "target": {"kind": "environment", "snapshot_id": "a" * 64},
            "frameworks": [{"id": "nist-800-53-rev5"}],
            "registry_hash": "b" * 64,
            "generated_at": "2026-07-19T00:00:00Z",
        },
        "coverage": {
            "nist-800-53-rev5": {
                "total_in_scope": 2,
                "deterministic": 1,
                "evidence_review": 0,
                "organizational": 1,
                "satisfied": 1,
                "not_satisfied": 0,
                "not_applicable": 0,
                "not_assessed": 1,
            }
        },
        "results": [
            {
                "framework": "nist-800-53-rev5",
                "control_id": "sc-28",
                "classification": "deterministic",
                "verdict": "satisfied",
                "verdict_source": "check",
                "check_id": "chk-encryption-at-rest",
                "evidence": [
                    {
                        "sha256": "c" * 64,
                        "kind": "inventory_snapshot_excerpt",
                        "locator": "cloud_inventory:resources",
                    }
                ],
            },
            {
                "framework": "nist-800-53-rev5",
                "control_id": "at-2",
                "classification": "organizational",
                "verdict": "not_assessed",
                "verdict_source": "check",
                "reason": "organizational — out of technical scope",
            },
        ],
    }


def test_gate_passes_minimal(tmp_path):
    doc = _minimal_assessment()
    assert vca.validate(doc, None, vca.SCHEMA) == []


def test_gate_blocks_narrative_verdict():
    doc = _minimal_assessment()
    del doc["results"][0]["evidence"]
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert failures and "evidence" in failures[0]


def test_gate_blocks_agent_verdict_on_deterministic():
    doc = _minimal_assessment()
    doc["results"][0]["verdict_source"] = "agent"
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert any("amendment 1" in f for f in failures)


def test_gate_blocks_organizational_satisfied():
    doc = _minimal_assessment()
    doc["results"][1]["verdict"] = "satisfied"
    doc["results"][1]["evidence"] = doc["results"][0]["evidence"]
    doc["coverage"]["nist-800-53-rev5"]["satisfied"] = 2
    doc["coverage"]["nist-800-53-rev5"]["not_assessed"] = 0
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert any("organizational" in f for f in failures)


def test_gate_verifies_evidence_hashes(tmp_path):
    doc = _minimal_assessment()
    obj = {"encryption_at_rest": True}
    sha = ca.evidence_id(obj)
    doc["results"][0]["evidence"][0]["sha256"] = sha
    (tmp_path / f"{sha}.json").write_text(json.dumps(obj))
    assert vca.validate(doc, tmp_path, vca.SCHEMA) == []
    # tampered bundle item
    (tmp_path / f"{sha}.json").write_text(json.dumps({"encryption_at_rest": False}))
    failures = vca.validate(doc, tmp_path, vca.SCHEMA)
    assert any("does not hash" in f for f in failures)
    # missing bundle item
    doc["results"][0]["evidence"][0]["sha256"] = "d" * 64
    failures = vca.validate(doc, tmp_path, vca.SCHEMA)
    assert any("no such item" in f for f in failures)


def test_gate_recomputes_coverage():
    doc = _minimal_assessment()
    doc["coverage"]["nist-800-53-rev5"]["satisfied"] = 5
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert any("coverage" in f for f in failures)


def test_gate_forbids_blended_percentage():
    doc = _minimal_assessment()
    doc["coverage"]["nist-800-53-rev5"]["total_in_scope"] = 2
    doc["metadata"]["compliance_pct"] = 87.0
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert any("blended" in f for f in failures)


def test_gate_framework_preconditions():
    doc = _minimal_assessment()
    doc["metadata"]["frameworks"].append({"id": "soc2-tsc"})
    doc["results"].append(
        {
            "framework": "soc2-tsc",
            "control_id": "CC1.1",
            "classification": "organizational",
            "verdict": "not_assessed",
            "verdict_source": "check",
            "reason": "organizational",
        }
    )
    doc["coverage"]["soc2-tsc"] = {
        "total_in_scope": 1,
        "deterministic": 0,
        "evidence_review": 0,
        "organizational": 1,
        "satisfied": 0,
        "not_satisfied": 0,
        "not_applicable": 0,
        "not_assessed": 1,
    }
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert any("trust_service_categories" in f for f in failures)
    doc["metadata"]["target"]["trust_service_categories"] = ["security"]
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert any("point-in-time" in f for f in failures)
    doc["metadata"]["frameworks"][1]["caveat"] = (
        "point-in-time evidence; a SOC 2 Type 2 examination attests a "
        "period — this is audit input, not an attestation"
    )
    assert vca.validate(doc, None, vca.SCHEMA) == []


def test_override_requires_attribution():
    doc = _minimal_assessment()
    doc["results"][0]["verdict_source"] = "human_override"
    failures = vca.validate(doc, None, vca.SCHEMA)
    assert failures  # schema: override block required
    doc["results"][0]["override"] = {
        "by": "reviewer1",
        "date": "2026-07-19",
        "rationale": "compensating control",
    }
    assert vca.validate(doc, None, vca.SCHEMA) == []
