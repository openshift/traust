#!/usr/bin/env python3
"""
Tests for the /cloud-config-audit skill's deterministic layer —
the run_checkov.py normalizer, offline argv guarantee, and report
gate. The scanner itself is never invoked; declared-layer only.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from traust.paths import skill_dir

REPO = Path(__file__).resolve().parent.parent


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "cca_runner", skill_dir("cloud-config-audit") / "scripts" / "run_checkov.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# offline guarantee — structural, so test it structurally
# ---------------------------------------------------------------------------


def test_runner_source_never_reaches_network():
    src = (skill_dir("cloud-config-audit") / "scripts" / "run_checkov.py").read_text(
        encoding="utf-8"
    )
    assert "urllib" not in src
    assert "requests" not in src


def test_runner_argv_offline_flags():
    """The argv builder always passes --skip-download, never an API
    key, and always skips the secrets framework (gitleaks owns that)."""
    runner = _load_runner()
    import inspect

    src = inspect.getsource(runner.run_checkov)
    assert '"--skip-download"' in src
    assert "bc-api-key" not in src
    # format-independent: ruff may split the two tokens across lines
    import re as _re

    assert _re.search(r'"--skip-framework",\s*"secrets"', src)


# ---------------------------------------------------------------------------
# normalizer
# ---------------------------------------------------------------------------


def _checkov_block(check_type="terraform", failed=None, passed=1, parsing_errors=0):
    failed = (
        failed
        if failed is not None
        else [
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                "check_result": {"result": "FAILED"},
                "file_path": "/main.tf",
                "repo_file_path": "/iac/main.tf",
                "file_line_range": [1, 12],
                "resource": "aws_s3_bucket.data",
                "guideline": "https://docs.example/ckv_aws_20",
                "severity": None,
            }
        ]
    )
    return {
        "check_type": check_type,
        "results": {
            "failed_checks": failed,
            "passed_checks": [],
            "skipped_checks": [],
            "parsing_errors": [],
        },
        "summary": {
            "passed": passed,
            "failed": len(failed),
            "skipped": 0,
            "parsing_errors": parsing_errors,
            "resource_count": passed + len(failed),
        },
    }


def test_normalize_single_block_and_list():
    runner = _load_runner()
    facts1, counts1 = runner.normalize_checkov(_checkov_block(), "myrepo")
    facts2, counts2 = runner.normalize_checkov(
        [_checkov_block(), _checkov_block(check_type="kubernetes", failed=[])], "myrepo"
    )
    assert len(facts1) == 1 and counts1["failed"] == 1
    assert len(facts2) == 1 and counts2["passed"] == 2
    assert counts2["frameworks"] == ["kubernetes", "terraform"]


def test_fact_fields_and_unrated_severity():
    runner = _load_runner()
    facts, _ = runner.normalize_checkov(_checkov_block(), "myrepo")
    f = facts[0]
    assert f["fact_id"].startswith("cca-")
    assert f["provider"] == "aws"
    assert f["framework"] == "terraform"
    assert f["scanner_severity"] == "unrated"  # OSS checkov: no severity
    assert f["file_path"] == "/iac/main.tf"
    assert f["resource"] == "aws_s3_bucket.data"


def test_fact_ids_deterministic():
    runner = _load_runner()
    a, _ = runner.normalize_checkov(_checkov_block(), "myrepo")
    b, _ = runner.normalize_checkov(_checkov_block(), "myrepo")
    assert a[0]["fact_id"] == b[0]["fact_id"]


def test_fact_ids_independent_of_clone_location():
    """Checkov sometimes reports absolute paths; the fact_id must not
    depend on where the repo was cloned (pilot-discovered defect)."""
    runner = _load_runner()
    block1, block2 = _checkov_block(), _checkov_block()
    for blk, root in ((block1, "/tmp/clone-a/myrepo"), (block2, "/home/x/myrepo")):
        c = blk["results"]["failed_checks"][0]
        c["repo_file_path"] = f"{root}/iac/main.tf"
    a, _ = runner.normalize_checkov(block1, "myrepo", target_root="/tmp/clone-a/myrepo")
    b, _ = runner.normalize_checkov(block2, "myrepo", target_root="/home/x/myrepo")
    assert a[0]["fact_id"] == b[0]["fact_id"]
    assert a[0]["file_path"] == "/iac/main.tf"


def test_provider_buckets():
    runner = _load_runner()
    cases = {
        "CKV_AWS_1": "aws",
        "CKV2_AZURE_2": "azure",
        "CKV_GCP_3": "gcp",
        "CKV_K8S_4": "kubernetes",
        "CKV_DOCKER_5": "docker",
        "CKV_LIN_6": "other",
    }
    for check_id, expected in cases.items():
        assert runner._provider(check_id) == expected, check_id


# ---------------------------------------------------------------------------
# report gate
# ---------------------------------------------------------------------------


def _report():
    return {
        "title": "Cloud config audit — myrepo (declared)",
        "metadata": {
            "target": "myrepo",
            "assessment_mode": "declared",
            "harness_version": "0.107.0-test",
            "checkov_version": "3.3.6",
            "facts_ref": "myrepo-cloud-facts.json",
            "facts_snapshot_id": "0" * 32,
            "deterministic_steps": [{"tool": "checkov", "invocation": "run_checkov.py"}],
        },
        "summary": {
            "facts_total": 1,
            "confirmed": 1,
            "suppressed": 0,
            "needs_review": 0,
            "gaps": 0,
        },
        "findings": [
            {
                "id": "CCA-myrepo-001",
                "fact_ids": ["cca-0123456789ab"],
                "framework": "terraform",
                "provider": "aws",
                "check_id": "CKV_AWS_20",
                "title": "public bucket ACL",
                "severity": "critical",
                "scanner_severity": "unrated",
                "status": "confirmed",
                "rationale": "R1 exposure: bucket ACL grants public READ "
                "on a data bucket (rubric row R1).",
            }
        ],
    }


def test_gate_accepts_conformant_report(tmp_path):
    pytest.importorskip("jsonschema")
    runner = _load_runner()
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_report()), encoding="utf-8")
    assert runner.validate_report(p) == 0


def test_gate_rejects_observed_mode(tmp_path):
    pytest.importorskip("jsonschema")
    runner = _load_runner()
    doc = _report()
    doc["metadata"]["assessment_mode"] = "observed"  # unrepresentable
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert runner.validate_report(p) == 1


def test_gate_rejects_unrated_severity_without_rationale(tmp_path):
    pytest.importorskip("jsonschema")
    runner = _load_runner()
    doc = _report()
    doc["findings"][0].pop("rationale")  # unrated fact, no rubric row
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert runner.validate_report(p) == 1


def test_gate_rejects_uncited_suppression(tmp_path):
    pytest.importorskip("jsonschema")
    runner = _load_runner()
    doc = _report()
    doc["findings"][0]["status"] = "suppressed"
    doc["findings"][0].pop("rationale")
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert runner.validate_report(p) == 1


def test_corpus_resolver_tags_cloud_config_kind(tmp_path):
    """The shared corpus resolver discovers *-cloud-config-audit.json
    and tags it report_kind='cloud-config' so no consumer can blend
    the units by accident."""
    from traust_engine.corpus import resolver as corpus

    ar = tmp_path / "analysis-results"
    d = ar / "cloud-config" / "t1"
    d.mkdir(parents=True)
    (d / "t1-cloud-config-audit.json").write_text("{}", encoding="utf-8")
    f = ar / "findings" / "prod" / "r1"
    f.mkdir(parents=True)
    (f / "r1-security-audit.json").write_text("{}", encoding="utf-8")
    from traust_contracts import CorpusConfig

    cfg = CorpusConfig.model_validate(
        {
            "version": 1,
            "trees": {
                "cloud-config": {"label": "cc", "ownership": "owned", "business_unit": "HP"},
                "findings": {"label": "hp", "ownership": "owned", "business_unit": "HP"},
            },
        }
    )
    res = corpus.resolve(ar, cfg)
    kinds = {r.base: r.report_kind for r in res.records}
    assert kinds == {"t1": "cloud-config", "r1": "code-audit"}


def test_gate_rejects_missing_fact_ids(tmp_path):
    pytest.importorskip("jsonschema")
    runner = _load_runner()
    doc = _report()
    doc["findings"][0]["fact_ids"] = []
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert runner.validate_report(p) == 1
