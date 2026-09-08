#!/usr/bin/env python3
"""Tests for traust.migrations.extract_benchmark_rule_candidates — the
identity-only post-scoring capture of rule-expressible shapes from
contamination-isolated benchmark runs."""

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


from traust.migrations import extract_benchmark_rule_candidates as ebrc
from traust.paths import skill_dir

PACK = skill_dir("secure-code-audit") / "opengrep-rules"


def _report(repo, findings):
    return {"metadata": {"repository": repo}, "findings": findings}


def _finding(fid, sev, cwes, path, title="finding"):
    return {"id": fid, "severity": sev, "cwes": cwes, "locations": [{"path": path}], "title": title}


@pytest.fixture
def runs(tmp_path):
    d = tmp_path / "runs" / "bt-x-001"
    d.mkdir(parents=True)
    (d / "x-security-audit.json").write_text(
        json.dumps(
            _report(
                "https://github.com/org/x",
                [
                    _finding(
                        "X-001", "high", ["CWE-319"], "cfg/values.yaml", "sslmode=disable default"
                    ),
                    _finding("X-002", "high", ["CWE-330"], "pkg/rand.go", "math/rand credentials"),
                    # dependency class: routed out, never a rule candidate
                    _finding("X-003", "high", ["CWE-1104"], "go.mod", "outdated dep"),
                    # semantic class: routed out with reason
                    _finding("X-004", "high", ["CWE-862"], "pkg/api.go", "missing authz"),
                    # below severity floor
                    _finding("X-005", "low", ["CWE-798"], "cfg/dev.yaml", "dev credential"),
                ],
            )
        )
    )
    return tmp_path / "runs"


def test_expressible_clusters_extracted(runs):
    data = ebrc.extract(runs, PACK, "medium")
    keys = {(c["cwe"], c["language"]) for c in data["clusters"]}
    assert ("CWE-319", "yaml") in keys
    assert ("CWE-330", "go") in keys


def test_dependency_and_semantic_routed_out_with_reasons(runs):
    data = ebrc.extract(runs, PACK, "medium")
    assert data["routed_out"]["dependency_version_class"] == 1
    assert data["routed_out"]["semantic_logic_class"] == 1
    assert data["routed_out"]["below_severity_floor"] == 1
    keys = {c["cwe"] for c in data["clusters"]}
    assert "CWE-1104" not in keys and "CWE-862" not in keys


def test_pack_coverage_flag(runs):
    data = ebrc.extract(runs, PACK, "medium")
    [dsn] = [c for c in data["clusters"] if c["cwe"] == "CWE-319" and c["language"] == "yaml"]
    # the shipped yaml cryptography pack covers CWE-319 DSN shapes
    assert dsn["pack_covered"] is True


def test_banner_and_identity_only_shape(runs):
    data = ebrc.extract(runs, PACK, "medium")
    assert "MUST NOT be ingested as findings" in data["banner"]
    for c in data["clusters"]:
        for cand in c["candidates"]:
            # identity fields only — no description/evidence/remediation
            assert set(cand) <= {"run", "repo", "finding_id", "severity", "title", "file"}
    md = ebrc.render_md(data)
    assert "BENCHMARK-DERIVED CANDIDATES" in md
    assert "NO — backlog" in md


def test_uncovered_clusters_sort_first(runs):
    data = ebrc.extract(runs, PACK, "medium")
    flags = [c["pack_covered"] for c in data["clusters"]]
    assert flags == sorted(flags)
