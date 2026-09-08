#!/usr/bin/env python3
"""Tests for harnessing/3-audit/compliance-check/scripts/compliance_scope_intake.py — the validated (and
only) interview write path into the compliance scope registry
(Phase 7)."""

import json

import compliance_scope_intake as csi
import pytest


@pytest.fixture
def graph(tmp_path):
    g = {
        "nodes": [
            {"id": "product:service:svc", "type": "product", "label": "Svc"},
            {"id": "repo:github.com/org/api", "type": "repo"},
            {"id": "repo:github.com/org/docs", "type": "repo"},
        ],
        "edges": [
            {"from": "product:service:svc", "to": "repo:github.com/org/api", "rel": "ships"},
            {"from": "product:service:svc", "to": "repo:github.com/org/docs", "rel": "ships"},
        ],
    }
    p = tmp_path / "graph.json"
    p.write_text(json.dumps(g))
    return p


def _run(tmp_path, graph, *extra, boundary="b1"):
    scope = tmp_path / "scope.yaml"
    return csi.main(
        [
            "--boundary",
            boundary,
            "--frameworks",
            "nist-800-53-rev5",
            "--resolves-via",
            "repo-graph",
            "--product",
            "product:service:svc",
            "--declared-by",
            "jdoe",
            "--scope",
            str(scope),
            "--graph",
            str(graph),
            *extra,
        ]
    ), scope


def test_unverified_records_as_draft(tmp_path, graph):
    rc, scope = _run(tmp_path, graph)
    assert rc == 0
    import yaml

    doc = yaml.safe_load(scope.read_text())
    b = doc["boundaries"]["b1"]
    assert b["declared_by"] == "draft:jdoe"
    assert b["declared_at"]


def test_overwrite_refused_without_update(tmp_path, graph):
    rc, _scope = _run(tmp_path, graph)
    assert rc == 0
    with pytest.raises(SystemExit, match="already declared"):
        _run(tmp_path, graph)


def test_update_flag_allows_modification(tmp_path, graph):
    _run(tmp_path, graph)
    rc, scope = _run(
        tmp_path, graph, "--update", "--exclude", "org/docs=docs only, outside boundary"
    )
    assert rc == 0
    import yaml

    doc = yaml.safe_load(scope.read_text())
    assert doc["boundaries"]["b1"]["exclude"] == [
        {"repo": "org/docs", "reason": "docs only, outside boundary"}
    ]


def test_rationale_mandatory_on_edges(tmp_path, graph):
    with pytest.raises(SystemExit, match="rationale is mandatory"):
        _run(tmp_path, graph, "--exclude", "org/docs")


def test_unresolvable_entry_refused_not_recorded(tmp_path, graph):
    scope = tmp_path / "scope.yaml"
    with pytest.raises(SystemExit, match="does not resolve"):
        csi.main(
            [
                "--boundary",
                "bad",
                "--frameworks",
                "nist-800-53-rev5",
                "--resolves-via",
                "repo-graph",
                "--product",
                "product:service:ghost",
                "--declared-by",
                "jdoe",
                "--scope",
                str(scope),
                "--graph",
                str(graph),
            ]
        )
    assert not scope.exists()


def test_schema_gate_rejects_bad_framework(tmp_path, graph):
    scope = tmp_path / "scope.yaml"
    with pytest.raises(SystemExit, match="scope schema"):
        csi.main(
            [
                "--boundary",
                "b1",
                "--frameworks",
                "iso-27001",
                "--resolves-via",
                "repo-graph",
                "--product",
                "product:service:svc",
                "--declared-by",
                "jdoe",
                "--scope",
                str(scope),
                "--graph",
                str(graph),
            ]
        )
    assert not scope.exists()


def test_dry_run_writes_nothing(tmp_path, graph):
    rc, scope = _run(tmp_path, graph, "--dry-run")
    assert rc == 0
    assert not scope.exists()


def test_verify_identity_failure_downgrades_to_draft(tmp_path, graph, monkeypatch):
    monkeypatch.setattr(csi, "verify_identity", lambda uid: False)
    rc, scope = _run(tmp_path, graph, "--verify-identity")
    assert rc == 0
    import yaml

    assert yaml.safe_load(scope.read_text())["boundaries"]["b1"]["declared_by"] == "draft:jdoe"


def test_verify_identity_success_signs(tmp_path, graph, monkeypatch):
    monkeypatch.setattr(csi, "verify_identity", lambda uid: True)
    rc, scope = _run(tmp_path, graph, "--verify-identity")
    assert rc == 0
    import yaml

    assert yaml.safe_load(scope.read_text())["boundaries"]["b1"]["declared_by"] == "jdoe"
