#!/usr/bin/env python3
"""Tests for traust.migrations.resolve_docs_version_refs — the doc-version →
repo@ref join (doc-variance lane part 2)."""

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

from traust.migrations import resolve_docs_version_refs as rdvr

GRAPH = {
    "edges": [
        {"rel": "ships_ref", "release": "9.9", "to": "ref:github.com/fict/api@release-9.9"},
        {"rel": "ships_ref", "release": "9.8", "to": "ref:github.com/fict/api@release-9.8"},
        {
            "rel": "has-findings",
            "from": "repo:github.com/fict/console",
            "to": "findings:fict/console__release-9.9",
        },
        {"rel": "ships", "from": "product:service:fict", "to": "repo:github.com/fict/worker"},
    ]
}


def _map(mode_rule, versions=("9.9", "9.8")):
    return {
        "products": {
            "fict_product": {
                "versions": list(versions),
                "graph_products": ["product:service:fict"],
                "version_to_refs": mode_rule,
                "confirmed": False,
            }
        }
    }


def test_graph_release_mode():
    res = rdvr.resolve(
        _map({"mode": "graph-release", "release": "{version}"}), GRAPH, "fict_product", "9.9"
    )
    assert res["repo_refs"] == [{"repo": "fict/api", "ref": "release-9.9"}]
    assert res["confirmed"] is False


def test_ref_pattern_mode_reads_findings_slugs():
    res = rdvr.resolve(
        _map({"mode": "ref-pattern", "pattern": "release-{version}"}), GRAPH, "fict_product", "9.9"
    )
    assert {"repo": "fict/console", "ref": "release-9.9"} in res["repo_refs"]


def test_head_mode_uses_ships_edges():
    res = rdvr.resolve(_map({"mode": "head"}), GRAPH, "fict_product", "9.9")
    assert res["repo_refs"] == [{"repo": "fict/worker", "ref": "HEAD"}]


def test_unenumerated_version_fails_loud():
    with pytest.raises(SystemExit, match="not in the enumerated set"):
        rdvr.resolve(_map({"mode": "head"}), GRAPH, "fict_product", "1.0")


def test_zero_pairs_truly_empty():
    g = {"edges": []}
    with pytest.raises(SystemExit, match="ZERO repo@ref"):
        rdvr.resolve(
            _map({"mode": "ref-pattern", "pattern": "release-{version}"}), g, "fict_product", "9.9"
        )
