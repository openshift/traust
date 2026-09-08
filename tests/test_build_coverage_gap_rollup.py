#!/usr/bin/env python3
"""Tests for harnessing/3-audit/secure-code-audit/scripts/build_coverage_gap_rollup.py — the enumerator-
expansion backlog aggregator (deep-fn Phase-B prioritization input)."""

import importlib.util
import json
from pathlib import Path

import pytest

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]


_SPEC = importlib.util.spec_from_file_location(
    "build_coverage_gap_rollup",
    skill_dir("secure-code-audit") / "scripts" / "build_coverage_gap_rollup.py",
)
bcg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bcg)

CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: Example}
"""


def _write(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _report(repo_url, additional=None, negative_results=None):
    return {
        "metadata": {"repository": repo_url, "additional": additional or {}},
        "findings": [],
        "negative_results": negative_results or [],
    }


@pytest.fixture
def workspace(tmp_path):
    cfg_path = tmp_path / "corpus-config.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    ar = tmp_path / "analysis-results"

    # repo1: structured coverage_gaps (the recording convention)
    _write(
        ar / "findings/prodA/repo1/repo1-security-audit.json",
        _report(
            "https://github.com/org/repo1",
            additional={
                "coverage_gaps": [
                    {"tool": "config-matrix", "system": "toml-ini-properties", "count": 25},
                    {"tool": "route-guards", "system": "express"},
                ],
                "deterministic_steps": {"opengrep": "ran"},
            },
        ),
    )
    # repo2: same TOML family (structured) + a skipped pre-scan
    _write(
        ar / "findings/prodA/repo2/repo2-security-audit.json",
        _report(
            "https://github.com/org/repo2",
            additional={
                "coverage_gaps": [
                    {"tool": "config-matrix", "system": "toml-ini-properties", "count": 3},
                ],
                "deterministic_steps": {"sanitizer-probes": "skipped: Python-only tool, Go target"},
            },
        ),
    )
    # repo3: text-tier signals only (legacy report, pre-convention)
    _write(
        ar / "findings/prodA/repo3/repo3-security-audit.json",
        _report(
            "https://github.com/org/repo3",
            negative_results=[
                {
                    "area": "Coverage gaps (deterministic tooling)",
                    "result": "opengrep traust pack has 0 Rust rules "
                    "(99 kLoC = ~75% of the code); express routes "
                    "detected but v1 enumerates only go-http — "
                    "this family's route×guard matrix is "
                    "UNENUMERATED",
                },
            ],
        ),
    )
    return ar, bcg.load_config(cfg_path)


def _family(data, tool, system):
    return next(
        (g for g in data["gap_families"] if g["tool"] == tool and g["system"] == system), None
    )


def test_structured_gaps_aggregate_across_repos(workspace):
    ar, cfg = workspace
    data = bcg.build_rollup(ar, cfg)
    fam = _family(data, "config-matrix", "toml-ini-properties")
    assert fam["repos_affected"] == 2
    assert fam["items_recorded"] == 28
    assert fam["signals"]["structured"] == 2


def test_skipped_prescan_becomes_steps_row(workspace):
    ar, cfg = workspace
    data = bcg.build_rollup(ar, cfg)
    fam = _family(data, "sanitizer-probes", "pre-scan-skipped")
    assert fam and fam["signals"]["steps"] == 1


def test_text_signatures_extract_language_and_framework(workspace):
    ar, cfg = workspace
    data = bcg.build_rollup(ar, cfg)
    rust = _family(data, "opengrep", "rust")
    assert rust and rust["signals"]["text"] == 1
    express = _family(data, "route-guards", "express")
    # repo1 structured + repo3 text merge into one family
    assert express["repos_affected"] == 2
    assert express["signals"] == {"structured": 1, "text": 1}


def test_ranking_by_repos_affected(workspace):
    ar, cfg = workspace
    data = bcg.build_rollup(ar, cfg)
    counts = [g["repos_affected"] for g in data["gap_families"]]
    assert counts == sorted(counts, reverse=True)


def test_population_block_and_render(workspace):
    ar, cfg = workspace
    data = bcg.build_rollup(ar, cfg)
    assert data["population"]["scored"] == 3
    md = bcg.render_md(data)
    assert "Population:" in md
    assert "toml-ini-properties" in md
    assert "corpus.py" in data["population"]["note"]


def test_unreadable_report_counted_not_fatal(workspace):
    ar, cfg = workspace
    (ar / "findings/prodA/repo4").mkdir(parents=True)
    (ar / "findings/prodA/repo4/repo4-security-audit.json").write_text("{not json")
    data = bcg.build_rollup(ar, cfg)
    assert data["population"]["unreadable"] == 1
    assert data["population"]["scored"] == 3


def test_no_gap_prose_never_fabricates(workspace, tmp_path):
    cfg_path = tmp_path / "c2.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    ar2 = tmp_path / "ar2" / "analysis-results"
    _write(
        ar2 / "findings/p/r/r-security-audit.json",
        _report(
            "https://github.com/org/r",
            negative_results=[
                {"area": "auth", "result": "all endpoints enforce RBAC; no coverage concerns"}
            ],
        ),
    )
    data = bcg.build_rollup(ar2, bcg.load_config(cfg_path))
    assert data["gap_families"] == []
