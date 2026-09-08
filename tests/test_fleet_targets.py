"""Tests for harnessing/7-remediate/fleet-fix/scripts/fleet_targets.py — fleet resolution."""

import importlib.util
import json
import sqlite3
import sys

from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "fleet_targets", skill_dir("fleet-fix") / "scripts" / "fleet_targets.py"
)
ft = importlib.util.module_from_spec(_SPEC)
sys.modules["fleet_targets"] = ft
_SPEC.loader.exec_module(ft)


def _layout(tmp_path):
    """Return (progress_tracker, analysis_results) roots under tmp_path."""
    tracker = tmp_path / "progress-tracker"
    results = tmp_path / "analysis-results"
    ip = tracker / "metrics/dashboards/insecure-patterns"
    ip.mkdir(parents=True)
    (ip / "insecure-patterns.json").write_text(
        json.dumps(
            {
                "patterns": [
                    {
                        "cwe": "CWE-1104",
                        "name": "Unpinned deps",
                        "repos": ["org/alpha", "org/beta"],
                    },
                    {"cwe": "CWE-89", "name": "SQLi", "repos": ["org/gamma"]},
                ]
            }
        )
    )
    mf = results / "findings/_manifest"
    mf.mkdir(parents=True)
    (mf / "PROGRESS.md").write_text(
        "| 1 | org/alpha | main@x | 0/1/0/0/0 | Konflux pipelineRef "
        "mutable main | `findings/p/alpha/` |\n"
        "| 2 | org/other | main@y | 0/0/1/0/0 | unrelated finding "
        "| `findings/p/other/` |\n"
    )
    g = results / "graph"
    g.mkdir(parents=True)
    (g / "repo-graph.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "id": "repo:github.com/org/alpha",
                        "type": "repo",
                        "label": "org/alpha",
                        "attrs": {"url": "https://github.com/org/alpha"},
                    },
                    {
                        "id": "repo:github.com/org/beta",
                        "type": "repo",
                        "label": "org/beta",
                        "attrs": {"url": "https://github.com/org/beta"},
                    },
                ],
                "edges": [
                    {"from": "category:x/Cat", "to": "repo:github.com/org/alpha", "rel": "ships"},
                    {"from": "category:y/Cat", "to": "repo:github.com/org/alpha", "rel": "ships"},
                    {
                        "from": "repo:github.com/org/alpha",
                        "to": "owner-team:Team A",
                        "rel": "owned-by",
                    },
                ],
            }
        )
    )
    con = sqlite3.connect(g / "portfolio-graph.db")
    con.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT, label TEXT, attrs TEXT)")
    con.execute("CREATE TABLE edges (src TEXT, dst TEXT, rel TEXT, attrs TEXT)")
    con.executemany(
        "INSERT INTO edges VALUES (?,?,?,NULL)",
        [
            ("repo:github.com/org/alpha", "module:github.com/dep/lib", "depends_on"),
            ("repo:github.com/org/beta", "srcpkg:github.com/dep/lib/pkg/sub", "imports_package"),
            ("repo:github.com/org/other", "module:github.com/dep/unrelated", "depends_on"),
            ("repo:github.com/org/goconsumer", "module:leftpad", "depends_on"),
            ("repo:github.com/org/npmconsumer", "pkg:npm/leftpad", "depends_on"),
        ],
    )
    con.commit()
    con.close()
    return tracker, results


def test_cwe_source(tmp_path):
    tracker, _ = _layout(tmp_path)
    repos = ft.from_cwe(tracker, "CWE-1104")
    assert set(repos) == {"org/alpha", "org/beta"}


def test_rollup_source(tmp_path):
    _, results = _layout(tmp_path)
    assert set(ft.from_rollup(results, "pipelineRef")) == {"org/alpha"}


def test_module_source_includes_subpackages(tmp_path):
    _, results = _layout(tmp_path)
    repos = ft.from_module(results, "github.com/dep/lib")
    assert set(repos) == {"org/alpha", "org/beta"}


def test_module_resolves_go_and_nongo_consumers(tmp_path):
    _, results = _layout(tmp_path)
    assert set(ft.from_module(results, "leftpad")) == {"org/goconsumer", "org/npmconsumer"}
    assert set(ft.from_module(results, "leftpad", "npm")) == {"org/npmconsumer"}
    npm = ft.from_module(results, "leftpad", "npm")
    assert "pkg:npm/leftpad" in npm["org/npmconsumer"]


def test_module_go_only_path_unchanged(tmp_path):
    _, results = _layout(tmp_path)
    go = ft.from_module(results, "github.com/dep/lib")
    assert set(go) == {"org/alpha", "org/beta"}
    assert all(v == "portfolio-graph imports/depends on github.com/dep/lib" for v in go.values())


def test_ecosystem_without_module_errors(tmp_path):
    _, results = _layout(tmp_path)
    with __import__("pytest").raises(SystemExit):
        ft.main(["--cwe", "CWE-1104", "--ecosystem", "npm", "--results-root", str(results)])


def test_enrichment_reach_owner_and_ordering(tmp_path):
    _, results = _layout(tmp_path)
    targets = ft.resolve(results, {"org/alpha": "e", "org/beta": "e", "org/unknown": "e"})
    assert [t["repo"] for t in targets] == ["org/alpha", "org/beta", "org/unknown"]
    a = targets[0]
    assert a["product_reach"] == 2 and a["owner_team"] == "Team A"
    unk = targets[2]
    assert not unk["in_repo_graph"]
    assert unk["url"] == "https://github.com/org/unknown"


def test_main_writes_fleet_json(tmp_path, monkeypatch):
    tracker, results = _layout(tmp_path)
    monkeypatch.setattr(ft, "load_engine", lambda config_home=None: object())
    monkeypatch.setattr(ft, "resolve_results_root", lambda args: results)
    monkeypatch.setattr(ft, "progress_tracker_dir", lambda engine: tracker)
    out = tmp_path / "fleet.json"
    rc = ft.main(["--cwe", "CWE-1104", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["source"] == "cwe:CWE-1104"
    assert len(doc["targets"]) == 2
