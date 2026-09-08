#!/usr/bin/env python3
"""Tests for harnessing/refresh-dashboards/scripts/build_dependency_exposure.py — the multi-ecosystem
dependency-exposure dashboard (graph blast radius + CVE/MAL exposure)."""

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]


_SPEC = importlib.util.spec_from_file_location(
    "build_dependency_exposure",
    skill_dir("refresh-dashboards") / "scripts" / "build_dependency_exposure.py",
)
bde = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bde)

CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: Example}
"""


def _seed_graph(db_path: Path):
    """A tiny portfolio graph: 2 products shipping 3 repos, npm + pypi +
    docker depends_on edges to shared packages."""
    con = sqlite3.connect(db_path)
    con.executescript(
        "CREATE TABLE nodes(id TEXT PRIMARY KEY, kind TEXT, label TEXT, "
        "attrs TEXT);"
        "CREATE TABLE edges(src TEXT, dst TEXT, rel TEXT, attrs TEXT);"
    )

    def node(nid, kind, label, attrs=None):
        con.execute(
            "INSERT INTO nodes VALUES(?,?,?,?)", (nid, kind, label, json.dumps(attrs or {}))
        )

    def edge(src, dst, rel, attrs=None):
        con.execute("INSERT INTO edges VALUES(?,?,?,?)", (src, dst, rel, json.dumps(attrs or {})))

    # products + repos
    node("product:web", "product", "web-console")
    node("product:api", "product", "api-server")
    for r in ("repo:github.com/org/r1", "repo:github.com/org/r2", "repo:github.com/org/r3"):
        node(r, "repo", r.split("/", 1)[1])
    edge("product:web", "repo:github.com/org/r1", "ships")
    edge("product:web", "repo:github.com/org/r2", "ships")
    edge("product:api", "repo:github.com/org/r3", "ships")

    # packages (npm lodash shared by r1+r2; pypi requests by r3; docker base)
    node(
        "pkg:npm/lodash", "package", "lodash", {"ecosystem": "npm", "name": "lodash", "internal": 0}
    )
    node(
        "pkg:npm/left-pad",
        "package",
        "left-pad",
        {"ecosystem": "npm", "name": "left-pad", "internal": 0},
    )
    node(
        "pkg:pypi/requests",
        "package",
        "requests",
        {"ecosystem": "pypi", "name": "requests", "internal": 0},
    )
    node(
        "pkg:docker/alpine",
        "package",
        "alpine",
        {"ecosystem": "docker", "name": "alpine", "internal": 0},
    )

    edge(
        "repo:github.com/org/r1",
        "pkg:npm/lodash",
        "depends_on",
        {"ecosystem": "npm", "version": "4.17.0", "indirect": 0},
    )
    edge(
        "repo:github.com/org/r2",
        "pkg:npm/lodash",
        "depends_on",
        {"ecosystem": "npm", "version": "4.17.21", "indirect": 0},
    )
    edge(
        "repo:github.com/org/r1",
        "pkg:npm/left-pad",
        "depends_on",
        {"ecosystem": "npm", "version": "1.0.0", "indirect": 1},
    )
    edge(
        "repo:github.com/org/r3",
        "pkg:pypi/requests",
        "depends_on",
        {"ecosystem": "pypi", "version": "2.20.0", "indirect": 0},
    )
    edge(
        "repo:github.com/org/r1",
        "pkg:docker/alpine",
        "depends_on",
        {"ecosystem": "docker", "version": "3.18", "indirect": 0},
    )
    con.commit()
    con.close()


def _seed_impact(impact_dir: Path):
    impact_dir.mkdir(parents=True, exist_ok=True)
    # a CVE affecting npm lodash across r1+r2
    (impact_dir / "cve-2099-0001-impact-analysis.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "cve": "CVE-2099-0001",
                    "module": "lodash",
                    "ecosystem": "npm",
                    "vulnerable_range": "< 4.17.21",
                    "feature_description": "prototype pollution",
                },
                "summary": {"repos_in_blast_radius": 2, "affected": 1},
                "repos": [
                    {
                        "repo": "repo:github.com/org/r1",
                        "classification": "affected",
                        "products": ["web-console"],
                    },
                    {
                        "repo": "repo:github.com/org/r2",
                        "classification": "version_not_in_range",
                        "products": ["web-console"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _seed_fleet(impact_dir: Path):
    impact_dir.mkdir(parents=True, exist_ok=True)
    (impact_dir / "fleet-osv-worklist-2099-01-01.json").write_text(
        json.dumps(
            {
                "artifact": "fleet-osv-worklist",
                "generated_at": "2099-01-01T00:00:00Z",
                "worklist": [
                    {
                        "id": "MAL-2099-6666",
                        "cve": None,
                        "osv": "MAL-2099-6666",
                        "malicious": True,
                        "severity": "CRITICAL",
                        "ecosystem": "npm",
                        "summary": "Shai-Hulud worm in left-pad",
                        "modules": ["left-pad"],
                        "in_range_repos": 1,
                        "manifest": {"left-pad": {"repo:github.com/org/r1": ["package.json"]}},
                    },
                ],
                "refuted_findings": [],
                "rejected_inputs": [],
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def cfg(tmp_path):
    cfg_path = tmp_path / "corpus-config.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    return bde.corpus.load_config(cfg_path)


@pytest.fixture
def seeded(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    (ar / "findings").mkdir(parents=True)
    db = ar / "graph" / "portfolio-graph.db"
    db.parent.mkdir(parents=True)
    _seed_graph(db)
    impact = ar / "impact"
    _seed_impact(impact)
    _seed_fleet(impact)
    stats = ar / "graph" / "deps-multi-stats.json"
    stats.write_text(
        json.dumps(
            {
                "npm": {"repos_with_manifest": 2, "pkg_nodes": 2, "dep_edges": 3},
                "pypi": {"repos_with_manifest": 1, "pkg_nodes": 1, "dep_edges": 1},
            }
        ),
        encoding="utf-8",
    )
    return ar, db, stats, impact, cfg


def test_per_ecosystem_coverage(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    cov = {c["ecosystem"]: c for c in data["coverage"]}
    assert cov["npm"]["pkg_nodes"] == 2
    assert cov["npm"]["dep_edges"] == 3  # lodash x2 + left-pad
    assert cov["npm"]["repos_with_deps"] == 2
    assert cov["npm"]["repos_with_manifest"] == 2  # from deps-multi-stats
    # docker is present but flagged graph-only (no OSV lane)
    assert cov["docker"]["graph_only"] is True


def test_top_shared_blast_radius(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    npm_top = data["top_shared"]["npm"]
    top = npm_top[0]
    assert top["package"] == "lodash"
    assert top["repo_blast_radius"] == 2
    # r1 -> web-console, r2 -> web-console => 1 distinct product
    assert top["product_blast_radius"] == 1


def test_cve_exposure_joined_to_graph(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    cve = next(a for a in data["exposure"] if a["advisory"] == "CVE-2099-0001")
    # only r1 is classified affected (r2 is version_not_in_range)
    assert cve["repos_exposed"] == 1
    assert cve["graph_matched"] is True
    assert cve["graph_repo_blast_radius"] == 2  # both r1+r2 depend on lodash
    assert cve["malicious"] is False


def test_malicious_exposure_row(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    assert data["totals"]["malicious_advisories"] == 1
    mal = data["malicious_exposure"][0]
    assert mal["advisory"] == "MAL-2099-6666"
    assert mal["ecosystem"] == "npm"
    assert mal["packages"] == ["left-pad"]
    assert mal["repos_exposed"] == 1
    assert "web-console" in mal["products"]  # r1 -> web-console
    # malicious sorts to the top of the combined exposure table
    assert data["exposure"][0]["malicious"] is True


def test_per_product_rollup(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    rollup = {p["product"]: p for p in data["per_product"]}
    # web-console (r1) is hit by both CVE-2099-0001 and MAL-2099-6666
    assert rollup["web-console"]["advisory_hits"] == 2
    assert rollup["web-console"]["malicious_hits"] == 1


def test_population_block_present(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    pop = "\n".join(data["population"])
    assert "## Population" in pop
    assert "dependency-exposure" in pop
    assert "portfolio-graph.db" in pop
    md = bde.render_md(data)
    assert "**Generated:**" in md  # drift-watch staleness stamp
    assert "Malicious-package (MAL-) exposure" in md
    html = bde.render_html(data)
    assert "<table" in html and "left-pad" in html


def test_json_strips_internal_keys(seeded):
    ar, db, stats, impact, cfg = seeded
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    clean = bde._strip_internal(data)
    assert all("_repos" not in a for a in clean["exposure"])
    assert all("_repos" not in a for a in clean["malicious_exposure"])


def test_empty_inputs_valid_empty_dashboard(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    (ar / "findings").mkdir(parents=True)
    db = ar / "graph" / "portfolio-graph.db"  # does not exist
    stats = ar / "graph" / "deps-multi-stats.json"  # does not exist
    impact = ar / "impact"  # does not exist
    data = bde.build(db, stats, impact, ar, cfg, top=10)
    assert data["has_data"] is False
    assert data["coverage"] == []
    assert data["exposure"] == []
    assert data["totals"]["advisories"] == 0
    # renderers must not crash on empty data and must carry the no-data note
    md = bde.render_md(data)
    assert "No dependency-exposure data available" in md
    assert "**Generated:**" in md
    html = bde.render_html(data)
    assert "No dependency-exposure data available" in html
    assert html.strip().endswith("</html>")
    # population block still present
    assert "## Population" in "\n".join(data["population"])


def test_malformed_artifacts_never_crash(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    (ar / "findings").mkdir(parents=True)
    db = ar / "graph" / "portfolio-graph.db"
    db.parent.mkdir(parents=True)
    _seed_graph(db)
    impact = ar / "impact"
    impact.mkdir(parents=True)
    (impact / "bad-impact-analysis.json").write_text("{not json", encoding="utf-8")
    (impact / "fleet-osv-worklist-x.json").write_text("[garbage", encoding="utf-8")
    data = bde.build(db, db.parent / "deps-multi-stats.json", impact, ar, cfg, top=10)
    assert data["impact_stats"]["impact_unreadable"] == 1
    assert data["impact_stats"]["fleet_unreadable"] == 1
    assert data["has_data"] is True  # graph still present
