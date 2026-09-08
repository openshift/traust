"""Tests for the per-product PQC report builder's additive cross-language
crypto-dependency section (build_pqc_product_reports.py)."""

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from traust.paths import skill_dir

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = skill_dir("pqc-readiness") / "scripts" / "build_pqc_product_reports.py"

spec = importlib.util.spec_from_file_location("build_pqc_product_reports", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def _seed_graph(db: Path, *, with_crypto: bool):
    """product:acme ships two repos with PQC attrs; optionally each repo also
    has a crypto `depends_on` edge (node-forge / cryptography)."""
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,"
        " label TEXT, attrs TEXT);"
        "CREATE TABLE edges (src TEXT NOT NULL, dst TEXT NOT NULL,"
        " rel TEXT NOT NULL, attrs TEXT, UNIQUE(src, dst, rel));"
    )
    repo_a = "repo:github.com/acme/web"
    repo_b = "repo:github.com/acme/api"
    for rid, slug, bucket, overall in [
        (repo_a, "web", "not-ready", 40),
        (repo_b, "api", "partial", 70),
    ]:
        con.execute(
            "INSERT INTO nodes (id, kind, label, attrs) VALUES (?,?,?,?)",
            (
                rid,
                "repo",
                slug,
                json.dumps(
                    {
                        "pqc": {
                            "slug": slug,
                            "overall": overall,
                            "readiness_bucket": bucket,
                            "hndl_priority": False,
                            "has_2030_clock_items": False,
                        }
                    }
                ),
            ),
        )
    edges = [
        ("product:acme", repo_a, "ships", None),
        ("product:acme", repo_b, "ships", None),
    ]
    if with_crypto:
        edges += [
            (
                repo_a,
                "pkg:npm/node-forge",
                "depends_on",
                json.dumps(
                    {"version": "1.3.1", "ecosystem": "npm", "manifest": ["ui/package.json"]}
                ),
            ),
            (
                repo_b,
                "pkg:pypi/cryptography",
                "depends_on",
                json.dumps(
                    {
                        "version": "44.0.0",
                        "ecosystem": "pypi",
                        "indirect": 1,
                        "manifest": ["requirements.txt"],
                    }
                ),
            ),
            # a non-crypto dep must not appear
            (
                repo_a,
                "pkg:npm/lodash",
                "depends_on",
                json.dumps(
                    {"version": "4.17.21", "ecosystem": "npm", "manifest": ["ui/package.json"]}
                ),
            ),
        ]
    con.executemany("INSERT INTO edges (src, dst, rel, attrs) VALUES (?,?,?,?)", edges)
    con.commit()
    con.close()


def _run(tmp_path, *, with_crypto: bool):
    results = tmp_path / "analysis-results"
    (results / "graph").mkdir(parents=True)
    (results / "pqc").mkdir(parents=True)
    _seed_graph(results / "graph" / "portfolio-graph.db", with_crypto=with_crypto)
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--results-root", str(results), "--out-dir", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return out


class TestCryptoSection:
    def test_renders_section_from_seeded_graph(self, tmp_path):
        out = _run(tmp_path, with_crypto=True)
        acme = (out / "acme.md").read_text()
        assert "## Cross-language crypto dependencies" in acme
        assert "node-forge" in acme
        assert "cryptography" in acme
        assert "inherits-from-openssl" in acme
        # classical-only rollup is surfaced as migration-relevant
        assert "classical-only" in acme
        # non-crypto dep excluded
        assert "lodash" not in acme
        # index carries the crypto-deps column
        readme = (out / "README.md").read_text()
        assert "Crypto-deps" in readme

    def test_degrades_cleanly_when_no_crypto_deps(self, tmp_path):
        out = _run(tmp_path, with_crypto=False)
        acme = (out / "acme.md").read_text()
        # section still present, additive, no crash
        assert "## Cross-language crypto dependencies" in acme
        assert "No curated crypto-library dependencies" in acme
        # TLS-readiness content is unchanged / still there
        assert "| Repo | Score | Bucket | HNDL | 2030-clock items |" in acme

    def test_section_handles_graph_absent_result(self):
        """The section builder never crashes when discovery reports the
        graph (or its multi-ecosystem layer) is absent."""
        lines = mod._crypto_deps_section({"github.com/acme/web"}, {}, {"graph_present": False})
        text = "\n".join(lines)
        assert "## Cross-language crypto dependencies" in text
        assert "unavailable" in text

    def test_section_escapes_untrusted_cells(self):
        """Repo/package names go through md_cell — a pipe cannot forge a
        column."""
        crypto_by_repo = {
            "github.com/acme/web": [
                {
                    "repo": "github.com/acme/web",
                    "package": "ev|il",
                    "version": "1.0",
                    "ecosystem": "npm",
                    "manifest": ["a|b"],
                    "posture": "classical-only",
                    "indirect": 0,
                }
            ]
        }
        lines = mod._crypto_deps_section(
            {"github.com/acme/web"}, crypto_by_repo, {"graph_present": True, "ecosystems": {}}
        )
        text = "\n".join(lines)
        assert "ev\\|il" in text
        assert "a\\|b" in text
