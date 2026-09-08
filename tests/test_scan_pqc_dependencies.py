"""Tests for the portfolio-graph crypto backfeed."""

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = skill_dir("pqc-readiness") / "scripts" / "scan_pqc_dependencies.py"

spec = importlib.util.spec_from_file_location("scan_pqc_dependencies", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestDepIdentity:
    def test_plain_name_at_version(self):
        assert mod.dep_identity("DEP_PYCA_CRYPTOGRAPHY", "cryptography@48.0.1") == (
            "cryptography",
            "48.0.1",
        )

    def test_masked_name_keeps_version(self):
        # masked matches fall back to the rule's canonical library name
        assert mod.dep_identity("DEP_GO_JOSE", "github.c***v4.1.4") == ("go-jose", "v4.1.4")

    def test_masked_version_is_unknown(self):
        name, ver = mod.dep_identity("DEP_BOUNCYCASTLE", "org.boun***nknown")
        assert name == "bouncycastle" and ver == "unknown"

    def test_unknown_rule_derives_name(self):
        name, _ = mod.dep_identity("DEP_NEW_THING", "")
        assert name == "new_thing"


class TestRepoNodeId:
    def test_https_url(self):
        assert mod.repo_node_id("https://github.com/openshift/router") == (
            "repo:github.com/openshift/router",
            "openshift/router",
        )

    def test_git_suffix_and_ssh(self):
        rid, _ = mod.repo_node_id("git@gitlab.example.com:org/repo.git")
        assert rid == "repo:gitlab.example.com/org/repo"


class TestEndToEnd:
    @pytest.fixture()
    def workspace(self, tmp_path):
        results = tmp_path / "analysis-results"
        graph = results / "graph"
        graph.mkdir(parents=True)
        db = graph / "portfolio-graph.db"
        con = sqlite3.connect(db)
        con.executescript(
            "CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,"
            " label TEXT, attrs TEXT);"
            "CREATE TABLE edges (src TEXT NOT NULL, dst TEXT NOT NULL,"
            " rel TEXT NOT NULL, attrs TEXT, UNIQUE(src, dst, rel));"
        )
        con.commit()
        con.close()
        slug = results / "pqc" / "demo"
        slug.mkdir(parents=True)
        (slug / "demo-pqc-facts.json").write_text(
            json.dumps(
                {
                    "repository": "https://github.com/example/demo",
                    "facts": [
                        {
                            "rule_id": "DEP_GO_JOSE",
                            "match": "go-jose@v4.1.4",
                            "file": "go.mod",
                            "path_class": "first_party",
                            "ir8547": {
                                "usage": "dep",
                                "qclass": "shor_112bit_or_higher",
                                "clock": {"deprecated_after": None},
                            },
                        },
                        {
                            "rule_id": "TLS_RSA_KEY_EXCHANGE",
                            "match": "TLS_RSA_WITH",
                            "file": "a.go",
                            "path_class": "first_party",
                            "ir8547": {
                                "usage": "ke",
                                "qclass": "shor_112bit_or_higher",
                                "clock": {"deprecated_after": 2030},
                            },
                        },
                    ],
                }
            )
        )
        (slug / "demo-pqc-readiness.json").write_text(
            json.dumps(
                {
                    "readiness_bucket": "partial",
                    "scores": {"overall": 72.5},
                    "flags": {"hndl_priority": True, "has_2030_clock_items": True},
                    "metadata": {"assessed_at": "2026-07-19"},
                }
            )
        )
        return results, db

    def test_backfeed_populates_and_is_idempotent(self, workspace):
        results, db = workspace
        for _ in range(2):  # second run must not duplicate or accumulate
            out = subprocess.run(
                [sys.executable, str(SCRIPT), "--results-root", str(results)],
                capture_output=True,
                text=True,
            )
            assert out.returncode == 0, out.stderr
        con = sqlite3.connect(db)
        deps = con.execute("SELECT src, dst FROM edges WHERE rel='uses_crypto_dep'").fetchall()
        assert deps == [("repo:github.com/example/demo", "crypto-dep:go-jose@v4.1.4")]
        usage = dict(con.execute("SELECT dst, attrs FROM edges WHERE rel='uses_crypto'").fetchall())
        assert "crypto-usage:ke:shor_112bit_or_higher" in usage
        ke = json.loads(usage["crypto-usage:ke:shor_112bit_or_higher"])
        assert ke["clock_2030"] == 1 and ke["first_party"] == 1
        attrs = json.loads(
            con.execute(
                "SELECT attrs FROM nodes WHERE id='repo:github.com/example/demo'"
            ).fetchone()[0]
        )
        assert attrs["pqc"]["readiness_bucket"] == "partial"
        assert attrs["pqc"]["hndl_priority"] is True
        con.close()
