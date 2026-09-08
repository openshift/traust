"""Tests for the graph-backed cross-language crypto-dependency discovery
step (scan_crypto_deps_graph.py — the PQC dep-graph wiring)."""

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from traust.paths import skill_dir

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = skill_dir("pqc-readiness") / "scripts" / "scan_crypto_deps_graph.py"
CAPS = skill_dir("pqc-readiness") / "notes" / "capabilities"
CARD_SCHEMA = skill_dir("pqc-readiness") / "notes" / "schemas" / "capability-card.schema.json"

spec = importlib.util.spec_from_file_location("scan_crypto_deps_graph", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def _seed_graph(db: Path):
    """A graph with the standard nodes/edges shape and a mix of crypto and
    non-crypto depends_on edges across ecosystems."""
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,"
        " label TEXT, attrs TEXT);"
        "CREATE TABLE edges (src TEXT NOT NULL, dst TEXT NOT NULL,"
        " rel TEXT NOT NULL, attrs TEXT, UNIQUE(src, dst, rel));"
    )
    edges = [
        # crypto: npm node-forge (classical-only)
        (
            "repo:github.com/example/web",
            "pkg:npm/node-forge",
            "depends_on",
            json.dumps(
                {
                    "version": "1.3.1",
                    "ecosystem": "npm",
                    "indirect": 0,
                    "manifest": ["ui/package.json"],
                }
            ),
        ),
        # crypto: pypi cryptography (inherits-from-openssl)
        (
            "repo:github.com/example/api",
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
        # non-crypto: must NOT be picked up
        (
            "repo:github.com/example/web",
            "pkg:npm/lodash",
            "depends_on",
            json.dumps({"version": "4.17.21", "ecosystem": "npm", "manifest": ["ui/package.json"]}),
        ),
        # a depends_on to a crypto id under the WRONG rel — must be ignored
        (
            "repo:github.com/example/web",
            "pkg:npm/node-forge",
            "declares",
            json.dumps({"manifest": ["ui/package.json"]}),
        ),
    ]
    con.executemany("INSERT INTO edges (src, dst, rel, attrs) VALUES (?,?,?,?)", edges)
    con.commit()
    con.close()


class TestSeedList:
    def test_real_seed_list_loads(self):
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        # all six graph ecosystems are seeded
        assert set(mod.GRAPH_ECOSYSTEMS) <= set(seeds)
        # a couple of well-known members are present
        assert "node-forge" in seeds["npm"]
        assert "cryptography" in seeds["pypi"]
        assert "ring" in seeds["cargo"]

    def test_every_posture_is_in_the_vocabulary(self):
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        for eco, pkgs in seeds.items():
            for name, meta in pkgs.items():
                assert meta["posture"] in mod.POSTURES, f"{eco}/{name}"

    def test_posture_label_folds_capability_card(self):
        assert (
            mod.posture_label({"posture": "inherits", "capability_card": "openssl"})
            == "inherits-from-openssl"
        )
        assert mod.posture_label({"posture": "classical-only"}) == "classical-only"

    def test_seed_additions_load_with_valid_postures(self):
        """The 2026-08 curated additions load and every posture is in the
        controlled vocabulary."""
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        expected = {
            "npm": [
                "bcrypt",
                "argon2",
                "jsonwebtoken",
                "jws",
                "jwa",
                "secp256k1",
                "hash.js",
                "aes-js",
                "scrypt-js",
            ],
            "pypi": [
                "paramiko",
                "bcrypt",
                "argon2-cffi",
                "jwcrypto",
                "authlib",
                "rsa",
                "python-jose",
                "itsdangerous",
            ],
            "ruby": ["jwt", "bcrypt"],
            "maven": [
                "com.nimbusds:nimbus-jose-jwt",
                "io.jsonwebtoken:jjwt",
                "com.google.crypto.tink:tink",
            ],
            "cargo": ["rsa", "p256", "p384", "aes-gcm", "chacha20poly1305", "jsonwebtoken"],
            "nuget": ["jose-jwt", "NSec.Cryptography", "BouncyCastle"],
        }
        for eco, names in expected.items():
            for name in names:
                assert name in seeds[eco], f"{eco}/{name} missing"
                assert seeds[eco][name]["posture"] in mod.POSTURES, f"{eco}/{name}"

    def test_native_tls_resolves_to_inherits_native_tls_card(self):
        """native-tls flipped from unknown -> inherits + native-tls card."""
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        entry = seeds["cargo"]["native-tls"]
        assert entry["posture"] == "inherits"
        assert entry["capability_card"] == "native-tls"
        assert mod.posture_label(entry) == "inherits-from-native-tls"

    def test_no_seed_remains_unknown(self):
        """The curated list should carry a real posture for every seed;
        native-tls was the last `unknown`."""
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        unknowns = [
            (eco, name)
            for eco, pkgs in seeds.items()
            for name, meta in pkgs.items()
            if meta["posture"] == "unknown"
        ]
        assert unknowns == [], f"unexpected unknown postures: {unknowns}"


class TestNativeTlsCard:
    def test_card_exists_and_matches_schema(self):
        import jsonschema

        card = yaml.safe_load((CAPS / "native-tls.yaml").read_text())
        schema = json.loads(CARD_SCHEMA.read_text())
        jsonschema.validate(card, schema)
        assert card["id"] == "native-tls"
        # inherits from the platform stack: no PQC of its own
        assert card["quantum_tls"]["by_default"]["floors"] == {}
        assert card["details"]["depends_on"] == "openssl"


class TestDiscover:
    @pytest.fixture()
    def db(self, tmp_path):
        db = tmp_path / "portfolio-graph.db"
        _seed_graph(db)
        return db

    def test_finds_only_crypto_deps_per_ecosystem(self, db):
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        data = mod.discover(db, seeds)
        assert data["graph_present"] is True
        # lodash (non-crypto) and the declares edge are excluded
        assert data["totals"]["hits"] == 2
        assert data["totals"]["repos"] == 2
        assert set(data["ecosystems"]) == {"npm", "pypi"}

        forge = data["ecosystems"]["npm"][0]
        assert forge["package"] == "node-forge"
        assert forge["repo"] == "github.com/example/web"
        assert forge["version"] == "1.3.1"
        assert forge["manifest"] == ["ui/package.json"]
        assert forge["posture"] == "classical-only"

        crypto = data["ecosystems"]["pypi"][0]
        assert crypto["package"] == "cryptography"
        assert crypto["version"] == "44.0.0"
        assert crypto["indirect"] == 1
        assert crypto["posture"] == "inherits-from-openssl"
        assert crypto["capability_card"] == "openssl"

    def test_posture_totals(self, db):
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        data = mod.discover(db, seeds)
        assert data["posture_totals"] == {"classical-only": 1, "inherits-from-openssl": 1}

    def test_graph_absent_is_a_clean_skip(self, tmp_path):
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        data = mod.discover(tmp_path / "nope.db", seeds)
        assert data["graph_present"] is False
        assert "not found" in data["note"]
        assert data["totals"]["hits"] == 0

    def test_legacy_db_without_tables_is_a_clean_skip(self, tmp_path):
        db = tmp_path / "legacy.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE something_else (x TEXT)")
        con.commit()
        con.close()
        seeds = mod.load_seeds(mod.DEFAULT_SEEDS)
        data = mod.discover(db, seeds)
        assert data["graph_present"] is False
        assert "legacy" in data["note"]


class TestEndToEnd:
    def test_main_writes_artifacts(self, tmp_path):
        results = tmp_path / "analysis-results"
        graph = results / "graph"
        graph.mkdir(parents=True)
        _seed_graph(graph / "portfolio-graph.db")
        out = subprocess.run(
            [sys.executable, str(SCRIPT), "--results-root", str(results)],
            capture_output=True,
            text=True,
        )
        assert out.returncode == 0, out.stderr
        j = results / "pqc" / "_manifest" / "crypto-deps.json"
        m = results / "pqc" / "_manifest" / "crypto-deps.md"
        assert j.exists() and m.exists()
        data = json.loads(j.read_text())
        assert data["totals"]["hits"] == 2
        md = m.read_text()
        assert "node-forge" in md and "cryptography" in md
        assert "lodash" not in md


def test_resolve_results_root_is_cwd_independent(tmp_path, monkeypatch):
    """Regression: results root must come from config, not cwd-relative guesses."""
    import argparse

    from tests.test_context import _minimal_home
    from traust.context import add_config_home_arg, resolve_results_root

    home = _minimal_home(tmp_path)
    ar = tmp_path / "ar"
    (home / "locations.yaml").write_text(
        __import__("yaml").safe_dump(
            {
                "workspace": str(tmp_path / "ws"),
                "analysis_results": str(ar),
                "progress_tracker": str(tmp_path / "pt"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    args = ap.parse_args([])
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert resolve_results_root(args) == ar.resolve()
