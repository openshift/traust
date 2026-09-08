"""Tests for harnessing/3-audit/pqc-readiness/scripts/build_xcrypto_tracker.py."""

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from build_xcrypto_tracker import collect, status_for

from traust.paths import skill_dir

SCRIPT = skill_dir("pqc-readiness") / "scripts" / "build_xcrypto_tracker.py"


def _corpus(tmp: Path) -> Path:
    root = tmp / "analysis-results"
    a = root / "pqc" / "repo-a"
    a.mkdir(parents=True)
    (a / "repo-a-xcrypto-usage.json").write_text(
        json.dumps(
            {
                "artifact": "xcrypto-usage",
                "repository": "https://github.com/org/repo-a",
                "import_sites": [
                    {
                        "file": "cmd/main.go",
                        "line": 5,
                        "package": "golang.org/x/crypto/openpgp",
                        "path_class": "first_party",
                    },
                    {
                        "file": "pkg/x_test.go",
                        "line": 3,
                        "package": "golang.org/x/crypto/hkdf",
                        "path_class": "test_docs",
                    },
                ],
                "gomod": [{"gomod": "go.mod", "require": ["v0.52.0"], "replace": []}],
                "callgraph": [
                    {
                        "entrypoint": "cmd/app",
                        "error": None,
                        "reachable": [
                            {
                                "function": "golang.org/x/crypto/ssh.Dial",
                                "somepath": [
                                    "example.com/app.main",
                                    "golang.org/x/crypto/ssh.Dial",
                                ],
                            },
                        ],
                    }
                ],
            }
        )
    )
    b = root / "pqc" / "repo-b"
    b.mkdir(parents=True)
    (b / "repo-b-pqc-facts.json").write_text(
        json.dumps(
            {
                "repository": "https://github.com/org/repo-b",
                "facts": [
                    {
                        "rule_id": "HP_EC_GO_ECDH_X25519",
                        "file": "vendor/golang.org/x/crypto/curve25519/c.go",
                        "line": 39,
                        "detail": "Go ECDH/X25519 usage.",
                    }
                ],
            }
        )
    )
    return root


class TestCollect(unittest.TestCase):
    def test_tiers_and_status(self):
        with tempfile.TemporaryDirectory() as td:
            rows = collect(_corpus(Path(td)))
            by = {(r["slug"], r["crypto_module_used"].split(";")[0].strip()): r for r in rows}
            ssh = by[("repo-a", "golang.org/x/crypto/ssh.Dial")]
            self.assertEqual(ssh["evidence_tier"], "callgraph")
            self.assertEqual(ssh["entrypoint"], "cmd/app")
            self.assertIn("->", ssh["dependency_graph"])
            pgp = by[("repo-a", "golang.org/x/crypto/openpgp")]
            self.assertEqual(pgp["evidence_tier"], "first-party-import")
            self.assertEqual(pgp["status_suggested"], "Unacceptable?")
            self.assertIn("go.mod: go.mod v0.52.0", pgp["comment"])
            hkdf = by[("repo-a", "golang.org/x/crypto/hkdf")]
            self.assertEqual(hkdf["evidence_tier"], "test-docs-import")
            cur = by[("repo-b", "golang.org/x/crypto/curve25519")]
            self.assertEqual(cur["evidence_tier"], "dependency-presence")
            self.assertEqual(cur["status_suggested"], "Acceptable?")
            self.assertEqual(cur["product_org"], "org")

    def test_status_table(self):
        self.assertEqual(status_for("golang.org/x/crypto/pkcs12"), "Unacceptable?")
        self.assertEqual(status_for("golang.org/x/crypto/nacl/box"), "Acceptable?")
        self.assertEqual(status_for("golang.org/x/crypto/unknownpkg"), "Unknown")


class TestMain(unittest.TestCase):
    def test_csv_and_md_written(self):
        with tempfile.TemporaryDirectory() as td:
            root = _corpus(Path(td))
            out = Path(td) / "dash"
            r = subprocess.run(
                [sys.executable, str(SCRIPT), "--results-root", str(root), "--out-dir", str(out)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            with (out / "xcrypto-tracker.csv").open() as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 4)
            self.assertTrue((out / "xcrypto-tracker.md").read_text().startswith("# x/crypto"))


if __name__ == "__main__":
    unittest.main()
