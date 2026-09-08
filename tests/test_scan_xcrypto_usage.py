"""Tests for harnessing/3-audit/pqc-readiness/scripts/scan_xcrypto_usage.py."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scan_xcrypto_usage import path_class, scan_gomod, scan_imports

from traust.paths import skill_dir

SCRIPT = skill_dir("pqc-readiness") / "scripts" / "scan_xcrypto_usage.py"


def _repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    (repo / "cmd" / "app").mkdir(parents=True)
    (repo / "cmd" / "app" / "main.go").write_text(
        'package main\n\nimport (\n\t"fmt"\n'
        '\t"golang.org/x/crypto/ssh"\n'
        '\t"golang.org/x/crypto/openpgp"\n)\n'
    )
    (repo / "pkg").mkdir()
    (repo / "pkg" / "hash_test.go").write_text(
        'package pkg\n\nimport "golang.org/x/crypto/bcrypt"\n'
    )
    # vendored copies must be excluded
    v = repo / "vendor" / "golang.org" / "x" / "crypto" / "ssh"
    v.mkdir(parents=True)
    (v / "ssh.go").write_text('package ssh\nimport "golang.org/x/crypto/ssh"\n')
    (repo / "go.mod").write_text(
        "module example.com/app\n\ngo 1.24\n\n"
        "require golang.org/x/crypto v0.52.0\n\n"
        "replace golang.org/x/crypto => github.com/fork/crypto v0.0.1\n"
    )
    nested = repo / "vendor" / "go.mod"
    nested.write_text("module v\nrequire golang.org/x/crypto v0.1.0\n")
    return repo


class TestImports(unittest.TestCase):
    def test_first_party_and_test_docs_tagged_vendor_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(Path(td))
            sites = scan_imports(repo)
            by_pkg = {(s["package"], s["path_class"]) for s in sites}
            self.assertIn(("golang.org/x/crypto/ssh", "first_party"), by_pkg)
            self.assertIn(("golang.org/x/crypto/openpgp", "first_party"), by_pkg)
            self.assertIn(("golang.org/x/crypto/bcrypt", "test_docs"), by_pkg)
            self.assertFalse(any("vendor" in s["file"] for s in sites))

    def test_path_class_testdata_dir(self):
        self.assertEqual(path_class(Path("testdata/x.go")), "test_docs")
        self.assertEqual(path_class(Path("pkg/x.go")), "first_party")


class TestGomod(unittest.TestCase):
    def test_require_and_replace_captured_vendor_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(Path(td))
            mods = scan_gomod(repo)
            self.assertEqual(len(mods), 1)
            self.assertEqual(mods[0]["gomod"], "go.mod")
            self.assertEqual(mods[0]["require"], ["v0.52.0"])
            self.assertEqual(mods[0]["replace"][0]["target"], "github.com/fork/crypto")


class TestArtifact(unittest.TestCase):
    def test_main_emits_artifact_without_callgraph(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(Path(td))
            out = Path(td) / "x.json"
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-dir",
                    str(repo),
                    "--repo-url",
                    "https://github.com/org/app",
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["artifact"], "xcrypto-usage")
            self.assertEqual(doc["summary"]["first_party_import_sites"], 2)
            self.assertEqual(doc["summary"]["gomod_refs"], 1)
            self.assertIn("skipped", doc["summary"]["callgraph"])
            self.assertIn("golang.org/x/crypto/ssh", doc["summary"]["packages"])
            self.assertTrue(doc["stamps"]["script_sha256"])


if __name__ == "__main__":
    unittest.main()
