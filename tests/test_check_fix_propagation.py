"""Tests for traust.cli.check_fix_propagation and the cross_repo
validator rule in validate_report.py."""

import json
import tempfile
import unittest
from pathlib import Path

from traust_engine.reporting.validate import ValidationResult, cross_validate_verification

from traust.cli.check_fix_propagation import check_go, check_manifests, main


class TestGoPropagation(unittest.TestCase):
    def _repo(self, gomod: str, vendor: str | None = None) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "go.mod").write_text(gomod)
        if vendor is not None:
            (d / "vendor").mkdir()
            (d / "vendor/modules.txt").write_text(vendor)
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        return d

    def test_consumed(self):
        repo = self._repo("module x\n\nrequire golang.org/x/net v0.18.0\n")
        out = check_go(repo, "golang.org/x/net", "v0.17.0")
        self.assertTrue(out and out[0]["consumed"])

    def test_pending(self):
        repo = self._repo("module x\n\nrequire golang.org/x/net v0.15.0\n")
        out = check_go(repo, "golang.org/x/net", "v0.17.0")
        self.assertTrue(out and out[0]["consumed"] is False)

    def test_vendor_pin_wins_visibility(self):
        repo = self._repo(
            "module x\n\nrequire golang.org/x/net v0.18.0\n",
            "# golang.org/x/net v0.15.0\n",
        )
        out = check_go(repo, "golang.org/x/net", "v0.17.0")
        sources = {c["source"]: c["consumed"] for c in out}
        self.assertTrue(sources["go.mod"])
        self.assertFalse(sources["vendor/modules.txt"])

    def test_main_pending_when_any_source_vulnerable(self):
        repo = self._repo(
            "module x\n\nrequire golang.org/x/net v0.18.0\n",
            "# golang.org/x/net v0.15.0\n",
        )
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(
                [
                    "--repo-dir",
                    str(repo),
                    "--module",
                    "golang.org/x/net",
                    "--fixed-version",
                    "v0.17.0",
                ]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["propagation"], "pending")

    def test_module_absent(self):
        repo = self._repo("module x\n")
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["--repo-dir", str(repo), "--module", "gone/mod", "--fixed-version", "v1.0.0"])
        self.assertEqual(json.loads(buf.getvalue())["propagation"], "module_absent")


class TestManifestPropagation(unittest.TestCase):
    def test_python_requirements(self):
        d = Path(tempfile.mkdtemp())
        (d / "requirements.txt").write_text("urllib3==1.26.5\n")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        out = check_manifests(d, "urllib3", "2.0.7")
        self.assertTrue(out and out[0]["consumed"] is False)


class TestCrossRepoValidatorRule(unittest.TestCase):
    def _report(self, verdict, propagation, fix_repo="https://github.com/o/lib"):
        return {
            "verified_findings": [
                {
                    "original_id": "X-1",
                    "verdict": verdict,
                    "cross_repo": {"fix_repo": fix_repo, "propagation": propagation},
                }
            ],
            "regressions": [],
            "commit_timeline": [],
            "summary": {},
            "metadata": {"repository": "https://github.com/o/app"},
        }

    def test_pending_resolved_rejected(self):
        r = ValidationResult(file_path="t.json")
        cross_validate_verification(self._report("resolved", "pending"), r)
        self.assertTrue(any("pending" in e for e in r.errors))

    def test_pending_partial_ok(self):
        r = ValidationResult(file_path="t.json")
        cross_validate_verification(self._report("partially_resolved", "pending"), r)
        self.assertFalse(any("pending" in e for e in r.errors))

    def test_same_repo_cross_block_rejected(self):
        r = ValidationResult(file_path="t.json")
        rep = self._report("resolved", "consumed", fix_repo="https://github.com/o/app")
        cross_validate_verification(rep, r)
        self.assertTrue(any("DIFFERENT repo" in e for e in r.errors))


if __name__ == "__main__":
    unittest.main()
