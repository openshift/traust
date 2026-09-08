"""Tests for traust.ops.enumerate_taint_flows (deep-fn Phase B4)."""

import json
import re
import unittest
from pathlib import Path
from unittest import mock

from traust.ops import enumerate_taint_flows as etf


class TestCatalog(unittest.TestCase):
    def test_all_patterns_compile(self):
        for _lang, cat in etf.CATALOG.items():
            re.compile(cat["sources"])
            for _fam, sink in cat["families"].items():
                re.compile(sink)

    def test_every_language_names_coverage_gaps(self):
        # the enumerator contract: un-modeled systems must be NAMED,
        # never implied covered
        for lang, cat in etf.CATALOG.items():
            self.assertTrue(cat["coverage_gaps"], lang)

    def test_sanitizer_hint_matches_expected_shapes(self):
        for s in (
            "sanitize",
            "escapeHtml",
            "URLEncoder",
            "validateInput",
            "replaceAll",
            "allowlist_check",
        ):
            self.assertTrue(etf.SANITIZER_HINT.search(s), s)
        self.assertFalse(etf.SANITIZER_HINT.search("computeTotal"))


class TestParseSite(unittest.TestCase):
    def test_full_blob(self):
        s = etf.parse_site("src/A.java|42|com.a.A.m|exec(cmd)")
        self.assertEqual(
            s, {"file": "src/A.java", "line": 42, "method": "com.a.A.m", "code": "exec(cmd)"}
        )

    def test_short_blob_tolerated(self):
        s = etf.parse_site("f.c|7")
        self.assertEqual((s["file"], s["line"]), ("f.c", 7))


class TestSkipPaths(unittest.TestCase):
    def test_skips_without_joern(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "facts.json"
            with mock.patch.object(etf.shutil, "which", return_value=None):
                rc = etf.main(["--repo", tmp, "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text())
            self.assertIn("joern not on PATH", doc["status"])
            # soundness contract on every artifact, ran or not
            self.assertIn("NEVER", doc["soundness"]["no_flow"])
            self.assertTrue(doc["coverage_gaps"])

    def test_skips_without_sources(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "facts.json"
            with mock.patch.object(etf.shutil, "which", return_value="/bin/joern"):
                rc = etf.main(["--repo", tmp, "--out", str(out), "--language", "c"])
            self.assertEqual(rc, 0)
            self.assertIn("no c sources", json.loads(out.read_text())["status"])

    def test_family_filter(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "facts.json"
            with mock.patch.object(etf.shutil, "which", return_value=None):
                etf.main(["--repo", tmp, "--out", str(out), "--families", "sql"])
            doc = json.loads(out.read_text())
            self.assertEqual(doc["families"], ["sql"])


if __name__ == "__main__":
    unittest.main()
