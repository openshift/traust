#!/usr/bin/env python3
"""Unit tests for traust.cli.check_citations (triage citation gate)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

from traust.cli.check_citations import extract_anchors, gate, resolve_path

GO_FILE = """package main

import "fmt"

func mergeAgentEnvironment(base map[string]string) map[string]string {
\tfor k, v := range base {
\t\tfmt.Println(k, v)
\t}
\treturn base
}

func isAllowedRegistry(image string) bool {
\treturn false
}
"""


def _repo(tmp: str) -> Path:
    repo = Path(tmp) / "target"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "reconciler.go").write_text(GO_FILE, encoding="utf-8")
    return repo


def _finding(**kw) -> dict:
    base = {
        "id": "f001",
        "file": "pkg/reconciler.go",
        "line": 5,
        "title": "Env merge overridable",
        "description": "Tenant env flows through `mergeAgentEnvironment` unchecked.",
    }
    base.update(kw)
    return base


class TestResolvePath(unittest.TestCase):
    def test_direct_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            self.assertIsNotNone(resolve_path(repo, "pkg/reconciler.go"))

    def test_prefix_stripping(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            self.assertIsNotNone(resolve_path(repo, "./pkg/reconciler.go"))
            self.assertIsNotNone(resolve_path(repo, "target/pkg/reconciler.go"))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            self.assertIsNone(resolve_path(repo, "pkg/nope.go"))

    def test_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            outside = Path(tmp) / "outside.go"
            outside.write_text("package x\n", encoding="utf-8")
            self.assertIsNone(resolve_path(repo, "../outside.go"))


class TestAnchorExtraction(unittest.TestCase):
    def test_backtick_symbols_extracted(self):
        anchors = extract_anchors(_finding())
        self.assertIn("mergeAgentEnvironment", anchors)

    def test_path_line_spans_skipped(self):
        f = _finding(description="See `pkg/reconciler.go:5` for the sink.")
        self.assertEqual(extract_anchors(f), [])

    def test_explicit_symbol_field(self):
        f = _finding(symbol="isAllowedRegistry")
        self.assertEqual(extract_anchors(f)[0], "isAllowedRegistry")


class TestGateTags(unittest.TestCase):
    def _run(self, finding):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            return gate([finding], repo, window=15)["results"][0]

    def test_ok_anchor_near_line(self):
        r = self._run(_finding())
        self.assertEqual(r["tag"], "ok")
        self.assertEqual(r["route"], "full_votes")

    def test_line_drifted_anchor_elsewhere(self):
        # cited line far from the real symbol, tiny window forces drift
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            f = _finding(line=14, description="`mergeAgentEnvironment` is the sink.")
            r = gate([f], repo, window=2)["results"][0]
        self.assertEqual(r["tag"], "line_drifted")
        self.assertEqual(r["route"], "full_votes")

    def test_anchor_absent(self):
        r = self._run(_finding(description="Sink is `totallyFabricatedFn` here."))
        self.assertEqual(r["tag"], "anchor_absent")
        self.assertEqual(r["route"], "single_vote")

    def test_file_missing(self):
        r = self._run(_finding(file="pkg/ghost.go"))
        self.assertEqual(r["tag"], "file_missing")
        self.assertEqual(r["route"], "skip_verification")

    def test_no_anchor_is_ok(self):
        r = self._run(_finding(description="No code spans quoted at all."))
        self.assertEqual(r["tag"], "ok")

    def test_line_out_of_range_no_anchor_drifts(self):
        r = self._run(_finding(line=999, description="prose only"))
        self.assertEqual(r["tag"], "line_drifted")

    def test_audit_report_locations_format(self):
        f = {
            "id": "FIND-001",
            "title": "x",
            "description": "`isAllowedRegistry` prefix match",
            "locations": [{"path": "pkg/reconciler.go", "lines": "12-14"}],
        }
        r = self._run(f)
        self.assertEqual(r["tag"], "ok")

    def test_worst_location_wins(self):
        f = {
            "id": "FIND-002",
            "title": "x",
            "description": "`isAllowedRegistry`",
            "locations": [
                {"path": "pkg/reconciler.go", "lines": "12"},
                {"path": "pkg/ghost.go", "lines": "1"},
            ],
        }
        r = self._run(f)
        self.assertEqual(r["tag"], "file_missing")

    def test_summary_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            out = gate([_finding(), _finding(id="f002", file="pkg/ghost.go")], repo, window=15)
        self.assertEqual(out["summary"]["ok"], 1)
        self.assertEqual(out["summary"]["file_missing"], 1)
        self.assertEqual(out["summary"]["total"], 2)


class TestCLIRoundTrip(unittest.TestCase):
    def test_cli_json_out(self):
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            findings = Path(tmp) / "phase1.json"
            findings.write_text(json.dumps({"findings": [_finding()]}), encoding="utf-8")
            out_path = Path(tmp) / "gate.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "traust.cli.check_citations",
                    str(findings),
                    "--repo",
                    str(repo),
                    "--json-out",
                    str(out_path),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(doc["summary"]["ok"], 1)


if __name__ == "__main__":
    unittest.main()
