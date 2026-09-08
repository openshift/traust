#!/usr/bin/env python3
"""Tests for traust.migrations.export_gitlab_sast (SARIF plan P2).

Covers: GitLab security-report structural shape, deterministic uuid5
ids, severity enum mapping, identifiers (finding id + CWE with URL),
FP exclusion default + --include-false-positives, disposition note in
description, pseudo-path location skipping, and CLI naming.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from traust.migrations import export_gitlab_sast as egs

_UUID_RX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$"
)
_TIME_RX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


def _report(findings=None):
    return {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-07-24",
            "scope": "test",
            "repository": "https://github.com/example/test-widget",
            "additional": {"harness_version": "0.167.0-abc1234"},
        },
        "findings": findings
        if findings is not None
        else [
            {
                "id": "TEST_WIDGET-abcdef0-001",
                "title": "Token logged at debug level",
                "severity": "high",
                "cwes": ["CWE-532"],
                "locations": [{"path": "pkg/auth/token.go", "lines": "10-20"}],
                "description": "Bearer token written to the debug log.",
                "remediation": "Redact the token before logging.",
                "validation_status": "not_verified",
            }
        ],
    }


class TestExport(unittest.TestCase):
    def test_structure(self):
        doc, excluded = egs.export(_report())
        self.assertEqual(excluded, 0)
        self.assertEqual(doc["version"], egs.SCHEMA_VERSION)
        scan = doc["scan"]
        self.assertEqual(scan["type"], "sast")
        self.assertEqual(scan["status"], "success")
        self.assertTrue(_TIME_RX.match(scan["start_time"]))
        self.assertEqual(scan["analyzer"]["id"], "traust")
        v = doc["vulnerabilities"][0]
        self.assertTrue(_UUID_RX.match(v["id"]))
        self.assertEqual(v["severity"], "High")
        self.assertEqual(v["solution"], "Redact the token before logging.")
        self.assertEqual(
            v["location"], {"file": "pkg/auth/token.go", "start_line": 10, "end_line": 20}
        )

    def test_ids_deterministic(self):
        a, _ = egs.export(_report())
        b, _ = egs.export(_report())
        self.assertEqual(a["vulnerabilities"][0]["id"], b["vulnerabilities"][0]["id"])

    def test_identifiers(self):
        v = egs.export(_report())[0]["vulnerabilities"][0]
        types = {i["type"]: i for i in v["identifiers"]}
        self.assertEqual(types["harness_finding_id"]["value"], "TEST_WIDGET-abcdef0-001")
        self.assertEqual(types["cwe"]["value"], "532")
        self.assertIn("cwe.mitre.org", types["cwe"]["url"])

    def test_severity_enum(self):
        for sev, expect in (
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("informational", "Info"),
        ):
            rep = _report()
            rep["findings"][0]["severity"] = sev
            v = egs.export(rep)[0]["vulnerabilities"][0]
            self.assertEqual(v["severity"], expect, sev)

    def test_fp_excluded_by_default(self):
        rep = _report()
        rep["findings"][0]["disposition"] = {"validity": "false_positive", "resolution": "open"}
        rep["findings"][0]["validation_status"] = "false_positive"
        doc, excluded = egs.export(rep)
        self.assertEqual(excluded, 1)
        self.assertEqual(doc["vulnerabilities"], [])
        doc, excluded = egs.export(rep, include_fps=True)
        self.assertEqual(excluded, 0)
        self.assertEqual(len(doc["vulnerabilities"]), 1)

    def test_disposition_note_in_description(self):
        rep = _report()
        rep["findings"][0]["disposition"] = {"validity": "confirmed", "resolution": "risk_accepted"}
        v = egs.export(rep)[0]["vulnerabilities"][0]
        self.assertIn("validity=confirmed", v["description"])
        self.assertIn("resolution=risk_accepted", v["description"])

    def test_pseudo_path_location_skipped(self):
        rep = _report()
        rep["findings"][0]["locations"] = [
            {"path": "pkg:golang/x/crypto@v0.1.0"},
            {"path": "go.mod", "lines": "3"},
        ]
        v = egs.export(rep)[0]["vulnerabilities"][0]
        self.assertEqual(v["location"], {"file": "go.mod", "start_line": 3})


class TestCli(unittest.TestCase):
    def test_default_naming(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "widget-security-audit.json"
            p.write_text(json.dumps(_report()), encoding="utf-8")
            self.assertEqual(egs.main([str(p)]), 0)
            out = Path(td) / "widget-security-audit-gl-sast.json"
            self.assertTrue(out.is_file())
            self.assertTrue(json.loads(out.read_text())["vulnerabilities"])

    def test_rejects_non_report(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            p.write_text("{}", encoding="utf-8")
            self.assertEqual(egs.main([str(p)]), 1)


if __name__ == "__main__":
    unittest.main()
