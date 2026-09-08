#!/usr/bin/env python3
"""Tests for harnessing/4-triage/triage/scripts/normalize_input.py (SARIF plan P1).

Covers: format detection for all three arms (SARIF 2.x from any producer,
Dependabot alerts export, govulncheck -json concatenated stream),
severity/CWE/location mapping, suppression skip + --include-suppressed,
CodeQL precision -> scanner_confidence, export_sarif round-trip, and CLI
behavior on unrecognized input.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name, rel):
    import importlib

    if rel.startswith("traust_engine.") or rel.startswith("traust."):
        return importlib.import_module(rel)
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ni = _load("normalize_input", "harnessing/4-triage/triage/scripts/normalize_input.py")
es = _load("export_sarif", "traust_engine.reporting.sarif")


def _codeql_sarif():
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.20.0",
                        "rules": [
                            {
                                "id": "go/log-injection",
                                "shortDescription": {"text": "Log injection"},
                                "fullDescription": {"text": "User input written to log."},
                                "help": {"text": "Sanitize before logging."},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-117"],
                                    "security-severity": "7.8",
                                    "precision": "high",
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "go/log-injection",
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": "Log entry from user input."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "pkg/api/handler.go"},
                                    "region": {"startLine": 42, "endLine": 44},
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": "aa11"},
                    },
                    {
                        "ruleId": "go/log-injection",
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": "Suppressed instance."},
                        "suppressions": [{"kind": "external"}],
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "pkg/api/other.go"}}}
                        ],
                    },
                ],
            }
        ],
    }


def _dependabot_alerts():
    return [
        {
            "number": 7,
            "state": "open",
            "dependency": {
                "package": {"ecosystem": "gomod", "name": "golang.org/x/crypto"},
                "manifest_path": "go.mod",
            },
            "security_advisory": {
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "cve_id": "CVE-2026-1234",
                "summary": "x/crypto ssh vulnerable",
                "description": "Terrapin-style weakness.",
                "severity": "high",
                "cwes": [{"cwe_id": "CWE-354", "name": "…"}],
            },
            "security_vulnerability": {
                "severity": "critical",
                "vulnerable_version_range": "< 0.17.0",
                "first_patched_version": {"identifier": "0.17.0"},
            },
        }
    ]


def _govulncheck_stream():
    records = [
        {
            "config": {
                "scanner_name": "govulncheck",
                "scanner_version": "v1.1.4",
                "db": "https://vuln.go.dev",
            }
        },
        {
            "osv": {
                "id": "GO-2026-0001",
                "summary": "http2 rapid reset",
                "details": "details here",
                "aliases": ["CVE-2026-9999"],
            }
        },
        {
            "finding": {
                "osv": "GO-2026-0001",
                "fixed_version": "v0.17.0",
                "trace": [
                    {
                        "module": "golang.org/x/net",
                        "version": "v0.10.0",
                        "package": "golang.org/x/net/http2",
                        "function": "Serve",
                        "position": {"filename": "server.go", "line": 100},
                    }
                ],
            }
        },
        {
            "finding": {
                "osv": "GO-2026-0001",
                "fixed_version": "v0.17.0",
                "trace": [{"module": "golang.org/x/net", "version": "v0.10.0"}],
            }
        },
    ]
    return "\n".join(json.dumps(r, indent=1) for r in records)


class TestSarifArm(unittest.TestCase):
    def test_detection_and_mapping(self):
        doc = _codeql_sarif()
        self.assertTrue(ni.is_sarif(doc))
        out = ni.normalize_sarif(doc, include_suppressed=False)
        self.assertEqual(out["suppressed_skipped"], 1)
        self.assertEqual(len(out["findings"]), 1)
        f = out["findings"][0]
        self.assertEqual(f["source_tool"], "CodeQL")
        self.assertEqual(f["severity"], "high")  # 7.8 -> high
        self.assertEqual(f["category"], "go/log-injection")
        self.assertEqual(f["cwes"], ["CWE-117"])
        self.assertEqual(f["file"], "pkg/api/handler.go")
        self.assertEqual(f["line"], 42)
        self.assertEqual(f["scanner_confidence"], 0.85)
        self.assertEqual(f["recommendation"], "Sanitize before logging.")

    def test_include_suppressed(self):
        out = ni.normalize_sarif(_codeql_sarif(), include_suppressed=True)
        self.assertEqual(len(out["findings"]), 2)
        self.assertEqual(out["suppressed_skipped"], 0)

    def test_level_fallback_without_security_severity(self):
        doc = _codeql_sarif()
        del doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
        f = ni.normalize_sarif(doc, False)["findings"][0]
        self.assertEqual(f["severity"], "high")  # level: error

    def test_security_severity_buckets(self):
        for score, expect in (
            ("9.9", "critical"),
            ("7.0", "high"),
            ("4.5", "medium"),
            ("1.0", "low"),
            ("0.0", "informational"),
        ):
            doc = _codeql_sarif()
            doc["runs"][0]["results"] = doc["runs"][0]["results"][:1]
            doc["runs"][0]["results"][0]["properties"] = {"security-severity": score}
            f = ni.normalize_sarif(doc, False)["findings"][0]
            self.assertEqual(f["severity"], expect, score)

    def test_export_sarif_round_trips(self):
        report = {
            "title": "t",
            "metadata": {
                "date": "2026-07-24",
                "scope": "test",
                "additional": {"harness_version": "0.165.0-abc1234"},
            },
            "findings": [
                {
                    "id": "TEST-abcdef0-001",
                    "title": "SSRF in webhook",
                    "severity": "critical",
                    "category": "ssrf",
                    "cwes": ["CWE-918"],
                    "fingerprint": "feed",
                    "locations": [{"path": "pkg/hook.go", "lines": "5-9"}],
                    "description": "d",
                    "validation_status": "not_verified",
                }
            ],
        }
        normalized = ni.normalize_sarif(es.export(report), False)
        f = normalized["findings"][0]
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["orig_id"], "TEST-abcdef0-001")
        self.assertEqual(f["file"], "pkg/hook.go")
        self.assertEqual(f["line"], 5)


class TestDependabotArm(unittest.TestCase):
    def test_detection_and_mapping(self):
        alerts = _dependabot_alerts()
        self.assertTrue(ni.is_dependabot(alerts))
        f = ni.normalize_dependabot(alerts)["findings"][0]
        self.assertEqual(f["source_tool"], "dependabot")
        self.assertEqual(f["category"], "supply-chain")
        self.assertEqual(f["severity"], "critical")  # vuln block wins
        self.assertEqual(f["orig_id"], "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(f["file"], "go.mod")
        self.assertEqual(f["cwes"], ["CWE-354"])
        self.assertIn("CVE-2026-1234", f["description"])
        self.assertEqual(f["recommendation"], "Upgrade to 0.17.0 or later.")


class TestGovulncheckArm(unittest.TestCase):
    def test_stream_detection_and_reduction(self):
        text = _govulncheck_stream()
        self.assertTrue(ni.looks_like_govulncheck_stream(text))
        out = ni.normalize_govulncheck(text)
        self.assertEqual(out["tools"][0]["version"], "v1.1.4")
        self.assertEqual(len(out["findings"]), 1)  # per-OSV dedup
        f = out["findings"][0]
        self.assertEqual(f["orig_id"], "GO-2026-0001")
        self.assertEqual(f["reachability"], "symbol_reachable")
        self.assertEqual(f["file"], "server.go")
        self.assertEqual(f["line"], 100)
        self.assertIn("CVE-2026-9999", f["description"])
        self.assertEqual(f["recommendation"], "Upgrade to v0.17.0 or later.")
        self.assertNotIn("severity", f)  # never guessed


class TestCli(unittest.TestCase):
    def _run(self, name, content):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / name
            p.write_text(content, encoding="utf-8")
            rc = ni.main([str(p)])
            outs = list(Path(td).glob("*-normalized-findings.json"))
            return rc, (json.loads(outs[0].read_text()) if outs else None)

    def test_all_three_arms_via_cli(self):
        for name, content in (
            ("scan.sarif", json.dumps(_codeql_sarif())),
            ("alerts.json", json.dumps(_dependabot_alerts())),
            ("govuln.json", _govulncheck_stream()),
        ):
            rc, doc = self._run(name, content)
            self.assertEqual(rc, 0, name)
            self.assertTrue(doc["findings"], name)
            self.assertIn("trust_note", doc["metadata"], name)

    def test_unrecognized_input_fails(self):
        rc, doc = self._run("random.json", json.dumps({"foo": "bar"}))
        self.assertEqual(rc, 1)
        self.assertIsNone(doc)


if __name__ == "__main__":
    unittest.main()
