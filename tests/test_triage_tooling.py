#!/usr/bin/env python3
"""Unit tests for harnessing/4-triage/triage/scripts/render_triage.py and harnessing/4-triage/triage/scripts/lint_verdict_citations.py."""

import unittest

from lint_verdict_citations import extract_citations, lint
from render_triage import render_triage


def _report():
    return {
        "triage_completed": "2026-07-11",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant platform",
            "votes_per_finding": 3,
            "repo": "/tmp/clone",
            "harness_version": "0.26.0-abc1234",
        },
        "summary": {
            "input_count": 4,
            "true_positives": 1,
            "hardening": 1,
            "false_positives": 1,
            "undetermined": 1,
            "duplicates": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            {
                "id": "f001",
                "title": "Heap overflow in parse_alpha",
                "file": "entry.c",
                "line": 25,
                "category": "memory-safety",
                "claimed_severity": "HIGH",
                "verdict": "true_positive",
                "verify_verdict": "exploitable",
                "confidence": 9.0,
                "severity": "high",
                "owner_hint": "@team",
                "rationale": "reachable from main at entry.c:53; no bounds check",
                "first_links": ["entry.c:53"],
                "vote_breakdown": {
                    "true_positive": 3,
                    "hardening": 0,
                    "false_positive": 0,
                    "cannot_verify": 0,
                },
            },
            {
                "id": "f006",
                "title": "No securityContext in deployment",
                "file": "deploy/deployment.yaml",
                "line": 19,
                "category": "insecure-workload-config",
                "claimed_severity": "MEDIUM",
                "verdict": "hardening",
                "verify_verdict": "hardening",
                "confidence": 8.0,
                "severity": None,
                "exclusion_rule": "13",
                "owner_hint": "@team",
                "rationale": "accurate CIS gap at deploy/deployment.yaml:19; no exploit path.",
                "first_links": ["deploy/deployment.yaml:19"],
            },
            {
                "id": "f005",
                "title": "Null deref after fopen",
                "file": "entry.c",
                "line": 51,
                "category": "null-deref",
                "claimed_severity": "LOW",
                "verdict": "false_positive",
                "verify_verdict": "refuted",
                "confidence": 8.0,
                "severity": None,
                "exclusion_rule": "2",
                "refute_reasons": ["already_handled"],
                "rationale": "guard exists at entry.c:47 before the fread call.",
                "first_links": ["entry.c:47"],
            },
            {
                "id": "f007",
                "title": "Command injection in ghost renderer",
                "file": "src/ghost.go",
                "line": 42,
                "category": "injection",
                "claimed_severity": "HIGH",
                "verdict": "undetermined",
                "verify_verdict": "needs_manual_test",
                "confidence": 0,
                "severity": None,
                "refute_reasons": ["unlocatable"],
                "rationale": "cited material not found under --repo",
            },
        ],
    }


from traust.paths import skill_dir

FIXTURE_TARGET = skill_dir("triage") / "fixtures" / "canary-target"


class TestRenderTriage(unittest.TestCase):
    def setUp(self):
        self.md = render_triage(_report())

    def test_section_order(self):
        idx = [
            self.md.index(h)
            for h in ("## Act on these", "## Hardening backlog", "## Undetermined", "## Dropped")
        ]
        self.assertEqual(idx, sorted(idx))

    def test_confirmed_entry_rendered(self):
        self.assertIn("### [HIGH] Heap overflow in parse_alpha  (f001)", self.md)
        self.assertIn("3T/0H/0F/0C", self.md)

    def test_hardening_not_in_dropped(self):
        dropped = self.md.split("## Dropped")[1]
        self.assertNotIn("f006", dropped)
        self.assertIn("NOT false positives", self.md)

    def test_undetermined_section_present(self):
        self.assertIn("f007", self.md.split("## Undetermined")[1].split("## Dropped")[0])

    def test_undetermined_section_omitted_when_empty(self):
        rep = _report()
        rep["findings"] = [f for f in rep["findings"] if f["verdict"] != "undetermined"]
        rep["summary"]["undetermined"] = 0
        rep["summary"]["input_count"] = 3
        self.assertNotIn("## Undetermined", render_triage(rep))

    def test_dropped_includes_rule(self):
        self.assertIn("already_handled (rule 2)", self.md)

    def test_summary_line(self):
        self.assertIn("4 in -> 1 confirmed", self.md)
        self.assertIn("1 hardening", self.md)

    def test_deterministic(self):
        self.assertEqual(self.md, render_triage(_report()))


class TestLintVerdictCitations(unittest.TestCase):
    def test_extract_citations(self):
        f = {
            "first_links": ["pkg/a.go:12"],
            "rationale": "guard at pkg/a.go:12 and helper.py:9-14; see https://x.io/a.go:1",
        }
        cites = [(c[0], c[1]) for c in extract_citations(f)]
        self.assertIn(("pkg/a.go", 12), cites)
        self.assertIn(("helper.py", 9), cites)

    def test_clean_verdicts_pass_against_fixture(self):
        out = lint(_report()["findings"], FIXTURE_TARGET)
        by_id = {r["id"]: r for r in out["results"]}
        self.assertEqual(by_id["f005"]["status"], "ok")
        self.assertEqual(by_id["f006"]["status"], "ok")
        self.assertEqual(out["summary"]["re_vote_recommended"], 0)

    def test_hallucinated_refutation_flagged_for_revote(self):
        findings = _report()["findings"]
        findings[2]["rationale"] = "guard exists at entry.c:9999 before use."
        findings[2]["first_links"] = ["lib/imaginary.c:12"]
        out = lint(findings, FIXTURE_TARGET)
        f005 = next(r for r in out["results"] if r["id"] == "f005")
        self.assertEqual(f005["action"], "re_vote_recommended")
        defects = " ".join(b["defect"] for b in f005["broken"])
        self.assertIn("out of range", defects)
        self.assertIn("not found", defects)

    def test_broken_tp_citation_is_review_not_revote(self):
        findings = _report()["findings"]
        findings[0]["first_links"] = ["lib/imaginary.c:12"]
        findings[0]["rationale"] = "reachable"
        out = lint(findings, FIXTURE_TARGET)
        f001 = next(r for r in out["results"] if r["id"] == "f001")
        self.assertEqual(f001["action"], "review_recommended")

    def test_duplicates_skipped(self):
        findings = [{"id": "f002", "verdict": "duplicate", "duplicate_of": "f001", "title": "dup"}]
        out = lint(findings, FIXTURE_TARGET)
        self.assertEqual(out["results"], [])


class TestCanaryFixture(unittest.TestCase):
    """The self-contained smoke-test target must support every canary."""

    def test_planted_lines_match_fixture_citations(self):
        import json

        fixture = json.loads((FIXTURE_TARGET.parent / "canary-findings.json").read_text())
        entry = (FIXTURE_TARGET / "entry.c").read_text().splitlines()
        expect = {
            "f001": "memcpy(buf",
            "f002": "malloc(8)",
            "f003": "memcpy(local",
            "f004": "fread(buf",
            "f005": "fread(buf",
        }
        for f in fixture["findings"]:
            if f["id"] in expect:
                self.assertIn(
                    expect[f["id"]], entry[f["line"] - 1], f"{f['id']} cites line {f['line']}"
                )

    def test_hardening_canary_target_exists(self):
        self.assertTrue((FIXTURE_TARGET / "deploy" / "deployment.yaml").is_file())

    def test_undetermined_canary_target_absent(self):
        self.assertFalse((FIXTURE_TARGET / "src" / "ghost.go").exists())


if __name__ == "__main__":
    unittest.main()
