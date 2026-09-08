#!/usr/bin/env python3
"""Unit tests for harnessing/threat-register/scripts/build_threat_register.py."""

import json
import tempfile
import unittest
from pathlib import Path

from build_threat_register import build

MODEL = """# Threat Model: {name}

## 1. System context

Example.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| data | records | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| api | REST API | unauth -> auth | data |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Data exfiltration via api injection | remote_unauth, insider | api | data | critical | likely | unmitigated | none | CVE-2026-1234 |
| T2 | DoS via api flood | remote_unauth | api | data | low | possible | mitigated | rate limit | |

## 5. Deprioritized

| threat | reason |
|---|---|

## 6. Open questions

- none

## 7. Provenance

- mode: bootstrap
- date: 2026-07-12
- target: x @ abc1234
- inputs: none
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| parameterized queries everywhere | T1 | yes | S |
| bigger cluster | T2 | no | L |
"""


# 11-column variant (attack_refs default since harness 0.82.0) — the
# register must parse it, not skip it as nonconforming.
MODEL_ATTACK = (
    MODEL.replace(
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |\n"
        "|---|---|---|---|---|---|---|---|---|---|",
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence | attack_refs |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|",
    )
    .replace("| CVE-2026-1234 |", "| CVE-2026-1234 | T1190 |")
    .replace("| rate limit | |", "| rate limit | | |")
)

# 12-column variant + section 10 (PEACH isolation lens Phase 1).
MODEL_MT = (
    MODEL.replace(
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |\n"
        "|---|---|---|---|---|---|---|---|---|---|",
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence | attack_refs | isolation_dimensions |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    )
    .replace("| CVE-2026-1234 |", "| CVE-2026-1234 | | privilege, authentication |")
    .replace("| rate limit | |", "| rate limit | | | |")
    + """
## 10. Tenant boundaries

| boundary_id | interface | kind | exposure | complexity | privilege | encryption | authentication | connectivity | hygiene | threat_ids | isolation_review_ref |
|---|---|---|---|---|---|---|---|---|---|---|---|
| IF-1 | tenant api | api | tenant | high | partial | yes | no | yes | partial | T1 | analysis-results/isolation/{name}/ |
| IF-2 | metrics store | data-store | internal | low | yes | na | yes | yes | yes | | |
"""
)


def make_portfolio(root):
    for product, repo in (("prodA", "svc"), ("prodB", "svc")):
        d = root / "findings" / product / repo
        d.mkdir(parents=True)
        (d / f"{repo}-threat-model.md").write_text(MODEL.format(name=repo), encoding="utf-8")


class TestBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        make_portfolio(self.root)
        self.reg = build(self.root, self.root / "threat-register")

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts(self):
        self.assertEqual(self.reg["meta"]["models"], 2)
        self.assertEqual(self.reg["meta"]["threat_count"], 4)
        self.assertEqual(self.reg["totals"]["by_status"]["unmitigated"], 2)
        self.assertEqual(self.reg["totals"]["evidence_backed"], 2)

    def test_keys_unique_and_product_qualified(self):
        keys = [t["key"] for t in self.reg["threats"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertIn("prodA/svc:T1", keys)
        self.assertIn("prodB/svc:T1", keys)

    def test_multi_actor_split(self):
        t1 = next(t for t in self.reg["threats"] if t["key"] == "prodA/svc:T1")
        self.assertEqual(t1["actors"], ["remote_unauth", "insider"])

    def test_sorted_by_score_desc(self):
        scores = [t["score"] for t in self.reg["threats"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_quick_wins(self):
        wins = self.reg["quick_wins"]
        self.assertEqual(len(wins), 2)  # closes_class=yes + effort S over open critical
        self.assertTrue(all("parameterized" in w["mitigation"] for w in wins))
        # the closes_class=no / effort L row is never a quick win
        self.assertFalse(any("bigger cluster" in w["mitigation"] for w in wins))

    def test_outputs_written(self):
        out = self.root / "threat-register"
        for ext in ("json", "md", "html"):
            p = out / f"threat-register.{ext}"
            self.assertTrue(p.is_file())
            self.assertGreater(p.stat().st_size, 100)
        data = json.loads((out / "threat-register.json").read_text())
        self.assertIn("scoring", data["meta"])

    def test_ownership_cuts(self):
        cuts = self.reg["ownership_cuts"]
        self.assertEqual(cuts["findings"]["models"], 2)
        self.assertEqual(cuts["findings"]["threats"], 4)
        self.assertEqual(cuts["findings"]["open"], 2)
        self.assertEqual(cuts["findings"]["open_critical_plus"], 2)
        self.assertEqual(cuts["oss-findings"]["models"], 0)
        md = (self.root / "threat-register" / "threat-register.md").read_text(encoding="utf-8")
        self.assertIn("## Ownership cuts", md)
        self.assertIn("Owned (findings/, Hybrid Platforms)", md)
        self.assertIn("Upstream (oss-findings/)", md)

    def test_no_isolation_keys_without_lens(self):
        # Backward compat: registers built from boundary-free portfolios
        # carry none of the optional Phase-1 keys.
        self.assertNotIn("tenant_boundaries", self.reg)
        self.assertNotIn("tenant_boundary_count", self.reg["meta"])
        for t in self.reg["threats"]:
            for k in ("isolation_dimensions", "isolation_boundaries", "isolation_review_ref"):
                self.assertNotIn(k, t)
        md = (self.root / "threat-register" / "threat-register.md").read_text(encoding="utf-8")
        self.assertNotIn("Weakest tenant boundaries", md)

    def test_nonconforming_model_skipped(self):
        bad = self.root / "findings" / "prodA" / "bad"
        bad.mkdir()
        (bad / "bad-threat-model.md").write_text("# not a threat model\n")
        reg = build(self.root, self.root / "threat-register")
        self.assertEqual(reg["meta"]["models_skipped_nonconforming"], 1)
        self.assertEqual(reg["meta"]["models"], 2)


class TestIsolationWiring(unittest.TestCase):
    """PEACH isolation lens Phase 1: optional isolation columns
    per register row + weakest-tenant-boundaries roll-up, and the register
    accepting the 11/12-column threat-table variants."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        make_portfolio(self.root)  # two plain 10-column models
        for product, repo, text in (("prodC", "atk", MODEL_ATTACK), ("prodD", "mtsvc", MODEL_MT)):
            d = self.root / "findings" / product / repo
            d.mkdir(parents=True)
            (d / f"{repo}-threat-model.md").write_text(text.format(name=repo), encoding="utf-8")
        self.reg = build(self.root, self.root / "threat-register")

    def tearDown(self):
        self.tmp.cleanup()

    def _threat(self, key):
        return next(t for t in self.reg["threats"] if t["key"] == key)

    def test_column_variants_not_skipped(self):
        # attack_refs (11-col) and isolation (12-col) models must be
        # parsed, not counted as nonconforming.
        self.assertEqual(self.reg["meta"]["models"], 4)
        self.assertEqual(self.reg["meta"]["models_skipped_nonconforming"], 0)
        self.assertIn("prodC/atk:T1", [t["key"] for t in self.reg["threats"]])

    def test_isolation_fields_on_tagged_row(self):
        t1 = self._threat("prodD/mtsvc:T1")
        self.assertEqual(t1["isolation_dimensions"], ["privilege", "authentication"])
        self.assertEqual(t1["isolation_boundaries"], ["IF-1"])
        self.assertEqual(t1["isolation_review_ref"], "analysis-results/isolation/mtsvc/")

    def test_isolation_fields_absent_elsewhere(self):
        for key in ("prodA/svc:T1", "prodC/atk:T1", "prodD/mtsvc:T2"):
            t = self._threat(key)
            for k in ("isolation_dimensions", "isolation_boundaries", "isolation_review_ref"):
                self.assertNotIn(k, t)

    def test_boundary_rollup_weakest_first(self):
        tb = self.reg["tenant_boundaries"]
        self.assertEqual(self.reg["meta"]["tenant_boundary_count"], 2)
        self.assertEqual([b["key"] for b in tb], ["prodD/mtsvc:IF-1", "prodD/mtsvc:IF-2"])
        worst = tb[0]
        self.assertEqual(worst["weakness"], 4)  # no=2 + 2 partials
        self.assertEqual(worst["weak_dimensions"], ["authentication"])
        self.assertEqual(worst["partial_dimensions"], ["privilege", "hygiene"])
        self.assertEqual(worst["open_threats"], ["prodD/mtsvc:T1"])
        self.assertEqual(tb[1]["weakness"], 0)

    def test_md_has_boundary_section(self):
        md = (self.root / "threat-register" / "threat-register.md").read_text(encoding="utf-8")
        self.assertIn("Weakest tenant boundaries", md)
        self.assertIn("prodD/mtsvc:IF-1", md)


if __name__ == "__main__":
    unittest.main()
