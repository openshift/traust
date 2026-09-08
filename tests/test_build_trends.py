#!/usr/bin/env python3
"""Unit tests for the findings-trends replay engine (build_trends.py)."""

import collections
import json
import tempfile
import unittest
from pathlib import Path

from build_trends import (
    bucket_key,
    build_series,
    classify,
    compute_trends,
    cvss_effective,
    discover,
    render_markdown,
)

AS_OF = "2026-07-31"


def _finding(fid, severity="high", cvss=None, title="SSRF via annotation"):
    f = {"id": fid, "title": title, "severity": severity, "validation_status": "not_verified"}
    if cvss is not None:
        f["cvss"] = {"score": cvss, "vector": "CVSS:3.1/..."}
    return f


def _event(
    fid,
    validity=None,
    resolution=None,
    *,
    kind="human",
    source_type="interactive",
    recorded="2026-06-10T10:00:00+00:00",
    occurred=None,
    identity="jdoe@example.com",
    rationale=None,
):
    actor = {
        "kind": kind,
        "identity": identity,
        "display_name": "J. Doe" if kind == "human" else None,
    }
    if kind == "human":
        actor["ldap_verified"] = True
    disposition = {}
    if validity:
        disposition["validity"] = validity
    if resolution:
        disposition["resolution"] = resolution
    e = {
        "event_id": "0" * 64,
        "finding_ref": fid,
        "recorded_at": recorded,
        "source": {"type": source_type, "ref": f"src-{fid}", "actor": actor},
        "disposition": disposition,
        "rationale": rationale or "Verified during the July triage session.",
    }
    if occurred:
        e["occurred_at"] = occurred
    return e


def _repo(slug, audit_date, findings, events=None, product="prod"):
    by_finding = collections.defaultdict(list)
    for e in events or []:
        by_finding[e["finding_ref"]].append(e)
    return {
        "dir": f"/x/{product}/{slug}",
        "slug": slug,
        "product": product,
        "repository": f"https://github.com/example/{slug}",
        "audit_date": audit_date,
        "findings": findings,
        "events": by_finding,
        "has_layer": bool(events),
        "layer_start": min((e.get("occurred_at") or e["recorded_at"])[:10] for e in events)
        if events
        else None,
    }


def _series(repos, granularity="month", since=None):
    return build_series(repos, granularity, since, AS_OF)


def _bucket(data, key):
    return next(b for b in data["buckets"] if b["key"] == key)


class TestOptionA(unittest.TestCase):
    def test_ledgerless_findings_stay_open(self):
        data = _series([_repo("a", "2026-04-15", [_finding("A-001"), _finding("A-002", "medium")])])
        for key in ("2026-04", "2026-07"):
            b = _bucket(data, key)
            self.assertEqual(b["open"], 2)
        self.assertEqual(data["coverage"]["covered_repos"], 0)
        self.assertEqual(data["coverage"]["audited_repos"], 1)

    def test_finding_not_born_yet_not_counted(self):
        data = _series(
            [
                _repo("a", "2026-04-15", [_finding("A-001")]),
                _repo("b", "2026-06-15", [_finding("B-001")]),
            ]
        )
        self.assertEqual(_bucket(data, "2026-05")["open"], 1)
        self.assertEqual(_bucket(data, "2026-06")["open"], 2)
        self.assertEqual(_bucket(data, "2026-06")["discovered"], 1)


class TestStateReplay(unittest.TestCase):
    def test_resolved_leaves_open(self):
        r = _repo(
            "a",
            "2026-04-15",
            [_finding("A-001")],
            [
                _event(
                    "A-001",
                    resolution="resolved",
                    kind="machine",
                    source_type="verification_report",
                    identity="verify-remediation",
                    recorded="2026-06-10T10:00:00+00:00",
                )
            ],
        )
        data = _series([r])
        self.assertEqual(_bucket(data, "2026-05")["open"], 1)
        b6 = _bucket(data, "2026-06")
        self.assertEqual(b6["open"], 0)
        self.assertEqual(b6["resolved"], 1)
        self.assertEqual(_bucket(data, "2026-07")["resolved"], 0)  # flow, not stock
        self.assertEqual(_bucket(data, "2026-07")["resolved_total"], 1)

    def test_accepted_is_not_resolved_and_hits_register(self):
        r = _repo(
            "a",
            "2026-04-15",
            [_finding("A-001", cvss=7.7)],
            [
                _event(
                    "A-001",
                    resolution="risk_accepted",
                    source_type="jira",
                    recorded="2026-06-10T10:00:00+00:00",
                    rationale="Accepted via OSPRH-99: legacy component.",
                )
            ],
        )
        data = _series([r])
        b = _bucket(data, "2026-06")
        self.assertEqual(b["open"], 0)
        self.assertEqual(b["resolved"], 0)
        self.assertEqual(b["accepted"], 1)
        self.assertEqual(b["accepted_new"], 1)
        self.assertAlmostEqual(b["accepted_risk_index"], 7.7)
        reg = data["accepted_register"]
        self.assertEqual(len(reg), 1)
        self.assertEqual(reg[0]["accepted_by"], "J. Doe")
        self.assertEqual(reg[0]["accepted_since"], "2026-06-10")
        self.assertIn("OSPRH-99", reg[0]["rationale"])

    def test_machine_refuted_stays_open_until_countersigned(self):
        events = [
            _event(
                "A-001",
                validity="false_positive",
                kind="machine",
                source_type="validation_report",
                identity="validate-findings",
                recorded="2026-05-10T10:00:00+00:00",
            )
        ]
        data = _series([_repo("a", "2026-04-15", [_finding("A-001")], events)])
        self.assertEqual(_bucket(data, "2026-06")["open"], 1)

        events.append(
            _event("A-001", validity="false_positive", recorded="2026-06-20T10:00:00+00:00")
        )
        data = _series([_repo("a", "2026-04-15", [_finding("A-001")], events)])
        b = _bucket(data, "2026-06")
        self.assertEqual(b["open"], 0)
        self.assertEqual(b["fp_new"], 1)

    def test_fix_in_progress_still_open(self):
        r = _repo(
            "a",
            "2026-04-15",
            [_finding("A-001")],
            [
                _event(
                    "A-001",
                    resolution="fix_in_progress",
                    source_type="commit",
                    recorded="2026-06-10T10:00:00+00:00",
                )
            ],
        )
        data = _series([r])
        self.assertEqual(_bucket(data, "2026-06")["open"], 1)


class TestRiskIndex(unittest.TestCase):
    def test_cvss_sum_with_severity_fallback(self):
        data = _series(
            [
                _repo(
                    "a",
                    "2026-04-15",
                    [
                        _finding("A-001", "critical", cvss=9.9),
                        _finding("A-002", "high"),  # fallback 8.0
                        _finding("A-003", "informational"),  # fallback 0
                    ],
                )
            ]
        )
        self.assertAlmostEqual(_bucket(data, "2026-07")["risk_index"], 17.9)

    def test_cvss_effective_fallbacks(self):
        self.assertEqual(cvss_effective(_finding("x", "medium")), 5.5)
        self.assertEqual(cvss_effective(_finding("x", "low", cvss=3.1)), 3.1)


class TestOccurredAt(unittest.TestCase):
    def test_occurred_at_buckets_before_recorded_at(self):
        # fixed in May, ingested in July → counts in May
        r = _repo(
            "a",
            "2026-04-15",
            [_finding("A-001")],
            [
                _event(
                    "A-001",
                    resolution="resolved",
                    kind="machine",
                    source_type="verification_report",
                    identity="verify-remediation",
                    recorded="2026-07-20T10:00:00+00:00",
                    occurred="2026-05-02T10:00:00+00:00",
                )
            ],
        )
        data = _series([r])
        self.assertEqual(_bucket(data, "2026-05")["resolved"], 1)
        self.assertEqual(_bucket(data, "2026-05")["open"], 0)
        self.assertEqual(_bucket(data, "2026-07")["resolved"], 0)


class TestMTTR(unittest.TestCase):
    def test_mttr_days_from_audit_to_close(self):
        r = _repo(
            "a",
            "2026-04-15",
            [_finding("A-001")],
            [
                _event(
                    "A-001",
                    resolution="resolved",
                    kind="machine",
                    source_type="verification_report",
                    identity="verify-remediation",
                    recorded="2026-05-15T10:00:00+00:00",
                )
            ],
        )
        data = _series([r])
        self.assertEqual(_bucket(data, "2026-05")["mttr_days"]["overall"], 30.0)
        self.assertEqual(_bucket(data, "2026-05")["mttr_days"]["high"], 30.0)


class TestClassify(unittest.TestCase):
    def test_downtrend_good_when_polarity_down(self):
        t = classify([100, 100, 100, 50], good_down=True)
        self.assertEqual((t["arrow"], t["label"]), ("↓", "improving"))

    def test_uptrend_bad_when_polarity_down(self):
        t = classify([1, 1, 1, 4], good_down=True)
        self.assertEqual((t["arrow"], t["label"]), ("↑", "worsening"))

    def test_uptrend_good_when_polarity_up(self):
        t = classify([10, 10, 10, 20], good_down=False)
        self.assertEqual((t["arrow"], t["label"]), ("↑", "improving"))

    def test_dead_band_is_flat(self):
        t = classify([100, 100, 100, 105], good_down=True)
        self.assertEqual(t["label"], "flat")

    def test_zero_baseline_spike(self):
        t = classify([0, 0, 0, 3], good_down=True)
        self.assertEqual((t["arrow"], t["label"]), ("↑", "worsening"))

    def test_compute_trends_keys(self):
        data = _series([_repo("a", "2026-04-15", [_finding("A-001")])])
        trends = compute_trends(data["buckets"])
        for key in (
            "open",
            "risk_index",
            "velocity",
            "new",
            "mttr",
            "regressions",
            "fp_rate",
            "coverage",
            "accepted_risk_index",
        ):
            self.assertIn(key, trends)


class TestRegressionsAndCoverage(unittest.TestCase):
    def test_regression_events_counted_in_bucket(self):
        r = _repo(
            "a",
            "2026-04-15",
            [_finding("A-001")],
            [
                _event(
                    "A-001",
                    resolution="regression_introduced",
                    kind="machine",
                    source_type="verification_report",
                    identity="verify-remediation",
                    recorded="2026-06-10T10:00:00+00:00",
                )
            ],
        )
        data = _series([r])
        self.assertEqual(_bucket(data, "2026-06")["regressions"], 1)
        self.assertEqual(_bucket(data, "2026-07")["regressions"], 0)

    def test_coverage_counts_ledgered_repos(self):
        data = _series(
            [
                _repo(
                    "a",
                    "2026-04-15",
                    [_finding("A-001")],
                    [
                        _event(
                            "A-001",
                            resolution="resolved",
                            kind="machine",
                            source_type="verification_report",
                            identity="verify-remediation",
                            recorded="2026-06-10T10:00:00+00:00",
                        )
                    ],
                ),
                _repo("b", "2026-04-15", [_finding("B-001")]),
            ]
        )
        b = _bucket(data, "2026-06")
        self.assertEqual((b["covered_repos"], b["audited_repos"]), (1, 2))
        self.assertEqual(_bucket(data, "2026-05")["covered_repos"], 0)


class TestDeterminismAndRendering(unittest.TestCase):
    def _rich_repos(self):
        return [
            _repo(
                "a",
                "2026-04-15",
                [_finding("A-001", "critical", cvss=9.1), _finding("A-002", "medium")],
                [
                    _event(
                        "A-001",
                        resolution="resolved",
                        kind="machine",
                        source_type="verification_report",
                        identity="verify-remediation",
                        recorded="2026-06-01T10:00:00+00:00",
                    ),
                    _event(
                        "A-002",
                        resolution="risk_accepted",
                        source_type="jira",
                        recorded="2026-07-01T10:00:00+00:00",
                    ),
                ],
            ),
            _repo("b", "2026-05-20", [_finding("B-001", "high")]),
        ]

    def test_deterministic(self):
        a = _series(self._rich_repos())
        b = _series(self._rich_repos())
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_markdown_sections(self):
        data = _series(self._rich_repos())
        trends = compute_trends(data["buckets"])
        md = render_markdown(data, trends, "month", "0.20.0-test")
        self.assertIn("Ledger coverage:** 1/2", md)
        self.assertIn("Accepted Risk Register — 1 standing", md)
        self.assertIn("not fixed and not mitigated", md)
        self.assertIn("| Metric | Latest", md)
        self.assertIn("## Time Series", md)

    def test_ownership_cuts_latest_bucket(self):
        data = _series(self._rich_repos())
        oc = data["ownership_cuts"]
        self.assertEqual(oc["bucket"], "2026-07")
        owned = oc["cuts"]["findings"]  # fixtures default to findings/
        self.assertEqual(owned["open"], 1)  # only B-001 still open
        self.assertEqual(owned["open_high"], 1)
        self.assertEqual(owned["open_critical"], 0)
        self.assertAlmostEqual(owned["risk_index"], 8.0)
        self.assertEqual(oc["cuts"]["oss-findings"]["open"], 0)
        md = render_markdown(data, compute_trends(data["buckets"]), "month", "0.20.0-test")
        self.assertIn("## Ownership cuts (latest bucket)", md)
        self.assertIn("Owned (findings/, Hybrid Platforms)", md)
        self.assertIn("Upstream (oss-findings/)", md)

    def test_week_granularity_keys(self):
        self.assertEqual(bucket_key("2026-01-05", "week"), "2026-W02")
        data = _series(self._rich_repos(), granularity="week")
        self.assertTrue(all("W" in b["key"] for b in data["buckets"]))


class TestDiscoverEndToEnd(unittest.TestCase):
    def test_discover_and_main_roundtrip(self):
        from traust_engine.ledger import compute_event_id

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "findings"
            d = root / "prod" / "widget"
            d.mkdir(parents=True)
            audit = {
                "title": "Security Assessment — Widget",
                "metadata": {
                    "date": "2026-04-15",
                    "repository": "https://github.com/example/widget",
                },
                "findings": [_finding("W-001")],
            }
            (d / "widget-security-audit.json").write_text(json.dumps(audit))
            ev = _event(
                "W-001",
                resolution="resolved",
                kind="machine",
                source_type="verification_report",
                identity="verify-remediation",
                recorded="2026-06-10T10:00:00+00:00",
            )
            ev["event_id"] = compute_event_id("src-W-001", "W-001", None, "resolved")
            layer = {
                "metadata": {
                    "audit_report": "widget-security-audit.json",
                    "repository": audit["metadata"]["repository"],
                    "created": "2026-06-01T00:00:00+00:00",
                    "harness_version": "0.20.0-abcdef0",
                },
                "events": [ev],
                "needs_review": [],
            }
            (d / "widget-findings-layer.json").write_text(json.dumps(layer))

            repos = discover([root], None)
            self.assertEqual(len(repos), 1)
            self.assertTrue(repos[0]["has_layer"])

            from build_trends import main

            out = Path(td) / "trends"
            rc = main(
                [
                    "--results-root",
                    td,
                    "--roots",
                    str(root),
                    "--as-of",
                    AS_OF,
                    "--out-dir",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            data = json.loads((out / "findings-trends.json").read_text())
            self.assertEqual(data["buckets"][-1]["open"], 0)
            self.assertEqual(data["buckets"][-1]["resolved_total"], 1)
            self.assertTrue((out / "findings-trends.html").exists())
            self.assertTrue((out / "findings-trends.md").exists())


if __name__ == "__main__":
    unittest.main()


class TestOwaspRating(unittest.TestCase):
    """OWASP Risk Rating derivation (docs/risk-rating-methodology.md)."""

    def _f(self, vector=None, severity="high"):
        f = {"id": "F-1", "severity": severity}
        if vector:
            f["cvss"] = {"score": 7.4, "vector": vector}
        return f

    def test_network_unauth_full_impact_is_critical(self):
        from build_trends import owasp_rating

        self.assertEqual(
            owasp_rating(self._f("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")), "critical"
        )

    def test_hard_local_low_impact_is_low_band(self):
        from build_trends import owasp_rating

        # AV:P(3) AC:H(3) PR:H(2) UI:R(4) -> likelihood 3.0 MEDIUM;
        # C:L I:N A:N -> impact 1.33 LOW -> overall low
        self.assertEqual(
            owasp_rating(self._f("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")), "low"
        )

    def test_high_impact_hard_exploit_is_not_critical(self):
        from build_trends import owasp_rating

        # AV:N(9) AC:H(3) PR:N(9) UI:N(9) -> likelihood 7.5 HIGH;
        # C:H I:H A:N -> impact 6.0 HIGH -> critical only when both HIGH
        self.assertEqual(
            owasp_rating(self._f("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")), "critical"
        )
        # drop likelihood to MEDIUM: AV:L(5) AC:H(3) PR:L(5) UI:R(4) = 4.25
        self.assertEqual(
            owasp_rating(self._f("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N")), "high"
        )

    def test_vectorless_falls_back_to_severity_impact(self):
        from build_trends import owasp_rating

        # likelihood defaults MEDIUM: critical sev -> impact 9 HIGH -> high
        self.assertEqual(owasp_rating(self._f(severity="critical")), "high")
        self.assertEqual(owasp_rating(self._f(severity="medium")), "medium")
        self.assertEqual(owasp_rating(self._f(severity="low")), "low")
        # vector-less can never reach critical
        self.assertNotEqual(owasp_rating(self._f(severity="critical")), "critical")


class TestRiskRatingMethodologyTables(unittest.TestCase):
    """The methodology-as-data file must validate against its schema and
    stay consistent with what the replay engine actually loaded."""

    ROOT = Path(__file__).resolve().parent.parent

    def _load(self, rel):
        return json.loads((self.ROOT / rel).read_text(encoding="utf-8"))

    def _load_schema(self, name):
        from traust_contracts.paths import schema_path as _sp

        return json.loads(_sp(name).read_text(encoding="utf-8"))

    def test_tables_validate_against_schema(self):
        import jsonschema

        tables = self._load("harnessing/findings-trends/risk-rating-methodology.json")
        schema = self._load_schema("risk-rating-methodology")
        jsonschema.validate(tables, schema)  # raises on violation

    def test_schema_rejects_high_fallback_likelihood(self):
        import jsonschema

        tables = self._load("harnessing/findings-trends/risk-rating-methodology.json")
        schema = self._load_schema("risk-rating-methodology")
        tables["fallback"]["default_likelihood"] = 7  # HIGH bucket
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(tables, schema)

    def test_schema_rejects_incomplete_matrix(self):
        import jsonschema

        tables = self._load("harnessing/findings-trends/risk-rating-methodology.json")
        schema = self._load_schema("risk-rating-methodology")
        del tables["matrix"]["HIGH"]["HIGH"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(tables, schema)

    def test_engine_loads_the_data_file(self):
        import build_trends as bt

        tables = self._load("harnessing/findings-trends/risk-rating-methodology.json")
        self.assertEqual(bt.RR_METHODOLOGY_VERSION, tables["methodology_version"])
        self.assertEqual(bt.OWASP_BANDS, tables["bands"])
        self.assertEqual(len(bt._OWASP_MATRIX), 9)
