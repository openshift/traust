"""Tests for harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py."""

import datetime
import json

import emit_drain_tranche as edt


def _worklist(tmp_path, *, age_hours=1, preroute=True, rate=2):
    gen = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=age_hours)
    doc = {
        "generated_at": gen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_version": "0.194.2-test",
        "summary": {
            "drain": {"pool": 4, "weekly_rate": rate},
            **({"preroute": {"eligible": 1}} if preroute else {}),
        },
        "decisions": [
            {
                "repo_url": "https://x/a",
                "repo_key": "k/a",
                "lane": "diff-scan-quarterly",
                "drain_order": 0,
                "tier": "P1",
                "exposure": "public-external",
                "C": 900,
                "rule": "rule-5",
                "reason": "r",
            },
            {
                "repo_url": "https://x/b",
                "repo_key": "k/b",
                "lane": "diff-scan-quarterly",
                "drain_order": 1,
                "tier": "P1",
                "exposure": "public-external",
                "C": 500,
                "rule": "rule-5",
                "reason": "r",
            },
            {
                "repo_url": "https://x/c",
                "repo_key": "k/c",
                "lane": "diff-scan-quarterly",
                "drain_order": 3,
                "tier": "P2",
                "exposure": "private-internal",
                "C": 100,
                "rule": "rule-5",
                "reason": "r",
            },
            {
                "repo_url": "https://x/d",
                "repo_key": "k/d",
                "lane": "diff-scan",
                "tier": "P2",
                "exposure": "public-external",
                "C": 250,
                "rule": "tripwire",
                "reason": "r",
            },
            {
                "repo_url": "https://x/e",
                "repo_key": "k/e",
                "lane": "full-audit",
                "tier": "P1",
                "exposure": "public-external",
                "C": 9000,
                "rule": "rule-2",
                "reason": "r",
            },
        ],
    }
    p = tmp_path / "rescan-worklist.json"
    p.write_text(json.dumps(doc))
    return p


def _run(tmp_path, wl, *extra):
    return edt.main(["--worklist", str(wl), "--out-dir", str(tmp_path / "out"), *extra])


class TestTranche:
    def test_selects_drain_rows_under_rate(self, tmp_path):
        wl = _worklist(tmp_path)
        assert _run(tmp_path, wl) == 0
        out = next((tmp_path / "out").glob("drain-tranche-*.json"))
        doc = json.loads(out.read_text())
        urls = [r["repo_url"] for r in doc["rows"]]
        assert urls == ["https://x/a", "https://x/b"]
        assert doc["drain_rate"] == 2

    def test_include_immediate_adds_diff_scan_lane(self, tmp_path):
        wl = _worklist(tmp_path)
        assert _run(tmp_path, wl, "--include-immediate") == 0
        out = next((tmp_path / "out").glob("drain-tranche-*.json"))
        urls = [r["repo_url"] for r in json.loads(out.read_text())["rows"]]
        assert "https://x/d" in urls
        assert "https://x/e" not in urls  # full-audit never included

    def test_stale_worklist_refused(self, tmp_path):
        wl = _worklist(tmp_path, age_hours=72)
        assert _run(tmp_path, wl) == 3

    def test_pre_preroute_worklist_refused(self, tmp_path):
        wl = _worklist(tmp_path, preroute=False)
        assert _run(tmp_path, wl) == 3

    def test_one_tranche_per_week_unless_force(self, tmp_path):
        wl = _worklist(tmp_path)
        assert _run(tmp_path, wl) == 0
        assert _run(tmp_path, wl) == 3
        assert _run(tmp_path, wl, "--force") == 0

    def test_week_override_names_file(self, tmp_path):
        wl = _worklist(tmp_path)
        assert _run(tmp_path, wl, "--week", "2026-W40") == 0
        assert (tmp_path / "out" / "drain-tranche-2026-W40.json").is_file()


# ---------------------------------------------------------------------------
# threat-model lanes in the tranche (cadence plan Phases 1-3)
# ---------------------------------------------------------------------------


def _tm_worklist(tmp_path, *, tm_rate=2):
    gen = datetime.datetime.now(datetime.UTC)
    doc = {
        "generated_at": gen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_version": "test",
        "summary": {
            "preroute": {"eligible": 1},
            "drain": {"pool": 2, "weekly_rate": 1},
            "threat_model": {"quarterly_weekly_rate": tm_rate},
        },
        "decisions": [
            {
                "repo_url": "https://x/a",
                "repo_key": "k/a",
                "lane": "diff-scan-quarterly",
                "drain_order": 0,
                "threat_model_pr": {"mode": "report-only", "model": "/m/a.md"},
            },
            {
                "repo_url": "https://x/b",
                "repo_key": "k/b",
                "lane": "threat-model-quarterly",
                "drain_order": 0,
                "threat_model_age_days": 140,
            },
            {
                "repo_url": "https://x/c",
                "repo_key": "k/c",
                "lane": "threat-model-quarterly",
                "drain_order": 9,
                "threat_model_age_days": 95,
            },
            {
                "repo_url": "https://x/d",
                "repo_key": "k/d",
                "lane": "threat-model-review",
                "release_version": "5.0.0",
                "release_change": "major",
            },
            {"repo_url": "https://x/e", "repo_key": "k/e", "lane": "full-audit"},
        ],
    }
    p = tmp_path / "rescan-worklist.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


class TestThreatModelLaneSelection:
    def test_pools_drain_by_their_own_rates(self, tmp_path):
        doc = json.loads(_tm_worklist(tmp_path).read_text())
        rows = edt.select_rows(doc, include_immediate=False)
        keys = [r["repo_key"] for r in rows]
        assert "k/b" in keys  # inside the threat-model rate
        assert "k/c" not in keys  # drain_order 9 >= rate 2
        assert "k/e" not in keys  # full-audit is not a tranche lane

    def test_release_review_rows_always_dispatch(self, tmp_path):
        """Release-triggered reviews are low-volume and event-shaped —
        they must not queue behind a quarterly drain order."""
        doc = json.loads(_tm_worklist(tmp_path).read_text())
        rows = edt.select_rows(doc, include_immediate=False)
        assert any(r["repo_key"] == "k/d" for r in rows)

    def test_missing_threat_model_rate_selects_no_quarterly_rows(self, tmp_path):
        """A worklist from a pre-cadence router has no threat_model
        summary block — degrade to selecting nothing, never to
        dispatching the whole pool."""
        doc = json.loads(_tm_worklist(tmp_path).read_text())
        del doc["summary"]["threat_model"]
        rows = edt.select_rows(doc, include_immediate=False)
        assert not any(r["lane"] == "threat-model-quarterly" for r in rows)
        assert any(r["lane"] == "threat-model-review" for r in rows)

    def test_manifest_carries_lane_and_pr_companion(self, tmp_path):
        wl = _tm_worklist(tmp_path)
        rc = edt.main(["--worklist", str(wl), "--out-dir", str(tmp_path), "--week", "2026-W32"])
        assert rc == 0
        m = json.loads((tmp_path / "drain-tranche-2026-W32.json").read_text())
        assert "threat-model-quarterly" in m["dispatch_by_lane"]
        by_key = {r["repo_key"]: r for r in m["rows"]}
        # the dispatcher can no longer assume every row is a diff
        assert by_key["k/b"]["lane"] == "threat-model-quarterly"
        assert by_key["k/b"]["threat_model_age_days"] == 140
        assert by_key["k/a"]["threat_model_pr"]["mode"] == "report-only"
        assert by_key["k/d"]["release_version"] == "5.0.0"
