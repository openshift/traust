"""Tests for traust.cli.budget_shadow — observe-mode budget accounting
(budget-guard widening plan, Phase 1)."""

import pytest

from traust.cli import budget_shadow as bs
from traust.cli import build_rescan_worklist as brw


class _FakeMetrics:
    def __init__(self, rows=None):
        self._rows = rows or []

    def rows(self):
        return self._rows

    def append(self, source, metrics, **kwargs):
        self.last_append = (source, metrics, kwargs)


class _FakeEngine:
    def __init__(self, rows=None):
        self.metrics = _FakeMetrics(rows)


def _row(key, lane, tier="P2", exposure="public-internal", rule="rule-5", **extra):
    return {
        "repo_key": key,
        "repo_url": f"https://x/{key}",
        "lane": lane,
        "tier": tier,
        "exposure": exposure,
        "rule": rule,
        **extra,
    }


@pytest.fixture
def no_ledger(monkeypatch):
    """Zero month-to-date so tests exercise the tranche term alone."""
    monkeypatch.setattr(
        bs,
        "month_to_date_lane_usd",
        lambda ws, month=None, **kwargs: {
            "month": "2026-08",
            "lane_usd": 0.0,
            "unattributed_usd": 0.0,
            "days_recorded": 0,
        },
    )


class TestObserveNeverWithholds:
    def test_report_contains_no_filtered_work_list(self, tmp_path, no_ledger):
        rows = [_row("a", "diff-scan-quarterly")] * 3
        v = bs.shadow_verdict(tmp_path, rows, 0.01, "test")
        assert v["mode"] == "observe"
        assert v["withheld_anything"] is False
        # a report, never a work list the caller might mistake for one
        assert "rows" not in v

    def test_observe_is_not_a_gating_mode_in_the_router(self):
        """The drop path must be physically unable to see an observe
        ceiling — that is the whole safety property of Phase 1."""
        assert bs is not None
        assert "observe" not in brw._POLICY_GATING_MODES

    def test_router_reports_observe_as_no_binding_ceiling(self, tmp_path):
        p = tmp_path / "budget-policy.yaml"
        p.write_text(
            "budget_policy:\n  enforcement: observe\n  monthly_budget: {usd_central: 23000}\n"
        )
        ceiling, why = brw.read_policy_budget(p)
        assert ceiling is None
        assert "observe" in why and "NOTHING is withheld" in why

    def test_shadow_reader_is_the_only_way_to_see_it(self, tmp_path):
        p = tmp_path / "budget-policy.yaml"
        p.write_text(
            "budget_policy:\n  enforcement: observe\n  monthly_budget: {usd_central: 23000}\n"
        )
        assert brw.read_policy_shadow_ceiling(p)[0] == 23000.0

    def test_shadow_reader_refuses_non_observe_modes(self, tmp_path):
        for mode in ("none", "advisory", "enforced"):
            p = tmp_path / "budget-policy.yaml"
            p.write_text(
                f"budget_policy:\n  enforcement: {mode}\n  monthly_budget: {{usd_central: 23000}}\n"
            )
            ceiling, why = brw.read_policy_shadow_ceiling(p)
            assert ceiling is None, mode
            assert "not observe mode" in why


class TestVerdicts:
    def test_within(self, tmp_path, no_ledger):
        v = bs.shadow_verdict(tmp_path, [_row("a", "diff-scan")], 1000.0, "t")
        assert v["verdict"] == "within" and v["headroom_usd"] > 0

    def test_would_exceed(self, tmp_path, no_ledger):
        rows = [_row(str(i), "full-audit") for i in range(5)]
        v = bs.shadow_verdict(tmp_path, rows, 50.0, "t")
        assert v["verdict"] == "would_exceed"
        assert v["overage_usd"] == pytest.approx(5 * 29.04 - 50, abs=0.01)

    def test_no_ceiling(self, tmp_path, no_ledger):
        v = bs.shadow_verdict(tmp_path, [_row("a", "diff-scan")], None, "t")
        assert v["verdict"] == "no_ceiling"
        assert "would_withhold" not in v


class TestSacrificeOrder:
    def test_least_exposure_goes_first_regardless_of_lane(self, tmp_path, no_ledger):
        rows = [
            _row("keep", "full-audit", tier="P0", exposure="public-external"),
            _row("drop", "diff-scan", tier="P0", exposure="private-internal"),
        ]
        v = bs.shadow_verdict(tmp_path, rows, 1.0, "t")
        assert v["would_withhold"][0]["repo_key"] == "drop"

    def test_tier_breaks_ties_within_an_exposure_band(self, tmp_path, no_ledger):
        rows = [
            _row("p0", "diff-scan", tier="P0", exposure="public-internal"),
            _row("p3", "diff-scan", tier="P3", exposure="public-internal"),
        ]
        v = bs.shadow_verdict(tmp_path, rows, 1.0, "t")
        assert v["would_withhold"][0]["repo_key"] == "p3"

    def test_stops_once_the_overage_is_covered(self, tmp_path, no_ledger):
        rows = [_row(str(i), "full-audit", exposure="private-internal") for i in range(10)]
        v = bs.shadow_verdict(tmp_path, rows, 29.04 * 8, "t")
        # overage is ~2 runs' worth, so ~2 rows are enough
        assert len(v["would_withhold"]) == 2


class TestProtections:
    def test_event_rows_are_never_withheld(self, tmp_path, no_ledger):
        rows = [
            _row("ev", "full-audit", exposure="private-internal", event_source="external-report")
        ]
        v = bs.shadow_verdict(tmp_path, rows, 1.0, "t")
        assert v["would_withhold"] == []
        assert v["protected_not_withheld"][0]["repo_key"] == "ev"

    def test_rule3_rows_are_never_withheld(self, tmp_path, no_ledger):
        rows = [_row("s", "diff-scan", rule="rule-3", exposure="private-internal")]
        v = bs.shadow_verdict(tmp_path, rows, 1.0, "t")
        assert v["would_withhold"] == []
        assert "rule-3" in v["protected_not_withheld"][0]["protected_reason"]

    def test_unmeetable_ceiling_is_stated_not_implied(self, tmp_path, no_ledger):
        """A ceiling with carve-outs can be exceeded with nothing left
        to give up. The report must say so rather than look satisfied."""
        rows = [_row("s", "full-audit", rule="rule-3")]
        v = bs.shadow_verdict(tmp_path, rows, 1.0, "t")
        assert v["ceiling_unmeetable"] is True
        assert "could NOT be met" in v["ceiling_unmeetable_note"]

    def test_meetable_ceiling_sets_no_flag(self, tmp_path, no_ledger):
        rows = [_row(str(i), "full-audit", exposure="private-internal") for i in range(4)]
        v = bs.shadow_verdict(tmp_path, rows, 29.04 * 3, "t")
        assert "ceiling_unmeetable" not in v


class TestPricing:
    def test_unmeasured_lanes_are_counted_not_zeroed(self, tmp_path, no_ledger):
        """threat-model lanes shipped without a measured unit cost.
        Pricing them at $0 would understate every projection."""
        rows = [_row("t", "threat-model-quarterly")]
        v = bs.shadow_verdict(tmp_path, rows, 100.0, "t")
        assert v["unpriced_rows"] == 1
        assert "threat-model-quarterly" in v["unpriced_lanes"]
        assert v["tranche_estimate_usd"] == 0.0  # excluded, but declared

    def test_unpriced_rows_are_not_selected_for_withholding(self, tmp_path, no_ledger):
        """Withholding a row whose cost is unknown frees nothing, so it
        cannot be used to satisfy an overage."""
        rows = [
            _row("t", "threat-model-quarterly", exposure="private-internal"),
            _row("f", "full-audit", exposure="public-external"),
        ]
        v = bs.shadow_verdict(tmp_path, rows, 1.0, "t")
        keys = [r["repo_key"] for r in v["would_withhold"]]
        assert "t" not in keys and "f" in keys

    def test_estimate_matches_measured_medians(self):
        est = bs.estimate_rows([_row("a", "full-audit"), _row("b", "diff-scan")])
        assert est["usd"] == pytest.approx(29.04 + 4.73, abs=0.01)


class TestMonthToDate:
    def test_reads_attribution_rows_and_splits_unattributed(self, tmp_path):
        """MTD must come from lane rows, not the workstation total —
        the $23K ceiling is a scanning ceiling."""
        engine = _FakeEngine(
            [
                {
                    "source": "spend-attribution:vuln-scan",
                    "metrics": {"date": "2026-08-01", "skill": "vuln-scan", "cost_usd": 10.0},
                },
                {
                    "source": "spend-attribution:unattributed",
                    "metrics": {"date": "2026-08-01", "skill": "unattributed", "cost_usd": 900.0},
                },
                {
                    "source": "model-spend:vuln-scan",  # declared: ignored
                    "metrics": {"date": "2026-08-01", "skill": "vuln-scan", "cost_usd": 5.0},
                },
            ]
        )
        got = bs.month_to_date_lane_usd(tmp_path, "2026-08", engine=engine)
        assert got["lane_usd"] == 10.0
        assert got["unattributed_usd"] == 900.0

    def test_other_months_excluded(self, tmp_path):
        engine = _FakeEngine(
            [
                {
                    "source": "spend-attribution:x",
                    "metrics": {"date": "2026-07-01", "skill": "x", "cost_usd": 99.0},
                }
            ]
        )
        assert bs.month_to_date_lane_usd(tmp_path, "2026-08", engine=engine)["lane_usd"] == 0.0


class TestVerdictLedger:
    def test_append_records_the_countable_fields(self, tmp_path):
        engine = _FakeEngine()
        ok = bs.append_verdict(
            tmp_path,
            "2026-W32",
            {
                "mode": "observe",
                "verdict": "would_exceed",
                "ceiling_usd": 23000,
                "month": "2026-08",
                "month_to_date_lane_usd": 1.0,
                "tranche_estimate_usd": 2.0,
                "projected_with_tranche_usd": 3.0,
                "would_withhold": [1, 2],
                "ceiling_unmeetable": True,
            },
            engine=engine,
        )
        assert ok
        source, payload, _kwargs = engine.metrics.last_append
        assert source == "budget-shadow"
        assert payload["week"] == "2026-W32"
        assert payload["would_withhold_rows"] == 2
        assert payload["ceiling_unmeetable"] is True
