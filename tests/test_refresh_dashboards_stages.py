"""Stage-order guarantees for refresh_dashboards.

Ordering here is load-bearing and invisible at runtime: if the reconciler
runs after the projection, findings.db carries last week's provenance and
nobody notices, because every stage still reports success.
"""

from pathlib import Path

from traust.cli.refresh_dashboards import build_stages

WS = Path("/ws")
RR = WS / "analysis-results"


def _stages():
    return build_stages(WS, RR, "note", False)


def _names():
    return [s[0] for s in _stages()]


def test_cve_stages_run_before_the_projection():
    n = _names()
    assert n.index("cve-feed") < n.index("cve-provenance") < n.index("findings-db")


def test_cve_stages_are_consumer_tier():
    """Projection tier aborts the run. An off-VPN or rate-limited feed
    must not take the whole dashboard rebuild with it — the reconciler is
    idempotent and catches up on the next cycle."""
    tiers = {s[0]: s[1] for s in _stages()}
    assert tiers["cve-feed"] == "consumer"
    assert tiers["cve-provenance"] == "consumer"


def test_reconciler_applies_and_reports_to_the_metrics_tree():
    argv = next(s[2] for s in _stages() if s[0] == "cve-provenance")
    assert "--apply" in argv, "a dry run would stamp nothing"
    report = argv[argv.index("--report") + 1]
    assert report.endswith(
        "progress-tracker/metrics/first-discovery/first-discovery-current.json"
    ), report
    # results-root must be explicit: a relative default resolves to zero
    # reports and the run reports success having stamped nothing
    assert str(RR) in argv
