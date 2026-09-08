"""Threat-intel (EPSS/KEV) likelihood factor in the OWASP risk rating."""

import importlib.util
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "build_trends_ti", skill_dir("findings-trends") / "scripts" / "build_trends.py"
)
bt = importlib.util.module_from_spec(_SPEC)
sys.modules["build_trends_ti"] = bt
_SPEC.loader.exec_module(bt)

# a network-reachable but hard-to-exploit vector: likelihood factors
# AV:N=9, AC:H=3, PR:L=5, UI:R=4 -> mean 5.25 (MEDIUM); impact C:H I:N
# A:N -> mean 3.0 (MEDIUM) => medium band without threat intel
VECTOR = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N"
FINDING = {
    "id": "F-1",
    "severity": "high",
    "cvss": {"vector": VECTOR},
    "description": "uses dep with CVE-2026-3333",
}


@pytest.fixture(autouse=True)
def _reset_feeds():
    saved = dict(bt._THREAT_INTEL)
    yield
    bt._THREAT_INTEL.update(saved)


def _set_feeds(epss=None, kev=None):
    bt._THREAT_INTEL["epss"] = epss if epss is not None else {}
    bt._THREAT_INTEL["kev"] = kev if kev is not None else {}


def test_no_feeds_no_change():
    bt._THREAT_INTEL["epss"] = None
    assert bt.threat_intel_score(FINDING) is None
    assert bt.owasp_rating(FINDING) == "medium"


def test_kev_membership_scores_max():
    _set_feeds(kev={"CVE-2026-3333": {"date_added": "2026-07-01"}})
    assert bt.threat_intel_score(FINDING) == 9.0


def test_epss_bands():
    for epss_val, expected in ((0.9, 9.0), (0.2, 7.0), (0.05, 5.0), (0.001, 2.0)):
        _set_feeds(epss={"CVE-2026-3333": {"epss": epss_val, "percentile": 0.5}})
        assert bt.threat_intel_score(FINDING) == expected, epss_val


def test_no_cve_id_means_no_factor():
    _set_feeds(kev={"CVE-2026-3333": {}})
    assert bt.threat_intel_score({"id": "F-2", "title": "no cve"}) is None


def test_kev_raises_rating_band():
    # medium on CVSS factors alone; KEV evidence pushes likelihood
    # (5.25*4 + 9)/5 = 6.0 -> HIGH bucket, so medium -> high
    assert bt.owasp_rating(FINDING) == "medium"
    assert bt.owasp_rating(FINDING, ti_score=9.0) == "high"


def test_unknown_cve_in_feeds_no_factor():
    _set_feeds(epss={"CVE-1999-0001": {"epss": 0.9}})
    assert bt.threat_intel_score(FINDING) is None


def test_methodology_json_declares_factor():
    assert bt._TI_FACTOR is not None
    assert bt._TI_FACTOR["kev_score"] <= 9
    bands = bt._TI_FACTOR["epss_bands"]
    assert bands == sorted(bands, key=lambda b: -b["min_epss"])
    assert bands[-1]["min_epss"] == 0.0
