"""Tests for reconcile_cve_provenance.py — CVE-provenance stamping."""

import json
from pathlib import Path

from traust.cli import reconcile_cve_provenance as rp


def test_sequence_ratio_rescues_tokenizer_splits():
    """Real 0.457 that should have been ~1.0.

    The CVE said "no_auth", our finding said "noauth"; token-Jaccard put
    them far apart, so Jaccard alone would have dropped a true match
    (CVE-2026-18941) below the stamp floor.
    """
    s = rp.score_titles(
        "Default authentication mode is no_auth", "Default authentication mode is noauth"
    )
    assert s >= rp.AUTO_CONFIRM, s


def test_cwe_promotes_but_never_blocks():
    """CWE corroborates 80% of true matches; the other 20% are the same
    issue under a sibling weakness (RH CWE-863 vs our CWE-302/807). A
    hard gate would drop 19% of true matches including the 9.9."""
    # mid band + overlapping CWE -> promoted
    assert rp.classify(0.60, "CWE-863", ["CWE-863"]) == "confirmed"
    # mid band + disjoint CWE -> still stamped, just weaker
    assert rp.classify(0.60, "CWE-863", ["CWE-302", "CWE-807"]) == "probable"
    # high band is never demoted by a disjoint CWE
    assert rp.classify(0.90, "CWE-312", ["CWE-522"]) == "confirmed"
    # below the floor, nothing
    assert rp.classify(0.40, "CWE-863", ["CWE-863"]) is None


def _report(component, date, layer, findings):
    return {
        "component": component,
        "date": date,
        "layer": layer,
        "audit_json": f"{component}-security-audit.json",
        "findings": findings,
    }


def _cve(pub, component, title, cwe="CWE-863"):
    return {
        "public_date": pub,
        "component": component,
        "title": title,
        "severity": "important",
        "cvss3": 9.1,
        "cwe": cwe,
    }


def test_only_cves_published_after_our_audit_count():
    """A CVE published before we audited is something we read, not
    something we found."""
    finding = {"id": "FIND-001", "title": "Broker token stored cleartext", "cwes": ["CWE-863"]}
    reports = [_report("comp", "2026-06-01", None, [finding])]
    cves = {
        "CVE-1": _cve("2026-07-01", "comp", "Broker token stored cleartext"),
        "CVE-2": _cve("2026-05-01", "comp", "Broker token stored cleartext"),
    }
    got = {m["cve"] for m in rp.reconcile(reports, cves, rp.AUTO_PROBABLE)}
    assert got == {"CVE-1"}


def test_one_cve_stamps_every_release_branch_of_a_component():
    """Each branch report has its own findings and its own layer, so the
    stamp fans out — but the headline must count distinct CVEs, not rows
    (console matched 11 branch reports for one CVE)."""
    f = {"id": "FIND-001", "title": "Authenticated SSRF via /ansibletower", "cwes": ["CWE-918"]}
    reports = [_report("console", "2026-06-01", f"l{i}.json", [f]) for i in range(3)]
    cves = {"CVE-9": _cve("2026-08-01", "console", "Authenticated SSRF via /ansibletower")}
    m = rp.reconcile(reports, cves, rp.AUTO_PROBABLE)
    assert len(m) == 3
    assert len({x["cve"] for x in m}) == 1


def test_stamp_is_idempotent_and_dry_run_writes_nothing(tmp_path):
    layer = tmp_path / "x-findings-layer.json"
    layer.write_text(
        json.dumps(
            {
                "metadata": {"audit_report": "x-security-audit.json"},
                "events": [],
                "needs_review": [],
            }
        )
    )
    match = {
        "cve": "CVE-2026-66792",
        "finding_id": "FIND-002",
        "confidence": "confirmed",
        "score": 0.78,
        "layer": str(layer),
    }

    layers, refs = rp.stamp([match], tmp_path, apply=False)
    assert (layers, refs) == (1, 1)
    assert "external_refs" not in json.loads(layer.read_text())["metadata"]

    assert rp.stamp([match], tmp_path, apply=True) == (1, 1)
    meta = json.loads(layer.read_text())["metadata"]
    ref = meta["external_refs"]["FIND-002"][0]
    assert ref["system"] == "cve" and ref["id"] == "CVE-2026-66792"
    assert ref["confidence"] == "confirmed"

    # re-running changes nothing: only the clock moved
    assert rp.stamp([match], tmp_path, apply=True) == (0, 0)


def test_stamp_supersedes_when_the_match_improves(tmp_path):
    layer = tmp_path / "y-findings-layer.json"
    layer.write_text(json.dumps({"metadata": {}, "events": [], "needs_review": []}))
    weak = {
        "cve": "CVE-1",
        "finding_id": "F1",
        "confidence": "probable",
        "score": 0.6,
        "layer": str(layer),
    }
    rp.stamp([weak], tmp_path, apply=True)
    strong = {**weak, "confidence": "confirmed", "score": 0.92}
    assert rp.stamp([strong], tmp_path, apply=True) == (1, 1)
    refs = json.loads(layer.read_text())["metadata"]["external_refs"]["F1"]
    assert len(refs) == 1, "an improved match supersedes, it does not append"
    assert refs[0]["confidence"] == "confirmed"


def test_stamp_never_touches_the_audit_baseline(tmp_path):
    """Gate A15: the baseline is never written."""
    layer = tmp_path / "z-findings-layer.json"
    layer.write_text(json.dumps({"metadata": {}, "events": [], "needs_review": []}))
    audit = tmp_path / "z-security-audit.json"
    audit.write_text(json.dumps({"findings": [{"id": "F1"}]}))
    before = audit.read_bytes()
    rp.stamp(
        [
            {
                "cve": "CVE-1",
                "finding_id": "F1",
                "confidence": "confirmed",
                "score": 0.9,
                "layer": str(layer),
            }
        ],
        tmp_path,
        apply=True,
    )
    assert audit.read_bytes() == before


def test_audit_index_resolves_a_relative_root(tmp_path, monkeypatch):
    """A relative --results-root must not silently yield zero reports.

    The corpus resolver walks nothing when handed a relative path, and the
    empty result prints as "0 matches" — a no-op that reads like success.
    """
    seen = {}

    class _FakeCorpus:
        def load_resolution(self, *, results_root=None, **_kw):
            seen["root"] = results_root
            return types.SimpleNamespace(records=[])

        def report_store(self, *, results_root=None):
            return object()

        def to_ref(self, _value, *, results_root=None):
            return None

    import types
    from types import SimpleNamespace

    engine = SimpleNamespace(corpus=_FakeCorpus())
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ar").mkdir()

    rp.audit_index(Path("ar"), engine)
    assert seen["root"].is_absolute(), seen["root"]
