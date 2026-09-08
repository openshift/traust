"""Tests for traust.ops.cve_replay_monitor — standing CVE-replay FN monitor."""

import json
import shutil
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
from traust.context import load_engine
from traust.ops import cve_replay_monitor as crm

mon = crm


def _engine_for_ws(tmp_path, ws, monkeypatch):
    home = tmp_path / "cfg"
    home.mkdir(exist_ok=True)
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "workspace": str(ws),
                "analysis_results": str(ws / "analysis-results"),
                "progress_tracker": str(ws / "progress-tracker"),
            }
        ),
        encoding="utf-8",
    )
    fixture = Path(__file__).parent / "fixtures" / "config"
    for name in fixture.iterdir():
        if name.is_file():
            shutil.copy2(name, home / name.name)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    return load_engine()


# ------------------------------------------------------------- fixtures


def _audit_report(
    repo_url="https://github.com/example/widget", finding_extra="", negative_extra=""
):
    return {
        "title": "widget security audit",
        "metadata": {"repository": repo_url, "commit": "deadbeef" * 5},
        "findings": [
            {
                "id": "FIND-001",
                "title": "TLS 1.0 permitted" + finding_extra,
                "severity": "medium",
                "description": "Outbound client allows TLS 1.0." + finding_extra,
                "locations": [{"path": "pkg/client/tls.go", "lines": "10-20"}],
            }
        ],
        "negative_results": [
            {
                "area": "Hardcoded secrets",
                "result": "No live credentials found." + negative_extra,
            }
        ],
    }


def _mk_workspace(tmp_path, report=None, base="widget"):
    """Fixture workspace: analysis-results/findings/<prod>/<repo>/... plus
    empty progress-tracker tree."""
    ws = tmp_path / "ws"
    repo_dir = ws / "analysis-results" / "findings" / "prod" / "widget"
    repo_dir.mkdir(parents=True)
    (repo_dir / f"{base}-security-audit.json").write_text(
        json.dumps(report or _audit_report()), encoding="utf-8"
    )
    (ws / "progress-tracker" / "metrics" / "trends").mkdir(parents=True)
    return ws


def _osv_vuln(
    vuln_id="GHSA-xxxx-yyyy-zzzz",
    aliases=("CVE-2026-11111",),
    published="2026-07-20",
    imports=None,
    severity="HIGH",
):
    v = {
        "id": vuln_id,
        "aliases": list(aliases),
        "published": f"{published}T10:00:00Z",
        "summary": "widget parser vulnerability",
        "database_specific": {"severity": severity},
        "affected": [
            {
                "package": {"name": "github.com/example/widget", "ecosystem": "Go"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            }
        ],
    }
    if imports:
        v["affected"][0]["ecosystem_specific"] = {"imports": imports}
    return v


def _run(ws, argv_extra=(), *, monkeypatch=None, tmp_path=None):
    if monkeypatch is not None and tmp_path is not None:
        _engine_for_ws(tmp_path, ws, monkeypatch)
    rc = mon.main(["--workspace-root", str(ws), *argv_extra])
    assert rc == 0
    return rc


def _trends_rows(ws):
    p = ws / mon.TRENDS_REL
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _queue_doc(ws):
    p = ws / mon.QUEUE_REL
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


# ----------------------------------------------------------- hit-check


def test_classify_id_match_detected():
    report = _audit_report(finding_extra=" tracked as CVE-2026-11111 upstream")
    idx = {"ids": {"CVE-2026-11111"}, "text": json.dumps(report).lower()}
    verdict, basis = mon.classify({"CVE-2026-11111", "GHSA-XXXX-YYYY-ZZZZ"}, [], idx)
    assert verdict == "detected"
    assert "CVE-2026-11111" in basis


def test_classify_negative_results_id_match(tmp_path):
    report = _audit_report(negative_extra=" CVE-2026-11111 checked: fix already present.")
    p = tmp_path / "r-security-audit.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    idx = mon.report_index(p)
    assert "CVE-2026-11111" in idx["ids"]
    verdict, _ = mon.classify({"CVE-2026-11111"}, [], idx)
    assert verdict == "detected"


def test_classify_area_match_unclear(tmp_path):
    p = tmp_path / "r-security-audit.json"
    p.write_text(json.dumps(_audit_report()), encoding="utf-8")
    idx = mon.report_index(p)
    verdict, basis = mon.classify({"CVE-2026-22222"}, ["pkg/client/tls.go"], idx)
    assert verdict == "unclear"
    assert "area-match" in basis


def test_classify_no_match_missed(tmp_path):
    p = tmp_path / "r-security-audit.json"
    p.write_text(json.dumps(_audit_report()), encoding="utf-8")
    idx = mon.report_index(p)
    verdict, _ = mon.classify({"CVE-2026-22222"}, ["cmd/otherbin"], idx)
    assert verdict == "missed"


def test_advisory_areas_strips_module_root():
    v = _osv_vuln(imports=[{"path": "github.com/example/widget/pkg/parser", "symbols": ["Decode"]}])
    areas = mon.advisory_areas(v)
    assert "pkg/parser" in areas
    assert "Decode" in areas
    assert "github.com/example/widget/pkg/parser" not in areas


# ----------------------------------------------------------- discovery


def test_corpus_discovery_fixture_tree(tmp_path, monkeypatch):
    ws = _mk_workspace(tmp_path)
    engine = _engine_for_ws(tmp_path, ws, monkeypatch)
    recs = mon.discover(ws / "analysis-results", engine)
    hits = [r for r in recs if r["slug"] == "widget"]
    assert len(hits) == 1
    assert hits[0]["repo_url"] == "https://github.com/example/widget"
    assert hits[0]["report"].endswith("widget-security-audit.json")
    assert hits[0]["ref"] is None


def test_fallback_discovery_matches_identity_rules(tmp_path):
    ws = _mk_workspace(tmp_path, base="widget__release-1.2")
    recs = mon.discover(ws / "analysis-results", use_corpus=False)
    assert len(recs) == 1
    assert recs[0]["slug"] == "widget"  # branch ref split off
    assert recs[0]["ref"] == "release-1.2"
    assert recs[0]["repo_url"] == "https://github.com/example/widget"


def test_osv_identity():
    assert mon.osv_identity("https://github.com/openshift/router") == (
        "github.com/openshift/router",
        "Go",
    )
    assert mon.osv_identity("https://gitlab.example.com/x/y") is None  # no OSV surface
    assert mon.osv_identity(None) is None


# ------------------------------------------------------------ backfill

BACKFILL = {
    "campaign": "sxs-2026-07 Phase-0a",
    "rows": [
        {
            "slug": "widget",
            "cve": "CVE-2025-1000",
            "ghsa": None,
            "published": "2025-03-01",
            "severity": "high",
            "present_at_audit": True,
            "audit_verdict": "missed",
            "summary": "missed vuln",
            "evidence": "not in report",
        },
        {
            "slug": "widget",
            "cve": "CVE-2025-2000",
            "ghsa": "GHSA-aaaa-bbbb-cccc",
            "published": "2025-04-01",
            "severity": "critical",
            "present_at_audit": True,
            "audit_verdict": "detected",
            "summary": "caught vuln",
            "evidence": "FIND-003 names it",
        },
        {
            "slug": "gadget",
            "cve": None,
            "ghsa": "GHSA-dddd-eeee-ffff",
            "published": "2025-05-01",
            "severity": "high",
            "present_at_audit": False,
            "audit_verdict": "unclear",
            "summary": "fixed before audit",
            "evidence": "post-fix ref",
        },
        {
            "slug": "gadget",
            "cve": "CVE-2025-3000",
            "ghsa": None,
            "published": "2025-06-01",
            "severity": "medium",
            "present_at_audit": True,
            "audit_verdict": "unclear",
            "summary": "ambiguous",
            "evidence": "area overlaps",
        },
    ],
}


def test_backfill_ingests_and_is_idempotent(tmp_path, capsys, monkeypatch):
    ws = _mk_workspace(tmp_path)
    cand = tmp_path / "candidates.json"
    cand.write_text(json.dumps(BACKFILL), encoding="utf-8")

    _run(ws, ["--backfill", str(cand)])
    trends = _trends_rows(ws)
    queue = _queue_doc(ws)

    # trends: missed rows only
    assert len(trends) == 1
    assert trends[0]["repo"] == "widget"
    assert trends[0]["advisory"] == "CVE-2025-1000"
    assert trends[0]["verdict"] == "missed"
    assert trends[0]["severity"] == "high"
    # queue: missed + unclear-not-adjudicated-absent; detected and
    # absent-at-audit unclear rows excluded
    assert queue["role"].startswith("QUEUE")
    assert "HUMAN-GATED" in queue["role"]
    got = {(r["repo"], r["advisory"]) for r in queue["rows"]}
    assert got == {("widget", "CVE-2025-1000"), ("gadget", "CVE-2025-3000")}
    # adjudications carried verbatim
    assert all(r["present_at_audit"] is True for r in queue["rows"])

    # -- re-run: no duplicates anywhere
    _run(ws, ["--backfill", str(cand)])
    assert len(_trends_rows(ws)) == 1
    assert len(_queue_doc(ws)["rows"]) == 2


# --------------------------------------------------------- incremental


def _patch_osv(monkeypatch, vulns):
    calls = []

    def fake_post(url, payload, timeout):
        calls.append(payload)
        return {"vulns": vulns}

    monkeypatch.setattr(mon, "_post_json", fake_post)
    return calls


def test_incremental_miss_flows_to_outputs_and_watermark(tmp_path, monkeypatch):
    ws = _mk_workspace(tmp_path)
    state_path = ws / "state.json"
    calls = _patch_osv(monkeypatch, [_osv_vuln()])

    _run(
        ws,
        ["--state", str(state_path), "--since", "2026-07-01"],
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )

    assert calls and calls[0]["package"]["name"] == "github.com/example/widget"
    trends = _trends_rows(ws)
    assert len(trends) == 1
    row = trends[0]
    assert row["repo"] == "widget"
    assert row["advisory"] == "CVE-2026-11111"  # CVE alias preferred
    assert row["verdict"] == "missed"
    assert row["severity"] == "high"
    assert row["present_at_audit"] is None  # human adjudication
    queue = _queue_doc(ws)
    assert len(queue["rows"]) == 1

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["watermarks"]["Go"] == "2026-07-20"  # max published seen
    assert state["last_network"] == "ok"


def test_incremental_second_run_no_duplicates(tmp_path, monkeypatch):
    ws = _mk_workspace(tmp_path)
    state_path = ws / "state.json"
    _patch_osv(monkeypatch, [_osv_vuln()])
    _run(
        ws,
        ["--state", str(state_path), "--since", "2026-07-01"],
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    # second run: watermark now 2026-07-20, same advisory filtered out
    _run(ws, ["--state", str(state_path)], monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert len(_trends_rows(ws)) == 1
    assert len(_queue_doc(ws)["rows"]) == 1


def test_incremental_detected_not_filed(tmp_path, monkeypatch):
    report = _audit_report(finding_extra=" upstream advisory CVE-2026-11111")
    ws = _mk_workspace(tmp_path, report=report)
    state_path = ws / "state.json"
    _patch_osv(monkeypatch, [_osv_vuln()])
    _run(
        ws,
        ["--state", str(state_path), "--since", "2026-07-01"],
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    assert _trends_rows(ws) == []
    queue = _queue_doc(ws)
    assert queue is None or queue["rows"] == []


def test_incremental_area_match_unclear_queued_not_trended(tmp_path, monkeypatch):
    ws = _mk_workspace(tmp_path)
    state_path = ws / "state.json"
    vuln = _osv_vuln(
        imports=[{"path": "github.com/example/widget/pkg/client", "symbols": ["tls.go"]}]
    )
    _patch_osv(monkeypatch, [vuln])
    _run(
        ws,
        ["--state", str(state_path), "--since", "2026-07-01"],
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    assert _trends_rows(ws) == []  # unclear ≠ miss
    queue = _queue_doc(ws)
    assert len(queue["rows"]) == 1
    assert queue["rows"][0]["verdict"] == "unclear"


def test_watermark_filters_old_advisories(tmp_path, monkeypatch):
    ws = _mk_workspace(tmp_path)
    state_path = ws / "state.json"
    state_path.write_text(
        json.dumps({"artifact": "cve-replay-monitor-state", "watermarks": {"Go": "2026-07-21"}}),
        encoding="utf-8",
    )
    _patch_osv(monkeypatch, [_osv_vuln(published="2026-07-20")])
    _run(ws, ["--state", str(state_path)], monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert _trends_rows(ws) == []
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["watermarks"]["Go"] == "2026-07-21"  # never regresses


def test_network_error_preserves_state_and_exits_zero(tmp_path, monkeypatch, capsys):
    ws = _mk_workspace(tmp_path)
    state_path = ws / "state.json"
    original = {"artifact": "cve-replay-monitor-state", "watermarks": {"Go": "2026-07-01"}}
    state_path.write_text(json.dumps(original), encoding="utf-8")

    def boom(url, payload, timeout):
        raise OSError("connection refused")

    _engine_for_ws(tmp_path, ws, monkeypatch)
    monkeypatch.setattr(mon, "_post_json", boom)
    rc = mon.main(["--workspace-root", str(ws), "--state", str(state_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "network: error" in out
    assert "NOT advanced" in out
    # state byte-identical: not advanced, not rewritten
    assert json.loads(state_path.read_text(encoding="utf-8")) == original


def test_offline_never_touches_network_or_state(tmp_path, monkeypatch):
    ws = _mk_workspace(tmp_path)
    state_path = ws / "state.json"

    def explode(*a, **kw):  # pragma: no cover
        raise AssertionError("network touched under --offline")

    _engine_for_ws(tmp_path, ws, monkeypatch)
    monkeypatch.setattr(mon, "_post_json", explode)
    rc = mon.main(["--workspace-root", str(ws), "--state", str(state_path), "--offline"])
    assert rc == 0
    assert not state_path.exists()


def test_bad_backfill_input_exits_one(tmp_path, capsys):
    ws = _mk_workspace(tmp_path)
    rc = mon.main(["--workspace-root", str(ws), "--backfill", str(tmp_path / "nope.json")])
    assert rc == 1


def test_backfill_then_incremental_dedupes_by_alias(tmp_path, monkeypatch):
    """An advisory backfilled under its CVE id must not re-file when the
    incremental pass sees it under its GHSA id (alias-set dedup)."""
    ws = _mk_workspace(tmp_path)
    cand = tmp_path / "candidates.json"
    cand.write_text(
        json.dumps(
            {
                "campaign": "0a",
                "rows": [
                    {
                        "slug": "widget",
                        "cve": "CVE-2026-11111",
                        "ghsa": "GHSA-xxxx-yyyy-zzzz",
                        "published": "2026-07-20",
                        "severity": "high",
                        "present_at_audit": True,
                        "audit_verdict": "missed",
                        "summary": "s",
                        "evidence": "e",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    _run(ws, ["--backfill", str(cand)])
    state_path = ws / "state.json"
    _patch_osv(monkeypatch, [_osv_vuln()])
    _run(
        ws,
        ["--state", str(state_path), "--since", "2026-07-01"],
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    assert len(_trends_rows(ws)) == 1
    assert len(_queue_doc(ws)["rows"]) == 1
