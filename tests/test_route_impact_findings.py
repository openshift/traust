"""Tests for traust.cli.route_impact_findings — the dependency filing
leg (lever 1c). No network; fake findings.db + baselines in tmp_path."""

import json
import sqlite3
from unittest.mock import MagicMock, patch

import fleet_sweep as fs
import pytest
from traust_engine.ledger import (
    compute_claim_hash,
    compute_event_id,
    stamp_report_reference,
)
from traust_engine.ledger.service import LedgerService as _RealLedgerService
from traust_ledger.client import LedgerClient

from traust.cli import route_impact_findings as rif


@pytest.fixture(autouse=True)
def _mock_ledger_service():
    """Patch engine.ledger.service so tests run without LAAS_TOKEN.

    ensure_layer_file delegates to the real file I/O implementation.
    submit_events replicates the SDK contract: append events, pin
    claim_hashes for event-carried findings, stamp Merkle metadata,
    stamp report reference, and atomically write the result.
    """

    def _make_service(*_args, **_kwargs):
        svc = MagicMock(spec=_RealLedgerService)
        _pending_layers: dict[str, dict] = {}

        def _ensure_layer_file(layer_path, *, shell=None):
            if layer_path.exists():
                return json.loads(layer_path.read_text(encoding="utf-8"))
            base = shell or {"events": [], "metadata": {}}
            _pending_layers[str(layer_path)] = base
            return base

        def _submit_events(layer_path, events, *, report_path=None, queue_items=None):
            if layer_path.exists():
                layer = json.loads(layer_path.read_text(encoding="utf-8"))
            else:
                layer = _pending_layers.pop(str(layer_path), {"events": [], "metadata": {}})
            existing = layer.get("events") or []
            existing_ids = {e.get("event_id") for e in existing}
            for ev in events:
                # The emitter no longer stamps event_id; the SDK computes the
                # canonical id server-side, which the stand-in reproduces.
                disp = ev.get("disposition") or {}
                eid = compute_event_id(
                    ev["source"]["ref"],
                    ev["finding_ref"],
                    disp.get("validity"),
                    disp.get("resolution"),
                )
                if eid not in existing_ids:
                    existing.append({**ev, "event_id": eid})
                    existing_ids.add(eid)
            layer["events"] = existing
            hashes = layer.setdefault("metadata", {}).setdefault("claim_hashes", {})
            for ev in events:
                finding = ev.get("finding")
                if isinstance(finding, dict) and finding.get("id"):
                    hashes.setdefault(finding["id"], compute_claim_hash(finding))
            if report_path is not None:
                stamp_report_reference(layer, str(report_path))
            layer_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
            LedgerClient(
                token="test-token",
                data_dir=str(layer_path.parent),
            ).sign(layer_path.stem)

        svc.ensure_layer_file.side_effect = _ensure_layer_file
        svc.submit_events.side_effect = _submit_events
        return svc

    mock_engine = MagicMock()
    mock_engine.ledger.service.side_effect = lambda data_dir=None: _make_service()

    orig_route = rif.route_artifact

    def _route_with_engine(*args, **kwargs):
        kwargs.setdefault("engine", mock_engine)
        return orig_route(*args, **kwargs)

    with patch.object(rif, "route_artifact", _route_with_engine):
        yield mock_engine


def _routed_finding(audit_path, layer_name=None):
    """The finding this router filed — on its EVENT since B3, not the baseline.

    Only /secure-code-audit, /secure-rpm-audit and /secure-container-audit may
    write a baseline (gate A15), so a routed dependency finding rides on its
    ledger event and build_cumulative unions it back at replay.
    """
    import json as _j
    from pathlib import Path as _P

    ap = _P(audit_path)
    lp = (
        ap.with_name(layer_name)
        if layer_name
        else ap.with_name(ap.name.replace("-security-audit.json", "-findings-layer.json"))
    )
    layer = _j.loads(lp.read_text())
    carried = [e["finding"] for e in layer.get("events", []) if e.get("finding")]
    return carried[-1]


def _mk_db(tmp_path, rows):
    db = tmp_path / "findings.db"
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE repos (repo_key TEXT, repo_url TEXT,
        report_path TEXT, report_kind TEXT, is_branch_audit INTEGER,
        audit_date TEXT)""")
    con.executemany(
        "INSERT INTO repos VALUES (?,?,?,?,?,?)",
        [
            (r["key"], r["url"], r["report"], "code-audit", 0, r.get("date", "2026-07-01"))
            for r in rows
        ],
    )
    con.commit()
    con.close()
    return db


def _mk_baseline(tmp_path, name, sha="ab12cd3" + "0" * 33, existing_ids=()):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    audit = d / f"{name}-security-audit.json"
    findings = [
        {
            "id": fid,
            "title": f"t {fid}",
            "severity": "high",
            "cwes": ["CWE-79"],
            "locations": [{"path": "a.go"}],
            "description": "d",
            "remediation": "r",
        }
        for fid in existing_ids
    ]
    audit.write_text(
        json.dumps(
            {
                "metadata": {
                    "repository": f"https://github.com/org/{name}",
                    "commit": f"{sha} (main HEAD)",
                },
                "findings": findings,
                "findings_summary": [],
                "executive_summary": {"severity_counts": {}},
            }
        )
    )
    return audit


def _artifact(tmp_path, repos, cve="CVE-2026-99999", module="github.com/lib/pq"):
    p = tmp_path / f"{cve.lower()}-impact-analysis.json"
    # REAL run_impact_analysis.py shape: advisory fields nested under
    # metadata (the 2026-07-28 bootstrap failed on a top-level fixture
    # that matched the router's assumption instead of reality)
    p.write_text(
        json.dumps(
            {
                "metadata": {
                    "cve": cve,
                    "module": module,
                    "vulnerable_range": "< v1.10.10",
                    "fixed_version": "v1.10.10",
                    "feature_description": "SQL scanning",
                    "generated_at": "2026-07-28T00:00:00Z",
                },
                "summary": {},
                "repos": repos,
            }
        )
    )
    return p


def _mk_graph(tmp_path, edges):
    """edges: list of (src, dst, rel, attrs_dict_or_None)."""
    gdb = tmp_path / "portfolio-graph.db"
    con = sqlite3.connect(gdb)
    con.execute("CREATE TABLE edges (src TEXT, dst TEXT, rel TEXT, attrs TEXT)")
    con.executemany(
        "INSERT INTO edges VALUES (?,?,?,?)",
        [(s, d, r, json.dumps(a) if a is not None else None) for s, d, r, a in edges],
    )
    con.commit()
    con.close()
    return gdb


def _repo_entry(name, classification="affected", version="v1.10.2"):
    return {
        "repo": f"repo:github.com/org/{name}",
        "products": ["p"],
        "classification": classification,
        "version": version,
        "direct": True,
        "evidence": {"evidence_level": "symbol", "l1_version_in_range": True},
    }


class TestRouting:
    def _setup(self, tmp_path, existing_ids=()):
        audit = _mk_baseline(tmp_path, "svc", existing_ids=existing_ids)
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc")])
        return audit, db, art

    def test_routes_affected_repo(self, tmp_path):
        audit_path, db, art = self._setup(tmp_path)
        stats = rif.route_artifact(
            art, db, "high", False, None, None, no_rebuild=True, dry_run=False
        )
        assert stats["routed"] == 1
        audit = json.loads(audit_path.read_text())
        layer = json.loads(audit_path.with_name("svc-findings-layer.json").read_text())
        # B3 — the BASELINE IS NOT TOUCHED. Only /secure-code-audit,
        # /secure-rpm-audit and /secure-container-audit may write one (gate
        # A15); this router's claim rides on its event.
        assert audit["findings"] == [], "route_impact_findings must not append to the baseline"
        f = layer["events"][0]["finding"]
        assert f["id"] == "SVC-ab12cd3-001"
        assert f["origin"] == "impact-analysis"
        assert f["category"] == "supply-chain"
        assert f["validation_status"] == "not_verified"
        assert "CVE-2026-99999" in f["title"]
        assert f["cwes"] == ["CWE-1395"]
        assert f["locations"][0]["path"] == "go.mod"
        assert f["fingerprint"]
        # The baseline's own summaries must be untouched too — they describe
        # the audit's claim set, and this finding is not in it.
        assert audit["executive_summary"]["severity_counts"].get("high", 0) == 0
        ev = layer["events"][0]
        assert ev["source"]["type"] == "impact_report"
        assert ev["source"]["actor"]["identity"] == "impact-analysis"
        assert ev["disposition"] == {"resolution": "open"}
        assert layer["metadata"]["claim_hashes"]["SVC-ab12cd3-001"]
        # The written layer must pass the schema gate — 'impact_report'
        # shipped in the emitter for months while missing from the
        # source_type enum, so every /dependency-watch layer failed
        # track-findings Phase 4. Never assert an emitted value without
        # schema-validating the artifact that carries it.
        import jsonschema
        from traust_contracts.paths import schema_path as _sp

        schema = json.loads(_sp("layer").read_text())
        jsonschema.validate(layer, schema)

    def test_rerun_is_noop(self, tmp_path):
        audit_path, db, art = self._setup(tmp_path)
        rif.route_artifact(art, db, "high", False, None, None, True, False)
        stats2 = rif.route_artifact(art, db, "high", False, None, None, True, False)
        assert stats2["routed"] == 0 and stats2["already_filed"] == 1
        audit = json.loads(audit_path.read_text())
        assert audit["findings"] == []
        layer = json.loads(audit_path.with_name("svc-findings-layer.json").read_text())
        # Dedupe now reads event-carried findings, so a re-run stays a no-op
        # even though nothing was written to the baseline.
        assert len(layer["events"]) == 1

    def test_numbering_continues_at_sha(self, tmp_path):
        audit_path, db, art = self._setup(
            tmp_path, existing_ids=["SVC-ab12cd3-001", "SVC-ab12cd3-002"]
        )
        rif.route_artifact(art, db, "high", False, None, None, True, False)
        layer = json.loads(audit_path.with_name("svc-findings-layer.json").read_text())
        # Numbering continues past the BASELINE's ids at that sha even though
        # the new id lives on an event.
        assert layer["events"][0]["finding"]["id"] == "SVC-ab12cd3-003"

    def test_likely_affected_gated(self, tmp_path):
        audit = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc", "likely_affected")])
        stats = rif.route_artifact(art, db, "high", False, None, None, True, False)
        assert stats["targets"] == 0
        stats = rif.route_artifact(art, db, "high", True, None, None, True, False)
        assert stats["routed"] == 1

    def test_no_baseline_listed_not_fatal(self, tmp_path):
        db = _mk_db(tmp_path, [])
        art = _artifact(tmp_path, [_repo_entry("ghost")])
        stats = rif.route_artifact(art, db, "high", False, None, None, True, False)
        assert stats["no_baseline"] == 1 and stats["routed"] == 0

    def test_nongo_ecosystem_cites_real_manifest_not_gomod(self, tmp_path):
        # pypi advisory: metadata.ecosystem drives the cited location
        audit = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit)}],
        )
        p = tmp_path / "cve-2026-pypi-impact-analysis.json"
        p.write_text(
            json.dumps(
                {
                    "metadata": {
                        "cve": "CVE-2026-2",
                        "module": "requests",
                        "ecosystem": "pypi",
                        "fixed_version": "v2.32.0",
                    },
                    "repos": [_repo_entry("svc")],
                }
            )
        )
        rif.route_artifact(p, db, "high", False, None, None, True, False)
        f = _routed_finding(audit)
        assert f["locations"][0]["path"] == "requirements.txt"

    def test_maven_ecosystem_cites_pom(self, tmp_path):
        audit = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit)}],
        )
        p = tmp_path / "cve-2026-mvn-impact-analysis.json"
        p.write_text(
            json.dumps(
                {
                    "metadata": {
                        "cve": "CVE-2026-3",
                        "module": "com.fasterxml.jackson.core:jackson-databind",
                        "ecosystem": "maven",
                        "fixed_version": "2.15.0",
                    },
                    "repos": [_repo_entry("svc")],
                }
            )
        )
        rif.route_artifact(p, db, "high", False, None, None, True, False)
        f = _routed_finding(audit)
        assert f["locations"][0]["path"] == "pom.xml"

    def test_graph_manifest_provenance_wins(self, tmp_path):
        # A `manifest` provenance path on the graph edge beats the
        # heuristic — cite the exact recorded path.
        audit_path, db, art = self._setup(tmp_path)  # module github.com/lib/pq
        gdb = _mk_graph(
            tmp_path,
            [
                (
                    "repo:github.com/org/svc",
                    "module:github.com/lib/pq",
                    "depends_on",
                    {"manifest": ["services/api/go.mod", "go.mod"]},
                ),
            ],
        )
        rif.route_artifact(art, db, "high", False, None, None, True, False, graph_db=gdb)
        f = _routed_finding(audit_path)
        # sorted-first of the two recorded paths — not the heuristic guess
        assert f["locations"][0]["path"] == "go.mod"
        # prove provenance, not heuristic: a non-root path is only
        # reachable by reading the edge attr
        assert (
            rif.manifest_from_graph(gdb, "repo:github.com/org/svc", "github.com/lib/pq", "go")
            == "go.mod"
        )

    def test_graph_manifest_nonroot_path_cited(self, tmp_path):
        audit_path, db, art = self._setup(tmp_path)
        gdb = _mk_graph(
            tmp_path,
            [
                (
                    "repo:github.com/org/svc",
                    "module:github.com/lib/pq",
                    "depends_on",
                    {"manifest": ["services/api/go.mod"]},
                ),
            ],
        )
        rif.route_artifact(art, db, "high", False, None, None, True, False, graph_db=gdb)
        f = _routed_finding(audit_path)
        assert f["locations"][0]["path"] == "services/api/go.mod"

    def test_missing_graph_db_falls_back_cleanly(self, tmp_path):
        audit_path, db, art = self._setup(tmp_path)
        rif.route_artifact(
            art, db, "high", False, None, None, True, False, graph_db=tmp_path / "does-not-exist.db"
        )
        f = _routed_finding(audit_path)
        assert f["locations"][0]["path"] == "go.mod"  # heuristic default

    def test_dry_run_writes_nothing(self, tmp_path):
        audit_path, db, art = self._setup(tmp_path)
        before = audit_path.read_text()
        stats = rif.route_artifact(art, db, "high", False, None, None, True, dry_run=True)
        assert stats["routed"] == 1
        assert audit_path.read_text() == before
        assert not audit_path.with_name("svc-findings-layer.json").exists()


class TestDerivedArtifactGuard:
    """Regression for the 2026-07-28 corruption: md-only repos' db
    report_path is the derived findings-current.json — never a filing
    target."""

    def test_findings_current_path_never_written(self, tmp_path):
        d = tmp_path / "svc"
        d.mkdir()
        cur = d / "svc-findings-current.json"
        cur.write_text(json.dumps({"metadata": {}, "findings": []}))
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(cur)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc")])
        before = cur.read_text()
        stats = rif.route_artifact(art, db, "high", False, None, None, True, False)
        assert stats.get("no_audit_json") == 1
        assert stats["routed"] == 0
        assert cur.read_text() == before
        assert not (d / "svc-findings-layer.json").exists()

    def test_findings_current_swapped_for_sibling_audit(self, tmp_path):
        audit = _mk_baseline(tmp_path, "svc")
        cur = audit.with_name("svc-findings-current.json")
        cur.write_text(json.dumps({"metadata": {}, "findings": []}))
        before_cur = cur.read_text()
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(cur)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc")])
        stats = rif.route_artifact(art, db, "high", False, None, None, True, False)
        assert stats["routed"] == 1
        # The router resolved the SIBLING audit rather than the derived
        # findings-current it was handed, and filed against that audit's layer.
        assert _routed_finding(audit)["origin"] == "impact-analysis"
        assert json.loads(audit.read_text())["findings"] == [], (
            "the sibling baseline must not be appended to either"
        )
        assert cur.read_text() == before_cur  # derived file untouched


class TestArtifactShapes:
    def test_top_level_fallback_accepted(self, tmp_path):
        audit = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit)}],
        )
        p = tmp_path / "flat-impact-analysis.json"
        p.write_text(
            json.dumps(
                {
                    "cve": "CVE-2026-1",
                    "module": "m",
                    "fixed_version": "v2",
                    "repos": [_repo_entry("svc")],
                }
            )
        )
        stats = rif.route_artifact(p, db, "high", False, None, None, True, False)
        assert stats["routed"] == 1


class TestHelpers:
    def test_manifest_for_module(self):
        assert rif.manifest_for_module("github.com/lib/pq") == "go.mod"
        assert rif.manifest_for_module("k8s.io/client-go") == "go.mod"
        assert rif.manifest_for_module("lodash") == "package.json"

    def test_manifest_for_module_by_ecosystem(self):
        # advisory ecosystem drives the location, overriding the guess
        assert rif.manifest_for_module("requests", "pypi") == "requirements.txt"
        assert rif.manifest_for_module("g:a", "maven") == "pom.xml"
        assert rif.manifest_for_module("serde", "cargo") == "Cargo.toml"
        assert rif.manifest_for_module("rails", "ruby") == "Gemfile"
        assert rif.manifest_for_module("Newtonsoft.Json", "nuget") == "*.csproj"
        assert rif.manifest_for_module("nginx", "docker") == "Dockerfile"
        # Go stays go.mod even with an explicit ecosystem
        assert rif.manifest_for_module("github.com/lib/pq", "go") == "go.mod"
        # ecosystem-less non-Go guesses: maven coordinate, bare npm token
        assert rif.manifest_for_module("com.google.guava:guava") == "pom.xml"
        assert rif.manifest_for_module("@babel/core") == "package.json"

    def test_manifest_from_graph_absent_is_none(self, tmp_path):
        assert rif.manifest_from_graph(None, "repo:x/y", "m", "go") is None
        assert rif.manifest_from_graph(tmp_path / "nope.db", "repo:x/y", "m", "npm") is None

    def test_repo_url_from_id(self):
        assert rif.repo_url_from_id("repo:github.com/a/b") == "https://github.com/a/b"
        assert rif.repo_url_from_id("weird") is None

    def test_slug_reuses_baseline_convention(self, tmp_path):
        audit = {"findings": [{"id": "MYSLUG-abcdef0-004"}]}
        assert rif.slug_for(audit, "https://github.com/x/whatever") == "MYSLUG"
        assert rif.slug_for({"findings": []}, "https://github.com/x/my-repo") == "MY_REPO"


# ---------------------------------------------------------------------------
# fleet_sweep (bootstrap mode) — pure functions, no network
# ---------------------------------------------------------------------------


class TestFleetSweep:
    def test_dedupe_by_cve_prefers_banded_record(self):
        details = {
            "GO-2026-1": {"aliases": ["CVE-2026-1"], "database_specific": {}},
            "GHSA-x": {"aliases": ["CVE-2026-1"], "database_specific": {"severity": "CRITICAL"}},
        }
        by = fs.dedupe_by_cve(details)
        assert by["CVE-2026-1"][0] == "GHSA-x"

    def test_sev_band_moderate_maps_medium(self):
        assert fs.sev_band({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
        assert fs.sev_band({}) == "UNKNOWN"

    def test_fixed_range(self):
        v = {
            "affected": [
                {
                    "package": {"name": "m"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "v1.2.3"}]}],
                }
            ]
        }
        assert fs.fixed_range(v, "m") == ("0", "v1.2.3")
        assert fs.fixed_range(v, "other") == (None, None)

    def test_worklist_staging_by_cap(self):
        d = {
            "aliases": ["CVE-2026-9"],
            "summary": "s",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"name": "m"}, "ranges": [{"events": [{"fixed": "v2"}]}]}],
        }
        by_cve = {"CVE-2026-9": ("GHSA-y", d)}
        hits = {"GHSA-y": {("m", "v1")}}
        pairs = {("m", "v1"): {f"repo:r{i}" for i in range(5)}}
        rows, _rej = fs.build_worklist(by_cve, hits, pairs, min_rank=4, deep_cap=100)
        assert rows[0]["commands"][0]["deep"] is True
        assert rows[0]["commands"][0]["route_argv"]
        rows, _rej = fs.build_worklist(by_cve, hits, pairs, min_rank=4, deep_cap=3)
        assert rows[0]["commands"][0]["deep"] is False
        assert "--skip-scan" in rows[0]["commands"][0]["impact_argv"]
        assert rows[0]["commands"][0]["route_argv"] is None

    def test_min_severity_filters(self):
        d = {"aliases": ["CVE-2026-8"], "database_specific": {"severity": "LOW"}, "affected": []}
        rows, _rej = fs.build_worklist({"CVE-2026-8": ("x", d)}, {}, {}, min_rank=4, deep_cap=100)
        assert rows == []


class TestB3EndToEnd:
    """The routed finding must be VISIBLE after the union, not just recorded.

    B3 removes the baseline append; if build_cumulative did not union
    event-carried findings back in, this router would file findings that no
    dashboard could ever see — tenet 5, wrongly dismissing silently deletes
    real risk. This test is the guard on that whole chain.
    """

    def test_routed_finding_appears_in_the_cumulative_projection(self, tmp_path):
        from traust.cli.build_cumulative import build_cumulative

        audit_path = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit_path)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc")])
        stats = rif.route_artifact(
            art, db, "high", False, None, None, no_rebuild=True, dry_run=False
        )
        assert stats["routed"] == 1

        audit = json.loads(audit_path.read_text())
        layer = json.loads(audit_path.with_name("svc-findings-layer.json").read_text())
        assert audit["findings"] == []  # baseline untouched
        audit.setdefault("title", "Security Assessment — svc")

        report = build_cumulative(
            audit, layer, "svc-findings-layer.json", "2026-08-17T12:00:00+00:00"
        )
        ids = {f["id"] for f in report["findings"]}
        assert "SVC-ab12cd3-001" in ids, (
            "a routed dependency finding must be visible in the projection"
        )
        f = next(x for x in report["findings"] if x["id"] == "SVC-ab12cd3-001")
        assert f["origin"] == "impact-analysis"
        assert f["disposition"]["resolution"] == "open"

    def test_claim_pin_verifies_against_the_event_carried_finding(self, tmp_path):
        from traust.cli.build_cumulative import verify_claim_hashes

        audit_path = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit_path)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc")])
        rif.route_artifact(art, db, "high", False, None, None, True, False)
        audit = json.loads(audit_path.read_text())
        layer = json.loads(audit_path.with_name("svc-findings-layer.json").read_text())
        # The router pins the claim; the verifier must resolve it via the event
        # rather than reporting it missing from the audit report.
        assert layer["metadata"]["claim_hashes"]["SVC-ab12cd3-001"]
        errors, _warnings = verify_claim_hashes(audit, layer)
        assert not any("missing from the audit report" in e for e in errors), errors


class TestLayerIsStamped:
    def test_written_layer_carries_a_merkle_root_without_rebuild(self, tmp_path):
        """This router was the only layer writer that never stamped.

        It relied on rebuild_cumulative(); with --no-rebuild it left a stale
        root, which traust-ledger v0.1.3 made an ERROR rather than a warning.
        """
        from traust_engine.ledger import Severity, verify_merkle_integrity

        audit_path = _mk_baseline(tmp_path, "svc")
        db = _mk_db(
            tmp_path,
            [{"key": "p/svc/svc", "url": "https://github.com/org/svc", "report": str(audit_path)}],
        )
        art = _artifact(tmp_path, [_repo_entry("svc")])
        rif.route_artifact(art, db, "high", False, None, None, no_rebuild=True, dry_run=False)
        layer = json.loads(audit_path.with_name("svc-findings-layer.json").read_text())
        assert layer["metadata"].get("merkle_root"), "layer must be stamped"
        assert layer["metadata"].get("leaf_format") == 2
        errs = [f.message for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]
        assert errs == [], errs
