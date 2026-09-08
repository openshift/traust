#!/usr/bin/env python3
"""Tests for explicit ref provenance (branch-awareness Phase 0):

1. Schema layer — optional metadata.ref/ref_kind accepted, bad values
   rejected, omission stays valid (all existing reports keep validating).
2. Resolver layer — corpus.py prefers declared metadata.ref over slug
   parsing; a fixture mimicking the legacy layout (no report declares
   metadata.ref) produces byte-identical ref semantics to the slug rules,
   so census/exec numbers cannot move.
3. Per-ref breakdown (branch-awareness Phase 1) — additive
   per-ref counter in aggregates(), sourced from slug and declared refs.
4. Backfill tool — traust.migrations.backfill_report_refs dry-run/apply
   round-trip in a tmp tree: dry-run writes nothing, apply stamps
   slug-derived refs once, re-runs are no-ops, HEAD reports and symlinks
   are untouched.
"""

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
from traust_engine.corpus import resolver as corpus

ROOT = Path(__file__).resolve().parents[1]


def _load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def _load_schema(name):
    from traust_contracts.paths import schema_path as _sp

    return json.loads(_sp(name).read_text(encoding="utf-8"))


def _errors(schema, doc):
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [e.message for e in validator.iter_errors(doc)]


def _report():
    """Minimal report that passes schema/report.schema.json."""
    return {
        "title": "Security Assessment — Ref Provenance Test",
        "metadata": {
            "date": "2026-07-21",
            "scope": "First-party Go source on the release branch",
        },
        "executive_summary": {
            "prose": (
                "One finding on the token handler of the audited release "
                "branch; provenance fields under test carry the ref."
            ),
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {
                "level": "critical",
                "definition": "Remote unauthenticated compromise of the control plane.",
            },
            {
                "level": "high",
                "definition": "Authenticated user escalates beyond granted privileges.",
            },
            {
                "level": "medium",
                "definition": "Requires elevated prerequisites or enables denial of service.",
            },
            {"level": "low", "definition": "Hardening gap with no direct exploitability."},
        ],
        "findings": [
            {
                "id": "TEST-001",
                "title": "Token logged at debug level",
                "severity": "high",
                "cwes": ["CWE-532"],
                "locations": [{"path": "pkg/auth/token.go", "lines": "10-20"}],
                "description": (
                    "The bearer token is written to the debug log on every "
                    "request, exposing credentials to log readers."
                ),
                "remediation": "Redact the token before logging.",
            },
        ],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 1, "finding_ids": ["TEST-001"]},
            {"severity": "medium", "count": 0, "finding_ids": []},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "P0",
                "action": "Redact bearer tokens from debug logging",
                "addresses": ["TEST-001"],
            },
        ],
    }


def _cca_report():
    """Minimal report that passes schema/cloud-config-audit.schema.json."""
    return {
        "title": "Cloud Config Audit — Ref Provenance Test",
        "metadata": {
            "target": "test-iac",
            "assessment_mode": "declared",
            "harness_version": "0.122.0-abc1234",
            "checkov_version": "3.2.0",
            "facts_ref": "test-iac-cloud-facts.json",
            "facts_snapshot_id": "0123456789abcdef",
            "deterministic_steps": [
                {"tool": "checkov", "invocation": "run_checkov.py --target-dir ."},
            ],
        },
        "summary": {
            "facts_total": 1,
            "confirmed": 1,
            "suppressed": 0,
            "needs_review": 0,
            "gaps": 0,
        },
        "findings": [
            {
                "id": "CCA-test-iac-001",
                "fact_ids": ["cca-0123456789ab"],
                "framework": "kubernetes",
                "provider": "kubernetes",
                "check_id": "CKV_K8S_TEST",
                "title": "No default-deny NetworkPolicy",
                "severity": "high",
                "status": "confirmed",
                "rationale": "Tenant-reachable path without default-deny.",
            },
        ],
    }


# ---------------------------------------------------------------------------
# 1. schema layer
# ---------------------------------------------------------------------------


class TestSchemaRefFields:
    REPORT_SCHEMA = _load_schema("report")
    CCA_SCHEMA = _load_schema("cloud-config-audit")

    @pytest.mark.parametrize("kind", ["branch", "tag", "default", "stream"])
    def test_report_accepts_ref_and_every_ref_kind(self, kind):
        r = _report()
        r["metadata"]["ref"] = "release-4.19"
        r["metadata"]["ref_kind"] = kind
        assert _errors(self.REPORT_SCHEMA, r) == []

    def test_report_omission_stays_valid(self):
        assert _errors(self.REPORT_SCHEMA, _report()) == []

    def test_report_rejects_bad_ref_kind(self):
        r = _report()
        r["metadata"]["ref"] = "release-4.19"
        r["metadata"]["ref_kind"] = "detached"
        assert _errors(self.REPORT_SCHEMA, r)

    def test_report_rejects_empty_ref(self):
        r = _report()
        r["metadata"]["ref"] = ""
        assert _errors(self.REPORT_SCHEMA, r)

    def test_cloud_config_accepts_ref_fields(self):
        r = _cca_report()
        r["metadata"]["ref"] = "main"
        r["metadata"]["ref_kind"] = "default"
        assert _errors(self.CCA_SCHEMA, r) == []

    def test_cloud_config_omission_stays_valid(self):
        assert _errors(self.CCA_SCHEMA, _cca_report()) == []

    def test_cloud_config_rejects_bad_ref_kind(self):
        r = _cca_report()
        r["metadata"]["ref_kind"] = "HEAD"
        assert _errors(self.CCA_SCHEMA, r)

    def test_ref_kind_enum_identical_across_schemas(self):
        report_enum = self.REPORT_SCHEMA["$defs"]["metadata"]["properties"]["ref_kind"]["enum"]
        cca_enum = self.CCA_SCHEMA["properties"]["metadata"]["properties"]["ref_kind"]["enum"]
        verification = _load_schema("verification")
        ver_enum = verification["$defs"]["verification_metadata"]["properties"]["ref_kind"]["enum"]
        assert report_enum == cca_enum == ver_enum == list(corpus.REF_KINDS)


# ---------------------------------------------------------------------------
# 2. resolver layer
# ---------------------------------------------------------------------------

FIXTURE_CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: Example}
"""


def _write_report(dirpath: Path, base: str, metadata: dict | None = None):
    dirpath.mkdir(parents=True, exist_ok=True)
    md = {"repository": f"https://github.com/org/{base}"}
    md.update(metadata or {})
    path = dirpath / f"{base}-security-audit.json"
    path.write_text(json.dumps({"metadata": md, "findings": []}, indent=2) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "corpus-config.yaml"
    p.write_text(FIXTURE_CONFIG, encoding="utf-8")
    return corpus.load_config(p)


def test_declared_ref_preferred_over_slug(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    # slug says release-4.19, metadata declares release-4.20 -> metadata wins
    _write_report(
        ar / "findings" / "prodA" / "repo1__release-4.19",
        "repo1__release-4.19",
        {"ref": "release-4.20", "ref_kind": "branch"},
    )
    res = corpus.resolve(ar, cfg)
    (rec,) = res.records
    assert rec.ref == "release-4.20"
    assert rec.ref_kind == "branch"
    assert rec.ref_source == "metadata"
    assert rec.is_branch_audit
    assert rec.base_slug == "repo1"  # identity collapse stays slug-driven


def test_declared_default_ref_is_not_branch_audit(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    _write_report(
        ar / "findings" / "prodA" / "repo2", "repo2", {"ref": "main", "ref_kind": "default"}
    )
    res = corpus.resolve(ar, cfg)
    (rec,) = res.records
    assert (rec.ref, rec.ref_kind, rec.ref_source) == ("main", "default", "metadata")
    assert not rec.is_branch_audit


def test_declared_stream_ref_is_not_branch_audit(tmp_path, cfg):
    # rpm profile: dist-git streams are mainline deliverables — a c10s
    # report must stay in the HEAD cuts, not vanish as a branch re-audit
    ar = tmp_path / "analysis-results"
    _write_report(
        ar / "findings" / "c10s" / "389-ds-base",
        "389-ds-base",
        {"ref": "c10s", "ref_kind": "stream"},
    )
    res = corpus.resolve(ar, cfg)
    (rec,) = res.records
    assert (rec.ref, rec.ref_kind, rec.ref_source) == ("c10s", "stream", "metadata")
    assert not rec.is_branch_audit


def test_declared_branch_without_slug_suffix_counts_as_branch(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    _write_report(
        ar / "findings" / "prodA" / "repo3", "repo3", {"ref": "stable-2.x", "ref_kind": "branch"}
    )
    res = corpus.resolve(ar, cfg)
    (rec,) = res.records
    assert rec.ref == "stable-2.x" and rec.is_branch_audit


def test_legacy_layout_semantics_unchanged(tmp_path, cfg):
    """Fixture mimicking the legacy corpus (no report declares
    metadata.ref): every ref must resolve exactly as the slug rules do
    today, so census/exec numbers cannot move (ref-provenance invariant)."""
    ar = tmp_path / "analysis-results"
    _write_report(ar / "findings" / "prodA" / "repo1", "repo1")
    _write_report(ar / "findings" / "prodA" / "repo1__release-4.19", "repo1__release-4.19")
    # dir-carried ref, org__repo name, and a '"ref"' probe false positive
    _write_report(ar / "findings" / "prodA" / "repo2__openshift-5.0", "repo2")
    _write_report(ar / "findings" / "prodA" / "quay__enhancements", "quay__enhancements")
    p = _write_report(ar / "findings" / "prodA" / "repo4", "repo4")
    doc = json.loads(p.read_text())
    doc["findings"] = [{"description": 'the "ref" key is discussed here'}]
    p.write_text(json.dumps(doc), encoding="utf-8")

    res = corpus.resolve(ar, cfg)
    assert all(r.ref_source != "metadata" for r in res.records)
    by_base = {r.base: r for r in res.records}
    assert by_base["repo1"].ref is None
    assert by_base["repo1__release-4.19"].ref == "release-4.19"
    assert by_base["repo1__release-4.19"].is_branch_audit
    assert by_base["repo1__release-4.19"].ref_source == "slug"
    assert by_base["repo2"].ref == "openshift-5.0"  # dir-carried
    assert by_base["quay__enhancements"].ref is None
    assert by_base["repo4"].ref is None  # probe FP tolerated

    agg = corpus.aggregates(res)
    f = agg["trees"]["findings"]
    assert f["reports"] == 5
    assert f["branch_reaudits"] == 2
    assert f["unique_base_slugs"] == 4


def test_declared_ref_without_kind_is_not_branch_audit(tmp_path, cfg):
    """Writers stamp both; a lone ref is provenance, not a branch claim."""
    ar = tmp_path / "analysis-results"
    _write_report(ar / "findings" / "prodA" / "repo5", "repo5", {"ref": "release-4.19"})
    res = corpus.resolve(ar, cfg)
    (rec,) = res.records
    assert rec.ref == "release-4.19" and rec.ref_kind is None
    assert not rec.is_branch_audit


def test_declared_ref_survives_manifest_roundtrip(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    _write_report(
        ar / "findings" / "prodA" / "repo1__release-4.19",
        "repo1__release-4.19",
        {"ref": "release-4.19", "ref_kind": "branch"},
    )
    res = corpus.resolve(ar, cfg)
    man = corpus.build_manifest(res, cfg)
    (rec,) = man["records"]
    assert rec["ref"] == "release-4.19"
    assert rec["ref_kind"] == "branch"
    assert rec["ref_source"] == "metadata"
    assert rec["is_branch_audit"] is True


# ---------------------------------------------------------------------------
# 3. per-ref breakdown (branch-awareness Phase 1)
# ---------------------------------------------------------------------------


def test_per_ref_counter_mixes_slug_and_declared(tmp_path, cfg):
    """aggregates() gains an additive per-ref counter sourced from BOTH
    legacy slug refs and declared metadata.ref; every pre-existing
    aggregate stays exactly as before."""
    ar = tmp_path / "analysis-results"
    # HEAD report — carries no ref, must not appear in the counter
    _write_report(ar / "findings" / "prodA" / "repo1", "repo1")
    # two legacy slug refs sharing one branch
    _write_report(ar / "findings" / "prodA" / "repo1__release-4.19", "repo1__release-4.19")
    _write_report(ar / "findings" / "prodA" / "repo2__release-4.19", "repo2__release-4.19")
    # declared branch beyond the slug whitelist
    _write_report(
        ar / "findings" / "prodA" / "repo3", "repo3", {"ref": "stable-2.x", "ref_kind": "branch"}
    )
    # declared default checkout — a ref, but NOT a branch re-audit
    _write_report(
        ar / "findings" / "prodA" / "repo4", "repo4", {"ref": "main", "ref_kind": "default"}
    )

    res = corpus.resolve(ar, cfg)
    agg = corpus.aggregates(res)
    f = agg["trees"]["findings"]
    expected = {"main": 1, "release-4.19": 2, "stable-2.x": 1}
    assert f["refs"] == expected
    assert agg["totals"]["refs"] == expected
    # pre-existing numbers untouched by the additive key
    assert f["reports"] == 5
    assert f["branch_reaudits"] == 3  # 2 slug + declared branch only
    assert f["head_reports"] == 2  # repo1 + declared-default repo4
    assert f["unique_base_slugs"] == 4


def test_per_ref_counter_empty_when_no_refs(tmp_path, cfg):
    ar = tmp_path / "analysis-results"
    _write_report(ar / "findings" / "prodA" / "repo1", "repo1")
    agg = corpus.aggregates(corpus.resolve(ar, cfg))
    assert agg["trees"]["findings"]["refs"] == {}
    assert agg["totals"]["refs"] == {}


# ---------------------------------------------------------------------------
# 4. backfill tool
# ---------------------------------------------------------------------------


def _valid_report_json(ref_metadata: dict | None = None) -> str:
    r = _report()
    r["metadata"].update(ref_metadata or {})
    return json.dumps(r, indent=2) + "\n"


@pytest.fixture
def backfill_tree(tmp_path):
    root = tmp_path / "findings"
    branch = root / "prodA" / "repo1__release-4.19"
    branch.mkdir(parents=True)
    (branch / "repo1__release-4.19-security-audit.json").write_text(
        _valid_report_json(), encoding="utf-8"
    )
    head = root / "prodA" / "repo1"
    head.mkdir(parents=True)
    (head / "repo1-security-audit.json").write_text(_valid_report_json(), encoding="utf-8")
    declared = root / "prodB" / "repo2__release-4.18"
    declared.mkdir(parents=True)
    (declared / "repo2__release-4.18-security-audit.json").write_text(
        _valid_report_json({"ref": "release-4.18", "ref_kind": "branch"}), encoding="utf-8"
    )
    # dedup alias: symlinked report must never be rewritten
    alias_dir = root / "prodC" / "repo1__release-4.19"
    alias_dir.mkdir(parents=True)
    (alias_dir / "repo1__release-4.19-security-audit.json").symlink_to(
        branch / "repo1__release-4.19-security-audit.json"
    )
    return root


def _run_backfill(root: Path, *extra):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.migrations.backfill_report_refs",
            "--results-root",
            str(root),
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def test_backfill_dry_run_is_default_and_writes_nothing(backfill_tree):
    before = {p: p.read_text() for p in backfill_tree.rglob("*.json") if not p.is_symlink()}
    proc = _run_backfill(backfill_tree)
    assert proc.returncode == 0, proc.stderr
    assert "DRY-RUN" in proc.stdout
    assert "would stamp:              1" in proc.stdout
    after = {p: p.read_text() for p in backfill_tree.rglob("*.json") if not p.is_symlink()}
    assert before == after


def test_backfill_apply_roundtrip_idempotent(backfill_tree):
    proc = _run_backfill(backfill_tree, "--apply")
    assert proc.returncode == 0, proc.stderr
    assert "stamped:                  1" in proc.stdout
    assert "prodA" in proc.stdout  # per-product batch summary

    branch = json.loads(
        (
            backfill_tree
            / "prodA"
            / "repo1__release-4.19"
            / "repo1__release-4.19-security-audit.json"
        ).read_text()
    )
    assert branch["metadata"]["ref"] == "release-4.19"
    assert branch["metadata"]["ref_kind"] == "branch"
    # schema-valid after the write
    schema = _load_schema("report")
    assert _errors(schema, branch) == []

    head = json.loads((backfill_tree / "prodA" / "repo1" / "repo1-security-audit.json").read_text())
    assert "ref" not in head["metadata"]  # HEAD reports untouched
    declared = json.loads(
        (
            backfill_tree
            / "prodB"
            / "repo2__release-4.18"
            / "repo2__release-4.18-security-audit.json"
        ).read_text()
    )
    assert declared["metadata"]["ref"] == "release-4.18"

    # second apply is a no-op
    proc2 = _run_backfill(backfill_tree, "--apply")
    assert proc2.returncode == 0, proc2.stderr
    assert "stamped:                  0" in proc2.stdout

    # the backfilled tree resolves with declared provenance, same counts
    cfg_path = backfill_tree.parent / "corpus-config.yaml"
    cfg_path.write_text(FIXTURE_CONFIG, encoding="utf-8")
    res = corpus.resolve(backfill_tree.parent, corpus.load_config(cfg_path))
    agg = corpus.aggregates(res)
    assert agg["trees"]["findings"]["reports"] == 3
    assert agg["trees"]["findings"]["branch_reaudits"] == 2
    stamped = next(r for r in res.records if r.base == "repo1__release-4.19")
    assert stamped.ref_source == "metadata"
