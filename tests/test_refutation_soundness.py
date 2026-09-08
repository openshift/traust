#!/usr/bin/env python3
"""
Tests for the refutation-soundness gate (Phase 1 of the scanning-skill
error-correction plan):

  - harnessing/5-validate/validate-findings/soundness.py — gate conditions:
    (a) error-signature transcripts, (b) zero-subject / template RBAC
    probes, (c) target-not-deployed runs (install-failure.yaml)
  - execute.py — step-level gating at dispatch time (+ audit log flag)
  - report.py — finding-level rollup carries soundness_flag; backstop
    gate on results that bypassed execute
  - traust.cli.emit_validation_ledger_events — flagged refutations route
    to needs_review (queue_reason unsound_refutation), never to the
    FP/countersign path or the refuted register
  - traust.ops.lint_refutation_soundness — retroactive corpus linter
"""

import hashlib
import json
import sys

import pytest
import soundness
from adapters import StepResult
from execute import run
from ingest import Finding, Normalized
from report import build_validation_json
from scope import ClusterScope, Scope

from traust.cli.emit_validation_ledger_events import (
    AuditResolver,
    build_events,
)
from traust.ops import lint_refutation_soundness as lint

FORBIDDEN = (
    "Error from server (Forbidden): pods is forbidden: User "
    '"probe-sa" cannot list resource "pods" in API group "" '
    'in the namespace "open-cluster-management"'
)
RBAC_EMPTY = "no\nvf-rbac-tried:\nvf-rbac-probe: verb=delete res=secrets"
RBAC_CONCRETE = (
    "no\nvf-rbac-tried: system:serviceaccount:odf:ocs-op "
    "system:serviceaccount:odf:rook-ceph\n"
    "vf-rbac-probe: verb=delete res=secrets"
)
RBAC_TEMPLATE = (
    "no\nvf-rbac-tried: system:serviceaccount:{ns}:{sa}\nvf-rbac-probe: verb=create res=pods"
)


# ======================================================================
# soundness.py — gate conditions
# ======================================================================


class TestErrorSignatures:
    @pytest.mark.parametrize(
        "observed,name",
        [
            (FORBIDDEN, "forbidden"),
            (
                'secrets is forbidden: User "system:anonymous" cannot get resource "secrets"',
                "forbidden",
            ),
            ("bash: openssl: command not found", "command-not-found"),
            ("error: error executing jsonpath: unrecognized identifier", "jsonpath-error"),
            ('Error from server (NotFound): deployments.apps "x" not found', "not-found"),
            ('namespace "ramen-ops" does not exist', "does-not-exist"),
            ("curl: (7) Could not connect to server", "could-not-connect"),
            ("impersonating system:serviceaccount:{ns}:{sa} failed", "unsubstituted-template"),
        ],
    )
    def test_signature_matches(self, observed, name):
        assert soundness.match_error_signature(observed) == name

    @pytest.mark.parametrize(
        "observed",
        [
            "yes",
            "no",
            "pod/pwn created",
            '{"paths": ["/apis"]}',
            "HTTP/1.1 200 OK\nvf-http-status:200",
            # a 403 body alone is not the validator's own RBAC failure
            "vf-http-status:403",
        ],
    )
    def test_clean_transcripts_do_not_match(self, observed):
        assert soundness.match_error_signature(observed) is None


class TestSoundnessFlag:
    def test_error_signature_flags(self):
        assert soundness.soundness_flag("raw", FORBIDDEN) == "error-signature:forbidden"

    def test_rbac_zero_subjects(self):
        assert soundness.soundness_flag("rbac-can-i", RBAC_EMPTY) == "rbac-zero-subjects"

    def test_rbac_marker_without_verb_still_rbac(self):
        # `verb: raw` steps that run the RBAC probe carry vf-rbac markers
        assert soundness.soundness_flag("raw", RBAC_EMPTY) == "rbac-zero-subjects"

    def test_rbac_template_placeholder(self):
        # the template signature also matches at the error-signature tier
        flag = soundness.soundness_flag("rbac-can-i", RBAC_TEMPLATE)
        assert flag in ("rbac-template-placeholder", "error-signature:unsubstituted-template")

    def test_rbac_concrete_subjects_pass(self):
        assert soundness.soundness_flag("rbac-can-i", RBAC_CONCRETE) is None

    def test_install_failure_wins(self):
        assert soundness.soundness_flag("raw", "no", install_failure=True) == "target-not-deployed"

    def test_clean_probe_passes(self):
        assert soundness.soundness_flag("port-forward+http", "HTTP/1.1 401 Unauthorized") is None


class TestGateVerdict:
    def test_gates_refuted_on_error_signature(self):
        verdict, flag = soundness.gate_verdict("refuted", "raw", FORBIDDEN)
        assert verdict == "inconclusive"
        assert flag == "error-signature:forbidden"

    def test_sound_refutation_passes(self):
        verdict, flag = soundness.gate_verdict("refuted", "rbac-can-i", RBAC_CONCRETE)
        assert verdict == "refuted"
        assert flag is None

    def test_confirmed_never_gated(self):
        # a confirm whose transcript happens to contain an error string
        # is untouched — only `refuted` is un-emittable
        verdict, flag = soundness.gate_verdict("confirmed", "raw", FORBIDDEN)
        assert verdict == "confirmed"
        assert flag is None

    def test_inconclusive_untouched(self):
        verdict, flag = soundness.gate_verdict("inconclusive", "raw", FORBIDDEN)
        assert verdict == "inconclusive"
        assert flag is None

    def test_install_failure_gates_whole_run(self):
        verdict, flag = soundness.gate_verdict(
            "refuted", "rbac-can-i", RBAC_CONCRETE, install_failure=True
        )
        assert verdict == "inconclusive"
        assert flag == "target-not-deployed"


class TestRunInstallFailed:
    def test_detects_marker(self, tmp_path):
        assert not soundness.run_install_failed(tmp_path)
        (tmp_path / "install-failure.yaml").write_text("reason: CSV failed\n")
        assert soundness.run_install_failed(tmp_path)


class TestFlagValidatedFinding:
    def _vf(self, verdict="refuted", observed=FORBIDDEN, steps=None, **kw):
        vf = {
            "source_id": "prod:repo/FIND-001",
            "verdict": verdict,
            "observed_impact": observed,
            "steps": steps or [],
        }
        vf.update(kw)
        return vf

    def test_explicit_flag_wins(self):
        vf = self._vf(verdict="inconclusive", observed="", soundness_flag="target-not-deployed")
        assert soundness.flag_validated_finding(vf) == "target-not-deployed"

    def test_retroactive_error_signature(self):
        assert soundness.flag_validated_finding(self._vf()) == "error-signature:forbidden"

    def test_install_failure_flags_any_refuted(self):
        vf = self._vf(observed="no")
        assert soundness.flag_validated_finding(vf, install_failure=True) == "target-not-deployed"

    def test_non_refuted_not_flagged(self):
        vf = self._vf(verdict="confirmed")
        assert soundness.flag_validated_finding(vf) is None

    def test_mixed_probes_sound_refutation_stands(self):
        steps = [
            {"verdict": "refuted", "verb": "raw", "observed": FORBIDDEN},
            {"verdict": "refuted", "verb": "rbac-can-i", "observed": RBAC_CONCRETE},
        ]
        vf = self._vf(observed="", steps=steps)
        assert soundness.flag_validated_finding(vf) is None

    def test_all_probes_unsound_flags(self):
        steps = [
            {"verdict": "refuted", "verb": "raw", "observed": FORBIDDEN},
            {"verdict": "refuted", "verb": "rbac-can-i", "observed": RBAC_EMPTY},
        ]
        vf = self._vf(observed="", steps=steps)
        assert soundness.flag_validated_finding(vf) == "error-signature:forbidden"


# ======================================================================
# execute.py — step-level gate
# ======================================================================


def _run_plan(tmp_path, steps):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"steps": steps}))
    scope = Scope()
    scope.clusters["lab"] = ClusterScope(
        context="lab", namespaces=["app"], explicit_namespaces={"app"}
    )
    return run(plan_path, scope, tmp_path, second_pass_novel=False)


class TestExecuteGate:
    def test_forbidden_transcript_gated(self, tmp_path):
        # `raw` verb runs the cmd via bash; echoing the validator-RBAC
        # denial makes the heuristic verdict `refuted`, which the gate
        # must downgrade.
        steps = [
            {
                "id": "s1",
                "adapter": "k8s",
                "verb": "raw",
                "target": {"context": "lab", "namespace": "app"},
                "classification": "safe",
                "cmd": f"echo '{FORBIDDEN}'",
                "expected": "pods listed across namespaces",
                "finding_ref": "F-1",
            }
        ]
        results, _audit = _run_plan(tmp_path, steps)
        assert results[0].verdict == "inconclusive"
        assert results[0].soundness_flag == "error-signature:forbidden"
        lines = [
            json.loads(l) for l in (tmp_path / "validation-audit.jsonl").read_text().splitlines()
        ]
        assert lines[0]["verdict"] == "inconclusive"
        assert lines[0]["soundness_flag"] == "error-signature:forbidden"

    def test_install_failure_gates_run(self, tmp_path):
        (tmp_path / "install-failure.yaml").write_text("reason: no CSV\n")
        steps = [
            {
                "id": "s1",
                "adapter": "k8s",
                "verb": "rbac-can-i",
                "target": {"context": "lab", "namespace": "app"},
                "classification": "safe",
                "cmd": ("printf 'no\nvf-rbac-tried: system:serviceaccount:app:sa1'"),
                "expected": "yes — SA can delete secrets cluster-wide",
                "finding_ref": "F-1",
            }
        ]
        results, _ = _run_plan(tmp_path, steps)
        assert results[0].verdict == "inconclusive"
        assert results[0].soundness_flag == "target-not-deployed"

    def test_sound_refutation_survives(self, tmp_path):
        steps = [
            {
                "id": "s1",
                "adapter": "k8s",
                "verb": "rbac-can-i",
                "target": {"context": "lab", "namespace": "app"},
                "classification": "safe",
                "cmd": ("printf 'no\nvf-rbac-tried: system:serviceaccount:app:sa1'"),
                "expected": "yes — SA can delete secrets cluster-wide",
                "finding_ref": "F-1",
            }
        ]
        results, _ = _run_plan(tmp_path, steps)
        assert results[0].verdict == "refuted"
        assert results[0].soundness_flag == ""


# ======================================================================
# report.py — rollup + backstop
# ======================================================================


def _normalized():
    n = Normalized(target_name="repoX", source_dir="/x")
    n.source_reports = [
        {"kind": "security-audit", "path": "/x/repoX-security-audit.json", "sha256": "ab" * 32}
    ]
    n.findings = [Finding(id="F-1", title="over-broad RBAC", severity="high")]
    return n


def _doc_for(step_results):
    return build_validation_json(
        _normalized(),
        Scope(),
        step_results,
        [],
        [],
        audit_path="validation-audit.jsonl",
        audit_sha256="",
        flags=[],
        approval={"mode": "auto"},
    )


class TestReportRollup:
    def test_gated_step_flag_travels_to_finding(self):
        r = StepResult(
            step_id="s1",
            adapter="k8s",
            verb="raw",
            target={},
            classification="safe",
            verdict="inconclusive",
            observed=FORBIDDEN,
            soundness_flag="error-signature:forbidden",
            finding_ref="F-1",
        )
        doc = _doc_for([r])
        vf = doc["validated_findings"][0]
        assert vf["verdict"] == "inconclusive"
        assert vf["soundness_flag"] == "error-signature:forbidden"

    def test_backstop_gates_ungated_refuted(self):
        # results that never passed through execute.py (e.g. hand-rolled)
        r = StepResult(
            step_id="s1",
            adapter="k8s",
            verb="rbac-can-i",
            target={},
            classification="safe",
            verdict="refuted",
            observed=RBAC_EMPTY,
            finding_ref="F-1",
        )
        doc = _doc_for([r])
        vf = doc["validated_findings"][0]
        assert vf["verdict"] == "inconclusive"
        assert vf["soundness_flag"] == "rbac-zero-subjects"
        assert doc["summary"]["by_verdict"]["refuted"] == 0
        assert doc["summary"]["by_verdict"]["inconclusive"] == 1

    def test_sound_refutation_reported(self):
        r = StepResult(
            step_id="s1",
            adapter="k8s",
            verb="rbac-can-i",
            target={},
            classification="safe",
            verdict="refuted",
            observed=RBAC_CONCRETE,
            finding_ref="F-1",
        )
        doc = _doc_for([r])
        vf = doc["validated_findings"][0]
        assert vf["verdict"] == "refuted"
        assert not vf.get("soundness_flag")


# ======================================================================
# emit_validation_ledger_events.py — ledger routing
# ======================================================================

RECORDED = "2026-07-22T12:00:00+00:00"
RUNNER = "/home/runner/ws"


def _mk_corpus(
    tmp_path, observed=FORBIDDEN, soundness_flag=None, verdict="refuted", install_failure=False
):
    results = tmp_path / "analysis-results"
    audit_dir = results / "findings" / "prodA" / "repoX"
    audit_dir.mkdir(parents=True)
    audit = {
        "metadata": {"repository": "https://example.invalid/repoX", "commit": "abc1234"},
        "findings": [
            {
                "id": "FIND-001",
                "title": "over-broad RBAC",
                "severity": "high",
                "description": "wildcard ClusterRole",
            }
        ],
    }
    audit_path = audit_dir / "repoX-security-audit.json"
    audit_path.write_text(json.dumps(audit))

    vdir = results / "validations" / "prodA"
    vdir.mkdir(parents=True)
    if install_failure:
        (vdir / "install-failure.yaml").write_text("reason: CSV failed\n")
    vf = {
        "source_id": "prodA:repoX/FIND-001",
        "source_report": f"{RUNNER}/analysis-results/findings/prodA/"
        f"repoX/repoX-security-audit.json",
        "title": "over-broad RBAC",
        "claimed_severity": "high",
        "verdict": verdict,
        "technique": "replay",
        "steps": [],
        "evidence": [],
        "observed_impact": observed,
        "deviation_from_claim": "",
    }
    if soundness_flag:
        vf["soundness_flag"] = soundness_flag
    audit_sha = hashlib.sha256(audit_path.read_bytes()).hexdigest()
    report = {
        "metadata": {"harness_version": "0.136.0-abc1234", "date": "2026-07-22"},
        "source_reports": [
            {"kind": "security-audit", "path": vf["source_report"], "sha256": audit_sha}
        ],
        "validated_findings": [vf],
    }
    report_path = vdir / "prodA-validation.json"
    report_path.write_text(json.dumps(report))
    return results, report, report_path


class TestLedgerRouting:
    def _build(self, tmp_path, **kw):
        install_failure = kw.pop("install_failure", False)
        results, report, _report_path = _mk_corpus(tmp_path, install_failure=install_failure, **kw)
        resolver = AuditResolver(results, tmp_path)
        return build_events(
            report,
            "validations/prodA/prodA-validation.json",
            resolver,
            RECORDED,
            install_failure=install_failure,
        )

    def test_unsound_refutation_routes_to_needs_review(self, tmp_path):
        out = self._build(tmp_path, observed=FORBIDDEN)
        assert out["counts"]["unsound"] == 1
        assert out["counts"]["refuted"] == 0
        bucket = next(iter(out["per_audit"].values()))
        assert bucket["events"] == []
        assert bucket["register"] == []
        item = bucket["needs_review"][0]
        assert item["queue_reason"] == "unsound_refutation"
        assert item["suggested_finding_ref"] == "FIND-001"
        assert "error-signature:forbidden" in item["quote"]
        assert item["status"] == "pending"

    def test_engine_stamped_inconclusive_routes_too(self, tmp_path):
        out = self._build(
            tmp_path,
            verdict="inconclusive",
            soundness_flag="rbac-zero-subjects",
            observed=RBAC_EMPTY,
        )
        assert out["counts"]["unsound"] == 1
        bucket = next(iter(out["per_audit"].values()))
        assert bucket["events"] == []
        assert bucket["needs_review"][0]["queue_reason"] == "unsound_refutation"

    def test_install_failure_gates_whole_report(self, tmp_path):
        out = self._build(tmp_path, observed=RBAC_CONCRETE, install_failure=True)
        assert out["counts"]["unsound"] == 1
        bucket = next(iter(out["per_audit"].values()))
        assert bucket["events"] == []
        assert "target-not-deployed" in bucket["needs_review"][0]["quote"]

    def test_sound_refutation_still_emits_fp_event(self, tmp_path):
        out = self._build(tmp_path, observed=RBAC_CONCRETE)
        assert out["counts"]["refuted"] == 1
        assert out["counts"]["unsound"] == 0
        bucket = next(iter(out["per_audit"].values()))
        assert bucket["events"][0]["disposition"]["validity"] == "false_positive"
        assert bucket["register"]
        assert bucket["needs_review"] == []

    def test_plain_inconclusive_still_no_event(self, tmp_path):
        out = self._build(tmp_path, verdict="inconclusive", observed="")
        assert out["counts"]["no_event"] == 1
        assert out["per_audit"] == {}


# ======================================================================
# countersign.py — raw probe output on cards
# ======================================================================


class TestCountersignRawObserved:
    def _mk_tree(self, tmp_path):
        results, _report, _report_path = _mk_corpus(tmp_path)
        layer_dir = results / "findings" / "prodA" / "repoX"
        layer = layer_dir / "repoX-findings-layer.json"
        layer.write_text(json.dumps({"metadata": {}, "events": [], "needs_review": []}))
        item = {
            "layer": str(layer),
            "finding": {
                "id": "FIND-001",
                "title": "over-broad RBAC",
                "severity": "high",
                "description": "wildcard ClusterRole",
                "locations": [{"path": "config/rbac/role.yaml"}],
            },
            "triage": None,
            "disposition": {},
            "refutation": {
                "recorded_at": RECORDED,
                "occurred_at": RECORDED,
                "source": {
                    "type": "validation_report",
                    "ref": "validations/prodA/prodA-validation.json",
                    "actor": {"kind": "machine", "identity": "validate-findings/0.1.0"},
                },
                "rationale": "live validation (replay): refuted — claim did not reproduce",
                "evidence_refs": [],
            },
        }
        return item

    def test_raw_observed_resolves_from_report(self, tmp_path):
        from traust.cli import countersign as cs

        cs._REPORT_CACHE.clear()
        item = self._mk_tree(tmp_path)
        raw, why = cs.raw_probe_observed(item)
        assert why == ""
        assert raw == FORBIDDEN

    def test_card_renders_raw_output_verbatim(self, tmp_path):
        from traust.cli import countersign as cs

        cs._REPORT_CACHE.clear()
        item = self._mk_tree(tmp_path)
        card = cs.render_card(item, 1, 1, tmp_path)
        assert "RAW PROBE OUTPUT" in card
        assert 'User "probe-sa" cannot list resource "pods"' in card

    def test_unavailable_raw_output_is_flagged_on_card(self, tmp_path):
        from traust.cli import countersign as cs

        cs._REPORT_CACHE.clear()
        item = self._mk_tree(tmp_path)
        item["refutation"]["source"]["ref"] = "validations/nope/x.json"
        card = cs.render_card(item, 1, 1, tmp_path)
        assert "RAW PROBE OUTPUT:** unavailable" in card

    def test_triage_refutation_card_unchanged(self, tmp_path):
        from traust.cli import countersign as cs

        item = self._mk_tree(tmp_path)
        item["refutation"]["source"]["type"] = "triage_report"
        card = cs.render_card(item, 1, 1, tmp_path)
        assert "RAW PROBE OUTPUT" not in card


# ======================================================================
# lint_refutation_soundness.py — retroactive linter
# ======================================================================


class TestLinter:
    def _mk_run(self, results, name, observed, install_failure=False, severity="high"):
        vdir = results / "validations" / name
        vdir.mkdir(parents=True)
        if install_failure:
            (vdir / "install-failure.yaml").write_text("reason: x\n")
        (vdir / "validation-audit.jsonl").write_text(
            json.dumps(
                {
                    "ts": RECORDED,
                    "step_id": "step-001",
                    "adapter": "k8s",
                    "verb": "raw",
                    "target": {},
                    "classification": "safe",
                    "verdict": "refuted",
                    "scope_check": "pass",
                    "evidence": [],
                    "finding_ref": "FIND-001",
                }
            )
            + "\n"
        )
        report = {
            "metadata": {"harness_version": "0.1.0", "date": "2026-06-01"},
            "source_reports": [],
            "validated_findings": [
                {
                    "source_id": f"{name}:repoX/FIND-001",
                    "source_report": "/x/repoX-security-audit.json",
                    "title": "t",
                    "claimed_severity": severity,
                    "verdict": "refuted",
                    "technique": "replay",
                    "steps": [
                        {
                            "step_id": "step-001",
                            "adapter": "k8s",
                            "verb": "raw",
                            "classification": "safe",
                            "verdict": "refuted",
                            "observed": observed,
                        }
                    ],
                    "observed_impact": observed,
                }
            ],
        }
        (vdir / f"{name}-validation.json").write_text(json.dumps(report))

    def test_linter_census_and_worklist(self, tmp_path, capsys, monkeypatch):
        results = tmp_path / "analysis-results"
        self._mk_run(results, "bad-forbidden", FORBIDDEN, severity="critical")
        self._mk_run(results, "bad-notdeployed", RBAC_CONCRETE, install_failure=True)
        self._mk_run(results, "good-sound", RBAC_CONCRETE)
        out = tmp_path / "worklist.json"
        monkeypatch.setattr(
            sys,
            "argv",
            ["lint_refutation_soundness.py", "--results-root", str(results), "--out", str(out)],
        )
        assert lint.main() == 0
        doc = json.loads(out.read_text())
        census = doc["census"]
        assert census["runs_scanned"] == 3
        assert census["refuted_findings_total"] == 3
        assert census["flagged_findings"] == 2
        assert census["flagged_criticals"] == 1
        assert census["by_condition"] == {"error-signature": 1, "target-not-deployed": 1}
        assert census["install_failure_runs"] == ["validations/bad-notdeployed"]
        flags = {e["run"]: e["soundness_flag"] for e in doc["worklist"]}
        assert flags == {
            "validations/bad-forbidden": "error-signature:forbidden",
            "validations/bad-notdeployed": "target-not-deployed",
        }

    def test_linter_is_read_only(self, tmp_path, monkeypatch):
        results = tmp_path / "analysis-results"
        self._mk_run(results, "bad-forbidden", FORBIDDEN)
        vdir = results / "validations" / "bad-forbidden"
        before = {p.name: p.read_bytes() for p in vdir.iterdir()}
        out = tmp_path / "scan-testing" / "worklist.json"
        monkeypatch.setattr(
            sys,
            "argv",
            ["lint_refutation_soundness.py", "--results-root", str(results), "--out", str(out)],
        )
        assert lint.main() == 0
        after = {p.name: p.read_bytes() for p in vdir.iterdir()}
        assert before == after
        assert out.is_file()
