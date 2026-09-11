#!/usr/bin/env python3
"""Unit tests for traust.cli.emit_validation_ledger_events — the
validation-report → disposition-ledger emitter — and the evidence-class
merge behaviour its events produce (build_cumulative.py)."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traust_engine.ledger import compute_event_id
from traust_engine.ledger.service import SubmitResult
from traust_engine.reporting.validate import compute_claim_hash

from traust.cli.build_cumulative import derive_disposition
from traust.cli.emit_validation_ledger_events import (
    AuditResolver,
    append_to_layer,
    build_events,
    layer_path_for,
    merge_register,
)

RECORDED = "2026-07-13T12:00:00+00:00"
RUNNER = "/home/runner/ws"  # the foreign absolute prefix validations record


def _finding(fid, title="Unsanitized path join in registrar"):
    return {
        "id": fid,
        "title": title,
        "severity": "high",
        "cwes": ["CWE-22"],
        "locations": ["pkg/reg.go:42"],
        "description": "A path traversal.",
        "remediation": "Sanitize.",
    }


def _audit(findings, repo="https://example.invalid/repoX"):
    return {"metadata": {"repository": repo, "commit": "abc1234"}, "findings": findings}


def _vfinding(fid, verdict, source_report, package="prodA:repoX", **kw):
    base = {
        "source_id": f"{package}/{fid}",
        "source_report": source_report,
        "title": "Unsanitized path join in registrar",
        "claimed_severity": "high",
        "surface": "runtime",
        "verdict": verdict,
        "technique": "replay",
        "steps": [],
        "evidence": [{"type": "http", "path": "artifacts/step-1.log", "sha256": "ab" * 32}],
        "observed_impact": "wrote outside the socket dir",
        "deviation_from_claim": "",
    }
    base.update(kw)
    return base


def _vreport(validated, source_reports=()):
    return {
        "title": "prodA validation",
        "metadata": {"date": "2026-06-25", "harness_version": "0.6.5-1234abc"},
        "source_reports": list(source_reports),
        "summary": {},
        "validated_findings": validated,
        "attack_chains": [],
        "novel_findings": [],
    }


def _canonical_id(event):
    """Reproduce the SDK's server-side canonical event id.

    The emitters no longer stamp event_id (the SDK computes it on submit),
    so the file-only stand-in derives it from the event's identifying fields
    exactly as the server does.
    """
    disp = event.get("disposition") or {}
    return compute_event_id(
        event["source"]["ref"],
        event["finding_ref"],
        disp.get("validity"),
        disp.get("resolution"),
    )


class _MockLedgerService:
    """File-only LedgerService stand-in that needs no LAAS_TOKEN."""

    def __init__(self, client=None, *, data_dir=None):
        pass

    def ensure_layer_file(self, layer_path, *, shell=None):
        if layer_path.exists():
            return json.loads(layer_path.read_text(encoding="utf-8"))
        base = shell or {"events": [], "metadata": {}}
        layer_path.parent.mkdir(parents=True, exist_ok=True)
        layer_path.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
        return base

    def submit_events(self, layer_path, events, *, report_path=None, queue_items=None):
        layer = json.loads(layer_path.read_text(encoding="utf-8"))
        existing_ids = {e["event_id"] for e in layer.get("events", [])}
        new, seen = [], set()
        for e in events:
            eid = _canonical_id(e)
            if eid not in existing_ids and eid not in seen:
                new.append({**e, "event_id": eid})
                seen.add(eid)
        layer.setdefault("events", []).extend(new)
        if queue_items:
            layer.setdefault("needs_review", []).extend(queue_items)
        layer_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
        return SubmitResult(
            event_ids=[e["event_id"] for e in new], queue_added=len(queue_items or [])
        )

    def sign(self, layer_path, **kw):
        pass

    def resolve_review_item(self, *a, **kw):
        return {}


class Workspace(unittest.TestCase):
    """Builds a throwaway workspace: results root + progress-tracker mirror."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.results = self.tmp / "analysis-results"
        self.canon = self.results / "findings" / "prodA" / "repoX"
        self.canon.mkdir(parents=True)
        self.audit_path = self.canon / "repoX-security-audit.json"
        self.audit = _audit([_finding("FIND-001"), _finding("FIND-002")])
        self.audit_path.write_text(json.dumps(self.audit))
        self.resolver = AuditResolver(self.results, self.tmp)
        p = patch("traust.cli.emit_validation_ledger_events.LedgerService", _MockLedgerService)
        p.start()
        self.addCleanup(p.stop)

    def foreign(self, local: Path) -> str:
        return f"{RUNNER}/{local.relative_to(self.tmp)}"

    def emit(self, validated, source_reports=()):
        report = _vreport(validated, source_reports)
        return build_events(
            report, "validations/prodA/prodA-validation.json", self.resolver, RECORDED
        )


class TestVerdictMapping(Workspace):
    def test_confirmed_emits_class1_confirmed(self):
        out = self.emit([_vfinding("FIND-001", "confirmed", self.foreign(self.audit_path))])
        [(path, bucket)] = out["per_audit"].items()
        self.assertEqual(path, self.audit_path.resolve())
        [e] = bucket["events"]
        self.assertEqual(e["disposition"], {"validity": "confirmed"})
        self.assertEqual(e["source"]["type"], "validation_report")
        self.assertEqual(e["source"]["actor"]["kind"], "machine")
        self.assertIn("confirmed", e["rationale"])
        self.assertEqual(e["occurred_at"], "2026-06-25T00:00:00+00:00")

    def test_refuted_emits_countersign_gated_fp_and_register(self):
        out = self.emit([_vfinding("FIND-002", "refuted", self.foreign(self.audit_path))])
        [bucket] = out["per_audit"].values()
        [e] = bucket["events"]
        self.assertEqual(e["disposition"], {"validity": "false_positive"})
        self.assertNotIn("auto_accept_tier", e)
        [r] = bucket["register"]
        self.assertEqual(r["tier"], "countersign")
        self.assertEqual(r["finding_ref"], "FIND-002")

    def test_quarantine_and_proposal_queue_items_are_schema_valid(self):
        # Regression for the pre-0.200 defect: E3/severity-proposal queue
        # items carried "note" instead of the required "quote" and used
        # queue_reasons missing from the enum — every layer they touched
        # failed the schema gate, and build_cumulative crashed rendering
        # them (KeyError: 'quote').
        import jsonschema
        from traust_contracts.paths import schema_path as _sp

        schema = json.loads(_sp("layer").read_text())
        out = self.emit(
            [
                _vfinding(
                    "FIND-001", "confirmed", self.foreign(self.audit_path), evidence_grade="E3"
                ),
                _vfinding(
                    "FIND-002",
                    "confirmed",
                    self.foreign(self.audit_path),
                    severity_validation={
                        "proposal": {"severity": "critical", "rationale": "chains to RCE"},
                        "delta": "+1",
                    },
                ),
            ]
        )
        [(_path, bucket)] = out["per_audit"].items()
        reasons = {i["queue_reason"] for i in bucket["needs_review"]}
        self.assertEqual(reasons, {"weak_confirmation", "severity_proposal"})
        for item in bucket["needs_review"]:
            self.assertIn("quote", item)
            self.assertNotIn("note", item)
        layer_path = self.canon / "repoX-findings-layer.json"
        append_to_layer(layer_path, self.audit_path, self.audit, bucket, RECORDED, "0.200.0")
        layer = json.loads(layer_path.read_text())
        jsonschema.validate(layer, schema)
        # ...and the cumulative Markdown render must survive pending items
        # (both the new "quote" shape and legacy "note" items written by
        # the pre-0.200 emitter bug).
        from traust.cli.build_cumulative import build_cumulative, render_markdown

        layer["needs_review"].append(
            {
                "queued_at": RECORDED,
                "source_ref": "legacy.json",
                "note": "legacy pre-0.200 item",
                "author": "machine:legacy",
                "queue_reason": "severity_proposal",
                "status": "pending",
            }
        )
        audit = dict(self.audit, title="repoX Security Audit")
        report = build_cumulative(audit, layer, "repoX-findings-layer.json", RECORDED)
        md = render_markdown(report, layer)
        self.assertIn("legacy pre-0.200 item", md)
        self.assertIn("chains to RCE", md)

    def test_undecided_verdicts_emit_nothing(self):
        out = self.emit(
            [
                _vfinding("FIND-001", "inconclusive", self.foreign(self.audit_path)),
                _vfinding("FIND-001", "not_attempted", self.foreign(self.audit_path)),
                _vfinding("FIND-001", "blocked_by_scope", self.foreign(self.audit_path)),
            ]
        )
        self.assertEqual(out["per_audit"], {})
        self.assertEqual(out["counts"]["no_event"], 3)

    def test_unknown_finding_id_skipped(self):
        out = self.emit(
            [
                _vfinding(
                    "FIND-999", "confirmed", self.foreign(self.audit_path), package="prodA:repoX"
                )
            ]
        )
        self.assertEqual(out["per_audit"], {})
        self.assertEqual(len(out["skipped"]), 1)


class TestResolution(Workspace):
    def test_symlinked_duplicate_resolves_to_canonical(self):
        dup_dir = self.results / "findings" / "prodB" / "repoX"
        dup_dir.mkdir(parents=True)
        dup = dup_dir / "repoX-security-audit.json"
        dup.symlink_to(self.audit_path)
        out = self.emit([_vfinding("FIND-001", "confirmed", self.foreign(dup))])
        [path] = out["per_audit"].keys()
        self.assertEqual(path, self.audit_path.resolve())

    def _mirror(self, content: str) -> Path:
        mdir = (
            self.tmp / "progress-tracker" / "processed-results" / "pkg-findings" / "sub" / "repoX"
        )
        mdir.mkdir(parents=True)
        mirror = mdir / "repoX-security-audit.json"
        mirror.write_text(content)
        return mirror

    def test_mirror_content_match(self):
        mirror = self._mirror(self.audit_path.read_text())
        out = self.emit([_vfinding("FIND-001", "confirmed", self.foreign(mirror))])
        [path] = out["per_audit"].keys()
        self.assertEqual(path, self.audit_path.resolve())

    def test_mirror_claim_match_fans_out_to_all_replicas(self):
        # An alias tree carries the byte-identical claim in a different file.
        alias_dir = self.results / "findings" / "prodC" / "repoX"
        alias_dir.mkdir(parents=True)
        alias = alias_dir / "repoX-security-audit.json"
        alias.write_text(json.dumps(_audit([_finding("FIND-001")], repo="https://alias.invalid/x")))
        # The mirror baseline differs from every canonical file but shares
        # FIND-001's claim.
        stale_mirror = _audit([_finding("FIND-001"), _finding("FIND-003")])
        mirror = self._mirror(json.dumps(stale_mirror))
        out = self.emit([_vfinding("FIND-001", "confirmed", self.foreign(mirror))])
        self.assertEqual(
            sorted(out["per_audit"]), sorted([self.audit_path.resolve(), alias.resolve()])
        )
        # Same event id in both ledgers: same source, finding, validity.
        ids = {_canonical_id(b["events"][0]) for b in out["per_audit"].values()}
        self.assertEqual(len(ids), 1)

    def test_claim_drift_in_mirror_is_skipped(self):
        drifted = _audit([_finding("FIND-001", title="A different claim")])
        mirror = self._mirror(json.dumps(drifted))
        out = self.emit([_vfinding("FIND-001", "confirmed", self.foreign(mirror))])
        self.assertEqual(out["per_audit"], {})
        self.assertEqual(len(out["skipped"]), 1)


class TestStaleBaseline(Workspace):
    def test_direct_hit_with_changed_sha_queues_stale_baseline(self):
        out = self.emit(
            [_vfinding("FIND-001", "confirmed", self.foreign(self.audit_path))],
            source_reports=[
                {
                    "kind": "security-audit",
                    "path": self.foreign(self.audit_path),
                    "sha256": "0" * 64,
                }
            ],
        )
        [bucket] = out["per_audit"].values()
        self.assertEqual(len(bucket["events"]), 1)  # the proof still lands
        [q] = bucket["needs_review"]
        self.assertEqual(q["queue_reason"], "stale_baseline")
        self.assertEqual(q["status"], "pending")

    def test_matching_sha_queues_nothing(self):
        import hashlib

        sha = hashlib.sha256(self.audit_path.read_bytes()).hexdigest()
        out = self.emit(
            [_vfinding("FIND-001", "confirmed", self.foreign(self.audit_path))],
            source_reports=[
                {"kind": "security-audit", "path": self.foreign(self.audit_path), "sha256": sha}
            ],
        )
        [bucket] = out["per_audit"].values()
        self.assertEqual(bucket["needs_review"], [])


class TestLayerAppend(Workspace):
    def _bucket(self, verdict="confirmed"):
        out = self.emit([_vfinding("FIND-001", verdict, self.foreign(self.audit_path))])
        return next(iter(out["per_audit"].values()))

    def test_append_is_idempotent(self):
        layer_path = layer_path_for(self.audit_path)
        bucket = self._bucket()
        c1 = append_to_layer(
            layer_path, self.audit_path, self.audit, bucket, RECORDED, "0.6.5-1234abc"
        )
        c2 = append_to_layer(
            layer_path, self.audit_path, self.audit, bucket, RECORDED, "0.6.5-1234abc"
        )
        self.assertEqual((c1["appended"], c2["appended"]), (1, 0))
        self.assertEqual(c2["duplicates_skipped"], 1)
        layer = json.loads(layer_path.read_text())
        self.assertEqual(len(layer["events"]), 1)

    def test_same_finding_reached_twice_in_one_batch_appends_once(self):
        # One report can reach the same canonical finding via two source
        # paths (e.g. two mirror sub-packages claim-matching to one audit);
        # the identical event_ids must dedupe within the batch, not just
        # against events already in the file (validator rejects duplicates).
        out = self.emit(
            [
                _vfinding(
                    "FIND-001", "refuted", self.foreign(self.audit_path), package="pkg:subA/repoX"
                ),
                _vfinding(
                    "FIND-001", "refuted", self.foreign(self.audit_path), package="pkg:subB/repoX"
                ),
            ]
        )
        [bucket] = out["per_audit"].values()
        self.assertEqual(len(bucket["events"]), 2)  # built twice...
        layer_path = layer_path_for(self.audit_path)
        counts = append_to_layer(
            layer_path, self.audit_path, self.audit, bucket, RECORDED, "0.6.5-1234abc"
        )
        self.assertEqual(counts["appended"], 1)  # ...appended once
        layer = json.loads(layer_path.read_text())
        ids = [e["event_id"] for e in layer["events"]]
        self.assertEqual(len(ids), len(set(ids)))
        # Register also dedupes within the batch.
        reg_path = layer_path.with_name(
            layer_path.name.replace("-findings-layer.json", "-refuted-register.json")
        )
        added = merge_register(reg_path, "validations/prodA/v.json", bucket["register"], RECORDED)
        self.assertEqual(added, 1)

    def test_recorded_at_clamped_to_stay_chronological(self):
        layer_path = layer_path_for(self.audit_path)
        later = "2026-08-01T00:00:00+00:00"
        layer = {
            "metadata": {
                "audit_report": self.audit_path.name,
                "repository": "https://example.invalid/repoX",
                "created": later,
                "harness_version": "0.6.5-1234abc",
            },
            "events": [
                {
                    "event_id": "f" * 64,
                    "finding_ref": "FIND-002",
                    "recorded_at": later,
                    "source": {"type": "triage_report", "ref": "t", "actor": {"kind": "machine"}},
                    "disposition": {"validity": "confirmed"},
                    "rationale": "an earlier determination",
                }
            ],
            "needs_review": [],
        }
        layer_path.write_text(json.dumps(layer))
        append_to_layer(
            layer_path, self.audit_path, self.audit, self._bucket(), RECORDED, "0.6.5-1234abc"
        )
        events = json.loads(layer_path.read_text())["events"]
        self.assertEqual(events[-1]["recorded_at"], later)

    def test_register_merge_never_clobbers_other_sources(self):
        layer_path = layer_path_for(self.audit_path)
        reg_path = layer_path.with_name(
            layer_path.name.replace("-findings-layer.json", "-refuted-register.json")
        )
        reg_path.parent.mkdir(parents=True, exist_ok=True)
        reg_path.write_text(
            json.dumps(
                {
                    "source": "TRIAGE.json",
                    "generated_at": "2026-07-01T00:00:00+00:00",
                    "entries": [{"finding_ref": "FIND-001", "asserted_by": "triage/0.27.0"}],
                }
            )
        )
        bucket = self._bucket("refuted")
        added = merge_register(reg_path, "validations/prodA/v.json", bucket["register"], RECORDED)
        doc = json.loads(reg_path.read_text())
        self.assertEqual(added, 1)
        self.assertEqual(len(doc["entries"]), 2)
        self.assertIn("TRIAGE.json", doc["sources"])
        self.assertIn("validations/prodA/v.json", doc["sources"])
        # Re-merge: nothing duplicated.
        self.assertEqual(
            merge_register(reg_path, "validations/prodA/v.json", bucket["register"], RECORDED), 0
        )


class TestMergeSemantics(Workspace):
    """The events this emitter writes drive the intended merge outcomes."""

    def _event(self, verdict):
        out = self.emit([_vfinding("FIND-001", verdict, self.foreign(self.audit_path))])
        [bucket] = out["per_audit"].values()
        ev = bucket["events"][0]
        return {**ev, "event_id": _canonical_id(ev)}

    def test_validation_confirmed_is_execution_proven(self):
        disp = derive_disposition(_finding("FIND-001"), [self._event("confirmed")], RECORDED)
        self.assertEqual(disp["validity"], "confirmed")
        self.assertEqual(disp["assurance"], "execution_proven")

    def test_validation_confirmed_outranks_machine_triage_fp(self):
        triage_fp = {
            "event_id": "a" * 64,
            "finding_ref": "FIND-001",
            "recorded_at": "2026-07-14T00:00:00+00:00",
            "source": {
                "type": "triage_report",
                "ref": "TRIAGE.json",
                "actor": {"kind": "machine", "identity": "triage/0.27.0"},
            },
            "disposition": {"validity": "false_positive"},
            "rationale": "static reasoning said unreachable",
        }
        disp = derive_disposition(
            _finding("FIND-001"), [self._event("confirmed"), triage_fp], RECORDED
        )
        self.assertEqual(disp["validity"], "confirmed")

    def test_validation_refuted_pends_awaiting_signoff(self):
        disp = derive_disposition(_finding("FIND-001"), [self._event("refuted")], RECORDED)
        self.assertNotEqual(disp["validity"], "false_positive")
        self.assertTrue(disp.get("refuted_awaiting_signoff"))


class TestHarnessVersionSanitizing(Workspace):
    def test_annotated_version_is_normalized_on_events(self):
        # recompute_verdicts.py stamps '+recompute' onto harness_version;
        # the layer schema pattern rejects it, so events keep only the
        # conforming prefix (raw string survives in the actor identity).
        report = _vreport([_vfinding("FIND-001", "confirmed", self.foreign(self.audit_path))])
        report["metadata"]["harness_version"] = "0.6.4-37419f1+recompute"
        out = build_events(
            report, "validations/prodA/prodA-validation.json", self.resolver, RECORDED
        )
        [bucket] = out["per_audit"].values()
        [e] = bucket["events"]
        self.assertEqual(e["harness_version"], "0.6.4-37419f1")
        self.assertEqual(
            e["source"]["actor"]["identity"], "validate-findings/0.6.4-37419f1+recompute"
        )

    def test_garbage_version_omits_the_field(self):
        report = _vreport([_vfinding("FIND-001", "confirmed", self.foreign(self.audit_path))])
        report["metadata"]["harness_version"] = "not-a-version"
        out = build_events(
            report, "validations/prodA/prodA-validation.json", self.resolver, RECORDED
        )
        [bucket] = out["per_audit"].values()
        self.assertNotIn("harness_version", bucket["events"][0])


class TestClaimHashContract(unittest.TestCase):
    def test_identical_claims_hash_equal_across_metadata_differences(self):
        a = _finding("FIND-001")
        b = dict(_finding("FIND-001"))
        self.assertEqual(compute_claim_hash(a), compute_claim_hash(b))


if __name__ == "__main__":
    unittest.main()


def test_layer_path_for_naming_conventions(tmp_path):
    """P0-4 emitter leg (docs-verification 2026-07-31): cloud-config
    baselines get the SHORT layer name (matching every production
    cloud-config ledger) unless a code audit shares the directory;
    container reports always keep the full stem."""
    lp = layer_path_for
    # code audit -> short
    assert lp(tmp_path / "foo-security-audit.json").name == "foo-findings-layer.json"
    # container -> full stem (shares the code audit's directory)
    assert (
        lp(tmp_path / "img-container-audit.json").name == "img-container-audit-findings-layer.json"
    )
    # solo cloud-config -> short
    assert lp(tmp_path / "repo-cloud-config-audit.json").name == "repo-findings-layer.json"
    # companion cloud-config beside a code audit -> full stem
    (tmp_path / "repo-security-audit.json").write_text("{}")
    assert (
        lp(tmp_path / "repo-cloud-config-audit.json").name
        == "repo-cloud-config-audit-findings-layer.json"
    )
