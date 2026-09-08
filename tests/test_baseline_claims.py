#!/usr/bin/env python3
"""Unit tests for harnessing/4-triage/track-findings/scripts/baseline_claims.py and the claim-hash verification
in validate_report.cross_validate_layer / build_cumulative.verify_claim_hashes."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import baseline_claims
import pytest
from traust_engine.reporting.validate import (
    ValidationResult,
    compute_claim_hash,
    cross_validate_layer,
)

import traust.cli.build_cumulative as build_cumulative


def _finding(nnn="001", **kw):
    base = {
        "id": f"EXAMPLE_REPO-abc1234-{nnn}",
        "title": "Command injection via unsanitized template value",
        "severity": "high",
        "cwes": ["CWE-78"],
        "locations": [{"path": "pkg/server/handler.go", "lines": "73"}],
        "description": "Untrusted template parameter reaches exec.Command.",
        "remediation": "Use a fixed argv; never a shell string.",
        "validation_status": "not_verified",
    }
    base.update(kw)
    return base


def _audit(findings):
    return {"findings": findings}


def _layer(audit_ref="audit.json", claim_hashes=None):
    meta = {
        "audit_report": audit_ref,
        "repository": "https://github.com/example/repo",
        "created": "2026-07-13T00:00:00+00:00",
        "harness_version": "0.39.0",
    }
    if claim_hashes is not None:
        meta["claim_hashes"] = claim_hashes
    return {"metadata": meta, "events": [], "needs_review": []}


def _write(tmp, audit, layer):
    ap = Path(tmp) / "audit.json"
    lp = Path(tmp) / "repo-findings-layer.json"
    ap.write_text(json.dumps(audit))
    lp.write_text(json.dumps(layer))
    return ap, lp


class TestClaimHash(unittest.TestCase):
    def test_deterministic_and_impls_agree(self):
        f = _finding()
        self.assertEqual(compute_claim_hash(f), compute_claim_hash(copy.deepcopy(f)))
        self.assertEqual(compute_claim_hash(f), build_cumulative.compute_claim_hash(f))

    def test_validation_status_excluded(self):
        a, b = _finding(), _finding(validation_status="confirmed")
        self.assertEqual(compute_claim_hash(a), compute_claim_hash(b))

    def test_claim_field_changes_hash(self):
        a, b = _finding(), _finding(severity="low")
        self.assertNotEqual(compute_claim_hash(a), compute_claim_hash(b))


@pytest.mark.requires_ledger
class TestRecord(unittest.TestCase):
    def test_record_adds_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ap, lp = _write(tmp, _audit([_finding()]), _layer())
            self.assertEqual(baseline_claims.record(ap, lp, set()), 0)
            layer = json.loads(lp.read_text())
            hashes = layer["metadata"]["claim_hashes"]
            self.assertEqual(list(hashes), ["EXAMPLE_REPO-abc1234-001"])
            self.assertEqual(baseline_claims.record(ap, lp, set()), 0)
            self.assertEqual(json.loads(lp.read_text())["metadata"]["claim_hashes"], hashes)

    def test_record_pins_appends_without_touching_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            f1 = _finding("001")
            ap, lp = _write(
                tmp, _audit([f1]), _layer(claim_hashes={f1["id"]: compute_claim_hash(f1)})
            )
            f2 = _finding("002", title="Second finding appended by vuln-scan")
            ap.write_text(json.dumps(_audit([f1, f2])))
            self.assertEqual(baseline_claims.record(ap, lp, set()), 0)
            hashes = json.loads(lp.read_text())["metadata"]["claim_hashes"]
            self.assertEqual(len(hashes), 2)

    def test_record_refuses_silent_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = _finding()
            ap, lp = _write(
                tmp,
                _audit([_finding(severity="low")]),
                _layer(claim_hashes={f["id"]: compute_claim_hash(f)}),
            )
            before = lp.read_text()
            self.assertEqual(baseline_claims.record(ap, lp, set()), 1)
            self.assertEqual(lp.read_text(), before)  # layer untouched

    def test_rebaseline_requires_corrected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = _finding()
            edited = _finding(severity="low")
            ap, lp = _write(
                tmp, _audit([edited]), _layer(claim_hashes={f["id"]: compute_claim_hash(f)})
            )
            self.assertEqual(baseline_claims.record(ap, lp, {f["id"]}), 1)
            corrected = _finding(severity="low", validation_status="corrected")
            ap.write_text(json.dumps(_audit([corrected])))
            self.assertEqual(baseline_claims.record(ap, lp, {f["id"]}), 0)
            hashes = json.loads(lp.read_text())["metadata"]["claim_hashes"]
            self.assertEqual(hashes[f["id"]], compute_claim_hash(corrected))


@pytest.mark.requires_ledger
class TestVerifyAndGates(unittest.TestCase):
    def _tampered(self, tmp):
        f = _finding()
        ap, lp = _write(
            tmp,
            _audit([_finding(description="Softened wording, same length padding.")]),
            _layer(claim_hashes={f["id"]: compute_claim_hash(f)}),
        )
        return ap, lp

    def test_verify_detects_tamper_and_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            ap, lp = self._tampered(tmp)
            self.assertEqual(baseline_claims.verify(ap, lp), 1)
            ap.write_text(json.dumps(_audit([])))  # baselined finding deleted
            self.assertEqual(baseline_claims.verify(ap, lp), 1)

    def test_cross_validate_layer_errors_on_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            _ap, lp = self._tampered(tmp)
            r = ValidationResult(file_path=str(lp))
            cross_validate_layer(json.loads(lp.read_text()), r)
            self.assertTrue(any("claim hash mismatch" in e for e in r.errors))

    def test_cross_validate_layer_warns_on_corrected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = _finding()
            _ap, lp = _write(
                tmp,
                _audit([_finding(severity="low", validation_status="corrected")]),
                _layer(claim_hashes={f["id"]: compute_claim_hash(f)}),
            )
            r = ValidationResult(file_path=str(lp))
            cross_validate_layer(json.loads(lp.read_text()), r)
            self.assertEqual([e for e in r.errors if "claim" in e], [])
            self.assertTrue(any("re-baseline" in w for w in r.warnings))

    def test_build_cumulative_refuses_tampered_baseline(self):
        f = _finding()
        audit = _audit([_finding(severity="low")])
        layer = _layer(claim_hashes={f["id"]: compute_claim_hash(f)})
        errors, _ = build_cumulative.verify_claim_hashes(audit, layer)
        self.assertTrue(errors)

    def test_sweep_creates_pins_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d1 = root / "product" / "repo-a"
            d1.mkdir(parents=True)
            (d1 / "repo-a-security-audit.json").write_text(
                json.dumps(
                    {
                        "metadata": {
                            "repository": "https://github.com/x/repo-a",
                            "commit": "5427fbae",
                        },
                        "findings": [_finding()],
                    }
                )
            )
            d2 = root / "product" / "repo-b"
            d2.mkdir(parents=True)
            f2 = _finding("002")
            (d2 / "repo-b-security-audit.json").write_text(
                json.dumps({"metadata": {}, "findings": [f2]})
            )
            (d2 / "repo-b-findings-layer.json").write_text(
                json.dumps(_layer("repo-b-security-audit.json"))
            )
            # symlinked duplicate must be skipped
            (root / "dup").mkdir()
            Path.symlink_to(
                d1 / "repo-a-security-audit.json", root / "dup" / "repo-a-security-audit.json"
            )

            self.assertEqual(baseline_claims.sweep(root), 0)
            new_layer = json.loads((d1 / "repo-a-findings-layer.json").read_text())
            self.assertEqual(new_layer["metadata"]["audit_commit"], "5427fbae")
            self.assertIn("EXAMPLE_REPO-abc1234-001", new_layer["metadata"]["claim_hashes"])
            existing = json.loads((d2 / "repo-b-findings-layer.json").read_text())
            self.assertIn(f2["id"], existing["metadata"]["claim_hashes"])
            self.assertFalse((root / "dup" / "repo-a-findings-layer.json").exists())
            # idempotent second pass
            before = (d1 / "repo-a-findings-layer.json").read_text()
            self.assertEqual(baseline_claims.sweep(root), 0)
            self.assertEqual((d1 / "repo-a-findings-layer.json").read_text(), before)

    def test_build_cumulative_accepts_clean_and_prehash_layers(self):
        f = _finding()
        audit = _audit([f])
        clean = _layer(claim_hashes={f["id"]: compute_claim_hash(f)})
        self.assertEqual(build_cumulative.verify_claim_hashes(audit, clean), ([], []))
        legacy = _layer()  # pre-0.39.0 layer, no claim_hashes
        self.assertEqual(build_cumulative.verify_claim_hashes(audit, legacy), ([], []))


if __name__ == "__main__":
    unittest.main()
