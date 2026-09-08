#!/usr/bin/env python3
"""Integration tests for Merkle metadata across ledger write paths."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema
import pytest
from traust_engine.ledger import (
    compute_event_id,
    verify_merkle_integrity,
)
from traust_ledger.client import LedgerClient


def stamp_layer(layer: dict) -> None:
    """Stamp Merkle metadata through LedgerClient — the real write path."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fixture-findings-layer.json"
        p.write_text(json.dumps(layer), encoding="utf-8")
        LedgerClient(token="test-token", data_dir=td).sign("fixture-findings-layer")
        stamped = json.loads(p.read_text())
    layer["metadata"] = stamped["metadata"]


from traust_engine.reporting.validate import (
    SCHEMA_DIR,
    ValidationResult,
    build_registry,
    cross_validate_layer,
    load_schema,
    validate_report,
)

GENERATED_AT = "2026-07-10T12:00:00+00:00"
F1 = "TEST_WIDGET-abcdef0-001"
LAYER_SCHEMA = load_schema(SCHEMA_DIR / "layer.schema.json")
REGISTRY = build_registry()


def _event(
    finding_ref,
    validity=None,
    *,
    at="2026-07-01T10:00:00+00:00",
    ref="https://example.com/mr/17#note_1",
):
    return {
        "event_id": compute_event_id(ref, finding_ref, validity, None),
        "finding_ref": finding_ref,
        "recorded_at": at,
        "source": {
            "type": "mr_comment",
            "ref": ref,
            "actor": {"kind": "human", "identity": "jdoe@example.com", "ldap_verified": True},
        },
        "disposition": {"validity": validity} if validity else {"validity": "confirmed"},
        "rationale": "Because the input is validated upstream in the webhook.",
    }


def _layer(events=()):
    return {
        "metadata": {
            "audit_report": "test-widget-security-audit.json",
            "audit_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "repository": "https://github.com/example/test-widget",
            "created": "2026-06-01T00:00:00+00:00",
            "harness_version": "0.18.0-1234567",
        },
        "events": list(events),
        "needs_review": [],
    }


def _audit():
    return {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-05-21",
            "commit": "abcdef0123456789abcdef0123456789abcdef01",
            "additional": {"harness_version": "0.18.0-1234567"},
        },
        "findings": [
            {
                "id": F1,
                "title": "SSRF via Webhook Annotation",
                "severity": "high",
                "validation_status": "not_verified",
            },
        ],
        "severity_criteria": [
            {"level": "critical", "criteria": "RCE"},
            {"level": "high", "criteria": "serious"},
            {"level": "medium", "criteria": "moderate"},
            {"level": "low", "criteria": "minor"},
        ],
        "findings_summary": [
            {"severity": "high", "count": 1, "finding_ids": [F1]},
        ],
        "executive_summary": {"severity_counts": {"high": 1}},
    }


def _cross(layer: dict) -> ValidationResult:
    result = ValidationResult(file_path="<test>")
    cross_validate_layer(layer, result)
    return result


def _schema_ok(layer: dict) -> bool:
    validator = jsonschema.Draft202012Validator(
        LAYER_SCHEMA,
        format_checker=jsonschema.FormatChecker(),
        registry=REGISTRY,
    )
    return not list(validator.iter_errors(layer))


class TestUpdateLayerMerkleMetadata(unittest.TestCase):
    def test_stamps_fields_on_first_enable(self):
        layer = _layer([_event(F1, validity="confirmed")])
        stamp_layer(layer)
        meta = layer["metadata"]
        self.assertEqual(meta["merkle_epoch"], 0)
        self.assertTrue(meta["merkle_root"])
        self.assertEqual(meta["merkle_size"], len(layer["events"]))
        self.assertEqual(meta["merkle_algorithm"], "sha256")
        self.assertNotIn("pre_merkle_checkpoint", meta)
        self.assertEqual(verify_merkle_integrity(layer), [])
        self.assertTrue(_schema_ok(layer))

    def test_root_changes_when_event_appended(self):
        layer = _layer([_event(F1, validity="confirmed")])
        stamp_layer(layer)
        first_root = layer["metadata"]["merkle_root"]
        layer["events"].append(
            _event(
                F1,
                validity="false_positive",
                ref="https://example.com/mr/18#note_2",
                at="2026-07-02T10:00:00+00:00",
            )
        )
        stamp_layer(layer)
        self.assertNotEqual(first_root, layer["metadata"]["merkle_root"])
        self.assertEqual(layer["metadata"]["merkle_size"], 2)


class TestValidateReportMerkle(unittest.TestCase):
    def _merkle_layer(self):
        layer = _layer(
            [
                _event(F1, validity="confirmed", at="2026-07-01T10:00:00+00:00"),
                _event(
                    F1,
                    validity="false_positive",
                    ref="https://example.com/mr/18#note_2",
                    at="2026-07-02T10:00:00+00:00",
                ),
            ]
        )
        stamp_layer(layer)
        return layer

    def test_valid_merkle_passes(self):
        result = _cross(self._merkle_layer())
        self.assertEqual(result.errors, [])

    def test_missing_merkle_root_errors(self):
        # traust-ledger v0.1.3 (plan P6): an unrooted layer has no
        # tamper-evidence at all, so this is an error rather than a warning.
        layer = _layer([_event(F1, validity="confirmed")])
        result = _cross(layer)
        self.assertTrue(any("merkle_root absent" in e for e in result.errors), result.errors)
        self.assertFalse(any("merkle_root absent" in w for w in result.warnings), result.warnings)

    def test_tampered_event_rejected(self):
        layer = self._merkle_layer()
        layer["events"][0]["finding_ref"] = "TEST_WIDGET-abcdef0-099"
        layer["events"][0]["event_id"] = compute_event_id(
            layer["events"][0]["source"]["ref"],
            "TEST_WIDGET-abcdef0-099",
            layer["events"][0]["disposition"]["validity"],
            None,
        )
        result = _cross(layer)
        self.assertTrue(any("merkle_root mismatch" in e for e in result.errors))

    def test_deleted_event_rejected(self):
        layer = self._merkle_layer()
        layer["events"].pop()
        result = _cross(layer)
        self.assertTrue(any("merkle_root mismatch" in e for e in result.errors))

    def test_reordered_events_rejected(self):
        layer = self._merkle_layer()
        layer["events"].reverse()
        result = _cross(layer)
        self.assertTrue(any("merkle_root mismatch" in e for e in result.errors))

    def test_inserted_event_rejected(self):
        layer = self._merkle_layer()
        layer["events"].insert(
            1,
            _event(
                F1,
                validity="confirmed",
                ref="https://example.com/mr/99#note_9",
                at="2026-07-01T11:00:00+00:00",
            ),
        )
        result = _cross(layer)
        self.assertTrue(any("merkle_root mismatch" in e for e in result.errors))

    def test_wrong_merkle_size_rejected(self):
        layer = self._merkle_layer()
        layer["metadata"]["merkle_size"] = 99
        result = _cross(layer)
        self.assertTrue(any("merkle_size mismatch" in e for e in result.errors))


class TestVerifyMerkleIntegrity(unittest.TestCase):
    def test_verify_rejects_negative_epoch(self):
        layer = _layer([_event(F1, validity="confirmed")])
        stamp_layer(layer)
        layer["metadata"]["merkle_epoch"] = -1
        result = _cross(layer)
        self.assertTrue(any("merkle_epoch is negative" in e for e in result.errors))

    def test_verify_rejects_epoch_equals_event_count(self):
        layer = _layer(
            [
                _event(F1, validity="confirmed", at="2026-07-01T10:00:00+00:00"),
                _event(
                    F1,
                    validity="false_positive",
                    ref="https://example.com/mr/18#note_2",
                    at="2026-07-02T10:00:00+00:00",
                ),
            ]
        )
        stamp_layer(layer)
        layer["metadata"]["merkle_epoch"] = len(layer["events"])
        result = _cross(layer)
        self.assertTrue(any("merkle_epoch equals event count" in e for e in result.errors))

    def test_verify_rejects_epoch_exceeds_event_count(self):
        layer = _layer([_event(F1, validity="confirmed")])
        stamp_layer(layer)
        layer["metadata"]["merkle_epoch"] = len(layer["events"]) + 1
        result = _cross(layer)
        self.assertTrue(any("merkle_epoch exceeds event count" in e for e in result.errors))

    def test_verify_catches_tampered_pre_merkle_checkpoint(self):
        layer = _layer(
            [
                _event(F1, validity="confirmed", at="2026-07-01T10:00:00+00:00"),
                _event(
                    F1,
                    validity="false_positive",
                    ref="https://example.com/mr/18#note_2",
                    at="2026-07-02T10:00:00+00:00",
                ),
            ]
        )
        stamp_layer(layer)
        layer["metadata"]["merkle_epoch"] = 1
        stamp_layer(layer)
        self.assertEqual(verify_merkle_integrity(layer), [])
        layer["events"][0]["rationale"] = "tampered pre-epoch rationale"
        result = _cross(layer)
        self.assertTrue(any("pre_merkle_checkpoint mismatch" in e for e in result.errors))


class TestWritePathMerkleStamp(unittest.TestCase):
    def test_countersign_append_produces_valid_merkle(self):
        from traust.cli.countersign import build_human_event

        layer = _layer([_event(F1, validity="false_positive")])
        actor = {
            "kind": "human",
            "identity": "jdoe@example.com",
            "ldap_verified": True,
        }
        layer["events"].append(
            build_human_event(
                F1,
                "false_positive",
                "Reviewed and agree with the machine refutation.",
                actor,
                "2026-07-03T10:00:00+00:00",
            )
        )
        stamp_layer(layer)
        self.assertEqual(verify_merkle_integrity(layer), [])
        self.assertIn("merkle_root", layer["metadata"])
        self.assertEqual(layer["metadata"]["merkle_size"], 2)
        self.assertEqual(_cross(layer).errors, [])

    @pytest.mark.requires_ledger
    def test_emit_validation_append_produces_valid_merkle(self):
        from traust.cli.emit_validation_ledger_events import append_to_layer

        audit = {
            "metadata": {
                "repository": "https://example.invalid/repoX",
                "commit": "abcdef0123456789abcdef0123456789abcdef01",
            },
            "findings": [{"id": F1, "title": "SSRF", "severity": "high"}],
        }
        bucket = {
            "events": [
                {
                    "event_id": compute_event_id(
                        "validations/prodA/prodA-validation.json",
                        F1,
                        "confirmed",
                        None,
                    ),
                    "finding_ref": F1,
                    "recorded_at": "2026-07-13T12:00:00+00:00",
                    "occurred_at": "2026-06-25T00:00:00+00:00",
                    "source": {
                        "type": "validation_report",
                        "ref": "validations/prodA/prodA-validation.json",
                        "actor": {
                            "kind": "machine",
                            "identity": "validate-findings/0.6.5",
                            "ldap_verified": False,
                        },
                    },
                    "disposition": {"validity": "confirmed"},
                    "rationale": "Confirmed via live validation replay.",
                }
            ],
            "needs_review": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audit_path = tmp_path / "test-widget-security-audit.json"
            layer_path = tmp_path / "test-widget-findings-layer.json"
            audit_path.write_text(json.dumps(audit))
            append_to_layer(
                layer_path,
                audit_path,
                audit,
                bucket,
                "2026-07-13T12:00:00+00:00",
                "0.6.5-1234abc",
            )
            layer = json.loads(layer_path.read_text())
            self.assertEqual(verify_merkle_integrity(layer), [])
            self.assertIn("merkle_root", layer["metadata"])
            self.assertEqual(layer["metadata"]["merkle_size"], 1)
            result = validate_report(str(layer_path), LAYER_SCHEMA, registry=REGISTRY)
            self.assertEqual(result.errors, [])


@pytest.mark.requires_ledger
class TestWritePathIntegration(unittest.TestCase):
    def test_build_cumulative_stamps_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audit_path = tmp_path / "test-widget-security-audit.json"
            layer_path = tmp_path / "test-widget-findings-layer.json"
            audit_path.write_text(json.dumps(_audit()))
            layer_path.write_text(
                json.dumps(
                    _layer(
                        [
                            _event(F1, validity="confirmed"),
                        ]
                    )
                )
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "traust.cli.build_cumulative",
                    str(audit_path),
                    str(layer_path),
                    "--generated-at",
                    GENERATED_AT,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

            layer = json.loads(layer_path.read_text())
            self.assertIn("merkle_root", layer["metadata"])
            self.assertEqual(layer["metadata"]["merkle_algorithm"], "sha256")

            result = validate_report(str(layer_path), LAYER_SCHEMA, registry=REGISTRY)
            self.assertEqual(result.errors, [], result.errors)

    def test_emit_triage_stamps_matching_root(self):
        weights = Path(__file__).parent.parent / "config" / "hardening-risk-weights.example.json"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            triage = {
                "triage_completed": "2026-07-09",
                "triage_context": {"harness_version": "0.27.0-abc1234"},
                "summary": {},
                "findings": [
                    {
                        "id": "f001",
                        "orig_id": F1,
                        "title": "SSRF",
                        "verdict": "true_positive",
                        "verify_verdict": "exploitable",
                        "confidence": 9.0,
                        "severity": "high",
                        "rationale": "reachable at handler.go:73",
                        "vote_breakdown": {"true_positive": 3, "hardening": 0, "false_positive": 0},
                        "refute_reasons": [],
                    }
                ],
            }
            audit = {
                "metadata": {"commit": "abcdef0", "repository": "https://x.invalid"},
                "peach_isolation_review": {"applicable": False},
                "findings": [{"id": F1, "title": "SSRF", "severity": "high"}],
            }
            (tmp_path / "TRIAGE.json").write_text(json.dumps(triage))
            (tmp_path / "audit-security-audit.json").write_text(json.dumps(audit))
            lint = {"results": [{"id": "f001", "status": "ok"}]}
            (tmp_path / "lint.json").write_text(json.dumps(lint))

            cmd = [
                sys.executable,
                "-m",
                "traust.cli.emit_triage_ledger_events",
                str(tmp_path / "TRIAGE.json"),
                "--audit",
                str(tmp_path / "audit-security-audit.json"),
                "--weights",
                str(weights),
                "--lint",
                str(tmp_path / "lint.json"),
                "--recorded-at",
                GENERATED_AT,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)

            layer = json.loads((tmp_path / "audit-findings-layer.json").read_text())
            stamp_layer(layer)
            expected_root = layer["metadata"]["merkle_root"]
            self.assertEqual(layer["metadata"]["merkle_size"], 1)
            self.assertEqual(layer["metadata"]["merkle_root"], expected_root)

            result = validate_report(
                str(tmp_path / "audit-findings-layer.json"), LAYER_SCHEMA, registry=REGISTRY
            )
            self.assertEqual(result.errors, [], result.errors)

    def test_epoch_migration_from_legacy_layer(self):
        layer = _layer(
            [
                _event(F1, validity="confirmed", at="2026-07-01T10:00:00+00:00"),
                _event(
                    F1,
                    validity="false_positive",
                    ref="https://example.com/mr/18#note_2",
                    at="2026-07-02T10:00:00+00:00",
                ),
            ]
        )
        self.assertNotIn("merkle_root", layer["metadata"])
        stamp_layer(layer)
        result = _cross(layer)
        self.assertEqual(result.errors, [])
        self.assertEqual(layer["metadata"]["merkle_epoch"], 0)
        self.assertEqual(layer["metadata"]["merkle_size"], 2)


if __name__ == "__main__":
    unittest.main()
