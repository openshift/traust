#!/usr/bin/env python3
"""Tests for the isolation-review skill (Phase 0):
fixture reports validated against schema/isolation-review.schema.json and
against the stdlib validator (validate_isolation_review.py) — the two gates
must agree."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

from traust.paths import skill_dir

ROOT = Path(__file__).resolve().parent.parent

_SPEC = importlib.util.spec_from_file_location(
    "validate_isolation_review",
    skill_dir("isolation-review") / "scripts" / "validate_isolation_review.py",
)
vir = importlib.util.module_from_spec(_SPEC)
sys.modules["validate_isolation_review"] = vir
_SPEC.loader.exec_module(vir)


def _schema():
    from traust_contracts.paths import schema_path as _sp

    return json.loads(_sp("isolation-review").read_text(encoding="utf-8"))


def _dim(result="yes", evidence=None, rationale="ok"):
    d = {"result": result, "rationale": rationale}
    if evidence is not None:
        d["evidence"] = evidence
    return d


def _valid_report():
    return {
        "title": "Tenant-isolation review: example-service",
        "metadata": {
            "service": "example-service",
            "repos": ["github.com/example/api-server", "github.com/example/worker"],
            "graph_ref": "analysis-results/graph/portfolio-graph.db@abc1234",
            "harness_version": "0.117.0-deadbee",
            "reviewed_at": "2026-07-20T00:00:00Z",
            "framework": "PEACH v1.1 (by reference)",
        },
        "interfaces": [
            {
                "id": "IF-1",
                "name": "tenant REST API",
                "kind": "api",
                "exposure": "tenant",
                "complexity": "medium",
                "shared_instance": True,
                "repos": ["github.com/example/api-server"],
                "dimensions": {
                    "privilege": _dim("yes"),
                    "encryption": _dim(
                        "partial",
                        evidence=["github.com/example/api-server//pkg/store/keys.go:42"],
                        rationale="one service-wide key over tenant rows",
                    ),
                    "authentication": _dim("yes"),
                    "connectivity": _dim(
                        "no",
                        evidence=["EXAMPLE-abc1234-003"],
                        rationale="no deny-by-default between tenants",
                    ),
                    "hygiene": _dim(
                        "na", rationale="no tenant-visible operational surface on this path"
                    ),
                },
            }
        ],
        "gaps": [
            {
                "severity": "high",
                "interface_id": "IF-1",
                "description": "connectivity separation absent on the tenant REST API path",
                "remediation": "add default-deny NetworkPolicy between tenant namespaces",
            }
        ],
        "posture": {
            "overall": "weak",
            "summary": "One shared API instance with a connectivity gap; "
            "highest-payoff fix is default-deny between tenants.",
            "interfaces_reviewed": 1,
            "dimension_rollup": {"yes": 2, "partial": 1, "no": 1, "na": 1},
        },
    }


class TestSchemaFixture(unittest.TestCase):
    def test_valid_report_passes_jsonschema(self):
        import jsonschema

        jsonschema.validate(_valid_report(), _schema())

    def test_uncited_partial_fails_jsonschema(self):
        import jsonschema

        bad = _valid_report()
        del bad["interfaces"][0]["dimensions"]["encryption"]["evidence"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, _schema())

    def test_bad_enum_fails_jsonschema(self):
        import jsonschema

        bad = _valid_report()
        bad["interfaces"][0]["complexity"] = "extreme"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, _schema())

    def test_missing_posture_fails_jsonschema(self):
        import jsonschema

        bad = _valid_report()
        del bad["posture"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, _schema())


class TestStdlibValidator(unittest.TestCase):
    """The stdlib gate must agree with the schema on the same fixtures."""

    def test_valid_report_passes(self):
        self.assertEqual(vir.validate(_valid_report()), [])

    def test_uncited_no_result_rejected(self):
        bad = _valid_report()
        bad["interfaces"][0]["dimensions"]["connectivity"] = {
            "result": "no",
            "rationale": "uncited",
        }
        errs = vir.validate(bad)
        self.assertTrue(any("evidence" in e for e in errs), errs)

    def test_every_dimension_required(self):
        bad = _valid_report()
        del bad["interfaces"][0]["dimensions"]["hygiene"]
        errs = vir.validate(bad)
        self.assertTrue(any("hygiene" in e for e in errs), errs)

    def test_gap_must_reference_known_interface(self):
        bad = _valid_report()
        bad["gaps"][0]["interface_id"] = "IF-99"
        errs = vir.validate(bad)
        self.assertTrue(any("IF-99" in e for e in errs), errs)

    def test_bad_severity_rejected(self):
        bad = _valid_report()
        bad["gaps"][0]["severity"] = "urgent"
        errs = vir.validate(bad)
        self.assertTrue(any("severity" in e for e in errs), errs)

    def test_missing_metadata_keys_rejected(self):
        bad = _valid_report()
        del bad["metadata"]["graph_ref"]
        errs = vir.validate(bad)
        self.assertTrue(any("graph_ref" in e for e in errs), errs)

    def test_cli_roundtrip(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            good = Path(td) / "good.json"
            good.write_text(json.dumps(_valid_report()), encoding="utf-8")
            self.assertEqual(vir.validate_file(good), 0)
            bad_doc = _valid_report()
            bad_doc["posture"]["overall"] = "fine"
            bad = Path(td) / "bad.json"
            bad.write_text(json.dumps(bad_doc), encoding="utf-8")
            self.assertEqual(vir.validate_file(bad), 1)


class TestLicensingGuardrail(unittest.TestCase):
    """The skill must state the by-reference-only rule and must itself stay
    clean under the license fingerprint gate."""

    def test_skill_states_by_reference_rule(self):
        text = (skill_dir("isolation-review") / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("by reference only", text.lower())
        self.assertIn("check_content_licenses", text)

    def test_dimension_keys_match_schema(self):
        schema = _schema()
        self.assertEqual(
            set(schema["definitions"]["interface"]["properties"]["dimensions"]["required"]),
            set(vir.DIMENSIONS),
        )


if __name__ == "__main__":
    unittest.main()
