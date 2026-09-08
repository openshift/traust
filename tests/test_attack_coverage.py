#!/usr/bin/env python3
"""Tests for the vendored ATT&CK tables and attack_refs validator."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

import attack_refs


class TestAttackTables(unittest.TestCase):
    def test_mapping_validates_against_schema(self):
        import jsonschema

        mapping = attack_refs.load_mapping()
        from traust_contracts.paths import schema_path as _sp

        schema = json.loads(_sp("attack-mapping").read_text())
        jsonschema.validate(mapping, schema)

    def test_mapping_referential_integrity(self):
        self.assertEqual(attack_refs.validate_tables(), [])

    def test_pinned_table_is_plausible(self):
        t = attack_refs.load_techniques()
        self.assertGreater(t["counts"]["techniques"], 500)
        self.assertIn("attribution", t)
        self.assertIn("MITRE", t["attribution"])
        self.assertEqual(t["attack_version"], t.get("attack_version"))
        esc = t["techniques"]["T1611"]
        self.assertEqual(esc["name"], "Escape to Host")
        self.assertTrue(esc["containers"])

    def test_validate_ids_rejects_bad_refs(self):
        self.assertEqual(attack_refs.validate_ids(["T1611"]), [])
        errs = attack_refs.validate_ids(["T9999", "not-an-id", "T1562"])
        self.assertEqual(len(errs), 3)
        self.assertIn("revoked", " ".join(errs))

    def test_capability_map_covers_chain_capabilities(self):
        cm = attack_refs.capability_map()
        for cap in (
            "pod-exec",
            "host-exec",
            "secret-read",
            "sa-token",
            "rbac-escalation",
            "cluster-admin",
            "etcd-access",
        ):
            self.assertIn(cap, cm)
            self.assertTrue(cm[cap])

    def test_category_map_covers_report_vocabulary(self):
        vocab = {
            "injection",
            "authentication",
            "authorization",
            "secrets-management",
            "supply-chain",
            "insecure-workload-config",
            "network-exposure",
            "cryptography",
            "input-validation",
            "path-traversal",
            "cross-site-scripting",
            "ssrf",
            "resource-management",
            "logging-monitoring",
            "data-exposure",
            "tenant-isolation",
        }
        self.assertEqual(set(attack_refs.category_map()), vocab)


if __name__ == "__main__":
    unittest.main()
