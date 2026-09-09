"""Tests for the integrity P0 fixes (self-audit -001/-002):
salted fail-closed FP audit valve and path confinement.

Countersigner identity is now verified from the signer's OIDC token by
the SDK (LedgerService.whoami); the old LDAP authenticated-bind path and
its tests were retired with the ledger→SDK migration (MR-2)."""

import unittest
from pathlib import Path
from unittest import mock

from traust.cli import emit_triage_ledger_events as etle


class TestValveSalted(unittest.TestCase):
    EVENT = {
        "finding_ref": "R-abc1234-001",
        "occurred_at": "2026-07-28T00:00:00+00:00",
        "disposition": {"validity": "false_positive"},
        "rationale": "unanimous fp",
        "evidence_refs": ["t.json"],
    }

    def test_fail_closed_without_salt(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            # no HARNESS_VALVE_SALT -> EVERY auto-accept queues for audit
            self.assertTrue(etle._valve_sampled(self.EVENT))
            self.assertTrue(etle._valve_sampled({**self.EVENT, "finding_ref": "R-abc1234-002"}))

    def test_salted_sampling_is_salt_dependent(self):
        # the agent cannot predict the sample without the secret salt:
        # different salts must not produce identical sampling decisions
        # across a spread of events
        decisions = {}
        for salt in ("salt-a", "salt-b"):
            with mock.patch.dict("os.environ", {"HARNESS_VALVE_SALT": salt}):
                decisions[salt] = [
                    etle._valve_sampled({**self.EVENT, "finding_ref": f"R-abc1234-{i:03d}"})
                    for i in range(200)
                ]
        self.assertNotEqual(decisions["salt-a"], decisions["salt-b"])
        # and the salted sample is ~1/10, not all-or-nothing
        hits = sum(decisions["salt-a"])
        self.assertGreater(hits, 0)
        self.assertLess(hits, 200)

    def test_event_id_no_longer_drives_sampling(self):
        # grinding event_id (via finding NNN renumbering) changed the old
        # key; the new key ignores event_id entirely
        with mock.patch.dict("os.environ", {"HARNESS_VALVE_SALT": "s"}):
            a = etle._valve_sampled({**self.EVENT, "event_id": "0" * 64})
            b = etle._valve_sampled({**self.EVENT, "event_id": "f" * 64})
        self.assertEqual(a, b)


class TestConfinePath(unittest.TestCase):
    def test_inside_root_ok(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "verdict-lint.json"
            p.write_text("{}")
            out = etle._confine_path(str(p), [Path(tmp)], "--lint")
            self.assertEqual(out, p.resolve())

    def test_outside_root_refused(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(SystemExit):
            etle._confine_path("/etc/passwd", [Path(tmp)], "--lint")


if __name__ == "__main__":
    unittest.main()
