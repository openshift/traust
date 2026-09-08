#!/usr/bin/env python3
"""Unit tests for traust.cli.route_regressions — verify-remediation
Phase-5 regressions becoming first-class ledger findings (user directive
2026-07-27): campaign-ID compliance, sha-scoped numbering continuation,
fingerprint integrity, ledger birth-event shape, provenance both ways,
and idempotent re-ingest."""

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from traust_engine._util.finding_identity import fingerprint
from traust_engine.reporting.validate import compute_claim_hash

from traust.cli import route_regressions
from traust.cli.build_cumulative import build_cumulative

CAMPAIGN_ID = re.compile(r"^[A-Z][A-Z0-9_]{0,23}-[a-f0-9]{7}-\d{3}$")
REPO_URL = "https://gitlab.example.com/ran/lift"
PATCHED = "47bbd1ebf8de375e21c07a93896082a1f2ba4712"


def _audit(findings=None):
    findings = findings or []
    return {
        "title": "lift Security Audit",
        "metadata": {
            "date": "2026-06-12",
            "scope": "full repository audit",
            "repository": REPO_URL,
            "commit": "3b804aa2db66eb59c998512f6759d68361e65f4e",
        },
        "executive_summary": {
            "prose": "Initial audit of the lift automation repository covering all frameworks.",
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "findings": findings,
        "findings_summary": [
            {"severity": s, "count": 0, "finding_ids": []}
            for s in ("critical", "high", "medium", "low", "informational")
        ],
    }


def _regression(nnn="001", severity="critical"):
    return {
        "id": f"LIFT-{PATCHED[:7]}-REG-{nnn}",
        "title": "sushy-tools emulator deployed without authentication",
        "severity": severity,
        "cwes": ["CWE-306", "CWE-319"],
        "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "locations": [{"path": "roles/sushy_setup/tasks/main.yaml", "lines": "48-80"}],
        "description": "The new sushy_setup role writes an emulator config "
        "with AUTH_FILE=None and binds 0.0.0.0, exposing "
        "unauthenticated BMC control of every libvirt domain.",
        "remediation": "Set SUSHY_EMULATOR_AUTH_FILE and bind to the provisioning interface.",
        "evidence": [{"language": "yaml", "code": "SUSHY_EMULATOR_AUTH_FILE = None"}],
        "introduced_by": "7d919904bbe7244a0b7125e8035dd534abcc1037",
    }


def _verification(regressions):
    return {
        "title": "lift Remediation Verification",
        "metadata": {
            "date": "2026-07-27",
            "original_report": "lift-security-audit.json",
            "original_commit": "3b804aa2db66eb59c998512f6759d68361e65f4e",
            "patched_commit": PATCHED,
            "repository": REPO_URL,
            "scope": "Targeted verification of the lift audit findings",
            "framework": "OWASP ASVS v5.0",
            "auditor": "traust",
            "harness_version": "0.195.0-abc1234",
        },
        "summary": {
            "total_findings": 0,
            "by_verdict": {},
            "regressions": len(regressions),
            "prose": "test",
        },
        "verified_findings": [],
        "regressions": regressions,
        "commit_timeline": [],
    }


class RouteRegressionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.vpath = self.dir / "lift-remediation-verification.json"
        self.apath = self.dir / "lift-security-audit.json"
        self.lpath = self.dir / "lift-findings-layer.json"

        def _make_ledger(*_a, **_kw):
            svc = MagicMock()
            _pending: dict[str, dict] = {}

            def _ensure(layer_path, *, shell=None):
                if layer_path.exists():
                    return json.loads(layer_path.read_text(encoding="utf-8"))
                base = shell or {"events": [], "metadata": {}}
                _pending[str(layer_path)] = base
                return base

            def _patch(layer_path, updates, *, sign=True):
                if layer_path.exists():
                    layer = json.loads(layer_path.read_text(encoding="utf-8"))
                else:
                    layer = _pending.get(str(layer_path), {"events": [], "metadata": {}})
                meta = layer.setdefault("metadata", {})
                for k, v in updates.items():
                    if isinstance(v, dict) and isinstance(meta.get(k), dict):
                        meta[k].update(v)
                    else:
                        meta[k] = v
                layer_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")

            def _submit(layer_path, events, *, report_path=None, queue_items=None):
                if layer_path.exists():
                    layer = json.loads(layer_path.read_text(encoding="utf-8"))
                else:
                    layer = _pending.pop(str(layer_path), {"events": [], "metadata": {}})
                seen = {e.get("event_id") for e in layer.get("events", [])}
                for ev in events:
                    if ev.get("event_id") not in seen:
                        layer.setdefault("events", []).append(ev)
                        seen.add(ev.get("event_id"))
                layer.setdefault("metadata", {})["merkle_size"] = len(layer["events"])
                if report_path is not None:
                    digest = hashlib.sha256(Path(report_path).read_bytes()).hexdigest()
                    layer.setdefault("metadata", {})["audit_report_sha256"] = digest
                layer_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")

            svc.ensure_layer_file.side_effect = _ensure
            svc.patch_layer_file.side_effect = _patch
            svc.submit_events.side_effect = _submit
            return svc

        p = patch(
            "traust.cli.route_regressions.LedgerService",
            side_effect=_make_ledger,
        )
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, audit, regressions, recorded_at="2026-07-27T23:00:00+00:00"):
        self.apath.write_text(json.dumps(audit))
        self.vpath.write_text(json.dumps(_verification(regressions)))
        return route_regressions.route(
            self.vpath, self.apath, self.lpath, recorded_at, dry_run=False
        )

    def _carried(self, fid=None):
        """The routed finding — on its EVENT since B4, not the baseline.

        Only the three secure*audit skills may write a baseline (gate A15), so a
        routed regression rides on its ledger event and build_cumulative unions
        it back at replay.
        """
        layer = json.loads(self.lpath.read_text())
        carried = [e["finding"] for e in layer.get("events", []) if e.get("finding")]
        if fid is None:
            return carried[-1]
        return next(f for f in carried if f["id"] == fid)

    def test_routes_regression_as_campaign_id_finding(self):
        result = self._run(_audit(), [_regression()])
        self.assertEqual(len(result["routed"]), 1)
        routed_id = result["routed"][0]["routed_id"]
        self.assertEqual(routed_id, f"LIFT-{PATCHED[:7]}-001")
        self.assertRegex(routed_id, CAMPAIGN_ID)

        audit = json.loads(self.apath.read_text())
        # B4 — the baseline is NOT appended to.
        self.assertEqual(audit["findings"], [], "route_regressions must not write the baseline")
        f = self._carried()
        self.assertEqual(f["id"], routed_id)
        self.assertEqual(f["validation_status"], "not_verified")
        self.assertEqual(f["origin"], "verify-remediation")
        # Provenance both ways: REG id + verification report on the finding…
        self.assertIn(f"LIFT-{PATCHED[:7]}-REG-001", f["source_findings"])
        self.assertIn("lift-remediation-verification.json", " ".join(f["source_findings"]))
        # …and routed_id on the verification report's regression entry.
        verification = json.loads(self.vpath.read_text())
        self.assertEqual(verification["regressions"][0]["routed_id"], routed_id)

    def test_baseline_summaries_are_left_alone(self):
        """B4 replaces the old summary-consistency test.

        The baseline's findings_summary / executive_summary describe the AUDIT's
        claim set. A routed regression is not in it, so those counts must not
        move — keeping them consistent was only necessary while this router
        appended to the baseline.
        """
        self._run(
            _audit(), [_regression(severity="critical"), _regression(nnn="002", severity="high")]
        )
        audit = json.loads(self.apath.read_text())
        by_sev = {e["severity"]: e for e in audit["findings_summary"]}
        self.assertEqual(by_sev["critical"]["count"], 0)
        self.assertEqual(by_sev["high"]["count"], 0)
        counts = audit["executive_summary"]["severity_counts"]
        self.assertEqual((counts["critical"], counts["high"]), (0, 0))
        # Both regressions are on events, with their severities intact.
        sevs = sorted(
            f["severity"]
            for f in [
                self._carried(f"LIFT-{PATCHED[:7]}-001"),
                self._carried(f"LIFT-{PATCHED[:7]}-002"),
            ]
        )
        self.assertEqual(sevs, ["critical", "high"])

    def test_numbering_continues_at_the_patched_sha(self):
        existing = {
            "id": f"LIFT-{PATCHED[:7]}-004",
            "title": "Existing finding already minted at the patched sha",
            "severity": "low",
            "cwes": ["CWE-1"],
            "locations": [{"path": "x.yaml", "lines": "1"}],
            "description": "Pre-existing finding at the same sha to prove "
            "sequence continuation, not restart.",
            "remediation": "n/a for this fixture",
            "validation_status": "not_verified",
        }
        audit = _audit([existing])
        audit["findings_summary"][3]["count"] = 1
        audit["findings_summary"][3]["finding_ids"] = [existing["id"]]
        audit["executive_summary"]["severity_counts"]["low"] = 1
        result = self._run(audit, [_regression()])
        self.assertEqual(result["routed"][0]["routed_id"], f"LIFT-{PATCHED[:7]}-005")

    def test_fingerprint_and_claim_hash_are_canonical(self):
        self._run(_audit(), [_regression()])
        layer = json.loads(self.lpath.read_text())
        f = self._carried()
        self.assertEqual(f["fingerprint"], fingerprint(f, REPO_URL))
        self.assertEqual(layer["metadata"]["claim_hashes"][f["id"]], compute_claim_hash(f))

    def test_ledger_birth_event_shape(self):
        self._run(_audit(), [_regression()])
        layer = json.loads(self.lpath.read_text())
        self.assertEqual(len(layer["events"]), 1)
        e = layer["events"][0]
        self.assertEqual(e["finding_ref"], f"LIFT-{PATCHED[:7]}-001")
        self.assertEqual(e["source"]["type"], "verification_report")
        self.assertEqual(
            e["source"]["actor"], {"kind": "machine", "identity": "verify-remediation"}
        )
        # Birth disposition: resolution open, validity NEVER set by an event
        # (not_verified is the audit-stage default).
        self.assertEqual(e["disposition"], {"resolution": "open"})
        # Canonical idempotency key.
        payload = f"{e['source']['ref']}|{e['finding_ref']}||open"
        self.assertEqual(e["event_id"], hashlib.sha256(payload.encode()).hexdigest())
        self.assertIn(e["source"]["ref"], e["evidence_refs"])
        self.assertEqual(e["occurred_at"], "2026-07-27T00:00:00+00:00")
        # Merkle metadata stamped on write.
        self.assertEqual(layer["metadata"]["merkle_size"], 1)

    def test_reingest_is_idempotent(self):
        self._run(_audit(), [_regression()])
        result2 = route_regressions.route(
            self.vpath, self.apath, self.lpath, "2026-07-28T00:00:00+00:00", dry_run=False
        )
        self.assertEqual(result2["routed"], [])
        self.assertEqual(len(result2["skipped"]), 1)
        self.assertEqual(result2["skipped"][0]["reason"], "already_routed")
        self.assertEqual(result2["events"], 0)
        audit = json.loads(self.apath.read_text())
        layer = json.loads(self.lpath.read_text())
        # B4 — nothing in the baseline; exactly one event-carried finding, and a
        # re-run adds neither. Idempotence now depends on the dedupe scan
        # reading event-carried source_findings back-references.
        self.assertEqual(audit["findings"], [])
        self.assertEqual(len(layer["events"]), 1)
        carried = [e for e in layer["events"] if e.get("finding")]
        self.assertEqual(len(carried), 1)

    def test_no_regressions_is_a_noop(self):
        result = self._run(_audit(), [])
        self.assertEqual(result["regressions"], 0)
        self.assertFalse(self.lpath.exists())

    def test_cumulative_shows_routed_finding_open_not_verified(self):
        self._run(_audit(), [_regression()])
        audit = json.loads(self.apath.read_text())
        layer = json.loads(self.lpath.read_text())
        report = build_cumulative(
            audit, layer, "lift-findings-layer.json", "2026-07-28T00:00:00+00:00"
        )
        f = report["findings"][-1]
        self.assertEqual(f["disposition"]["validity"], "not_verified")
        self.assertEqual(f["disposition"]["resolution"], "open")
        ds = report["disposition_summary"]
        self.assertEqual(ds["by_resolution"]["open"], 1)
        self.assertEqual(ds["by_validity"]["not_verified"], 1)


if __name__ == "__main__":
    unittest.main()


class B4RegressionLinkTest(RouteRegressionsTest):
    """B4 — the fingerprint link, and end-to-end visibility."""

    def test_fingerprint_match_records_the_original_id(self):
        """Decision 2026-08-17: a returning vulnerability stays a NEW finding at
        the patched sha, but records the link instead of leaving it inferable."""
        audit = _audit()
        reg = _regression()
        # Pre-seed the baseline with a finding whose claim matches the
        # regression, so their fingerprints collide.
        probe = route_regressions.transcribe(reg, "LIFT-aaaaaaa-001", REPO_URL, "v.json")
        audit["findings"].append(
            {
                "id": "LIFT-aaaaaaa-001",
                "title": probe["title"],
                "severity": probe["severity"],
                "cwes": probe["cwes"],
                "locations": probe["locations"],
                "description": probe["description"],
                "remediation": probe["remediation"],
                "fingerprint": probe["fingerprint"],
            }
        )
        self._run(audit, [reg])
        f = self._carried()
        self.assertNotEqual(f["id"], "LIFT-aaaaaaa-001", "a regression stays a NEW finding")
        self.assertIn(
            "LIFT-aaaaaaa-001", f["source_findings"], "the original finding id must be linked"
        )

    def test_no_link_when_fingerprints_differ(self):
        audit = _audit()
        audit["findings"].append(
            {
                "id": "LIFT-aaaaaaa-001",
                "title": "unrelated",
                "severity": "low",
                "cwes": ["CWE-1"],
                "locations": [{"path": "other.go"}],
                "description": "d",
                "remediation": "r",
                "fingerprint": "0" * 64,
            }
        )
        self._run(audit, [_regression()])
        self.assertNotIn("LIFT-aaaaaaa-001", self._carried()["source_findings"])

    def test_two_regressions_get_distinct_ids(self):
        """The in-run accumulation guard: next_sequence reads event-carried ids,
        so without appending the birth event in-loop both would mint -001."""
        self._run(_audit(), [_regression(), _regression(nnn="002", severity="high")])
        layer = json.loads(self.lpath.read_text())
        ids = sorted(e["finding"]["id"] for e in layer["events"] if e.get("finding"))
        self.assertEqual(ids, [f"LIFT-{PATCHED[:7]}-001", f"LIFT-{PATCHED[:7]}-002"])

    def test_routed_regression_is_visible_in_the_projection(self):
        from traust.cli.build_cumulative import build_cumulative

        self._run(_audit(), [_regression()])
        audit = json.loads(self.apath.read_text())
        layer = json.loads(self.lpath.read_text())
        self.assertEqual(audit["findings"], [])
        audit.setdefault("title", "Security Assessment — lift")
        report = build_cumulative(
            audit, layer, "lift-findings-layer.json", "2026-08-17T12:00:00+00:00"
        )
        ids = {f["id"] for f in report["findings"]}
        self.assertIn(f"LIFT-{PATCHED[:7]}-001", ids)
