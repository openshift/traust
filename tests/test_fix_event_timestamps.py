"""`fix_event_timestamps`: pure repair logic, then end-to-end with signing unavailable.

Signing-unavailable is the normal workstation state and the one that produced
the 2026-08-31 incident, where 112 layers were written re-rooted and unsigned
while the migration reported success.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from traust_contracts.v1.timestamps import is_rfc3339

from traust.migrations.fix_event_timestamps import (
    converted,
    dropped,
    repair_events,
    unrepairable,
)

REPO = Path(__file__).resolve().parent.parent
MODULE = "traust.migrations.fix_event_timestamps"

CORRUPT = "TrueT00:00:00+00:00"
BARE_DATE = "2026-07-20"
GOOD = "2026-06-24T00:00:00+00:00"


def _event(**overrides: object) -> dict:
    return {"event_id": "e1", "recorded_at": GOOD, **overrides}


class TestRepairEvents:
    """Both timestamp fields take the same path; only droppability differs."""

    @pytest.mark.parametrize("field_name", ["recorded_at", "occurred_at"])
    def test_bare_date_is_converted(self, field_name: str) -> None:
        events = [_event(**{field_name: BARE_DATE})]
        repair = repair_events(events)

        assert repair.problems == []
        assert repair.counts[converted(field_name)] == 1
        assert events[0][field_name] == f"{BARE_DATE}T00:00:00+00:00"
        assert is_rfc3339(events[0][field_name])

    def test_converting_recorded_at_preserves_the_event_id_day_key(self) -> None:
        """Every consumer slices [:10]; padding must not move it."""
        events = [_event(recorded_at=BARE_DATE)]
        repair_events(events)
        assert events[0]["recorded_at"][:10] == BARE_DATE

    def test_unconvertible_occurred_at_is_dropped(self) -> None:
        events = [_event(occurred_at=CORRUPT), _event(event_id="e2", occurred_at=GOOD)]
        repair = repair_events(events)

        assert repair.problems == []
        assert repair.counts[dropped("occurred_at")] == 1
        assert "occurred_at" not in events[0]
        assert events[0]["recorded_at"] == GOOD
        assert events[1]["occurred_at"] == GOOD

    def test_unconvertible_recorded_at_is_reported_not_dropped(self) -> None:
        """Required, so inventing a value is the only alternative to refusing."""
        events = [{"event_id": "e1", "recorded_at": CORRUPT}]
        repair = repair_events(events)

        assert repair.changed == 0
        assert repair.counts[unrepairable("recorded_at")] == 1
        assert len(repair.problems) == 1
        assert events[0]["recorded_at"] == CORRUPT

    @pytest.mark.parametrize("field_name", ["recorded_at", "occurred_at"])
    def test_absent_field_is_not_added(self, field_name: str) -> None:
        events = [{"event_id": "e1"}]
        assert repair_events(events).changed == 0
        assert field_name not in events[0]

    def test_conforming_event_is_untouched(self) -> None:
        assert repair_events([_event(occurred_at=GOOD)]).changed == 0

    @pytest.mark.parametrize("field_name", ["recorded_at", "occurred_at"])
    @pytest.mark.parametrize("value", [CORRUPT, BARE_DATE])
    def test_idempotent(self, field_name: str, value: str) -> None:
        events = [_event(**{field_name: value})]
        first = repair_events(events).changed
        assert repair_events(events).changed == 0
        assert first <= 1

    def test_both_fields_repaired_in_one_pass(self) -> None:
        events = [_event(recorded_at=BARE_DATE, occurred_at=CORRUPT)]
        repair = repair_events(events)

        assert repair.counts[converted("recorded_at")] == 1
        assert repair.counts[dropped("occurred_at")] == 1
        assert repair.changed == 2

    def test_event_id_never_changes(self) -> None:
        events = [_event(event_id="a" * 64, occurred_at=CORRUPT)]
        repair_events(events)
        assert events[0]["event_id"] == "a" * 64


AUDIT = {
    "title": "probe audit",
    "metadata": {"repository": "https://example.com/probe"},
    "findings": [
        {
            "id": "FIND-001",
            "title": "probe finding",
            "severity": "medium",
            "cwes": ["CWE-79"],
            "locations": [{"path": "cmd/main.go", "line": 10}],
            "fingerprint": "b" * 64,
            "fingerprint_algo": "v2",
        }
    ],
}


def _layer(*, signed: bool, occurred_at: str | None = CORRUPT) -> dict:
    metadata = {
        "audit_report": "probe-security-audit.json",
        "repository": "https://example.com/probe",
        "created": GOOD,
        "harness_version": "0.1.0",
        "claim_hashes": {},
        "merkle_epoch": 0,
        "leaf_format": 2,
    }
    if signed:
        metadata |= {
            "merkle_root_signature": '{"mediaType":"application/probe"}',
            "merkle_signing_method": "keypair",
            "merkle_signature_format": 4,
        }
    event = {
        "event_id": "a" * 64,
        "finding_ref": "FIND-001",
        "recorded_at": GOOD,
        "source": {
            "type": "triage_report",
            "ref": "probe-triage.json",
            "actor": {"kind": "machine", "identity": "triage/0.1.0"},
        },
        "disposition": {"validity": "confirmed"},
        "rationale": "probe rationale long enough to pass gates",
    }
    if occurred_at is not None:
        event["occurred_at"] = occurred_at
    return {"metadata": metadata, "events": [event], "needs_review": []}


def _with_real_merkle_root(layer: dict) -> dict:
    """A fake root takes a different sign() path and hides the incident."""
    import tempfile

    from traust_ledger.client import LedgerClient

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture-findings-layer.json"
        path.write_text(json.dumps(layer), encoding="utf-8")
        LedgerClient(token="test-token", data_dir=tmp).sign("fixture-findings-layer")
        layer.update(json.loads(path.read_text()))
    return layer


def _corpus(root: Path, *, signed: bool, occurred_at: str | None = CORRUPT) -> Path:
    repo = root / "probe"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "probe-security-audit.json").write_text(json.dumps(AUDIT), encoding="utf-8")
    layer_path = repo / "probe-findings-layer.json"
    layer_path.write_text(
        json.dumps(
            _with_real_merkle_root(_layer(signed=signed, occurred_at=occurred_at)), indent=2
        ),
        encoding="utf-8",
    )
    return layer_path


def _run(root: Path, *extra: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, "-m", MODULE, str(root), *extra],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
            "LEDGER_LOCAL_IDENTITY": "probe@example.com",
            # Without this, load_engine exits before doing any work and every
            # "file unchanged" assertion below would pass vacuously.
            "TRAUST_CONFIG_HOME": os.environ["TRAUST_CONFIG_HOME"],
        },
        timeout=300,
    )
    if "layer files" not in result.stdout:
        pytest.fail(
            f"migration did not run; assertions would be vacuous.\n"
            f"rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


class TestEndToEnd:
    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        layer_path = _corpus(tmp_path, signed=False)
        before = layer_path.read_bytes()
        result = _run(tmp_path)

        assert layer_path.read_bytes() == before
        assert "DRY RUN" in result.stdout
        assert dropped("occurred_at") in result.stdout

    def test_apply_drops_field_and_re_roots(self, tmp_path: Path) -> None:
        layer_path = _corpus(tmp_path, signed=False)
        before = json.loads(layer_path.read_text())
        result = _run(tmp_path, "--apply")

        after = json.loads(layer_path.read_text())
        event = after["events"][0]
        assert "occurred_at" not in event, result.stdout
        assert event["recorded_at"] == GOOD
        assert event["event_id"] == "a" * 64
        assert after["metadata"]["merkle_root"] != before["metadata"]["merkle_root"]
        assert after["metadata"]["claim_hashes"] == before["metadata"]["claim_hashes"]

    def test_apply_is_idempotent(self, tmp_path: Path) -> None:
        layer_path = _corpus(tmp_path, signed=False)
        _run(tmp_path, "--apply")
        once = layer_path.read_bytes()
        second = _run(tmp_path, "--apply")

        assert layer_path.read_bytes() == once
        assert dropped("occurred_at") not in second.stdout

    def test_clean_layer_is_untouched(self, tmp_path: Path) -> None:
        layer_path = _corpus(tmp_path, signed=False, occurred_at=GOOD)
        before = layer_path.read_bytes()
        _run(tmp_path, "--apply")

        assert layer_path.read_bytes() == before

    def test_signed_layer_is_never_left_unsigned(self, tmp_path: Path) -> None:
        layer_path = _corpus(tmp_path, signed=True)
        result = _run(tmp_path, "--apply")

        metadata = json.loads(layer_path.read_text())["metadata"]
        assert metadata.get("merkle_root_signature"), result.stdout

    def test_refused_write_restores_byte_exactly_and_reports(self, tmp_path: Path) -> None:
        layer_path = _corpus(tmp_path, signed=True)
        before = layer_path.read_bytes()
        result = _run(tmp_path, "--apply")

        assert layer_path.read_bytes() == before
        assert result.returncode == 1
