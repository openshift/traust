"""`backfill_event_fingerprints` must not leave a signed layer unsigned.

Stamping a fingerprint changes the event, which changes the leaf under
`leaf_format 2`, which moves the Merkle root and voids the signature. The
migration therefore re-signs. When it *can't*, two separate defects turned that
into silent damage on 2026-08-31 — 112 signed corpus layers written re-rooted and
unsigned:

1. **The layer was written before signing.** Every failure path then `continue`d
   with the modified file already on disk, while the tally reported
   ``sign failed — NOT written``. The label was false: it *was* written, and
   written unsigned.

2. **The check could not see the damage.** `verify_merkle_signature` reports no
   error on an unsigned layer — there is no signature to fail — so gating on it
   alone calls an unsigned layer clean. The presence of a signature has to be
   asserted separately.

These tests drive the migration with signing unavailable, which is the state that
produced the incident (and the normal state on a workstation, since the key lives
in Vault).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MODULE = "traust.migrations.backfill_event_fingerprints"

# `build_index` maps finding_ref -> fingerprint from the baseline, so the audit
# finding must carry one — an unstamped baseline yields an empty index and the
# migration correctly skips the layer as "no resolvable baseline".
FINDING = {
    "id": "FIND-001",
    "title": "probe finding",
    "severity": "medium",
    "cwes": ["CWE-79"],
    "locations": [{"path": "cmd/main.go", "line": 10}],
    "fingerprint": "b" * 64,
    "fingerprint_algo": "v2",
}

AUDIT = {
    "title": "probe audit",
    "metadata": {"repository": "https://example.com/probe"},
    "findings": [FINDING],
}


def _layer(signed: bool) -> dict:
    meta = {
        "audit_report": "probe-security-audit.json",
        "repository": "https://example.com/probe",
        "created": "2026-08-31T00:00:00+00:00",
        "claim_hashes": {},
        "merkle_epoch": 0,
        "leaf_format": 2,
    }
    if signed:
        # A stale-but-present signature is what a real signed layer carries before
        # its root moves. The value need not verify; these tests are about whether
        # the field survives, and about what the migration claims it did.
        meta["merkle_root_signature"] = '{"mediaType":"application/probe"}'
        meta["merkle_signing_method"] = "keypair"
        meta["merkle_signature_format"] = 4
    return {
        "metadata": meta,
        "events": [
            {
                "event_id": "a" * 64,
                "finding_ref": "FIND-001",
                "recorded_at": "2026-08-31T00:00:00+00:00",
                "source": {
                    "type": "triage_report",
                    "ref": "probe-triage.json",
                    "actor": {"kind": "machine", "identity": "probe/1.0"},
                },
                "disposition": {"validity": "confirmed"},
                "rationale": "probe",
            }
        ],
        "needs_review": [],
    }


def _realistic(layer: dict) -> dict:
    """Give the layer a genuine Merkle root, as a corpus layer has.

    A first fixture set only `merkle_epoch`/`leaf_format`, leaving `merkle_root`
    absent — and `sign()` takes a different path on a layer that has never been
    rooted, so the incident did not reproduce and the tests passed against the
    unfixed code. The root has to be real for the signature to be droppable.
    """
    import tempfile

    from traust_ledger.client import LedgerClient

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fixture-findings-layer.json"
        p.write_text(json.dumps(layer), encoding="utf-8")
        LedgerClient(token="test-token", data_dir=td).sign("fixture-findings-layer")
        layer.update(json.loads(p.read_text()))
    return layer


@pytest.fixture
def corpus(tmp_path):
    d = tmp_path / "probe"
    d.mkdir()
    (d / "probe-security-audit.json").write_text(json.dumps(AUDIT), encoding="utf-8")
    layer = d / "probe-findings-layer.json"
    layer.write_text(json.dumps(_realistic(_layer(signed=True)), indent=2), encoding="utf-8")
    return tmp_path, layer


def _run(root: Path, *extra: str) -> subprocess.CompletedProcess:
    """Run the migration with signing unavailable, in a subprocess.

    A subprocess so the stripped environment cannot leak into other tests, and so
    this exercises the module exactly as an operator invokes it.
    """
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "LEDGER_LOCAL_IDENTITY": "probe@example.com",
    }
    cmd = [sys.executable, "-m", MODULE, str(root), *extra]
    if cfg_home := os.environ.get("TRAUST_CONFIG_HOME"):
        env["TRAUST_CONFIG_HOME"] = cfg_home
        cmd.extend(["--config-home", cfg_home])
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO,
        env=env,
        timeout=300,
    )


def test_a_signed_layer_is_never_left_unsigned(corpus):
    """The core property: signing unavailable must mean nothing was written."""
    root, layer_path = corpus
    before = layer_path.read_bytes()

    result = _run(root, "--apply")

    after = json.loads(layer_path.read_text())
    meta = after["metadata"]
    assert meta.get("merkle_root_signature"), (
        "layer arrived signed and is now UNSIGNED — the migration wrote it before "
        f"signing and could not re-sign.\nstdout:\n{result.stdout}"
    )
    # Either it re-signed successfully, or it restored — never a half-written state.
    stamped = any(e.get("fingerprint") for e in after["events"])
    if not stamped:
        assert layer_path.read_bytes() == before, (
            "nothing was stamped, so the file should be byte-identical to before"
        )


def test_the_tally_does_not_claim_not_written_for_a_written_layer(corpus):
    """`NOT written` must mean the bytes on disk are unchanged."""
    root, layer_path = corpus
    before = layer_path.read_bytes()

    result = _run(root, "--apply")
    claims_not_written = "NOT written" in result.stdout

    if claims_not_written:
        assert layer_path.read_bytes() == before, (
            f"tally says NOT written but the file changed.\nstdout:\n{result.stdout}"
        )


def test_dry_run_never_touches_the_file(corpus):
    root, layer_path = corpus
    before = layer_path.read_bytes()
    _run(root)
    assert layer_path.read_bytes() == before


def test_an_unsigned_layer_is_allowed_to_stay_unsigned(tmp_path):
    """The guard is 'arrived signed → leaves signed', not 'must be signed'.

    A corpus where signing was never configured must still be stampable, or the
    fix would block the very backfill it protects.
    """
    d = tmp_path / "probe"
    d.mkdir()
    (d / "probe-security-audit.json").write_text(json.dumps(AUDIT), encoding="utf-8")
    layer_path = d / "probe-findings-layer.json"
    layer_path.write_text(json.dumps(_realistic(_layer(signed=False)), indent=2), encoding="utf-8")

    _run(tmp_path, "--apply")

    after = json.loads(layer_path.read_text())
    assert any(e.get("fingerprint") for e in after["events"]), (
        "an unsigned layer must still be stampable"
    )
