"""`backfill_artifact_digests` must not leave a signed layer unsigned.

This is the highest-risk migration to get wrong. Populating `artifact_digests`
**changes the format-4 signed payload** — verified directly: at format 4 the
payload differs once the map is populated, while at format 3 the field is
ignored. So every layer it touches must be re-signed, or it ends up carrying
digests that nobody vouches for.

It shipped with the identical shape that unsigned 112 corpus layers on
2026-08-31 via its sibling `backfill_event_fingerprints`:

1. the layer was written *before* signing, so failure paths `continue`d with the
   modified file already on disk while the tally reported ``NOT written``;
2. the only check was `verify_merkle_signature`, which reports nothing on an
   unsigned layer — there is no signature to fail — so it called the damage clean.

These drive the migration with signing unavailable, which is the state that
produced the incident and the normal state on a workstation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MODULE = "traust.migrations.backfill_artifact_digests"

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

TRIAGE = {"triage_completed": "2026-06-24", "findings": []}


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
                "fingerprint": "b" * 64,
                "fingerprint_algo": "v2",
            }
        ],
        "needs_review": [],
    }


def _realistic(layer: dict) -> dict:
    """Give the layer a genuine Merkle root, as a corpus layer has.

    Without one, `sign()` takes a different path and the incident does not
    reproduce — a fixture that skipped this passed against the unfixed code.
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
    # a sibling artifact, so there is something to digest
    (d / "probe-triage.json").write_text(json.dumps(TRIAGE), encoding="utf-8")
    layer = d / "probe-findings-layer.json"
    layer.write_text(json.dumps(_realistic(_layer(signed=True)), indent=2), encoding="utf-8")
    return tmp_path, layer


def _run(root: Path, *extra: str) -> subprocess.CompletedProcess:
    """Run with signing unavailable, in a subprocess so nothing leaks."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "LEDGER_LOCAL_IDENTITY": "probe@example.com",
    }
    return subprocess.run(
        [sys.executable, "-m", MODULE, str(root), *extra],
        capture_output=True,
        text=True,
        cwd=REPO,
        env=env,
        timeout=300,
    )


def test_a_signed_layer_is_never_left_unsigned(corpus):
    root, layer_path = corpus
    result = _run(root, "--apply")
    meta = json.loads(layer_path.read_text())["metadata"]
    assert meta.get("merkle_root_signature"), (
        "layer arrived signed and is now UNSIGNED — its artifact_digests would be "
        f"vouched for by nobody.\nstdout:\n{result.stdout}"
    )


def _signing_configured() -> bool:
    import os

    key = os.environ.get("LAAS_SIGNING_KEY_PATH") or os.environ.get("HARNESS_SIGNING_KEY_PATH")
    return bool(key and Path(key).is_file() and os.environ.get("COSIGN_PASSWORD"))


@pytest.mark.skipif(
    not _signing_configured(),
    reason="needs LAAS_SIGNING_KEY_PATH + COSIGN_PASSWORD (operator/CI signing key)",
)
def test_a_valid_signature_is_never_left_stale(tmp_path):
    """The real hazard here, and it is not an absent signature.

    `artifact_digests` lives in metadata, not events, so populating it does NOT
    move the Merkle root — the old signature is therefore never dropped. But at
    format 4 the signed payload covers a digest OVER that map, so a signature made
    against an empty map no longer verifies once it is filled. The layer keeps a
    present-but-invalid signature, which D8 calls indistinguishable from tampering
    and which is strictly worse than leaving it unsigned.

    A fixture with a fake signature cannot see this: it never verified to begin
    with. This one signs for real, then runs the migration with signing
    unavailable, and requires the layer either to still verify or to be untouched.
    """
    from traust_ledger.api.integrity import verify_merkle_signature
    from traust_ledger.client import LedgerClient

    d = tmp_path / "probe"
    d.mkdir()
    (d / "probe-security-audit.json").write_text(json.dumps(AUDIT), encoding="utf-8")
    (d / "probe-triage.json").write_text(json.dumps(TRIAGE), encoding="utf-8")
    layer_path = d / "probe-findings-layer.json"
    layer_path.write_text(json.dumps(_realistic(_layer(signed=False)), indent=2), encoding="utf-8")
    LedgerClient(token="test-token", data_dir=str(d)).sign(layer_path.stem)

    from traust.paths import optional_config_path

    pub = optional_config_path("ledger-signing-key.pub")
    signed = json.loads(layer_path.read_text())
    assert not [
        f for f in verify_merkle_signature(signed, str(pub)) if f.severity.name == "ERROR"
    ], "precondition: the layer must genuinely verify before the migration runs"
    before = layer_path.read_bytes()

    result = _run(tmp_path, "--apply")

    after = json.loads(layer_path.read_text())
    if layer_path.read_bytes() == before:
        return  # untouched — the honest outcome when it cannot re-sign
    bad = [f for f in verify_merkle_signature(after, str(pub)) if f.severity.name == "ERROR"]
    assert not bad, (
        "the migration wrote a layer whose signature no longer verifies — "
        f"stale, not absent, so nothing reports it as damaged.\n{bad[0].message[:160]}"
        f"\nstdout:\n{result.stdout}"
    )


def test_not_written_means_the_bytes_are_unchanged(corpus):
    root, layer_path = corpus
    before = layer_path.read_bytes()
    result = _run(root, "--apply")
    if "NOT written" in result.stdout:
        assert layer_path.read_bytes() == before, (
            f"tally says NOT written but the file changed.\nstdout:\n{result.stdout}"
        )


def test_dry_run_never_touches_the_file(corpus):
    root, layer_path = corpus
    before = layer_path.read_bytes()
    _run(root)
    assert layer_path.read_bytes() == before


def test_populating_the_map_changes_the_format4_signed_payload():
    """Why re-signing is mandatory here, unlike a no-op metadata edit.

    Format 4 binds a digest of ``artifact_digests`` into the signed payload.
    Populating the map must change the payload (requiring re-sign). Format 3
    ignores the map, so older layers are unaffected.
    """
    import copy
    import hashlib

    def _payload(meta: dict, fmt: int) -> bytes:
        claim = meta.get("claim_hashes")
        claim_digest = (
            hashlib.sha256(
                json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if claim
            else None
        )
        doc = {
            "merkle_root": meta.get("merkle_root"),
            "leaf_format": meta.get("leaf_format", 1),
            "merkle_epoch": meta.get("merkle_epoch", 0),
            "merkle_size": meta.get("merkle_size"),
            "pre_merkle_checkpoint": meta.get("pre_merkle_checkpoint"),
            "claim_hashes_digest": claim_digest,
        }
        if fmt >= 3:
            doc["audit_report_sha256"] = meta.get("audit_report_sha256")
        if fmt >= 4:
            arts = meta.get("artifact_digests")
            doc["artifact_digests_digest"] = (
                hashlib.sha256(
                    json.dumps(arts, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if arts
                else None
            )
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    meta = {
        "merkle_root": "a" * 64,
        "merkle_size": 3,
        "leaf_format": 2,
        "merkle_epoch": 0,
        "audit_report_sha256": "b" * 64,
        "merkle_signature_format": 4,
        "claim_hashes": {},
    }
    populated = copy.deepcopy(meta)
    populated["artifact_digests"] = {"probe-triage.json": "c" * 64}
    assert _payload(meta, 4) != _payload(populated, 4)
    assert _payload(meta, 3) == _payload(populated, 3)
