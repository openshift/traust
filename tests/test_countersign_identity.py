"""countersign: the signer is the ledger identity token holder.

Unit tests stub the ledger's actor resolution; the end-to-end test runs the
real SDK path (local identity token, cosign keypair signing) and is skipped
where cosign is not installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
from traust_contracts.v1.models.layer import LayerActor

from traust.cli import countersign as cs

HUMAN = LayerActor(
    kind="human",
    identity="alice@example.com",
    identity_verified=True,
    identity_provider="oidc",
    identity_subject="alice",
)


def _with_actor(actor):
    return mock.patch("traust_ledger.cli.identity.actor.require_verified_actor", return_value=actor)


def test_resolve_actor_returns_token_holder(monkeypatch):
    _no_directory(monkeypatch)
    with _with_actor(HUMAN):
        a = cs.resolve_actor()
    assert a["identity"] == "alice@example.com"
    assert a["identity_verified"] is True
    assert a["identity_provider"] == "oidc"


def test_no_token_is_refused():
    with _with_actor(None), pytest.raises(RuntimeError, match="no verifiable"):
        cs.resolve_actor()


def test_machine_token_cannot_countersign():
    bot = LayerActor(kind="machine", identity="ci-bot", identity_verified=True)
    with _with_actor(bot), pytest.raises(RuntimeError, match="human signer"):
        cs.resolve_actor()


LOCAL = LayerActor(kind="human", identity="solo", identity_verified=True, identity_provider="local")


def test_local_token_refused_by_default(monkeypatch):
    monkeypatch.delenv("HARNESS_COUNTERSIGN_ALLOW_LOCAL", raising=False)
    with _with_actor(LOCAL), pytest.raises(RuntimeError, match="local issuer"):
        cs.resolve_actor()


def test_local_token_accepted_when_deployment_opts_in(monkeypatch):
    monkeypatch.setenv("HARNESS_COUNTERSIGN_ALLOW_LOCAL", "1")
    with _with_actor(LOCAL):
        assert cs.resolve_actor()["identity_provider"] == "local"


def test_oidc_token_needs_no_opt_in(monkeypatch):
    monkeypatch.delenv("HARNESS_COUNTERSIGN_ALLOW_LOCAL", raising=False)
    with _with_actor(HUMAN):
        assert cs.resolve_actor()["identity"] == "alice@example.com"


def _no_directory(monkeypatch):
    monkeypatch.delenv("LEDGER_DIRECTORY_COMMAND", raising=False)


def test_directory_refusal_blocks_before_anything(monkeypatch):
    from traust_ledger.auth.directory import ScriptDirectory

    monkeypatch.setattr(
        "traust_ledger.auth.directory.load_directory",
        lambda env=None: ScriptDirectory(
            [
                sys.executable,
                "-c",
                "import sys; print(f'RESULT uid={sys.argv[1]} status=terminated')",
            ]
        ),
    )
    with _with_actor(HUMAN), pytest.raises(RuntimeError, match="terminated"):
        cs.resolve_actor()


def test_directory_active_is_stamped(monkeypatch):
    from traust_ledger.auth.directory import ScriptDirectory

    monkeypatch.setattr(
        "traust_ledger.auth.directory.load_directory",
        lambda env=None: ScriptDirectory(
            [sys.executable, "-c", "import sys; print(f'RESULT uid={sys.argv[1]} status=active')"]
        ),
    )
    with _with_actor(HUMAN):
        assert cs.resolve_actor()["employee_status"] == "active"


def test_directory_misconfiguration_refuses(monkeypatch):
    monkeypatch.setenv("LEDGER_DIRECTORY_COMMAND", "/nonexistent/check-employee")
    with _with_actor(HUMAN), pytest.raises(RuntimeError, match="unusable"):
        cs.resolve_actor()


def test_source_has_no_ldap_or_direct_write_path():
    src = Path(cs.__file__).read_text()
    assert "subprocess" not in src  # no shelling out to a directory check
    assert "store_layer(" not in src  # no raw layer writes
    assert ".sign(" not in src  # signing happens inside submit
    assert "ldap3" not in src


# --------------------------------------------------------------------------
# end-to-end: real SDK submit, local identity token, keypair signing
# --------------------------------------------------------------------------

from tests.test_countersign import REF


def _fixture(tmp: Path) -> Path:
    """Reuse test_countersign's audit/layer shapes (a real refuted finding
    awaiting sign-off) so the cumulative rebuild has everything it needs."""
    from traust_ledger.client import LedgerClient

    from tests.test_countersign import _audit, _layer  # fixtures stay module-local

    d = tmp / "findings" / "prod" / "t"
    d.mkdir(parents=True)
    (d / "t-security-audit.json").write_text(json.dumps(_audit(REF)))
    (d / "t-findings-layer.json").write_text(json.dumps(_layer(REF)))
    # Stamp Merkle metadata so this is a realistic already-signed ledger: the
    # SDK countersign verb appends to a rooted layer (valid_epoch gate), exactly
    # as production layers are — the triage/validation emitters sign on write.
    LedgerClient(token="test-token", data_dir=str(d)).sign("t-findings-layer")
    return d / "t-findings-layer.json"


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_end_to_end_submit_stamps_token_actor_and_signs(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    keys = tmp_path / "keys"
    keys.mkdir()
    env = {**os.environ, "HOME": str(home), "COSIGN_PASSWORD": ""}
    subprocess.run(
        ["cosign", "generate-key-pair"], cwd=keys, env=env, check=True, capture_output=True
    )
    lp = _fixture(tmp_path)
    env.update(
        {
            "LEDGER_LOCAL_IDENTITY": "smoketest",
            "LAAS_SIGNING_REQUIRED": "true",
            "LAAS_SIGNING_KEY_PATH": str(keys / "cosign.key"),
        }
    )
    for k in ("LAAS_TOKEN", "LEDGER_TOKEN", "LEDGER_TOKEN_PATH", "HARNESS_COUNTERSIGN_ALLOW_LOCAL"):
        env.pop(k, None)

    # a self-minted token is refused unless the deployment opts in — and
    # the refusal happens before any write
    before = lp.read_text()
    r0 = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli.countersign",
            "record",
            "--layer",
            str(lp),
            "--finding",
            REF,
            "--decision",
            "false_positive",
            "--rationale",
            "x",
            "--root",
            str(tmp_path / "findings"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r0.returncode == 1 and "local issuer" in r0.stderr, r0.stderr
    assert lp.read_text() == before
    env["HARNESS_COUNTERSIGN_ALLOW_LOCAL"] = "1"

    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli.countersign",
            "record",
            "--layer",
            str(lp),
            "--finding",
            REF,
            "--decision",
            "false_positive",
            "--rationale",
            "reviewed: guard exists",
            "--root",
            str(tmp_path / "findings"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "verified via local" in r.stdout

    layer = json.loads(lp.read_text())
    human = [e for e in layer["events"] if e["source"]["actor"].get("kind") == "human"]
    assert len(human) == 1
    actor = human[0]["source"]["actor"]
    # stamped by the SDK from the token — not asserted by the CLI
    assert actor["identity"] == "smoketest"
    assert actor["identity_verified"] is True
    assert actor["identity_provider"] == "local"
    assert layer["metadata"].get("merkle_root")
    assert layer["metadata"].get("merkle_root_signature")
    # and the signature verifies against the generated public key
    # (LedgerService.verify has no public-key parameter, so go to the
    # integrity module the ledger CLI's `verify --pubkey` uses)
    from traust_ledger._internal.integrity.ledger import verify_merkle_signature

    with mock.patch.dict(os.environ, {"LAAS_SIGNING_REQUIRED": "1"}):
        findings = verify_merkle_signature(layer, pubkey_path=str(keys / "cosign.pub"))
    bad = [f for f in findings if str(getattr(f, "severity", "")).lower().endswith("error")]
    assert not bad, [f.message for f in findings]

    # the deployment's employee directory: terminated → refused, nothing
    # written; active → stamped employee_status
    dir_script = tmp_path / "directory.py"
    dir_script.write_text(
        "import sys\n"
        "table = {'smoketest': 'terminated', 'second': 'active'}\n"
        "print(f\"RESULT uid={sys.argv[1]} status={table.get(sys.argv[1], 'not_found')}\")\n"
    )
    env["LEDGER_DIRECTORY_COMMAND"] = f"{sys.executable} {dir_script}"
    before = lp.read_text()
    rd = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli.countersign",
            "record",
            "--layer",
            str(lp),
            "--finding",
            REF,
            "--decision",
            "keep_open",
            "--rationale",
            "still real",
            "--root",
            str(tmp_path / "findings"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rd.returncode == 1 and "terminated" in rd.stderr, rd.stderr
    assert lp.read_text() == before

    # a second signer with a different token gets a distinct event —
    # and the directory says active, so employee_status is stamped by the SDK
    env["LEDGER_LOCAL_IDENTITY"] = "second"
    r2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli.countersign",
            "record",
            "--layer",
            str(lp),
            "--finding",
            REF,
            "--decision",
            "false_positive",
            "--rationale",
            "concur with the refutation",
            "--root",
            str(tmp_path / "findings"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r2.returncode == 0, r2.stderr + r2.stdout
    humans = {
        e["source"]["actor"]["identity"]: e["source"]["actor"]
        for e in json.loads(lp.read_text())["events"]
        if e["source"]["actor"].get("kind") == "human"
    }
    assert set(humans) == {"smoketest", "second"}
    assert humans["second"]["employee_status"] == "active"
    assert (
        humans["smoketest"].get("employee_status") is None
    )  # recorded before the directory was configured
    env.pop("LEDGER_DIRECTORY_COMMAND")
