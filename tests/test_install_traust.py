"""scripts/install_traust — the adopter's starting point and its --doctor."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "install_traust"
TEMPLATES = sorted(p for p in (REPO / "config").glob("*.example.*"))


def _run(args, env_extra=None, cwd=REPO):
    env = {**os.environ, "HOME": os.environ.get("HOME", "/tmp"), **(env_extra or {})}
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=cwd
    )


def test_help_exits_zero():
    r = _run(["--help"])
    assert r.returncode == 0 and "TRAUST_CONFIG_HOME" in r.stdout


def test_noninteractive_install_copies_every_copyable_template(tmp_path):
    home = tmp_path / "cfg"
    r = _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    assert r.returncode == 0, r.stdout + r.stderr
    written = sorted(p.name for p in home.iterdir())
    # every non-key template, plus the three shipped-as-is filled defaults
    # (model-registry + the MANIFEST-required feeds/external-tools).
    expected = sorted(
        [t.name.replace(".example", "") for t in TEMPLATES if not t.name.endswith(".pub")]
        + ["model-registry.yaml", "feeds.yaml", "external-tools.yaml"]
    )
    for shipped in ("model-registry.yaml", "feeds.yaml", "external-tools.yaml"):
        assert (home / shipped).read_text() == (REPO / "config" / shipped).read_text()
    assert written == expected
    # the key template is instructions, never copied as a key
    assert not (home / "ledger-signing-key.pub").exists()
    assert "ledger-signing-key.pub" in r.stdout


def test_install_never_overwrites_without_force(tmp_path):
    home = tmp_path / "cfg"
    home.mkdir()
    (home / "corpus-config.yaml").write_text("version: 1\ntrees: {}\n")
    r = _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    assert r.returncode == 0
    assert (home / "corpus-config.yaml").read_text() == "version: 1\ntrees: {}\n"
    assert "kept existing corpus-config.yaml" in r.stdout


def test_doctor_fails_closed_when_unset_and_default_absent(tmp_path):
    env = {"HOME": str(tmp_path)}
    r = subprocess.run(
        ["bash", str(SCRIPT), "--doctor"],
        capture_output=True,
        text=True,
        env={k: v for k, v in {**os.environ, **env}.items() if k != "TRAUST_CONFIG_HOME"},
        cwd=REPO,
    )
    assert r.returncode == 1 and "run scripts/install_traust" in r.stdout


def test_doctor_smoke_reports_empty_estate(tmp_path):
    """Fresh install: completeness fails on empty corpus; load_context still parses."""
    home = tmp_path / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    r = _run(
        ["--doctor", "--toolchain", "ledger-signing"], env_extra={"TRAUST_CONFIG_HOME": str(home)}
    )
    assert r.returncode == 1
    assert "trees is empty" in r.stdout
    assert "ledger-signing-key.pub missing" not in r.stdout


@pytest.mark.skipif(
    not os.environ.get("TRAUST_CONFIG_HOME") or os.environ.get("HARNESS_TEST_FIXTURE_CONFIG"),
    reason="no operational config in this environment (the suite fixture is a bare template)",
)
def test_doctor_passes_on_the_operational_config():
    """With a real TRAUST_CONFIG_HOME (developer workstation / SCI) the doctor's
    file + resolver sections pass; toolchain is checked for the smallest profile."""
    r = _run(["--doctor", "--toolchain", "ledger-signing"])
    assert "every operational file resolves under" in r.stdout, r.stdout
    assert "missing" not in r.stdout.split("3. Resolver")[0].replace("openssl not found", "")
