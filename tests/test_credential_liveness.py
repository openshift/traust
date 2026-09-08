"""Tests for validate-findings credential_liveness.py + credential scope."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_VF = skill_dir("validate-findings")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cl = _load("credential_liveness", _VF / "credential_liveness.py")
scope_mod = _load("vf_scope_test", _VF / "scope.py")
Scope, Action = scope_mod.Scope, scope_mod.Action

FAKE_GH = "ghp_" + "a" * 36
FAKE_OC = "sha256~" + "C" * 43


# ---------- scope: credential adapter is explicit-only ------------------


def _targets(tmp_path, classes):
    f = tmp_path / "targets.yaml"
    f.write_text(
        "engagement: t\nauthorized_by: t\n"
        "credential_probes:\n  classes: [" + ", ".join(classes) + "]\n"
    )
    return f


def test_credential_scope_requires_explicit_mode():
    s = Scope()
    s.modes.add("inline")
    s.credential_probe_classes.add("github")  # even if somehow populated
    ok, reason = s.is_in_scope(Action(adapter="credential", verb="introspect", resource="github"))
    assert not ok and "mode-1" in reason


def test_credential_scope_class_gate(tmp_path):
    s = Scope.from_targets_file(_targets(tmp_path, ["github"]))
    ok, _ = s.is_in_scope(Action(adapter="credential", verb="introspect", resource="github"))
    assert ok
    ok, reason = s.is_in_scope(Action(adapter="credential", verb="introspect", resource="aws"))
    assert not ok and "aws" in reason


def test_credential_scope_read_only_verb(tmp_path):
    s = Scope.from_targets_file(_targets(tmp_path, ["github"]))
    ok, reason = s.is_in_scope(Action(adapter="credential", verb="rotate", resource="github"))
    assert not ok and "read-only" in reason


def test_inferred_scope_never_populates_credentials():
    s = Scope()
    s.merge_inferred({"clusters": {"ctx": ["ns"]}})
    assert not s.credential_probe_classes


# ---------- secret recovery ---------------------------------------------


def _mk_repo(tmp_path, content):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "conf.py").write_text(content)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"],
        check=True,
    )
    return repo


@pytest.mark.requires_git
def test_recover_secret_from_tree(tmp_path):
    repo = _mk_repo(tmp_path, f'tok = "{FAKE_GH}"\n')
    cand = {"liveness_class": "github", "path": "conf.py", "start_line": 1, "end_line": 1}
    assert cl.recover_secret(repo, cand) == FAKE_GH


@pytest.mark.requires_git
def test_recover_secret_from_history(tmp_path):
    repo = _mk_repo(tmp_path, f'tok = "{FAKE_OC}"\n')
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "conf.py").write_text("clean\n")
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-aqm",
            "wipe",
        ],
        check=True,
    )
    cand = {
        "liveness_class": "openshift",
        "path": "conf.py",
        "commit": head,
        "start_line": 1,
        "end_line": 1,
    }
    assert cl.recover_secret(repo, cand) == FAKE_OC


# ---------- probes (mocked transport) ------------------------------------


def test_probe_github_live_and_revoked(monkeypatch):
    monkeypatch.setattr(
        cl, "_http", lambda url, h, method="GET": (200, json.dumps({"login": "svc-account"}))
    )
    res = cl.probe("github", FAKE_GH, {})
    assert res["verdict"] == "CONFIRMED_LIVE"
    assert res["identity"] == "svc-account"
    monkeypatch.setattr(cl, "_http", lambda url, h, method="GET": (401, "{}"))
    assert cl.probe("github", FAKE_GH, {})["verdict"] == "REVOKED"


def test_probe_openshift_needs_endpoint():
    res = cl.probe("openshift", FAKE_OC, {})
    assert res["verdict"] == "UNTESTABLE"
    assert "endpoint" in res["reason"]


def test_probe_aws_without_pair_untestable():
    res = cl.probe("aws", "AKIA" + "Q" * 16, {}, file_text="just the key")
    assert res["verdict"] == "UNTESTABLE"
    assert "paired secret" in res["reason"]


def test_probe_network_error_untestable(monkeypatch):
    monkeypatch.setattr(cl, "_http", lambda url, h, method="GET": (None, "connection refused"))
    assert cl.probe("github", FAKE_GH, {})["verdict"] == "UNTESTABLE"


# ---------- end-to-end main(): fail-closed + secret-free artifact --------


def _candidates_file(tmp_path, cands):
    f = tmp_path / "x-gitleaks.json"
    f.write_text(json.dumps({"metadata": {}, "candidates": cands}))
    return f


@pytest.mark.requires_git
def test_main_fail_closed_without_targets(tmp_path, monkeypatch):
    repo = _mk_repo(tmp_path, f'tok = "{FAKE_GH}"\n')
    cands = _candidates_file(
        tmp_path,
        [
            {
                "fingerprint": "f1",
                "rule_id": "github-pat",
                "path": "conf.py",
                "start_line": 1,
                "end_line": 1,
                "liveness_class": "github",
            }
        ],
    )
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(cl, "_http", lambda *a, **k: calls.append(a) or (200, "{}"))
    rc = cl.main(["--candidates", str(cands), "--repo", str(repo)])
    assert rc == 0
    assert not calls, "probe ran without explicit scope!"
    out = json.loads((tmp_path / "x-credential-liveness.json").read_text())
    assert out["summary"]["UNTESTABLE"] == 1
    assert out["verdicts"][0]["reason"].startswith("scope:")


@pytest.mark.requires_git
def test_main_probes_in_scope_and_redacts(tmp_path, monkeypatch):
    repo = _mk_repo(tmp_path, f'tok = "{FAKE_GH}"\n')
    cands = _candidates_file(
        tmp_path,
        [
            {
                "fingerprint": "f1",
                "rule_id": "github-pat",
                "path": "conf.py",
                "start_line": 1,
                "end_line": 1,
                "liveness_class": "github",
            },
            {
                "fingerprint": "f2",
                "rule_id": "generic-api-key",
                "path": "conf.py",
                "liveness_class": None,
            },
        ],
    )
    targets = _targets(tmp_path, ["github"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cl, "_http", lambda url, h, method="GET": (200, json.dumps({"login": "svc"}))
    )
    rc = cl.main(["--candidates", str(cands), "--repo", str(repo), "--targets", str(targets)])
    assert rc == 0
    text = (tmp_path / "x-credential-liveness.json").read_text()
    assert FAKE_GH not in text, "secret leaked into artifact"
    out = json.loads(text)
    assert out["summary"] == {"CONFIRMED_LIVE": 1, "REVOKED": 0, "UNTESTABLE": 1}
    live = next(v for v in out["verdicts"] if v["verdict"] == "CONFIRMED_LIVE")
    assert live["secret_prefix"] == FAKE_GH[:4] + "…"
    assert live["identity"] == "svc"
    audit = (tmp_path / "credential-liveness-audit.jsonl").read_text()
    assert FAKE_GH not in audit
    assert '"scope_allowed": true' in audit


@pytest.mark.requires_git
def test_main_dry_run_never_reads_secrets(tmp_path, monkeypatch):
    repo = _mk_repo(tmp_path, f'tok = "{FAKE_GH}"\n')
    cands = _candidates_file(
        tmp_path,
        [
            {
                "fingerprint": "f1",
                "rule_id": "github-pat",
                "path": "conf.py",
                "start_line": 1,
                "end_line": 1,
                "liveness_class": "github",
            }
        ],
    )
    targets = _targets(tmp_path, ["github"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cl, "recover_secret", lambda *a: pytest.fail("dry-run recovered secret"))
    rc = cl.main(
        ["--candidates", str(cands), "--repo", str(repo), "--targets", str(targets), "--dry-run"]
    )
    assert rc == 0
