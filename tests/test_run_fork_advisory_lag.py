"""Tests for harnessing/3-audit/secure-code-audit/scripts/run_fork_advisory_lag.py — fork advisory-lag pre-scan."""

import importlib.util
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "run_fork_advisory_lag", skill_dir("secure-code-audit") / "scripts" / "run_fork_advisory_lag.py"
)
rfl = importlib.util.module_from_spec(_SPEC)
sys.modules["run_fork_advisory_lag"] = rfl
_SPEC.loader.exec_module(rfl)

GIT_ENV = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _mk_repo(tmp_path, module, origin=None, name="target"):
    repo = tmp_path / name
    repo.mkdir()
    (repo / "go.mod").write_text(f"module {module}\n\ngo 1.21\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    if origin:
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", origin], check=True)
    subprocess.run(["git", "-C", str(repo), *GIT_ENV, "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), *GIT_ENV, "commit", "-qm", "init"], check=True)
    return repo


OSV_VULN = {
    "id": "GHSA-m9w6-wp3h-vq8g",
    "aliases": ["CVE-2024-0874"],
    "summary": "CoreDNS gRPC lameduck vulnerability",
    "affected": [
        {
            "package": {"name": "github.com/coredns/coredns", "ecosystem": "Go"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.11.2"}]}],
        }
    ],
}


# ----------------------------------------------------------- stage 1


@pytest.mark.requires_git
def test_gomod_module_path_fork_detection(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/coredns/coredns", "https://github.com/openshift/coredns.git"
    )
    signals, upstreams = rfl.stage1_detect(repo)
    assert upstreams, "fork not detected"
    up = upstreams[0]
    assert up["identity"] == "github.com/coredns/coredns"
    ev = up["evidence"][0]
    assert ev["file"] == "go.mod"
    assert ev["line"] == 1
    assert "coredns/coredns" in ev["quote"]
    assert any(s["type"] == "go-mod-module-path" for s in signals)


@pytest.mark.requires_git
def test_version_constant_resolves_tracked_version(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/coredns/coredns", "https://github.com/openshift/coredns.git"
    )
    (repo / "coremain").mkdir()
    (repo / "coremain" / "version.go").write_text(
        'package coremain\n\nconst (\n\tCoreVersion = "1.11.1"\n\tGoVersion = "1.21.5"\n)\n'
    )
    _, upstreams = rfl.stage1_detect(repo)
    up = upstreams[0]
    assert up["tracked_version"] == "1.11.1"  # GoVersion excluded
    assert any(e["file"] == "coremain/version.go" and e["line"] == 4 for e in up["evidence"])


@pytest.mark.requires_git
def test_replace_directive_fork(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/router", "https://github.com/openshift/router.git"
    )
    (repo / "go.mod").write_text(
        "module github.com/openshift/router\n\ngo 1.21\n\n"
        "require github.com/coredns/coredns v1.11.1\n\n"
        "replace github.com/coredns/coredns => "
        "github.com/openshift/coredns v1.11.2\n"
    )
    signals, upstreams = rfl.stage1_detect(repo)
    assert any(s["type"] == "go-mod-replace" for s in signals)
    up = next(u for u in upstreams if u["identity"] == "github.com/coredns/coredns")
    assert up["tracked_version"] == "1.11.2"
    assert up["evidence"][0]["file"] == "go.mod"


@pytest.mark.requires_git
def test_vendored_project_detection(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/thing", "https://github.com/openshift/thing.git"
    )
    vend = repo / "third_party" / "coredns"
    vend.mkdir(parents=True)
    (vend / "go.mod").write_text("module github.com/coredns/coredns\n")
    (vend / "version.go").write_text('package coredns\n\nvar Version = "1.10.0"\n')
    signals, upstreams = rfl.stage1_detect(repo)
    assert any(s["type"] == "vendored-project" for s in signals)
    up = next(u for u in upstreams if u["identity"] == "github.com/coredns/coredns")
    assert up["tracked_version"] == "1.10.0"
    assert any(e["file"] == "third_party/coredns/go.mod" for e in up["evidence"])


@pytest.mark.requires_git
def test_non_fork_repo(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/foo", "https://github.com/openshift/foo.git", name="foo"
    )
    signals, upstreams = rfl.stage1_detect(repo)
    assert signals == []
    assert upstreams == []


@pytest.mark.requires_git
def test_vanity_module_path_is_not_a_fork(tmp_path):
    repo = _mk_repo(
        tmp_path,
        "k8s.io/kubernetes",
        "https://github.com/kubernetes/kubernetes.git",
        name="kubernetes",
    )
    _signals, upstreams = rfl.stage1_detect(repo)
    assert upstreams == []


# ----------------------------------------------------------- stage 2


def test_osv_query_mocked(monkeypatch):
    calls = []

    def fake_post(url, payload, timeout):
        calls.append(payload)
        return {"vulns": [OSV_VULN]}

    monkeypatch.setattr(rfl, "_post_json", fake_post)
    up = {
        "identity": "github.com/coredns/coredns",
        "osv_package": "github.com/coredns/coredns",
        "ecosystem": "Go",
        "tracked_version": "1.11.1",
        "evidence": [],
        "advisories": [],
    }
    status = rfl.stage2_advisories([up], "https://example.invalid/q", 5)
    assert status == "ok"
    assert calls[0]["version"] == "1.11.1"
    assert calls[0]["package"] == {"name": "github.com/coredns/coredns", "ecosystem": "Go"}
    adv = up["advisories"][0]
    assert adv["id"] == "GHSA-m9w6-wp3h-vq8g"
    assert "CVE-2024-0874" in adv["aliases"]
    assert adv["fixed_version"] == "1.11.2"
    assert adv["in_range"] is True
    assert adv["affected_ranges"][0]["type"] == "SEMVER"


def test_network_error_is_graceful(monkeypatch):
    def broken_post(url, payload, timeout):
        raise urllib.error.URLError("network unreachable")

    monkeypatch.setattr(rfl, "_post_json", broken_post)
    up = {
        "identity": "github.com/coredns/coredns",
        "osv_package": "github.com/coredns/coredns",
        "ecosystem": "Go",
        "tracked_version": "1.11.1",
        "evidence": [],
        "advisories": [],
    }
    status = rfl.stage2_advisories([up], "https://example.invalid/q", 5)
    assert status.startswith("error:")
    assert "unreachable" in status
    assert up["advisories"] == []  # stage-1 output survives


def test_unresolved_version_skips_query(monkeypatch):
    def fail_post(url, payload, timeout):  # pragma: no cover
        raise AssertionError("must not query without a tracked version")

    monkeypatch.setattr(rfl, "_post_json", fail_post)
    up = {
        "identity": "github.com/coredns/coredns",
        "osv_package": "github.com/coredns/coredns",
        "ecosystem": "Go",
        "tracked_version": None,
        "evidence": [],
        "advisories": [],
    }
    assert rfl.stage2_advisories([up], "https://example.invalid/q", 5) == "ok"


# ----------------------------------------------------------------- CLI


def _run_cli(repo, out, *extra):
    return subprocess.run(
        [
            sys.executable,
            str(skill_dir("secure-code-audit") / "scripts" / "run_fork_advisory_lag.py"),
            "--repo",
            str(repo),
            "--out",
            str(out),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.mark.requires_git
def test_cli_offline_mode_skips_network(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/coredns/coredns", "https://github.com/openshift/coredns.git"
    )
    out = tmp_path / "out.json"
    proc = _run_cli(repo, out, "--offline")
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(out.read_text())
    assert doc["fork_detected"] is True
    assert doc["network"] == "skipped"
    assert doc["upstreams"][0]["advisories"] == []
    assert doc["tool_version"]


@pytest.mark.requires_git
def test_cli_non_fork_writes_negative_result(tmp_path):
    repo = _mk_repo(
        tmp_path, "github.com/openshift/foo", "https://github.com/openshift/foo.git", name="foo"
    )
    out = tmp_path / "out.json"
    proc = _run_cli(repo, out)  # no --offline: must not need net
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(out.read_text())
    assert doc["fork_detected"] is False
    assert doc["signals"] == []
    assert doc["upstreams"] == []
    assert doc["network"] == "skipped"


def test_cli_rejects_missing_repo(tmp_path):
    proc = _run_cli(tmp_path / "nope", tmp_path / "out.json", "--offline")
    assert proc.returncode == 1
