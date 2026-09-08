"""inventory-repositories/scripts/fetch_forge_owners.py — URL gate + parsing.

No network: the forge CLI is stubbed.
"""

from __future__ import annotations

import base64
import importlib.util
import json

import pytest

from traust.paths import skill_dir

SCRIPT = skill_dir("inventory-repositories") / "scripts" / "fetch_forge_owners.py"


def _load():
    spec = importlib.util.spec_from_file_location("ffo", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "url,host,path",
    [
        ("https://github.com/acme/api", "github.com", "acme/api"),
        ("https://github.com/acme/api.git/", "github.com", "acme/api"),
        ("https://gitlab.example.com/grp/sub/proj", "gitlab.example.com", "grp/sub/proj"),
    ],
)
def test_repo_url_gate_accepts_https_forges(url, host, path):
    assert _load().parse_repo_url(url) == (host, path)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/acme/api",  # not https
        "https://github.com/acme",  # no repo
        "https://example.com/acme/api",  # unknown host
        "git@github.com:acme/api.git",  # ssh
        "https://github.com/acme/api;rm -rf /",  # shell metacharacters
    ],
)
def test_repo_url_gate_rejects_everything_else(url):
    with pytest.raises(SystemExit):
        _load().parse_repo_url(url)


def test_approvers_from_owners_yaml_and_codeowners():
    m = _load()
    assert m.approvers_from_owners(
        "reviewers:\n- r1\napprovers:\n  - alice\n  - bob\nlabels: [x]\n"
    ) == ["alice", "bob"]
    assert m.approvers_from_owners("approvers: [alice, 'bob']\n") == ["alice", "bob"]
    assert m.approvers_from_owners("# comment\n*.go @carol @acme/team\ndocs/ @dave\n") == [
        "carol",
        "acme/team",
        "dave",
    ]
    assert m.approvers_from_owners(None) == []


def test_github_path_uses_gh_api_only_and_drops_bots(monkeypatch):
    m = _load()
    calls: list[list[str]] = []

    def fake_run(argv):
        calls.append(argv)
        assert argv[0] == "gh" and argv[1] == "api"
        if argv[2].endswith("/contents/OWNERS"):
            return base64.b64encode(b"approvers:\n- alice\n").decode()
        if "/contributors" in argv[2]:
            return "alice\nweb-flow\ndependabot[bot]\nbob\n"
        return None

    monkeypatch.setattr(m, "_run", fake_run)
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/bin/gh")
    res = m.github("acme/api", None)
    assert res["owners_file_name"] == "OWNERS"
    assert res["contributors"] == ["alice", "bob"]
    assert m.approvers_from_owners(res["owners_file"]) == ["alice"]
    assert all(c[0] == "gh" for c in calls)
    assert not any("curl" in " ".join(c) for c in calls)


def test_main_emits_json(monkeypatch, capsys):
    m = _load()
    monkeypatch.setattr(
        m,
        "github",
        lambda path, file: {
            "owners_file": "approvers:\n- alice\n",
            "owners_file_name": "OWNERS",
            "contributors": ["alice"],
            "file": None,
        },
    )
    assert m.main(["--repo-url", "https://github.com/acme/api"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["repo"] == "acme/api" and out["approvers"] == ["alice"]
