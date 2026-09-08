"""Tests for harnessing/3-audit/vuln-scan/scripts/build_diff_packet.py."""

import json
import subprocess

import build_diff_packet as dp
import pytest


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    (r / "pkg").mkdir(parents=True)
    (r / "cmd").mkdir()
    _git(tmp_path, "init", "-q", "r")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "pkg" / "auth.go").write_text(
        'package pkg\n\nfunc CheckToken(t string) bool {\n\treturn t != ""\n}\n'
    )
    (r / "cmd" / "main.go").write_text(
        'package main\n\nimport "r/pkg"\n\nfunc main() {\n\t_ = pkg.CheckToken("x")\n}\n'
    )
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    anchor = subprocess.run(
        ["git", "-C", str(r), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    with (r / "pkg" / "auth.go").open("a") as f:
        f.write("\nfunc CheckSession(s string) bool {\n\treturn len(s) > 4\n}\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "change")
    return r, anchor


def _scope(repo, anchor, **over):
    doc = {
        "refuse": False,
        "target": str(repo),
        "repo_url": "https://x/r",
        "baseline_report": None,
        "anchor": anchor,
        "resolution_source": "override",
        "changed_files": [{"path": "pkg/auth.go", "added": 4, "deleted": 0, "sensitive": True}],
        "clusters": [{"name": "pkg", "files": ["pkg/auth.go"]}],
        "C": 4,
        "sensitive_lines": 4,
        "deps_manifests_changed": False,
        "baseline_findings_for_changed_files": [
            {
                "id": "R-1",
                "title": "tok",
                "severity": "high",
                "paths": ["pkg/auth.go"],
                "fingerprint": None,
            }
        ],
    }
    doc.update(over)
    return doc


def _write_scope(tmp_path, doc):
    p = tmp_path / "r-diff-scope.json"
    p.write_text(json.dumps(doc))
    return p


@pytest.mark.requires_git
class TestPacket:
    def test_happy_path_embeds_hunks_callers_baseline(self, tmp_path, repo):
        r, anchor = repo
        scope = _write_scope(tmp_path, _scope(r, anchor))
        out = tmp_path / "packet.json"
        assert dp.main(["--scope", str(scope), "--out", str(out)]) == 0
        doc = json.loads(out.read_text())
        cl = doc["clusters"][0]
        assert "CheckSession" in cl["files"][0]["diff"]
        assert not cl["files"][0]["truncated"]
        assert cl["baseline_findings"][0]["id"] == "R-1"
        # CheckToken is referenced from cmd/main.go (outside changed set)
        assert any(c["file"] == "cmd/main.go" for c in cl["callers"])
        assert doc["anchor"] == anchor
        assert doc["stats"]["changed_files"] == 1

    def test_default_out_derived_from_scope_name(self, tmp_path, repo):
        r, anchor = repo
        scope = _write_scope(tmp_path, _scope(r, anchor))
        assert dp.main(["--scope", str(scope), "--no-callers"]) == 0
        assert (tmp_path / "r-diff-packet.json").is_file()

    def test_refusal_scope_rejected(self, tmp_path, repo):
        r, anchor = repo
        scope = _write_scope(tmp_path, _scope(r, anchor, refuse=True))
        assert dp.main(["--scope", str(scope)]) == 3

    def test_no_callers_flag(self, tmp_path, repo):
        r, anchor = repo
        scope = _write_scope(tmp_path, _scope(r, anchor))
        out = tmp_path / "p.json"
        assert dp.main(["--scope", str(scope), "--out", str(out), "--no-callers"]) == 0
        doc = json.loads(out.read_text())
        assert doc["callers_note"] == "skipped: --no-callers"
        assert doc["clusters"][0]["callers"] == []

    def test_per_file_byte_cap_truncates_with_marker(self, tmp_path, repo):
        r, anchor = repo
        scope = _write_scope(tmp_path, _scope(r, anchor))
        out = tmp_path / "p.json"
        assert (
            dp.main(
                ["--scope", str(scope), "--out", str(out), "--no-callers", "--max-file-bytes", "50"]
            )
            == 0
        )
        doc = json.loads(out.read_text())
        f = doc["clusters"][0]["files"][0]
        assert f["truncated"]
        assert "truncated at 50 bytes" in f["diff"]

    def test_total_byte_cap_lists_omissions(self, tmp_path, repo):
        r, anchor = repo
        doc = _scope(r, anchor)
        doc["changed_files"].append(
            {"path": "cmd/main.go", "added": 1, "deleted": 0, "sensitive": False}
        )
        doc["clusters"].append({"name": "cmd", "files": ["cmd/main.go"]})
        scope = _write_scope(tmp_path, doc)
        out = tmp_path / "p.json"
        assert (
            dp.main(
                ["--scope", str(scope), "--out", str(out), "--no-callers", "--max-total-bytes", "1"]
            )
            == 0
        )
        packet = json.loads(out.read_text())
        # first file embeds (cap checked before each file), second omits
        assert any("cmd/main.go" in o for o in packet["omitted"])

    def test_missing_anchor_errors(self, tmp_path, repo):
        r, _ = repo
        doc = _scope(r, "ignored")
        doc["anchor"] = None
        scope = _write_scope(tmp_path, doc)
        assert dp.main(["--scope", str(scope)]) == 2

    def test_non_checkout_errors(self, tmp_path, repo):
        _r, anchor = repo
        scope = _write_scope(tmp_path, _scope(tmp_path / "nope", anchor))
        assert dp.main(["--scope", str(scope)]) == 2
