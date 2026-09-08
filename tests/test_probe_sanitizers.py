#!/usr/bin/env python3
"""Tests for harnessing/3-audit/secure-code-audit/scripts/probe_sanitizers.py — the Phase-B3 (D4 narrow slice)
sanitizer micro-probe lane tool. The bypassable-sanitizer fixture mirrors
bt-awx-001 residual #3 (a sanitize_jinja that strips ASCII jinja markers
but not variants); the soundness fixtures pin the Phase-1 rule that an
error transcript is never evidence of safety."""

import json
import subprocess
import sys

import probe_sanitizers as ps
import pytest

from traust.paths import skill_dir

_SECURE_CODE_AUDIT_SCRIPTS = skill_dir("secure-code-audit") / "scripts"

SCRIPT = _SECURE_CODE_AUDIT_SCRIPTS / "probe_sanitizers.py"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "util.py").write_text(
        "def sanitize_jinja(value):\n"
        "    # strips ASCII jinja markers only — fullwidth survives\n"
        "    return value.replace('{{', '').replace('{%', '')\n"
        "\n"
        "def sanitize_label(value):\n"
        "    # strict whitelist: every corpus survival token carries a\n"
        "    # non-alphanumeric character, so nothing survives this\n"
        "    return ''.join(c for c in value\n"
        "                   if c.isascii() and (c.isalnum() or c == ' '))\n"
        "\n"
        "def validate_name(value):\n"
        "    raise RuntimeError('needs app context')\n"
        "\n"
        "def unrelated_helper(a, b):\n"
        "    return a + b\n"
    )
    return tmp_path


# --------------------------------------------------------------------------
# discovery (--list, the default: executes nothing)
# --------------------------------------------------------------------------


def test_discovery_finds_sanitizer_shapes(repo):
    names = {c["function"] for c in ps.discover(repo)}
    assert names == {"sanitize_jinja", "sanitize_label", "validate_name"}


def test_discovery_skips_multi_arg_and_tests(repo, tmp_path):
    (tmp_path / "util_test.py").write_text("def sanitize_ignored(v):\n    return v\n")
    names = {c["function"] for c in ps.discover(repo)}
    assert "unrelated_helper" not in names
    assert "sanitize_ignored" not in names


def test_discovery_records_location(repo):
    [cand] = [c for c in ps.discover(repo) if c["function"] == "sanitize_jinja"]
    assert cand["path"] == "util.py"
    assert cand["line"] == 1


def test_only_filter_matches_any_single_arg_function(repo):
    # --only bypasses the name heuristic (probe a judge-named target)
    [cand] = ps.discover(repo, only="sanitize_jinja")
    assert cand["function"] == "sanitize_jinja"


# --------------------------------------------------------------------------
# probing (--run) — the acceptance shape: residual #3 detected
# --------------------------------------------------------------------------


def test_bypassable_sanitizer_survives_unicode_variant(repo):
    cands = [c for c in ps.discover(repo) if c["function"] == "sanitize_jinja"]
    [result] = ps.probe(repo, cands, timeout=30)
    assert result["outcome"] == "survived"
    by_payload = {t["payload"]: t["outcome"] for t in result["transcript"]}
    # ASCII jinja markers are stripped, but the fullwidth variant and the
    # dunder body both survive — exactly the bypass shape narrative
    # review missed on awx
    assert by_payload["{{7*7}}"] == "neutralized"
    assert by_payload["｛｛7*7｝｝"] == "survived"
    assert by_payload["{{''.__class__.__mro__}}"] == "survived"


def test_effective_sanitizer_neutralizes(repo):
    cands = [c for c in ps.discover(repo) if c["function"] == "sanitize_label"]
    [result] = ps.probe(repo, cands, timeout=30)
    assert result["outcome"] == "neutralized"
    assert result["survived"] == 0


def test_erroring_function_is_inconclusive_never_safe(repo):
    cands = [c for c in ps.discover(repo) if c["function"] == "validate_name"]
    [result] = ps.probe(repo, cands, timeout=30)
    assert result["outcome"] == "inconclusive"
    assert all(t["outcome"] == "error" for t in result["transcript"])
    assert "RuntimeError" in result["transcript"][0]["exception"]


def test_unimportable_module_is_skipped_with_reason(tmp_path):
    (tmp_path / "needs_dep.py").write_text(
        "import definitely_not_installed_dep\ndef sanitize_x(v):\n    return v\n"
    )
    cands = ps.discover(tmp_path)
    [result] = ps.probe(tmp_path, cands, timeout=30)
    assert result["outcome"] == "skipped"
    assert "definitely_not_installed_dep" in result["reason"]


def test_transcript_records_payload_and_output(repo):
    cands = [c for c in ps.discover(repo) if c["function"] == "sanitize_jinja"]
    [result] = ps.probe(repo, cands, timeout=30)
    entry = result["transcript"][0]
    assert {"class", "payload", "outcome"} <= set(entry)
    assert any("output_excerpt" in t for t in result["transcript"])


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------


def test_cli_default_is_list_only(repo, tmp_path):
    out = tmp_path / "probes.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--out", str(out)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["mode"] == "list"
    assert "probes" not in data
    assert data["stats"]["candidates"] == 3
    assert "EXECUTING" not in proc.stderr


def test_cli_run_mode_warns_and_probes(repo, tmp_path):
    out = tmp_path / "probes.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--run", "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "EXECUTING repository code" in proc.stderr
    data = json.loads(out.read_text())
    assert data["mode"] == "run"
    assert data["stats"]["survived"] == 1
    assert data["stats"]["inconclusive"] >= 1
