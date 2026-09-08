"""Tests for harnessing/3-audit/dependency-watch/scripts/verify_dep_provenance.py — subdir-aware auto-
verification of dependency findings against their source manifests.

NO network: every fetch is an injected fake `fetch=`. The load-bearing case
is `refuted` for an npm alias (`"x":"npm:real@ver"` when checking for `x`) —
exactly the legacy-swc-helpers false positive that only manual source
inspection used to catch.
"""

import importlib.util
import json
import sys
from pathlib import Path

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "verify_dep_provenance", skill_dir("dependency-watch") / "scripts" / "verify_dep_provenance.py"
)
vdp = importlib.util.module_from_spec(_SPEC)
sys.modules["verify_dep_provenance"] = vdp
_SPEC.loader.exec_module(vdp)


def _ok(text):
    """A fetch fake that returns ok + `text` for any (org, name, path, eco)."""
    return lambda org, name, path, eco: ("ok", text)


# --------------------------------------------------------------------------
# refuted — the npm-alias false positive (legacy-swc-helpers)
# --------------------------------------------------------------------------


def test_refuted_npm_alias_masking_a_different_package():
    # package.json declares the LEGIT @swc/helpers under a local alias name
    # `legacy-swc-helpers`; checking for the malicious `legacy-swc-helpers`
    # must REFUTE — the alias resolves to a different real package.
    text = json.dumps(
        {"name": "app", "dependencies": {"legacy-swc-helpers": "npm:@swc/helpers@0.4.14"}}
    )
    res = vdp.verify_dep(
        "repo:acme/app",
        "npm",
        "legacy-swc-helpers",
        "1.0.0",
        ["services/api/package.json"],
        fetch=_ok(text),
    )
    assert res["status"] == "refuted"
    # paper trail names the real package the alias pointed at
    assert "@swc/helpers" in res["evidence"]
    assert res["manifest"] == "services/api/package.json"


def test_refuted_package_genuinely_absent():
    text = json.dumps({"dependencies": {"lodash": "^4.17.0"}})
    res = vdp.verify_dep(
        "repo:acme/app", "npm", "evil-pkg", "1.0.0", ["package.json"], fetch=_ok(text)
    )
    assert res["status"] == "refuted"
    assert "evil-pkg" in res["evidence"]
    assert res["manifest"] == "package.json"


# --------------------------------------------------------------------------
# confirmed — a real declaration
# --------------------------------------------------------------------------


def test_confirmed_real_declaration_version_matches():
    text = json.dumps({"name": "app", "dependencies": {"lodash": "4.17.20"}})
    res = vdp.verify_dep(
        "repo:acme/app", "npm", "lodash", "4.17.20", ["package.json"], fetch=_ok(text)
    )
    assert res["status"] == "confirmed"
    assert res["manifest"] == "package.json"
    assert "lodash" in res["evidence"]
    assert "matches" in res["evidence"]


def test_confirmed_alias_resolves_to_the_checked_real_package():
    # here the REAL package IS the one we are checking for, reached via an
    # alias entry: parser resolves `npm:lodash@4.17.20` -> (lodash, ...).
    text = json.dumps({"dependencies": {"ld": "npm:lodash@4.17.20"}})
    res = vdp.verify_dep(
        "repo:acme/app", "npm", "lodash", "4.17.20", ["package.json"], fetch=_ok(text)
    )
    assert res["status"] == "confirmed"


def test_confirmed_pypi_name_normalization():
    # pypi names are PEP 503 normalized by the parser; a case/separator
    # difference must still CONFIRM, never falsely refute.
    text = "Flask_Login==0.6.3\n"
    res = vdp.verify_dep(
        "repo:acme/app", "pypi", "flask-login", "0.6.3", ["requirements.txt"], fetch=_ok(text)
    )
    assert res["status"] == "confirmed"


# --------------------------------------------------------------------------
# unverifiable — fetch failure or no manifest recorded
# --------------------------------------------------------------------------


def test_unverifiable_on_fetch_failure():
    res = vdp.verify_dep(
        "repo:acme/app",
        "npm",
        "lodash",
        "4.17.20",
        ["package.json"],
        fetch=lambda *a: ("error", ""),
    )
    assert res["status"] == "unverifiable"
    assert res["manifest"] is None


def test_unverifiable_when_fetch_raises():
    def boom(*a):
        raise RuntimeError("network down")

    res = vdp.verify_dep("repo:acme/app", "npm", "lodash", "4.17.20", ["package.json"], fetch=boom)
    assert res["status"] == "unverifiable"


def test_unverifiable_no_manifest_path_recorded():
    res = vdp.verify_dep("repo:acme/app", "npm", "lodash", "4.17.20", [], fetch=_ok("{}"))
    assert res["status"] == "unverifiable"
    assert "no source-manifest path" in res["evidence"]


def test_unverifiable_bad_repo_id_never_fetches():
    calls = []

    def spy(*a):
        calls.append(a)
        return "ok", "{}"

    res = vdp.verify_dep("not-a-repo-node", "npm", "lodash", "4.17.20", ["package.json"], fetch=spy)
    assert res["status"] == "unverifiable"
    assert calls == []  # fail closed before any gh api call


# --------------------------------------------------------------------------
# fetch is a literal contents-style call: org/name/path threaded through
# --------------------------------------------------------------------------


def test_fetch_receives_org_name_path_from_repo_id():
    seen = {}

    def spy(org, name, path, eco):
        seen.update(org=org, name=name, path=path, eco=eco)
        return "ok", json.dumps({"dependencies": {"lodash": "1.0.0"}})

    vdp.verify_dep(
        "repo:acme/widget", "npm", "lodash", "1.0.0", ["deep/dir/package.json"], fetch=spy
    )
    assert seen == {"org": "acme", "name": "widget", "path": "deep/dir/package.json", "eco": "npm"}


def test_path_traversal_rejected():
    res = vdp.verify_dep(
        "repo:acme/app", "npm", "lodash", "1.0.0", ["../../etc/passwd"], fetch=_ok("{}")
    )
    # the only recorded path is unsafe -> treated as no usable path
    assert res["status"] == "unverifiable"


# --------------------------------------------------------------------------
# multi-manifest: confirmation in ANY recorded manifest wins over absence
# --------------------------------------------------------------------------


def test_confirmed_wins_across_multiple_manifests():
    def fetch(org, name, path, eco):
        if path == "a/package.json":
            return "ok", json.dumps({"dependencies": {"other": "1.0.0"}})
        return "ok", json.dumps({"dependencies": {"lodash": "4.17.20"}})

    res = vdp.verify_dep(
        "repo:acme/app",
        "npm",
        "lodash",
        "4.17.20",
        ["a/package.json", "b/package.json"],
        fetch=fetch,
    )
    assert res["status"] == "confirmed"
    assert res["manifest"] == "b/package.json"
