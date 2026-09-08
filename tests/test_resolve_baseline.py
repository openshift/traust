"""Tests for harnessing/3-audit/vuln-scan/scripts/resolve_baseline.py — the /vuln-scan
--diff deterministic baseline resolver. No network: baselines come from
a fake findings.db in tmp_path and anchors from real tiny git repos
created with subprocess git init/commit."""

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
import resolve_baseline as rb

from traust.cli import build_rescan_worklist as rw

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=T", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _init_repo(path: Path, remote: str | None = "https://github.com/acme/widget.git") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    if remote:
        _git(path, "remote", "add", "origin", remote)
    return path


@pytest.fixture
def repo(tmp_path):
    """22 first-party files at the base commit (20 pkg files +
    internal/auth/login.go + go.mod), plus excluded vendor/ and .md."""
    r = _init_repo(tmp_path / "widget")
    for i in range(20):
        d = r / f"pkg{i % 4}"
        d.mkdir(exist_ok=True)
        (d / f"file{i}.go").write_text(f"package p{i % 4}\n// f{i}\n")
    (r / "internal" / "auth").mkdir(parents=True)
    (r / "internal" / "auth" / "login.go").write_text("package auth\n// login\n")
    (r / "go.mod").write_text("module widget\n")
    (r / "vendor").mkdir()
    (r / "vendor" / "dep.go").write_text("package dep\n")
    (r / "README.md").write_text("# widget\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base_sha = _git(r, "rev-parse", "HEAD")
    return r, base_sha


def _advance(r: Path) -> None:
    """A modest change on top of the base commit: 3 changed first-party
    files (13.6% of 22 — under the 30% rule), one sensitive, one deps
    manifest."""
    (r / "pkg0" / "file0.go").write_text("package p0\n// changed\nvar X=1\n")
    with (r / "internal" / "auth" / "login.go").open("a") as f:
        f.write("func Login() {}\n")
    (r / "go.mod").write_text("module widget\n\nrequire x v1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "change")


def _write_report(path: Path, sha: str, findings=None, prose: bool = True) -> Path:
    commit = f"{sha} (main HEAD, analyzed 2026-07-01)" if prose else sha
    path.write_text(
        json.dumps(
            {
                "metadata": {"commit": commit, "repository": "https://github.com/acme/widget"},
                "findings": findings or [],
            }
        )
    )
    return path


def _make_db(path: Path, rows) -> Path:
    """rows: (repo_key, repo_url, report_path, audit_date,
    report_kind, is_branch_audit)"""
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE repos (repo_key TEXT PRIMARY KEY, repo_url TEXT, "
        "report_path TEXT, audit_date TEXT, report_kind TEXT, "
        "is_branch_audit INTEGER)"
    )
    con.executemany("INSERT INTO repos VALUES (?,?,?,?,?,?)", rows)
    con.commit()
    con.close()
    return path


def _run(args) -> tuple[int, dict]:
    out = args[-1]  # convention: last arg is the --out path
    rc = rb.main([str(a) for a in args])
    doc = json.loads(Path(out).read_text())
    return rc, doc


# ---------------------------------------------------------------------------
# URL normalization -> db lookup (freshest wins), override precedence
# ---------------------------------------------------------------------------


@pytest.mark.requires_git
class TestResolution:
    def test_auto_resolution_freshest_wins(self, repo, tmp_path):
        r, base_sha = repo
        _advance(r)
        # older filing pins an unreachable SHA; fresher one the real base
        old = _write_report(tmp_path / "old-security-audit.json", "deadbeef" * 5)
        new = _write_report(tmp_path / "new-security-audit.json", base_sha)
        db = _make_db(
            tmp_path / "findings.db",
            [
                (
                    "t/a/widget",
                    "<https://github.com/acme/widget.git>",
                    str(old),
                    "2026-01-01",
                    "code-audit",
                    0,
                ),
                (
                    "t/b/widget",
                    "https://github.com/acme/widget",
                    str(new),
                    "2026-06-01",
                    "code-audit",
                    0,
                ),
            ],
        )
        rc, doc = _run([r, "--db", db, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert doc["refuse"] is False
        assert doc["baseline_report"] == str(new)
        assert doc["anchor"] == base_sha
        assert doc["resolution_source"] == "auto"

    def test_branch_and_noncode_rows_excluded(self, repo, tmp_path):
        r, base_sha = repo
        _advance(r)
        good = _write_report(tmp_path / "good-security-audit.json", base_sha)
        bad = _write_report(tmp_path / "bad-security-audit.json", "deadbeef" * 5)
        db = _make_db(
            tmp_path / "findings.db",
            [
                # fresher rows that must be ignored: branch audit / cloud-config
                (
                    "t/br/widget",
                    "https://github.com/acme/widget",
                    str(bad),
                    "2026-07-01",
                    "code-audit",
                    1,
                ),
                (
                    "t/cc/widget",
                    "https://github.com/acme/widget",
                    str(bad),
                    "2026-07-01",
                    "cloud-config",
                    0,
                ),
                (
                    "t/ok/widget",
                    "https://github.com/acme/widget",
                    str(good),
                    "2026-02-01",
                    "code-audit",
                    0,
                ),
            ],
        )
        rc, doc = _run([r, "--db", db, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert doc["baseline_report"] == str(good)

    def test_baseline_override_beats_db(self, repo, tmp_path):
        r, base_sha = repo
        _advance(r)
        db_report = _write_report(tmp_path / "db-security-audit.json", "deadbeef" * 5)
        override = _write_report(tmp_path / "ovr-security-audit.json", base_sha)
        db = _make_db(
            tmp_path / "findings.db",
            [
                (
                    "t/a/widget",
                    "https://github.com/acme/widget",
                    str(db_report),
                    "2026-06-01",
                    "code-audit",
                    0,
                )
            ],
        )
        rc, doc = _run([r, "--db", db, "--baseline", override, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert doc["baseline_report"] == str(override)
        assert doc["resolution_source"] == "override"

    def test_since_override_anchors_without_baseline(self, repo, tmp_path):
        r, base_sha = repo
        _advance(r)
        db = _make_db(tmp_path / "findings.db", [])  # nothing resolvable
        rc, doc = _run([r, "--db", db, "--since", base_sha, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert doc["anchor"] == base_sha
        assert doc["resolution_source"] == "override"
        assert doc["baseline_report"] is None
        assert doc["baseline_findings_for_changed_files"] == []

    def test_sha_parsed_from_prose_metadata_commit(self, repo, tmp_path):
        r, base_sha = repo
        _advance(r)
        report = _write_report(tmp_path / "p-security-audit.json", base_sha, prose=True)
        assert json.loads(report.read_text())["metadata"]["commit"] != base_sha  # genuinely prose
        rc, doc = _run([r, "--baseline", report, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert doc["anchor"] == base_sha

    def test_ssh_remote_normalizes_to_https(self, tmp_path):
        r = _init_repo(tmp_path / "sshrepo", remote="git@github.com:acme/widget.git")
        assert rb.repo_origin_url(r) == "https://github.com/acme/widget"

    def test_token_in_url_remote_is_stripped(self, tmp_path):
        # token-in-URL clones must never leak the credential into the
        # scope package or refusal messages (2026-07-27 re-pilot leak)
        r = _init_repo(
            tmp_path / "tokrepo",
            remote="https://oauth2:glpat-SECRET123@gitlab.example.com/grp/proj.git",
        )
        url = rb.repo_origin_url(r)
        assert url == "https://gitlab.example.com/grp/proj"
        assert "SECRET123" not in url


# ---------------------------------------------------------------------------
# refusal rules — exit 3, recommend full-audit, never whole-repo fallback
# ---------------------------------------------------------------------------


class TestRefusals:
    def _assert_refusal(self, rc, doc, needle):
        assert rc == 3
        assert doc["refuse"] is True
        assert doc["recommend"] == "full-audit"
        assert needle in doc["reason"]

    @pytest.mark.requires_git
    def test_refuse_no_baseline(self, repo, tmp_path):
        r, _ = repo
        _advance(r)
        db = _make_db(tmp_path / "findings.db", [])
        rc, doc = _run([r, "--db", db, "--out", tmp_path / "v.json"])
        self._assert_refusal(rc, doc, "no valid HEAD code-audit baseline")

    @pytest.mark.requires_git
    def test_refuse_unreachable_anchor(self, repo, tmp_path):
        r, _ = repo
        _advance(r)
        report = _write_report(tmp_path / "x-security-audit.json", "deadbeef" * 5)
        rc, doc = _run([r, "--baseline", report, "--out", tmp_path / "v.json"])
        self._assert_refusal(rc, doc, "not reachable")

    @pytest.mark.requires_git
    def test_refuse_over_30pct_files_changed(self, repo, tmp_path):
        r, base_sha = repo
        # touch 8 of 22 first-party files (36%)
        for i in range(8):
            (r / f"pkg{i % 4}" / f"file{i}.go").write_text(f"package p{i % 4}\n// rewritten {i}\n")
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", "wide change")
        report = _write_report(tmp_path / "r-security-audit.json", base_sha)
        rc, doc = _run([r, "--baseline", report, "--out", tmp_path / "v.json"])
        self._assert_refusal(rc, doc, "first-party files changed")

    @pytest.mark.requires_git
    def test_refuse_8000_first_party_lines(self, repo, tmp_path):
        r, base_sha = repo
        (r / "pkg0" / "big.go").write_text(
            "package p0\n" + "\n".join(f"// l{i}" for i in range(9000)) + "\n"
        )
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", "big change")
        report = _write_report(tmp_path / "c-security-audit.json", base_sha)
        rc, doc = _run([r, "--baseline", report, "--out", tmp_path / "v.json"])
        self._assert_refusal(rc, doc, str(rw.CHURN_FULL_LINES))

    def test_refuse_not_a_git_checkout(self, tmp_path):
        d = tmp_path / "plain"
        d.mkdir()
        (d / "a.go").write_text("package a\n")
        rc, doc = _run([d, "--out", tmp_path / "v.json"])
        self._assert_refusal(rc, doc, "not a git checkout")

    @pytest.mark.requires_git
    def test_refuse_baseline_without_parseable_sha(self, repo, tmp_path):
        r, _ = repo
        _advance(r)
        report = tmp_path / "n-security-audit.json"
        report.write_text(json.dumps({"metadata": {"commit": "the main branch"}, "findings": []}))
        rc, doc = _run([r, "--baseline", report, "--out", tmp_path / "v.json"])
        self._assert_refusal(rc, doc, "no parseable pinned SHA")


# ---------------------------------------------------------------------------
# router parity — a diverging matcher between router and scanner is a bug
# ---------------------------------------------------------------------------


class TestRouterParity:
    def test_shared_objects_are_the_routers(self):
        assert rb.is_first_party is rw.is_first_party
        assert rb.is_deps_manifest is rw.is_deps_manifest
        assert rb.SENSITIVE_RX is rw.SENSITIVE_RX
        assert rb.parse_pinned_sha is rw.parse_pinned_sha
        assert rb.CHURN_FULL_LINES == rw.CHURN_FULL_LINES == 8000

    @pytest.mark.parametrize(
        "path,first_party,sensitive,deps",
        [
            ("pkg/server.go", True, False, False),
            ("vendor/lib/x.go", False, False, False),
            ("node_modules/a/b.js", False, False, False),
            ("api/zz_generated.deepcopy.go", False, False, False),
            ("pkg/api.pb.go", False, False, False),
            ("docs/README.md", False, False, False),
            ("internal/auth/login.go", True, True, False),
            ("pkg/tls_config.go", True, True, False),
            ("go.mod", True, False, True),
            ("ui/package-lock.json", True, False, True),
            ("requirements-dev.txt", True, False, True),
        ],
    )
    def test_matcher_behavior_parity(self, path, first_party, sensitive, deps):
        for mod in (rb, rw):
            assert mod.is_first_party(path) is first_party
            assert bool(mod.SENSITIVE_RX.search(path)) is sensitive
            assert mod.is_deps_manifest(path) is deps


# ---------------------------------------------------------------------------
# scope-package pieces
# ---------------------------------------------------------------------------


class TestClusters:
    def test_groups_by_top_level_dir(self):
        clusters = rb.cluster_paths(["pkg/a.go", "pkg/b.go", "cmd/main.go", "go.mod"])
        names = {c["name"] for c in clusters}
        assert names == {"pkg", "cmd", "(root)"}
        by_name = {c["name"]: c["files"] for c in clusters}
        assert by_name["pkg"] == ["pkg/a.go", "pkg/b.go"]
        assert by_name["(root)"] == ["go.mod"]

    def test_caps_at_five_groups_with_other(self):
        paths = [f"d{i}/f.go" for i in range(8)] + ["d0/g.go"]
        clusters = rb.cluster_paths(paths)
        assert len(clusters) == 5
        assert clusters[0]["name"] == "d0"  # largest stays named
        other = [c for c in clusters if c["name"] == "other"]
        assert len(other) == 1
        assert len(other[0]["files"]) == 4  # the merged tail
        # every path lands in exactly one cluster
        assert sorted(f for c in clusters for f in c["files"]) == sorted(paths)

    def test_empty(self):
        assert rb.cluster_paths([]) == []


class TestBaselineFindings:
    def test_extraction_by_changed_paths(self):
        report = {
            "findings": [
                {
                    "id": "W-1",
                    "fingerprint": "aaa",
                    "title": "SQLi",
                    "severity": "high",
                    "locations": [{"path": "internal/auth/login.go", "lines": "10-12"}],
                },
                {
                    "id": "W-2",
                    "fingerprint": None,
                    "title": "XSS",
                    "severity": "medium",
                    "locations": [{"path": "./pkg0/file0.go"}],
                },
                {
                    "id": "W-3",
                    "fingerprint": "ccc",
                    "title": "unrelated",
                    "severity": "low",
                    "locations": [{"path": "pkg3/file3.go"}],
                },
            ]
        }
        got = rb.baseline_findings_for(report, ["internal/auth/login.go", "pkg0/file0.go"])
        assert [f["id"] for f in got] == ["W-1", "W-2"]
        assert got[0]["fingerprint"] == "aaa"
        assert got[0]["title"] == "SQLi"
        assert got[0]["paths"] == ["internal/auth/login.go"]
        assert set(got[0]) == {"id", "fingerprint", "title", "severity", "paths"}

    def test_no_report_or_no_changes(self):
        assert rb.baseline_findings_for(None, ["a.go"]) == []
        assert rb.baseline_findings_for({"findings": [{"id": "x"}]}, []) == []


class TestNumstatParsing:
    def test_rename_brace_normalization(self):
        assert rb._normalize_numstat_path("pkg/{old => new}/f.go") == "pkg/new/f.go"
        assert rb._normalize_numstat_path("old.go => new.go") == "new.go"
        assert rb._normalize_numstat_path("{ => cmd}/main.go") == "cmd/main.go"
        assert rb._normalize_numstat_path("plain/path.go") == "plain/path.go"


# ---------------------------------------------------------------------------
# end-to-end scope package (synthetic repo + fake db, no network)
# ---------------------------------------------------------------------------

SCOPE_KEYS = {
    "refuse",
    "target",
    "repo_url",
    "baseline_report",
    "anchor",
    "resolution_source",
    "changed_files",
    "clusters",
    "C",
    "sensitive_lines",
    "deps_manifests_changed",
    "baseline_findings_for_changed_files",
    "total_first_party_files",
    "changed_first_party_ratio",
}


@pytest.mark.requires_git
class TestScopePackage:
    def test_schema_keys_and_metrics(self, repo, tmp_path):
        r, base_sha = repo
        _advance(r)
        report = _write_report(
            tmp_path / "w-security-audit.json",
            base_sha,
            findings=[
                {
                    "id": "W-1",
                    "fingerprint": "aaa",
                    "title": "t",
                    "severity": "high",
                    "locations": [{"path": "internal/auth/login.go"}],
                }
            ],
        )
        db = _make_db(
            tmp_path / "findings.db",
            [
                (
                    "t/a/widget",
                    "https://github.com/acme/widget",
                    str(report),
                    "2026-06-01",
                    "code-audit",
                    0,
                )
            ],
        )
        rc, doc = _run([r, "--db", db, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert set(doc) == SCOPE_KEYS
        assert doc["repo_url"] == "https://github.com/acme/widget"

        changed = {c["path"]: c for c in doc["changed_files"]}
        assert set(changed) == {"pkg0/file0.go", "internal/auth/login.go", "go.mod"}
        for c in doc["changed_files"]:
            assert set(c) == {"path", "added", "deleted", "sensitive"}
        assert changed["internal/auth/login.go"]["sensitive"] is True
        assert changed["pkg0/file0.go"]["sensitive"] is False
        assert changed["internal/auth/login.go"]["added"] >= 1

        assert doc["deps_manifests_changed"] is True
        assert doc["C"] == sum(c["added"] + c["deleted"] for c in doc["changed_files"])
        assert doc["sensitive_lines"] >= 1
        assert doc["total_first_party_files"] == 22
        assert 0 < doc["changed_first_party_ratio"] <= 0.30

        cluster_names = {c["name"] for c in doc["clusters"]}
        assert cluster_names == {"pkg0", "internal", "(root)"}
        assert 1 <= len(doc["clusters"]) <= 5

        blf = doc["baseline_findings_for_changed_files"]
        assert [f["id"] for f in blf] == ["W-1"]
        assert blf[0]["paths"] == ["internal/auth/login.go"]

    def test_vendor_and_md_changes_excluded(self, repo, tmp_path):
        r, base_sha = repo
        (r / "vendor" / "dep.go").write_text("package dep\n// changed\n")
        (r / "README.md").write_text("# widget\nchanged\n")
        (r / "pkg1" / "file1.go").write_text("package p1\n// changed\n")
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", "mixed change")
        report = _write_report(tmp_path / "v-security-audit.json", base_sha)
        rc, doc = _run([r, "--baseline", report, "--out", tmp_path / "scope.json"])
        assert rc == 0
        assert [c["path"] for c in doc["changed_files"]] == ["pkg1/file1.go"]
        assert doc["deps_manifests_changed"] is False
