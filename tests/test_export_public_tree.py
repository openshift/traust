"""export_public_tree — strips, rewrites, truncates, fresh history; source untouched."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from traust.migrations import export_public_tree as ex

PRIV = "ssh://git@git.example.internal/example-group"
PUB = "https://github.com/example-org"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _source_repo(ws: Path, name: str) -> Path:
    r = ws / name
    (r / ".tekton").mkdir(parents=True)
    (r / ".tekton" / "build.yaml").write_text("internal: pipeline\n")
    (r / ".gitlab-ci.yml").write_text("ci: internal\n")
    (r / "VERSION").write_text("1.2.3\n")
    (r / "CHANGELOG.md").write_text("# Changelog\n\n## v1.2.3\n- codename Foo\n")
    (r / "pyproject.toml").write_text(
        f'[tool.uv.sources]\ndep = {{ git = "{PRIV}/dep.git", tag = "v1" }}\n'
    )
    (r / "uv.lock").write_text(f'source = {{ git = "{PRIV}/dep.git?tag=v1#abc" }}\n')
    (r / "README.md").write_text(f"See {PRIV.replace('ssh://git@', 'https://')}/{name}\n")
    (r / "untracked.txt").write_text("never exported\n")
    (r / "blob.bin").write_bytes(b"\0\1\2" + PRIV.encode())
    _git(r, "init", "-q", "-b", "main")
    _git(
        r,
        "add",
        "VERSION",
        "CHANGELOG.md",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        ".tekton",
        ".gitlab-ci.yml",
        "blob.bin",
    )
    _git(r, "commit", "-q", "-m", "src")
    return r


def _cfg(tmp: Path) -> Path:
    p = tmp / "export.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "public_base_url": PUB,
                "private_base_urls": [PRIV, PRIV.replace("ssh://git@", "https://")],
                "repos": ["alpha"],
                "strip": [".tekton/", ".gitlab-ci.yml", "missing-file"],
                "changelog": {"mode": "truncate", "note": "History begins at public release."},
                "commit_author": "Maintainers <m@example.org>",
            }
        )
    )
    return p


def test_export_produces_a_clean_fresh_tree(tmp_path):
    ws = tmp_path / "ws"
    src = _source_repo(ws, "alpha")
    out = tmp_path / "out"
    rc = ex.main(
        ["--config", str(_cfg(tmp_path)), "--workspace", str(ws), "--out", str(out), "--no-scan"]
    )
    assert rc == 0
    t = out / "alpha"
    # stripped
    assert not (t / ".tekton").exists() and not (t / ".gitlab-ci.yml").exists()
    # untracked never travels
    assert not (t / "untracked.txt").exists()
    # rewritten everywhere, both URL forms, binary untouched
    assert (
        t / "pyproject.toml"
    ).read_text() == f'[tool.uv.sources]\ndep = {{ git = "{PUB}/dep.git", tag = "v1" }}\n'
    assert PUB in (t / "uv.lock").read_text() and PRIV not in (t / "uv.lock").read_text()
    assert (t / "README.md").read_text() == f"See {PUB}/alpha\n"
    assert PRIV.encode() in (t / "blob.bin").read_bytes()
    # changelog truncated with provenance + version
    cl = (t / "CHANGELOG.md").read_text()
    assert "codename Foo" not in cl and "v1.2.3" in cl and "History begins" in cl
    # fresh history: exactly one commit, by the configured author
    log = _git(t, "log", "--format=%an <%ae> %s")
    assert log.count("\n") == 1 and log.startswith("Maintainers <m@example.org> alpha v1.2.3")
    # source untouched
    assert (src / ".tekton" / "build.yaml").exists()
    assert PRIV in (src / "pyproject.toml").read_text()
    # report
    rep = (out / "export-report.md").read_text()
    assert "| `alpha` |" in rep and "truncated" in rep
    import json

    j = json.loads((out / "export-report.json").read_text())
    assert j["repos"][0]["stripped"] == [".tekton/", ".gitlab-ci.yml"]
    assert j["repos"][0]["lock_needs_regeneration"] is True


def test_gitlab_web_paths_become_github_paths():
    pub = "https://github.com/example-org"
    text = (
        f"see {pub}/traust/-/blob/main/docs/x.md and "
        f"{pub}/traust/-/tree/main/docs, MR {pub}/traust/-/merge_requests/7; "
        f"untouched: https://gitlab.example/g/p/-/blob/main/README.md"
    )
    out = ex._fix_forge_paths(text, pub)
    assert f"{pub}/traust/blob/main/docs/x.md" in out
    assert f"{pub}/traust/tree/main/docs" in out
    assert f"{pub}/traust/pulls/7" in out
    assert "gitlab.example/g/p/-/blob/main/README.md" in out  # other hosts untouched
    assert "/-/" not in out.split("untouched:")[0]


def test_rewrite_urls_fixes_paths_end_to_end(tmp_path):
    (tmp_path / "doc.md").write_text(
        f"[x]({PRIV.replace('ssh://git@', 'https://')}/traust/-/blob/main/docs/x.md)\n"
    )
    ex.rewrite_urls(tmp_path, [PRIV, PRIV.replace("ssh://git@", "https://")], PUB)
    assert (tmp_path / "doc.md").read_text() == f"[x]({PUB}/traust/blob/main/docs/x.md)\n"


def test_per_component_version_files(tmp_path):
    t = tmp_path / "sdk"
    (t / "go").mkdir(parents=True)
    (t / "python").mkdir()
    (t / "go" / "VERSION").write_text("0.11.0\n")
    (t / "python" / "VERSION").write_text("0.3.0\n")
    assert ex.read_version(t) == "go 0.11.0, python 0.3.0"
    (t / "VERSION").write_text("9.9.9\n")
    assert ex.read_version(t) == "9.9.9"  # root wins
    (tmp_path / "nothing").mkdir()
    assert ex.read_version(tmp_path / "nothing") is None


def test_missing_required_key_fails_loud(tmp_path):
    p = tmp_path / "export.yaml"
    p.write_text("repos: [a]\n")
    import pytest

    with pytest.raises(SystemExit, match="public_base_url"):
        ex.load_export_config(p)
