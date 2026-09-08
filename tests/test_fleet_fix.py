"""Tests for harnessing/7-remediate/fleet-fix/scripts/apply_fleet_fix.py."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "apply_fleet_fix", skill_dir("fleet-fix") / "scripts" / "apply_fleet_fix.py"
)
ff = importlib.util.module_from_spec(_SPEC)
sys.modules["apply_fleet_fix"] = ff
_SPEC.loader.exec_module(ff)

PILOT_SPEC = skill_dir("fleet-fix") / "specs" / "konflux-mutable-pipelineref.yaml"

TEKTON = """\
apiVersion: tekton.dev/v1
kind: PipelineRun
spec:
  pipelineRef:
    resolver: git
    params:
      - name: url
        value: "https://github.com/example/konflux-build-catalog"
      - name: revision
        value: main
      - name: pathInRepo
        value: pipelines/docker-build.yaml
"""


def _repo(tmp_path, files):
    repo = tmp_path / "clone"
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
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
            "-qm",
            "init",
        ],
        check=True,
    )
    return repo


@pytest.mark.requires_git
def test_pilot_spec_is_schema_valid_and_golden_tests_pass():
    spec = ff.load_spec(PILOT_SPEC)
    assert ff.run_golden_tests(spec, "2026-07-18") == []


@pytest.mark.requires_git
def test_apply_pins_revision(tmp_path):
    repo = _repo(tmp_path, {".tekton/pr.yaml": TEKTON})
    out = tmp_path / "out"
    rc = ff.main(
        [
            "--spec",
            str(PILOT_SPEC),
            "--repo",
            str(repo),
            "--out-dir",
            str(out),
            "--pin",
            "a" * 40,
            "--date",
            "2026-07-18",
        ]
    )
    assert rc == 0
    text = (repo / ".tekton/pr.yaml").read_text()
    assert (
        f"value: {'a' * 40}  # fleet-fix(konflux-mutable-pipelineref): "
        f"pinned from main 2026-07-18" in text
    )
    assert "value: main" not in text
    result = json.loads((out / "clone-konflux-mutable-pipelineref-result.json").read_text())
    assert result["applied"] and result["files_changed"] == [".tekton/pr.yaml"]
    assert (out / "clone-konflux-mutable-pipelineref.diff").read_text()


@pytest.mark.requires_git
def test_out_of_scope_files_untouched(tmp_path):
    repo = _repo(
        tmp_path,
        {
            ".tekton/pr.yaml": TEKTON,
            "config/deploy.yaml": "params:\n  - name: revision\n    value: main\n",
        },
    )
    ff.main(
        [
            "--spec",
            str(PILOT_SPEC),
            "--repo",
            str(repo),
            "--out-dir",
            str(tmp_path / "o"),
            "--pin",
            "a" * 40,
        ]
    )
    assert "value: main" in (repo / "config/deploy.yaml").read_text()


@pytest.mark.requires_git
def test_dirty_tree_guard(tmp_path):
    repo = _repo(tmp_path, {".tekton/pr.yaml": TEKTON})
    (repo / "dirty.txt").write_text("x")
    rc = ff.main(
        [
            "--spec",
            str(PILOT_SPEC),
            "--repo",
            str(repo),
            "--out-dir",
            str(tmp_path / "o"),
            "--pin",
            "a" * 40,
        ]
    )
    assert rc == 2
    assert "value: main" in (repo / ".tekton/pr.yaml").read_text()


@pytest.mark.requires_git
def test_no_match_reports_not_applied(tmp_path):
    repo = _repo(tmp_path, {".tekton/pr.yaml": "spec: {}\n"})
    out = tmp_path / "o"
    rc = ff.main(
        ["--spec", str(PILOT_SPEC), "--repo", str(repo), "--out-dir", str(out), "--pin", "a" * 40]
    )
    assert rc == 0
    result = json.loads((out / "clone-konflux-mutable-pipelineref-result.json").read_text())
    assert not result["applied"]


@pytest.mark.requires_git
def test_golden_failure_aborts(tmp_path):
    spec = ff.load_spec(PILOT_SPEC)
    spec["tests"][0]["after_contains"] = ["THIS WILL NOT APPEAR"]
    bad = tmp_path / "bad.yaml"
    import yaml as _y

    bad.write_text(_y.safe_dump(spec, sort_keys=False))
    repo = _repo(tmp_path, {".tekton/pr.yaml": TEKTON})
    rc = ff.main(
        [
            "--spec",
            str(bad),
            "--repo",
            str(repo),
            "--out-dir",
            str(tmp_path / "o"),
            "--pin",
            "a" * 40,
        ]
    )
    assert rc == 2
    assert "value: main" in (repo / ".tekton/pr.yaml").read_text()


@pytest.mark.requires_git
def test_max_files_guard_reverts(tmp_path):
    files = {f".tekton/p{i}.yaml": TEKTON for i in range(15)}
    repo = _repo(tmp_path, files)
    rc = ff.main(
        [
            "--spec",
            str(PILOT_SPEC),
            "--repo",
            str(repo),
            "--out-dir",
            str(tmp_path / "o"),
            "--pin",
            "a" * 40,
        ]
    )
    assert rc == 2
    assert "value: main" in (repo / ".tekton/p0.yaml").read_text()
