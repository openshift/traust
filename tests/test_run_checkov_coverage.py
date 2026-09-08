#!/usr/bin/env python3
"""
Tests for the /cloud-config-audit runner's engine-gap register
(Phase-0 sweep, 2026-07): Containerfile aliasing in the temp scan
tree (checkov 3.3.6's dockerfile framework only matches
Dockerfile-named files) and mechanical provider/framework
coverage-gap detection. Pure-function level — checkov itself is
never invoked.
"""

import importlib.util
import json
from pathlib import Path

from traust.paths import skill_dir

REPO = Path(__file__).resolve().parent.parent


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "cca_runner_cov", skill_dir("cloud-config-audit") / "scripts" / "run_checkov.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fixture_tree(tmp_path: Path) -> Path:
    """Tiny target checkout: a Containerfile (top-level and nested),
    a provider-only .tf, an OpenShift Template, a .tekton PipelineRun,
    a Bicep file, and third-party noise that must be skipped."""
    root = tmp_path / "myrepo"
    (root / "vllm-bootc").mkdir(parents=True)
    (root / "vendor" / "x").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / ".tekton").mkdir()
    (root / "Containerfile").write_text("FROM scratch\n")
    (root / "vllm-bootc" / "Containerfile").write_text("FROM quay.io/base\nUSER root\n")
    (root / "vllm-bootc" / "Containerfile.ostree").write_text("FROM quay.io/ostree\n")
    (root / "vendor" / "x" / "Containerfile").write_text("FROM x\n")
    (root / ".git" / "Containerfile").write_text("FROM x\n")
    (root / "main.tf").write_text('resource "rhoas_kafka" "k" {}\n')
    (root / "template.yaml").write_text(
        "apiVersion: template.openshift.io/v1\nkind: Template\nobjects: []\n"
    )
    (root / "deploy.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\n")
    (root / ".tekton" / "push.yaml").write_text("apiVersion: tekton.dev/v1\nkind: PipelineRun\n")
    (root / "infra.bicep").write_text("param location string\n")
    return root


# ---------------------------------------------------------------------------
# 1. Containerfile support
# ---------------------------------------------------------------------------


def test_find_containerfiles_first_party_only(tmp_path):
    runner = _load_runner()
    root = _fixture_tree(tmp_path)
    rels = sorted(p.as_posix() for p in runner.find_containerfiles(root))
    # vendor/ and hidden dirs are not first-party
    assert rels == ["Containerfile", "vllm-bootc/Containerfile", "vllm-bootc/Containerfile.ostree"]


def test_materialize_scan_tree_aliases_and_readonly_target(tmp_path):
    runner = _load_runner()
    root = _fixture_tree(tmp_path)
    tmp_root = tmp_path / "scan"
    tmp_root.mkdir()
    cfs = runner.find_containerfiles(root)
    scan_dir, aliases, skipped = runner.materialize_scan_tree(root, tmp_root, cfs)
    # aliases exist in the TEMP tree, named so checkov's dockerfile
    # framework matches them, and resolve to the real Containerfiles
    assert (scan_dir / "Dockerfile").is_symlink()
    assert (scan_dir / "Dockerfile").resolve() == (root / "Containerfile").resolve()
    assert (scan_dir / "vllm-bootc" / "Dockerfile").is_symlink()
    assert (scan_dir / "vllm-bootc" / "Dockerfile.ostree").is_symlink()
    # alias map cites real paths for the normalizer to map back
    assert aliases == {
        "/Dockerfile": "/Containerfile",
        "/vllm-bootc/Dockerfile": "/vllm-bootc/Containerfile",
        "/vllm-bootc/Dockerfile.ostree": "/vllm-bootc/Containerfile.ostree",
    }
    assert skipped == []
    # the target checkout is never modified (read-only guarantee)
    assert not (root / "Dockerfile").exists()
    assert not (root / "vllm-bootc" / "Dockerfile").exists()
    # non-Containerfile entries are still reachable in the scan tree
    assert (scan_dir / "main.tf").is_symlink()
    assert (scan_dir / "template.yaml").resolve() == (root / "template.yaml").resolve()


def test_materialize_scan_tree_mirrors_off_path_dirs_as_real(tmp_path):
    """Regression (live re-baseline 2026-07-29): checkov's file
    discovery does not descend through DIRECTORY symlinks, so every
    directory must be mirrored as a real dir (files as symlinks). A
    partial mirror (real dirs only on Containerfile paths) silently
    dropped all 32 kubernetes+terraform facts on rhoim-bootc-images —
    infra/ and vllm-bootc/ocp/ became dir symlinks checkov never
    entered."""
    runner = _load_runner()
    root = _fixture_tree(tmp_path)
    # scannable content in dirs that carry no Containerfile
    (root / "infra").mkdir()
    (root / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    (root / "vllm-bootc" / "ocp").mkdir()
    (root / "vllm-bootc" / "ocp" / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n"
    )
    tmp_root = tmp_path / "scan"
    tmp_root.mkdir()
    scan_dir, _aliases, _skipped = runner.materialize_scan_tree(
        root, tmp_root, runner.find_containerfiles(root)
    )
    for rel in ("infra", "vllm-bootc/ocp", "vendor", ".tekton"):
        d = scan_dir / rel
        assert d.is_dir() and not d.is_symlink(), (
            f"{rel} must be a real dir (checkov skips dir symlinks)"
        )
    assert (scan_dir / "infra" / "main.tf").is_symlink()
    assert (scan_dir / "vllm-bootc" / "ocp" / "deploy.yaml").is_symlink()
    # a symlinked dir in the SOURCE stays a symlink (loop safety)
    (root / "loop").symlink_to(root)
    scan2 = tmp_path / "scan2"
    scan2.mkdir()
    scan_dir2, _, _ = runner.materialize_scan_tree(root, scan2, runner.find_containerfiles(root))
    assert (scan_dir2 / "loop").is_symlink()


def test_materialize_scan_tree_skips_existing_dockerfile_twin(tmp_path):
    runner = _load_runner()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Containerfile").write_text("FROM a\n")
    (root / "Dockerfile").write_text("FROM b\n")  # real twin exists
    tmp_root = tmp_path / "scan"
    tmp_root.mkdir()
    scan_dir, aliases, skipped = runner.materialize_scan_tree(
        root, tmp_root, runner.find_containerfiles(root)
    )
    assert aliases == {}
    assert skipped == ["Containerfile"]
    # the real Dockerfile is still the one scanned, not overwritten
    assert (scan_dir / "Dockerfile").resolve() == (root / "Dockerfile").resolve()


def test_normalize_maps_alias_paths_back_to_containerfile(tmp_path):
    """Facts must cite the REAL Containerfile path, and the fact_id
    must be identical to what a native Dockerfile-named scan of the
    same content at the same real path would produce."""
    runner = _load_runner()
    aliases = {"/vllm-bootc/Dockerfile": "/vllm-bootc/Containerfile"}

    def block(file_path, resource):
        return {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_8",
                        "check_name": "Ensure the last USER is not root",
                        "file_path": file_path,
                        "repo_file_path": file_path,
                        "file_line_range": [2, 2],
                        "resource": resource,
                    }
                ]
            },
            "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
        }

    aliased, _ = runner.normalize_checkov(
        block("/vllm-bootc/Dockerfile", "/vllm-bootc/Dockerfile.USER"),
        "myrepo",
        path_aliases=aliases,
    )
    direct, _ = runner.normalize_checkov(
        block("/vllm-bootc/Containerfile", "/vllm-bootc/Containerfile.USER"), "myrepo"
    )
    assert aliased[0]["file_path"] == "/vllm-bootc/Containerfile"
    assert aliased[0]["resource"] == "/vllm-bootc/Containerfile.USER"
    assert aliased[0]["fact_id"] == direct[0]["fact_id"]


def test_run_checkov_scans_temp_tree_with_alias(tmp_path, monkeypatch):
    """run_checkov must route a Containerfile target through the ONE
    temp-scan-tree mechanism: the directory handed to checkov is a
    temp tree containing the Dockerfile alias, and the alias map comes
    back for the normalizer."""
    runner = _load_runner()
    root = tmp_path / "repo"
    (root / "img").mkdir(parents=True)
    (root / "img" / "Containerfile").write_text("FROM scratch\n")
    seen = {}

    def fake_run(cmd, **kwargs):
        scan_dir = Path(cmd[cmd.index("--directory") + 1])
        seen["scan_dir"] = str(scan_dir)
        seen["alias_exists"] = (scan_dir / "img" / "Dockerfile").is_symlink()

        class P:
            stdout = json.dumps([])
            stderr = ""
            returncode = 0

        return P()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    _raw, err, extra_roots, notes, aliases = runner.run_checkov(root, None)
    assert err is None
    assert seen["scan_dir"] != str(root.resolve())  # temp tree used
    assert seen["alias_exists"]
    assert aliases == {"/img/Dockerfile": "/img/Containerfile"}
    assert extra_roots == (seen["scan_dir"],)
    assert "containerfile_alias_workaround" in notes
    # temp tree is cleaned up after the scan
    assert not Path(seen["scan_dir"]).exists()


# ---------------------------------------------------------------------------
# 2. mechanical coverage-gap detection
# ---------------------------------------------------------------------------


def test_terraform_present_zero_checks_is_a_gap(tmp_path):
    runner = _load_runner()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "kafka.tf").write_text('resource "rhoas_kafka" "k" {}\n')
    gaps = runner.detect_coverage_gaps(root, [], "repo")
    assert len(gaps) == 1
    assert "terraform framework evaluated zero checks" in gaps[0]
    assert "rhoas" in gaps[0] and "NOT ASSESSED" in gaps[0]


def test_terraform_evaluated_is_not_a_gap(tmp_path):
    runner = _load_runner()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    assert runner.detect_coverage_gaps(root, ["terraform"], "repo") == []


def test_bicep_present_zero_checks_is_a_gap(tmp_path):
    runner = _load_runner()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "infra.bicep").write_text("param location string\n")
    gaps = runner.detect_coverage_gaps(root, ["terraform"], "repo")
    assert len(gaps) == 1
    assert "Bicep" in gaps[0] and "NOT ASSESSED" in gaps[0]


def test_template_and_tekton_files_always_gap(tmp_path):
    runner = _load_runner()
    root = _fixture_tree(tmp_path)
    gaps = runner.detect_coverage_gaps(
        root, ["terraform", "bicep", "dockerfile", "kubernetes"], "myrepo"
    )
    joined = "\n".join(gaps)
    assert "1 OpenShift Template file(s)" in joined
    assert "1 .tekton/ PipelineRun file(s)" in joined
    # frameworks that evaluated checks do not gap
    assert "terraform framework evaluated zero" not in joined
    assert "Bicep file(s) present but" not in joined


def test_plain_k8s_yaml_is_not_a_template_gap(tmp_path):
    runner = _load_runner()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "deploy.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\n")
    assert runner.detect_coverage_gaps(root, ["kubernetes"], "repo") == []


def test_gap_detection_skips_third_party_dirs(tmp_path):
    runner = _load_runner()
    root = tmp_path / "repo"
    (root / "vendor").mkdir(parents=True)
    (root / ".cache").mkdir()
    (root / "vendor" / "m.tf").write_text("{}\n")
    (root / ".cache" / "t.yaml").write_text("kind: Template\n")
    assert runner.detect_coverage_gaps(root, [], "repo") == []
