#!/usr/bin/env python3
"""Tests for harnessing/7-remediate/remediate-finding/scripts/fork_map.py.

The private-forge tier is deployment config (``remediation.yaml``): the
harness ships no hostname of anyone's internal forge, and resolves nothing as
"internal" until a deployment says which hosts are its own.
"""

import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from traust.context import remediation_settings
from traust.paths import skill_dir

FORK_MAP = skill_dir("remediate-finding") / "scripts" / "fork_map.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("fork_map_under_test", FORK_MAP)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolves annotations via sys.modules
    spec.loader.exec_module(mod)
    return mod


def _config_home(tmp_path: Path, remediation: dict) -> Path:
    home = tmp_path / "cfg"
    home.mkdir()
    home.joinpath("locations.yaml").write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "ws"),
                "analysis_results": str(tmp_path / "ar"),
                "progress_tracker": str(tmp_path / "pt"),
            }
        ),
        encoding="utf-8",
    )
    for f in (Path(__file__).parent / "fixtures" / "config").iterdir():
        if f.is_file():
            shutil.copy2(f, home / f.name)
    home.joinpath("remediation.yaml").write_text(yaml.safe_dump(remediation), encoding="utf-8")
    return home


@pytest.fixture
def fork_map(tmp_path, monkeypatch, request):
    settings = getattr(request, "param", {"fork_org": "mirror-org"})
    home = _config_home(tmp_path, settings)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    monkeypatch.delenv("HARNESS_FORK_ORG", raising=False)
    monkeypatch.delenv("HARNESS_PRIVATE_FORGE_HOSTS", raising=False)
    mod = _load_module()
    mod.configure_paths(tmp_path / "ar")  # no fork-map.csv there — heuristics only
    return mod


PRIVATE = {"fork_org": "mirror-org", "private_forge_hosts": ["forge.example.internal"]}


def test_github_repo_maps_into_the_configured_mirror_org(fork_map):
    f = fork_map.resolve("https://github.com/some-org/some-repo.git")
    assert f.fork_url == "https://github.com/mirror-org/some-repo"
    assert f.host == "github"
    assert f.visibility == "private"


@pytest.mark.parametrize("fork_map", [PRIVATE], indirect=True)
@pytest.mark.parametrize(
    "url",
    [
        "https://forge.example.internal/group/repo",
        "https://forge.example.internal/group/subgroup/repo.git",
        "https://sub.forge.example.internal/group/repo",
    ],
)
def test_configured_forge_host_is_its_own_downstream_fork(fork_map, url):
    f = fork_map.resolve(url)
    assert f.fork_url == f.upstream_url == url.removesuffix(".git")
    assert f.host == "private-forge"
    assert f.visibility == "internal"


@pytest.mark.parametrize("fork_map", [PRIVATE], indirect=True)
def test_forge_host_matches_the_host_only_not_a_lookalike_path(fork_map):
    with pytest.raises(KeyError):
        fork_map.resolve("https://evil.example.com/forge.example.internal/repo")


def test_unconfigured_host_has_no_mapping(fork_map):
    """No host is 'internal' by default — the tool knows nobody's forge."""
    for url in (
        "https://gitlab.com/some-org/some-repo",
        "https://forge.example.internal/group/repo",
        "https://git.example.org/group/repo",
    ):
        with pytest.raises(KeyError):
            fork_map.resolve(url)


def test_env_override_supplies_forge_hosts(tmp_path, monkeypatch):
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(_config_home(tmp_path, {"fork_org": "o"})))
    monkeypatch.setenv("HARNESS_PRIVATE_FORGE_HOSTS", "https://Forge.Example.Internal/, other.host")
    assert remediation_settings()["private_forge_hosts"] == (
        "forge.example.internal",
        "other.host",
    )


def test_no_hostname_of_any_deployment_is_hardcoded():
    """Regression: fork_map.py once carried an internal forge's hostname.

    A tool that ships an organisation's internal hostnames has published them,
    so the only host literal allowed here is the public forge it heuristically
    mirrors from.
    """
    source = FORK_MAP.read_text(encoding="utf-8").replace("\\.", ".")
    hosts = re.findall(
        r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|internal|corp|local)\b", source
    )
    assert set(hosts) <= {"github.com"}
