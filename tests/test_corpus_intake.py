"""Tests for harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py."""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from traust.context import load_engine
from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "corpus_intake", skill_dir("corpus-intake") / "scripts" / "corpus_intake.py"
)
ci = importlib.util.module_from_spec(_SPEC)
sys.modules["corpus_intake"] = ci
_SPEC.loader.exec_module(ci)

BASE = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: Example}
engagements:
  contoso:
    label: contoso
    ownership: external-bu
    business_unit: Contoso
    tree: contoso-findings
    status: registered
"""


@pytest.fixture
def cfg_path(tmp_path):
    p = tmp_path / "corpus-config.yaml"
    p.write_text(BASE, encoding="utf-8")
    return p


def _run(cfg_path, *argv):
    return ci.main(
        ["--config", str(cfg_path), "--analysis-results", str(cfg_path.parent / "nope"), *argv]
    )


def test_add_tree_roundtrip(cfg_path):
    assert (
        _run(
            cfg_path,
            "add-tree",
            "new-findings",
            "--label",
            "new-bu",
            "--ownership",
            "external-bu",
            "--business-unit",
            "New BU",
        )
        == 0
    )
    cfg = yaml.safe_load(cfg_path.read_text())
    assert cfg["trees"]["new-findings"] == {
        "label": "new-bu",
        "ownership": "external-bu",
        "business_unit": "New BU",
    }
    # untouched entries survive the re-render byte-for-byte semantically
    assert cfg["engagements"]["contoso"]["tree"] == "contoso-findings"
    assert "through the /corpus-intake skill" in cfg_path.read_text()


def test_add_engagement_and_activation_fields(cfg_path):
    assert (
        _run(
            cfg_path,
            "add-engagement",
            "ansible",
            "--label",
            "ansible",
            "--ownership",
            "external-bu",
            "--business-unit",
            "Ansible",
            "--tree",
            "ansible-findings",
            "--inventory",
            "inputs/ansible/x.csv",
            "--notes",
            "product AND BU — catalog operators stay owned "
            "under findings/; this covers the upstream "
            "segment only",
        )
        == 0
    )
    cfg = yaml.safe_load(cfg_path.read_text())
    e = cfg["engagements"]["ansible"]
    assert e["status"] == "registered"
    assert e["inventory"].endswith("x.csv")
    assert "product AND BU" in e["notes"]


@pytest.mark.parametrize(
    "argv,msg",
    [
        (
            (
                "add-tree",
                "findings",
                "--label",
                "z",
                "--ownership",
                "owned",
                "--business-unit",
                "Z",
            ),
            "already registered",
        ),
        (
            ("add-tree", "z", "--label", "contoso", "--ownership", "owned", "--business-unit", "Z"),
            "label",
        ),
        (
            (
                "add-engagement",
                "z",
                "--label",
                "z",
                "--ownership",
                "external-bu",
                "--business-unit",
                "Z",
                "--tree",
                "contoso-findings",
            ),
            "already mapped",
        ),
        (
            (
                "add-tree",
                "bad/name",
                "--label",
                "z",
                "--ownership",
                "owned",
                "--business-unit",
                "Z",
            ),
            "invalid name",
        ),
    ],
)
def test_rejections_leave_file_untouched(cfg_path, argv, msg, capsys):
    before = cfg_path.read_text()
    assert _run(cfg_path, *argv) == 2
    assert msg in capsys.readouterr().err
    assert cfg_path.read_text() == before


def test_update_field(cfg_path):
    assert (
        _run(
            cfg_path, "update", "engagement", "contoso", "--business-unit", "Contoso OSS Initiative"
        )
        == 0
    )
    cfg = yaml.safe_load(cfg_path.read_text())
    assert cfg["engagements"]["contoso"]["business_unit"] == "Contoso OSS Initiative"
    assert _run(cfg_path, "update", "tree", "missing", "--label", "x") == 2


def test_dry_run_writes_nothing(cfg_path, capsys):
    before = cfg_path.read_text()
    assert (
        _run(
            cfg_path,
            "add-tree",
            "t2",
            "--label",
            "l2",
            "--ownership",
            "upstream",
            "--business-unit",
            "B2",
            "--dry-run",
        )
        == 0
    )
    assert cfg_path.read_text() == before
    assert "t2:" in capsys.readouterr().out


def test_render_roundtrips_shipped_config():
    cfg = load_engine().corpus.config().model_dump(exclude_none=True)
    reparsed = yaml.safe_load(ci.render_config(cfg))
    for section in ("trees", "engagements", "overrides"):
        assert (reparsed.get(section) or {}) == (cfg.get(section) or {})


def test_resolver_accepts_written_file(cfg_path):
    _run(
        cfg_path,
        "add-engagement",
        "e2",
        "--label",
        "l-e2",
        "--ownership",
        "external-bu",
        "--business-unit",
        "E2",
        "--tree",
        "e2-findings",
    )
    cfg = ci.corpus.load_config(cfg_path)  # raises if invalid
    assert cfg.engagements["e2"].tree == "e2-findings"
