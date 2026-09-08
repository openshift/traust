"""A16 — ledger layers are written through the SDK, never directly.

traust-engine 0.9.6 collapsed four write mechanisms into one: layer mutations go
through `LedgerClient`, where mutate + stamp + sign happen inside a single
`Backend.mutate` lock. A direct write bypasses that lock and reintroduces the split
that left 112 signed corpus layers unsigned on 2026-08-31 while every one was reported
written and successful.

The rule lands with **zero** violations — Phase 2 removed the last caller — so it is a
ratchet, not a cleanup. That makes these tests the only thing standing between it and
quiet uselessness: a rule that cannot fail proves nothing.

Both false positives below were real, found while writing it:

- `build_attack_coverage.py` writes an **ATT&CK Navigator** layer, a different thing
  that happens to be called a layer;
- `emit_triage_ledger_events` builds the refuted-register path with
  `.replace("-findings-layer.json", "-refuted-register.json")`, so a layer name sits
  right next to a write of something else.

And two true positives it initially missed: the binding usually sits several lines
above the write, which same-line matching does not see.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from traust.cli.check_skill_alignment import (
    a16_layer_write_boundary_failures,
)

REPO = Path(__file__).resolve().parent.parent


def _run(tmp_repo: Path) -> list[str]:
    return a16_layer_write_boundary_failures(tmp_repo)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src" / "traust" / "cli").mkdir(parents=True)
    return tmp_path


def _write(repo: Path, name: str, body: str) -> None:
    (repo / "src" / "traust" / "cli" / name).write_text(body, "utf-8")


def test_the_real_tree_is_clean():
    """The ratchet must start green, or it will be waived on day one."""
    assert a16_layer_write_boundary_failures(REPO) == []


def test_catches_the_private_helper(repo):
    _write(
        repo,
        "bad1.py",
        (
            "from traust_engine.ledger import LedgerService\n"
            "def bad(lp, layer):\n"
            "    LedgerService._write_layer_file(lp, layer)\n"
        ),
    )
    assert len(_run(repo)) == 1


def test_catches_a_raw_write_bound_several_lines_above(repo):
    """The shape finding_identity.py and backfill_report_digest.py actually used."""
    _write(
        repo,
        "bad2.py",
        (
            "from pathlib import Path\n"
            "def bad():\n"
            "    lp = Path('x-findings-layer.json')\n"
            "    payload = {}\n"
            "    more = 1\n"
            "    lp.write_text('{}')\n"
        ),
    )
    assert len(_run(repo)) == 1


def test_ignores_a_sibling_derived_from_a_layer_name(repo):
    """The refuted-register false positive."""
    _write(
        repo,
        "ok1.py",
        (
            "def ok(layer_path, blob):\n"
            "    register_path = layer_path.with_name(\n"
            "        layer_path.name.replace('-findings-layer.json',\n"
            "                                '-refuted-register.json'))\n"
            "    register_path.write_text(blob)\n"
        ),
    )
    assert _run(repo) == []


def test_ignores_an_unrelated_thing_called_a_layer(repo):
    """The ATT&CK Navigator false positive."""
    _write(
        repo,
        "ok2.py",
        (
            "import json\n"
            "def ok(out_dir, layer):\n"
            "    layer_path = out_dir / 'attack-navigator-layer.json'\n"
            "    layer_path.write_text(json.dumps(layer))\n"
        ),
    )
    assert _run(repo) == []


def test_ignores_ordinary_report_writes(repo):
    _write(repo, "ok3.py", ("def ok(out, text):\n    out.write_text(text)\n"))
    assert _run(repo) == []


def test_ignores_commented_out_code(repo):
    _write(
        repo,
        "ok4.py",
        ("def ok(lp, layer):\n    # LedgerService._write_layer_file(lp, layer)\n    pass\n"),
    )
    assert _run(repo) == []


def test_ignores_tests(repo):
    d = repo / "src" / "traust" / "cli" / "tests"
    d.mkdir()
    (d / "test_thing.py").write_text(
        "from traust_engine.ledger import LedgerService\n"
        "def t(lp, layer):\n"
        "    LedgerService._write_layer_file(lp, layer)\n",
        "utf-8",
    )
    assert _run(repo) == []
