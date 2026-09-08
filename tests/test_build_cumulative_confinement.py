"""P9b: build_cumulative must not write a ledger outside the findings tree.

It took a bare `Path(args.layer)` and wrote wherever it was told — including
outside analysis-results/ and through a symlink — while three of the five
writers already refused that. Ledger plan §0 item 2.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parents[1]


def _audit(path: Path):
    path.write_text(
        json.dumps(
            {
                "title": "t",
                "metadata": {
                    "date": "2026-08-18",
                    "scope": "s",
                    "repository": "https://github.com/org/repo",
                    "commit": "a" * 40,
                    "harness_version": "0.292.0",
                },
                "findings": [],
            }
        )
    )


def _layer(path: Path, audit_name: str):
    path.write_text(
        json.dumps(
            {
                "metadata": {
                    "audit_report": audit_name,
                    "repository": "https://github.com/org/repo",
                    "created": "2026-08-18T00:00:00+00:00",
                    "harness_version": "0.292.0",
                },
                "events": [],
                "needs_review": [],
            }
        )
    )


def _run(audit: Path, layer: Path, *extra):
    return subprocess.run(
        [sys.executable, "-m", "traust.cli.build_cumulative", str(audit), str(layer), *extra],
        capture_output=True,
        text=True,
        cwd=str(HARNESS),
    )


def test_refuses_a_layer_outside_the_declared_root(tmp_path):
    tree = tmp_path / "findings" / "repo"
    tree.mkdir(parents=True)
    audit = tree / "repo-security-audit.json"
    _audit(audit)
    outside = tmp_path / "escaped-findings-layer.json"
    _layer(outside, "repo-security-audit.json")

    r = _run(audit, outside, "--findings-root", str(tmp_path / "findings"))

    assert r.returncode == 2, r.stdout + r.stderr
    assert "outside the allowed root" in (r.stdout + r.stderr)


@pytest.mark.requires_ledger
def test_accepts_a_layer_inside_the_tree(tmp_path):
    tree = tmp_path / "findings" / "repo"
    tree.mkdir(parents=True)
    audit = tree / "repo-security-audit.json"
    _audit(audit)
    layer = tree / "repo-findings-layer.json"
    _layer(layer, "repo-security-audit.json")

    r = _run(audit, layer, "--findings-root", str(tmp_path / "findings"))

    assert r.returncode == 0, r.stdout + r.stderr
    assert (tree / "repo-findings-current.json").is_file()


def test_symlink_out_of_the_tree_is_caught_not_followed(tmp_path):
    tree = tmp_path / "findings" / "repo"
    tree.mkdir(parents=True)
    audit = tree / "repo-security-audit.json"
    _audit(audit)
    real = tmp_path / "real-findings-layer.json"
    _layer(real, "repo-security-audit.json")
    link = tree / "repo-findings-layer.json"
    link.symlink_to(real)

    r = _run(audit, link, "--findings-root", str(tmp_path / "findings"))

    assert r.returncode == 2, r.stdout + r.stderr
    assert "outside the allowed root" in (r.stdout + r.stderr)
