"""Tests for check_reference_integrity gate."""

from traust.cli import check_reference_integrity as C


def test_reference_integrity_clean_on_repo():
    results = C.run()
    assert sum(len(v) for v in results.values()) == 0


def test_stale_top_level_scripts_path_detected(tmp_path):
    doc = tmp_path / "README.md"
    doc.write_text("Run `scripts/validate_report.py` before push.\n")
    failures = C.scripts_path_failures(tmp_path)
    assert any("scripts/validate_report.py" in f for f in failures)


def test_harnessing_skill_scripts_path_allowed(tmp_path):
    doc = tmp_path / "README.md"
    doc.write_text("python3 harnessing/census/scripts/build_census.py --summary\n")
    assert C.scripts_path_failures(tmp_path) == []
