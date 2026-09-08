#!/usr/bin/env python3
"""Content-license guard tests.

Thin wrapper around `traust.cli.check_content_licenses` (the single source of
truth for the rules). The guard enforces the licensing constraints from
docs/external-dependencies.md: no re-imported CC-NC-licensed PEACH content
and no CIS benchmark recommendation text — anywhere in the harness tree.
"""

import tempfile
import unittest
from pathlib import Path

from traust_engine.reporting import validate as V

from traust.cli import check_content_licenses as G
from traust.cli import check_docs_consistency as D


def _mini_repo(tmp: Path, skill_text: str) -> Path:
    """Minimal tree: one skill file plus the allowlisted licensing docs."""
    (tmp / "harnessing" / "some-skill").mkdir(parents=True)
    (tmp / "harnessing" / "some-skill" / "SKILL.md").write_text(skill_text)
    (tmp / "docs").mkdir()
    # Allowlisted files may name the licenses freely.
    (tmp / "docs" / "external-dependencies.md").write_text(
        "PEACH upstream is CC BY-NC-ND vs BY-NC-SA (NonCommercial).\n"
        "CIS titles look like: Ensure that the --profiling argument is set "
        "to false (Automated).\n"
    )
    (tmp / "CHANGELOG.md").write_text("mentions NonCommercial history\n")
    return tmp


class TestContentLicenseGuard(unittest.TestCase):
    def test_current_tree_is_clean(self):
        failures = G.content_license_failures(G.REPO)
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_extracted_from_docs_checker(self):
        # The guard is its own gate (/check-licensing) since v0.60.0 —
        # deliberately NOT a docs-consistency check.
        self.assertNotIn("content-license guard (PEACH/CIS)", [name for name, _ in D.CHECKS])

    def test_pre_push_hook_runs_the_guard(self):
        hook = Path(G.REPO, ".githooks", "pre-push").read_text()
        self.assertIn("check_content_licenses.py", hook)
        self.assertIn("check_docs_consistency.py", hook)

    def test_clean_mini_repo_passes(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(
                Path(d), "Assess tenant isolation per PEACH (PEACH-P..PEACH-H); cite CIS 5.1.3.\n"
            )
            self.assertEqual(G.content_license_failures(repo), [])

    def test_detects_nc_license_marker(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "licensed CC BY-NC-SA 4.0 by upstream\n")
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("NonCommercial license marker", failures[0])
            self.assertIn("harnessing/some-skill/SKILL.md:1", failures[0])

    def test_detects_noncommercial_word(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "this content is non-commercial only\n")
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 1a", failures[0])

    def test_detects_peach_adaptation_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "| Arbitrary code execution environment | ... |\n")
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("Wiz-derived", failures[0])
            self.assertIn("rule 1b", failures[0])

    def test_detects_pci_requirement_text(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(
                Path(d), "Customized Approach Objective: malicious software cannot execute\n"
            )
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 4", failures[0])
            self.assertIn("PCI", failures[0])

    def test_detects_pci_defined_approach_heading(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "Defined Approach Testing Procedures ...\n")
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 4", failures[0])

    def test_bare_pci_ids_pass(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "Maps to PCI DSS 8.3.6 and PCI DSS 3.5.1.\n")
            self.assertEqual(G.content_license_failures(repo), [])

    def test_detects_tsc_coso_principle_text(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(
                Path(d), "COSO Principle 1: The entity demonstrates a commitment to integrity\n"
            )
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 5", failures[0])
            self.assertIn("TSC", failures[0])

    def test_detects_tsc_points_of_focus_boilerplate(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "points of focus that highlight important characteristics\n")
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 5", failures[0])

    def test_bare_tsc_ids_pass(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "Maps to TSC CC6.1, CC7.2, and A1.2.\n")
            self.assertEqual(G.content_license_failures(repo), [])

    def test_detects_cis_recommendation_text(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(
                Path(d), "Ensure that the --anonymous-auth argument is set to false\n"
            )
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 2", failures[0])

    def test_detects_cis_scoring_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "CIS 1.2.16 something (Automated)\n")
            failures = G.content_license_failures(repo)
            self.assertEqual(len(failures), 1)
            self.assertIn("rule 2", failures[0])

    def test_allowlisted_files_exempt(self):
        # The mini repo's allowlisted docs contain every marker class and a
        # CIS title; a clean skill file must still yield zero failures.
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "clean skill text\n")
            self.assertEqual(G.content_license_failures(repo), [])

    def test_symlinks_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _mini_repo(Path(d), "clean\n")
            link = repo / "harnessing" / "some-skill" / "alias.md"
            link.symlink_to(repo / "docs" / "external-dependencies.md")
            self.assertEqual(G.content_license_failures(repo), [])


class TestDependencyIntake(unittest.TestCase):
    PYPROJECT = """\
[project]
name = "x"
dependencies = [
    "pyyaml",
    "jsonschema>=4.0",
]

[project.optional-dependencies]
graph = [
    "tree-sitter",
]
signing = ["sigstore>=4.0,<5.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
"""

    def _repo(self, tmp: Path, doc_text: str) -> Path:
        (tmp / "pyproject.toml").write_text(self.PYPROJECT)
        (tmp / "docs").mkdir()
        (tmp / "docs" / "external-dependencies.md").write_text(doc_text)
        return tmp

    def test_parser_handles_inline_and_block_groups(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(Path(d), "")
            deps = G.pyproject_dependencies(repo)
            self.assertEqual(deps, ["jsonschema", "pyyaml", "sigstore", "tree-sitter"])

    def test_missing_row_fails(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(
                Path(d), "| pyyaml | | | |\n| jsonschema | | | |\n| tree-sitter | | | |\n"
            )
            fails = G.dependency_intake_failures(repo)
            self.assertEqual(len(fails), 1)
            self.assertIn("'sigstore' has no row", fails[0])

    def test_all_rows_present_passes(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(Path(d), "pyyaml jsonschema tree-sitter sigstore\n")
            self.assertEqual(G.dependency_intake_failures(repo), [])

    def test_live_tree_intake_clean(self):
        self.assertEqual(G.dependency_intake_failures(G.REPO), [])
        self.assertIn("sigstore", G.pyproject_dependencies(G.REPO))


class TestValidatorCisTextWarning(unittest.TestCase):
    def _strict(
        self, description="valid description of the issue found", remediation="fix it properly"
    ):
        report = {
            "findings": [
                {
                    "id": "X-abc1234-001",
                    "description": description,
                    "remediation": remediation,
                }
            ],
            "metadata": {},
            "executive_summary": {},
        }
        result = V.ValidationResult(file_path="t.json")
        V.strict_checks(report, result)
        return [w for w in result.warnings if "recommendation-title phrasing" in w]

    def test_clean_prose_no_warning(self):
        self.assertEqual(self._strict(), [])

    def test_copied_cis_title_warns(self):
        warns = self._strict(
            description="Per CIS 1.2.16: Ensure that the --profiling argument is set to false."
        )
        self.assertEqual(len(warns), 1)

    def test_copied_title_in_remediation_warns(self):
        warns = self._strict(
            remediation="Ensure that the --anonymous-auth argument is set to false on the kubelet."
        )
        self.assertEqual(len(warns), 1)


if __name__ == "__main__":
    unittest.main()
