#!/usr/bin/env python3
"""Bicep-transpile fallback in cloud-config-audit/run_checkov.py.

checkov 3.3.6's bicep parser fails on a large share of real-world Bicep
(82/188 ARO-HCP, Phase-0 sweep; 71/75 recovered by the live fallback
run 2026-07-29). Parse-failed .bicep files are transpiled with the
pinned bicep CLI (`bicep build --no-restore`, offline) and re-scanned
through the arm framework; fact paths alias back to the source .bicep.
Everything here is mocked — no bicep or checkov binary required.
"""

import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

from traust.paths import skill_dir

REPO = Path(__file__).resolve().parent.parent


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "cca_runner_bicep", skill_dir("cloud-config-audit") / "scripts" / "run_checkov.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bicep_block(parse_failures):
    return {
        "check_type": "bicep",
        "results": {"failed_checks": [], "parsing_errors": list(parse_failures)},
        "summary": {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": len(parse_failures)},
    }


class TestParseFailureExtraction(unittest.TestCase):
    def test_strips_roots_and_filters_non_bicep(self):
        runner = _load_runner()
        parsed = [_bicep_block(["/scan/root/a/b.bicep", "/scan/root/c.yaml"])]
        rels = runner._bicep_parse_failures(parsed, ("/scan/root",))
        self.assertEqual(rels, ["/a/b.bicep"])

    def test_no_failures_no_work(self):
        runner = _load_runner()
        self.assertEqual(runner._bicep_parse_failures([_bicep_block([])], ()), [])


class TestFallback(unittest.TestCase):
    def test_absent_bicep_cli_notes_and_keeps_gap(self):
        runner = _load_runner()
        with mock.patch.object(runner, "_find_bicep", return_value=None):
            blocks, _roots, _aliases, notes, ok, failed = runner._bicep_fallback(
                Path("/repo"), [_bicep_block(["/repo/x.bicep"])], ("/repo",)
            )
        self.assertEqual(blocks, [])
        self.assertEqual(ok, [])
        self.assertEqual(failed, ["/x.bicep"])
        self.assertIn("not installed", notes["bicep_transpile_fallback"])

    def test_transpile_and_rescan_aliases_source_paths(self):
        runner = _load_runner()
        import tempfile

        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "infra").mkdir()
            src = Path(repo) / "infra" / "kv.bicep"
            src.write_text("param x string\n")

            calls = []

            def fake_run(cmd, **kw):
                calls.append(cmd)
                m = mock.Mock(returncode=0, stderr="")
                if cmd[0] == "fake-bicep":
                    # bicep build --no-restore --outfile <dst>
                    self.assertIn("--no-restore", cmd)
                    Path(cmd[cmd.index("--outfile") + 1]).write_text("{}")
                    m.stdout = ""
                else:  # checkov arm re-scan
                    self.assertIn("--framework", cmd)
                    self.assertEqual(cmd[cmd.index("--framework") + 1], "arm")
                    self.assertIn("--skip-download", cmd)
                    tmp_root = cmd[cmd.index("--directory") + 1]
                    m.stdout = json.dumps(
                        {
                            "check_type": "arm",
                            "results": {
                                "failed_checks": [
                                    {
                                        "check_id": "CKV_AZURE_189",
                                        "check_name": "kv public access",
                                        "file_path": f"{tmp_root}/infra/kv.bicep.arm.json",
                                        "file_line_range": [1, 2],
                                        "resource": "Microsoft.KeyVault/vaults.kv",
                                    }
                                ],
                                "parsing_errors": [],
                            },
                            "summary": {
                                "passed": 0,
                                "failed": 1,
                                "skipped": 0,
                                "parsing_errors": 0,
                            },
                        }
                    )
                return m

            with (
                mock.patch.object(runner, "_find_bicep", return_value="fake-bicep"),
                mock.patch.object(runner.subprocess, "run", side_effect=fake_run),
            ):
                blocks, roots, aliases, notes, ok, failed = runner._bicep_fallback(
                    Path(repo), [_bicep_block([f"{repo}/infra/kv.bicep"])], (repo,)
                )

            self.assertEqual(ok, ["/infra/kv.bicep"])
            self.assertEqual(failed, [])
            self.assertEqual(aliases, {"/infra/kv.bicep.arm.json": "/infra/kv.bicep"})
            self.assertIn("1/1", notes["bicep_transpile_fallback"])
            # normalize with the returned roots+aliases cites the SOURCE
            facts, _counts = runner.normalize_checkov(
                blocks, "t", target_root=roots, path_aliases=aliases
            )
            self.assertEqual(facts[0]["file_path"], "/infra/kv.bicep")
            self.assertEqual(facts[0]["framework"], "arm")

    def test_transpile_failure_stays_failed(self):
        runner = _load_runner()
        import tempfile

        with tempfile.TemporaryDirectory() as repo:
            src = Path(repo) / "broken.bicep"
            src.write_text("module m 'br:registry/x:1' = {}\n")

            def fake_run(cmd, **kw):
                return mock.Mock(returncode=1, stdout="", stderr="boom")

            with (
                mock.patch.object(runner, "_find_bicep", return_value="fake-bicep"),
                mock.patch.object(runner.subprocess, "run", side_effect=fake_run),
            ):
                blocks, _roots, _aliases, notes, ok, failed = runner._bicep_fallback(
                    Path(repo), [_bicep_block([f"{repo}/broken.bicep"])], (repo,)
                )
            self.assertEqual(ok, [])
            self.assertEqual(failed, ["/broken.bicep"])
            self.assertEqual(blocks, [])
            self.assertIn("0/1", notes["bicep_transpile_fallback"])


class TestFactDedupe(unittest.TestCase):
    def test_repeated_fact_identity_collapses_to_one_row(self):
        # a module instantiated 3x in transpiled ARM yields the same
        # framework|check|file|resource identity at different lines —
        # one fact row (live: 6 dupe ids on ARO-HCP before the fix)
        runner = _load_runner()
        check = {
            "check_id": "CKV_AZURE_111",
            "check_name": "soft delete",
            "file_path": "/t/kv.bicep",
            "resource": "Microsoft.KeyVault/vaults.[p('kv')]",
        }
        block = {
            "check_type": "arm",
            "results": {
                "failed_checks": [
                    {**check, "file_line_range": [1, 5]},
                    {**check, "file_line_range": [100, 105]},
                    {**check, "file_line_range": [200, 205]},
                ],
                "parsing_errors": [],
            },
            "summary": {"passed": 0, "failed": 3, "skipped": 0, "parsing_errors": 0},
        }
        facts, counts = runner.normalize_checkov([block], "t")
        self.assertEqual(len(facts), 1)
        self.assertEqual(counts["failed"], 3)  # raw count preserved


if __name__ == "__main__":
    unittest.main()
