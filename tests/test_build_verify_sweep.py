"""Tests for harnessing/8-verify/verify-remediation/scripts/build_verify_sweep.py."""

import json
import sys
import unittest
from pathlib import Path

import build_verify_sweep as bvs
from build_verify_sweep import (
    classify,
    covered_shas_by_url,
    discover,
    ledger_remediation_events,
    parse_pinned_sha,
    sev_counts,
)


def _entry(**over):
    e = {
        "repository": "https://github.com/org/repo",
        "pinned_sha": "aaaaaaa",
        "head_sha": "bbbbbbbbbb",
        "criticals": 0,
        "highs": 0,
        "ledger_signal_events": 0,
        "verification_exists": False,
        "network": True,
    }
    e.update(over)
    return e


class TestParsePinnedSha(unittest.TestCase):
    def test_plain_sha(self):
        self.assertEqual(
            parse_pinned_sha("edb306fe69dc305ae7988080b6f7e7b9"), "edb306fe69dc305ae7988080b6f7e7b9"
        )

    def test_prose_wrapped_sha(self):
        # real campaign shape: 'edb306fe… (main HEAD, 2026-04-15) — requested…'
        self.assertEqual(
            parse_pinned_sha(
                "edb306fe69dc305ae7988080b6f7e7b99cc8a00b "
                "(main HEAD, 2026-04-15) — fell back to main"
            ),
            "edb306fe69dc305ae7988080b6f7e7b99cc8a00b",
        )

    def test_none_and_junk(self):
        self.assertIsNone(parse_pinned_sha(None))
        self.assertIsNone(parse_pinned_sha("main"))


class TestClassify(unittest.TestCase):
    def test_ledger_signal_wins(self):
        self.assertEqual(classify(_entry(ledger_signal_events=2, criticals=3)), "T1")

    def test_drifted_critical(self):
        self.assertEqual(classify(_entry(criticals=1)), "T2")

    def test_drifted_high(self):
        self.assertEqual(classify(_entry(highs=2)), "T3")

    def test_drifted_other(self):
        self.assertEqual(classify(_entry()), "T4")

    def test_unchanged_head_skipped(self):
        e = _entry(pinned_sha="abc1234", head_sha="abc1234def5678900000000000000000000000ff")
        self.assertEqual(classify(e), "skip:head_unchanged")

    def test_already_verified_skipped(self):
        self.assertEqual(classify(_entry(verification_exists=True)), "skip:already_verified")

    def test_unreachable_skipped(self):
        self.assertEqual(classify(_entry(head_sha=None)), "skip:unreachable")

    def test_no_url_skipped(self):
        self.assertEqual(classify(_entry(repository=None)), "skip:no_repo_url")

    def test_unknown_drift_queues(self):
        # offline mode: head unknown, network False -> not 'unreachable',
        # drift unknown -> queued by severity
        e = _entry(head_sha=None, network=False, highs=1)
        self.assertEqual(classify(e), "T3")


class TestDiscover(unittest.TestCase):
    def _tree(self, tmp: Path):
        d = tmp / "findings" / "prod" / "repo"
        d.mkdir(parents=True)
        report = {
            "metadata": {
                "repository": "https://github.com/org/repo",
                "commit": "aaaaaaa111 (main HEAD)",
            },
            "findings": [{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}],
        }
        (d / "repo-security-audit.json").write_text(json.dumps(report))
        layer = {
            "events": [
                {"disposition": {"resolution": "fix_in_progress"}},
                {"disposition": {"validity": "confirmed"}},
            ]
        }
        (d / "repo-findings-layer.json").write_text(json.dumps(layer))
        # a release-branch report that must be excluded by default
        (d / "repo__release-4.19-security-audit.json").write_text(json.dumps(report))
        return tmp / "findings"

    def test_discover_and_signals(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            root = self._tree(Path(td))
            entries = discover([root], include_branches=False)
            self.assertEqual(len(entries), 1)
            e = entries[0]
            self.assertEqual(e["pinned_sha"], "aaaaaaa111")
            self.assertEqual(e["criticals"], 1)
            self.assertEqual(e["highs"], 2)
            self.assertEqual(e["ledger_signal_events"], 1)
            self.assertFalse(e["verification_exists"])
            branch_entries = discover([root], include_branches=True)
            self.assertEqual(len(branch_entries), 2)

    def test_existing_verification_detected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            root = self._tree(Path(td))
            d = root / "prod" / "repo"
            (d / "repo-remediation-verification.json").write_text("{}")
            entries = discover([root], include_branches=False)
            self.assertTrue(entries[0]["verification_exists"])


class TestHelpers(unittest.TestCase):
    def test_sev_counts(self):
        c = sev_counts({"findings": [{"severity": "High"}, {"severity": "high"}, {}]})
        self.assertEqual(c["high"], 2)

    def test_ledger_events_missing_file(self):
        self.assertEqual(ledger_remediation_events(Path("/nonexistent")), 0)


class TestMdFallbackSha(unittest.TestCase):
    def test_analyzed_row_preferred_over_requested(self):
        import tempfile

        from build_verify_sweep import md_fallback_sha

        with tempfile.TemporaryDirectory() as td:
            aj = Path(td) / "repo-security-audit.json"
            aj.write_text("{}")
            (Path(td) / "repo-security-audit.md").write_text(
                "# Audit\n"
                "| Ref requested | `8f588d5f3ea6aabb111111111111111111111111` |\n"
                "| Ref analyzed (fallback) | `faacf148913b47015c087621950"
                "87a74f3d9c6d1` (main) |\n"
            )
            self.assertEqual(md_fallback_sha(aj), "faacf148913b47015c08762195087a74f3d9c6d1")

    def test_no_md_returns_none(self):
        import tempfile

        from build_verify_sweep import md_fallback_sha

        with tempfile.TemporaryDirectory() as td:
            aj = Path(td) / "repo-security-audit.json"
            aj.write_text("{}")
            self.assertIsNone(md_fallback_sha(aj))

    def test_discover_uses_md_fallback(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "findings" / "prod" / "repo"
            d.mkdir(parents=True)
            report = {"metadata": {"repository": "https://github.com/o/r"}, "findings": []}
            (d / "repo-security-audit.json").write_text(json.dumps(report))
            (d / "repo-security-audit.md").write_text(
                "| Analyzed commit | `aaaaaaa111222233334444555566667777888899` |\n"
            )
            entries = discover([Path(td) / "findings"], include_branches=False)
            self.assertEqual(entries[0]["pinned_sha"], "aaaaaaa111222233334444555566667777888899")


class TestSkippedArtifact(unittest.TestCase):
    def test_skipped_reports_listed_per_repo(self):
        import subprocess
        import tempfile

        from traust.paths import skill_dir

        script = skill_dir("verify-remediation") / "scripts" / "build_verify_sweep.py"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "findings"
            d = root / "prod" / "repo"
            d.mkdir(parents=True)
            report = {
                "metadata": {
                    "repository": "https://github.com/org/repo",
                    "commit": "aaaaaaa111 (main HEAD)",
                },
                "findings": [{"severity": "high"}],
            }
            (d / "repo-security-audit.json").write_text(json.dumps(report))
            # existing verification -> the repo must land in skipped[],
            # per-report, not just as a summary count
            (d / "repo-remediation-verification.json").write_text("{}")
            out = Path(td) / "worklist.json"
            subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--results-root",
                    td,
                    "--roots",
                    str(root),
                    "--no-network",
                    "--out",
                    str(out),
                ],
                check=True,
                capture_output=True,
            )
            doc = json.loads(out.read_text())
            self.assertEqual(doc["summary"]["skipped"]["already_verified"], 1)
            self.assertEqual(len(doc["skipped"]), 1)
            row = doc["skipped"][0]
            self.assertEqual(row["skip_reason"], "already_verified")
            self.assertEqual(row["repository"], "https://github.com/org/repo")
            self.assertTrue(row["report"].endswith("repo-security-audit.json"))
            self.assertEqual(doc["worklist"], [])


class TestCoveredElsewhere(unittest.TestCase):
    HEAD = "e06aa739aeadc1b9a23cf03df74a3d78acff6ab5"

    def _entries(self):
        canonical = _entry(verification_exists=True, verified_patched_sha=self.HEAD)
        sibling = _entry(
            verified_patched_sha=None, head_sha=self.HEAD, ledger_signal_events=2
        )  # fan-out re-queue shape
        return canonical, sibling

    def test_covered_map_built_from_verified_siblings(self):
        canonical, sibling = self._entries()
        covered = covered_shas_by_url([canonical, sibling])
        self.assertEqual(covered, {"https://github.com/org/repo": {self.HEAD}})

    def test_short_sha_prefix_matches(self):
        canonical, _ = self._entries()
        canonical["verified_patched_sha"] = self.HEAD[:12]
        covered = covered_shas_by_url([canonical])
        (sha,) = covered["https://github.com/org/repo"]
        self.assertTrue(self.HEAD.startswith(sha))

    def test_main_skips_covered_sibling(self):
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "findings"
            report = {
                "metadata": {
                    "repository": "https://github.com/org/repo",
                    "commit": "aaaaaaa111 (release-4.20)",
                },
                "findings": [{"severity": "high"}],
            }
            # canonical dir: audit + verification pinning HEAD
            can = root / "prodA" / "repo"
            can.mkdir(parents=True)
            (can / "repo-security-audit.json").write_text(json.dumps(report))
            (can / "repo-remediation-verification.json").write_text(
                json.dumps({"metadata": {"patched_commit": self.HEAD}})
            )
            # sibling dir: audit only, plus a ledger with fan-out signal
            sib = root / "prodB" / "repo"
            sib.mkdir(parents=True)
            (sib / "repo-security-audit.json").write_text(json.dumps(report))
            (sib / "repo-findings-layer.json").write_text(
                json.dumps({"events": [{"disposition": {"resolution": "partially_resolved"}}]})
            )
            out = Path(td) / "worklist.json"
            argv = [
                "build_verify_sweep.py",
                "--results-root",
                td,
                "--roots",
                str(root),
                "--out",
                str(out),
            ]
            with (
                mock.patch.object(bvs, "ls_remote_head", lambda url, timeout=25: self.HEAD),
                mock.patch.object(sys, "argv", argv),
            ):
                self.assertEqual(bvs.main(), 0)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["worklist"], [])
            reasons = {r["repo_dir"].split("/")[-2]: r["skip_reason"] for r in doc["skipped"]}
            self.assertEqual(reasons["prodA"], "already_verified")
            self.assertEqual(reasons["prodB"], "covered_elsewhere")
            self.assertEqual(doc["summary"]["skipped"]["covered_elsewhere"], 1)


class TestLoadLiveness(unittest.TestCase):
    def test_missing_artifact_is_empty(self):
        import tempfile

        from build_verify_sweep import load_liveness

        with tempfile.TemporaryDirectory() as d:
            tracker = Path(d) / "progress-tracker"
            tracker.mkdir()
            self.assertEqual(load_liveness(tracker), {})

    def test_statuses_mapped_by_url(self):
        import json as _json
        import tempfile

        from build_verify_sweep import load_liveness

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            tracker = root / "progress-tracker"
            metrics = tracker / "metrics"
            metrics.mkdir(parents=True)
            (metrics / "repo-liveness.json").write_text(
                _json.dumps(
                    {
                        "repos": {
                            "https://github.com/org/live": {"status": "active"},
                            "https://github.com/org/old": {
                                "status": "archived",
                                "status_since": "2026-01-01",
                            },
                        }
                    }
                )
            )
            m = load_liveness(tracker)
            self.assertEqual(m["https://github.com/org/old"], "archived")
            self.assertEqual(m["https://github.com/org/live"], "active")


if __name__ == "__main__":
    unittest.main()
