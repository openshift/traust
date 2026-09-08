"""Tests for traust.cli.calibrate_rule_pack — Stage-A rule-pack
calibration. No network, no clones: the scan and clone seams are faked."""

import json

from traust.cli import calibrate_rule_pack as crp


def _tp(repo, commit, locs, cwe="CWE-295", language="go"):
    return {
        "repo": repo,
        "commit": commit,
        "locations": locs,
        "cwe": cwe,
        "cwes": [cwe],
        "language": language,
        "title": f"tp in {repo}",
    }


class TestTargetSelection:
    def test_groups_by_repo_and_commit(self, tmp_path):
        corpus = [
            _tp("https://x/a", "a" * 40, ["p/one.go"]),
            _tp("https://x/a", "a" * 40, ["p/two.go"]),
            _tp("https://x/b", "b" * 40, ["q/three.go"]),
        ]
        t = crp.select_targets(corpus, "crypto")
        assert len(t) == 2
        assert t[("https://x/a", "a" * 40)]["locations"] == {"p/one.go", "p/two.go"}
        assert t[("https://x/a", "a" * 40)]["count"] == 2

    def test_rows_without_a_pinned_commit_are_unusable(self):
        """Without the commit we cannot reproduce the code the judge saw,
        so scoring against it would be meaningless."""
        corpus = [
            _tp("https://x/a", None, ["p/one.go"]),
            _tp("https://x/b", "not-a-sha", ["p/one.go"]),
        ]
        assert crp.select_targets(corpus, "crypto") == {}

    def test_rows_without_locations_are_unusable(self):
        assert crp.select_targets([_tp("https://x/a", "a" * 40, [])], "crypto") == {}

    def test_non_crypto_cwes_filtered_out(self):
        corpus = [_tp("https://x/a", "a" * 40, ["p/one.go"], cwe="CWE-306")]
        assert crp.select_targets(corpus, "crypto") == {}
        assert len(crp.select_targets(corpus, None)) == 1  # cwe_set=all

    def test_languages_the_pack_cannot_cover_are_excluded(self):
        """yaml/bash TPs cannot be rediscovered by a pack with no yaml or
        bash rules — scoring them would understate the pack."""
        corpus = [
            _tp("https://x/a", "a" * 40, ["p/x.yaml"], language="yaml"),
            _tp("https://x/b", "b" * 40, ["p/y.go"], language="go"),
        ]
        t = crp.select_targets(corpus, "crypto")
        assert list(t) == [("https://x/b", "b" * 40)]


class TestClassify:
    def test_path_match_is_a_rediscovery(self):
        got = crp.classify([{"rule_id": "r1", "path": "p/one.go"}], {"p/one.go"})
        assert len(got["rediscovery"]) == 1 and not got["novel"]

    def test_other_paths_are_novel(self):
        got = crp.classify([{"rule_id": "r1", "path": "p/other.go"}], {"p/one.go"})
        assert not got["rediscovery"] and len(got["novel"]) == 1

    def test_leading_dot_slash_is_normalized_both_sides(self):
        got = crp.classify([{"rule_id": "r1", "path": "./p/one.go"}], {"./p/one.go"})
        assert len(got["rediscovery"]) == 1


class TestAggregate:
    def _repo(self, name, redis, novel):
        return {
            "repo": name,
            "scanned": True,
            "tp_locations": ["x"],
            "rediscovery": [{"rule_id": r, "path": "p"} for r in redis],
            "novel": [{"rule_id": r, "path": "q"} for r in novel],
        }

    def test_gate_needs_three_distinct_repos(self):
        """The gate counts REPOS rediscovered, not raw hits — three hits
        in one repo is one shape, not three."""
        rows = [self._repo("a", ["r1", "r1", "r1"], [])]
        res = crp.aggregate(rows)
        assert res["rules"]["r1"]["rediscoveries"] == 3
        assert res["rules"]["r1"]["repos_rediscovered"] == 1
        assert res["rules"]["r1"]["clears_rediscovery_gate"] is False

    def test_three_repos_clears_the_gate(self):
        rows = [self._repo(n, ["r1"], []) for n in "abc"]
        assert crp.aggregate(rows)["rules"]["r1"]["clears_rediscovery_gate"]

    def test_unscanned_repos_counted_but_not_scored(self):
        rows = [self._repo("a", ["r1"], []), {"repo": "b", "scanned": False}]
        t = crp.aggregate(rows)["totals"]
        assert t["repos"] == 2 and t["scanned"] == 1

    def test_totals_split_rediscovery_and_novel(self):
        res = crp.aggregate([self._repo("a", ["r1"], ["r2", "r2"])])
        assert res["totals"]["rediscovery"] == 1
        assert res["totals"]["novel"] == 2
        assert res["rules"]["r2"]["novel"] == 2


class TestNovelSample:
    def test_bounded_and_deterministic(self):
        rows = [
            {
                "repo": f"https://x/r{i}",
                "commit": "c",
                "rediscovery": [],
                "novel": [{"rule_id": f"rule{j}", "path": f"p{j}.go"} for j in range(10)],
            }
            for i in range(10)
        ]
        a = crp.novel_sample(rows, 12)
        b = crp.novel_sample(rows, 12)
        assert len(a) <= 12 and a == b  # stable across runs

    def test_empty_input(self):
        assert crp.novel_sample([], 10) == []


class TestRender:
    def _res(self):
        return crp.aggregate(
            [
                {
                    "repo": f"https://x/{n}",
                    "scanned": True,
                    "tp_locations": ["a"],
                    "rediscovery": [{"rule_id": "good", "path": "a"}],
                    "novel": [{"rule_id": "noisy", "path": "b"}],
                }
                for n in "abc"
            ]
        )

    def test_states_precision_is_not_computed_here(self):
        """Precision accrues automatically from scanner_correlation once
        the pack runs; the report must not imply a manual queue."""
        body = crp.render(self._res(), "src", [])
        assert "not computed here" in body.lower()
        assert "scanner_correlation" in body
        assert "No human review required" in body

    def test_flags_path_level_matching_as_a_limitation(self):
        body = crp.render(self._res(), "src", [])
        assert "path-level" in body
        assert "biases rediscovery counts upward" in body

    def test_reports_findings_per_repo_as_the_triage_cost_number(self):
        body = crp.render(self._res(), "src", [])
        assert "findings per" in body

    def test_gate_column_marks_passing_rules(self):
        body = crp.render(self._res(), "src", [])
        assert "**good**" in body  # 3 repos -> clears
        assert "| noisy |" in body  # 0 rediscoveries -> does not


class TestScanSeam:
    def test_missing_output_file_yields_no_findings(self, tmp_path, monkeypatch):
        """A failed scan must degrade to zero findings, never raise —
        one unscannable repo cannot abort a 290-repo run."""

        class _P:
            returncode, stderr, stdout = 0, "", ""

        monkeypatch.setattr(crp.subprocess, "run", lambda *a, **k: _P())
        facts, err = crp.scan(tmp_path / "nope", "src")
        assert facts == [] and err  # empty AND an explicit error

    def test_normalizes_rule_id_and_path_keys(self, tmp_path, monkeypatch):
        out = tmp_path / "t-opengrep.json"

        def _ok():
            class _P:
                returncode, stderr, stdout = 0, "", ""

            return _P()

        def fake_run(*a, **k):
            out.write_text(
                json.dumps(
                    {
                        "facts": [
                            {"check_id": "r1", "file": "./a.go"},
                            {"rule_id": "r2", "path": "b.go"},
                        ]
                    }
                )
            )

        monkeypatch.setattr(crp.subprocess, "run", lambda *a, **k: (fake_run(), _ok())[1])
        got, err = crp.scan(tmp_path / "t", "src")
        assert err is None
        assert {f["rule_id"] for f in got} == {"r1", "r2"}
        assert {f["path"] for f in got} == {"a.go", "b.go"}


class TestCloneGuard:
    def test_non_https_refused(self, tmp_path):
        """Rule S3: never fetch a non-https remote."""
        assert crp.clone_at("git@github.com:x/y.git", "a" * 40, tmp_path / "d") is False


class TestScanFailureIsNotEmptiness:
    """The defect this class exists for: an unpinned --rules value was
    rejected by run_opengrep, swallowed by scan(), and reported as
    'ZERO findings — the rules are not loading'. A broken invocation
    must never read as a clean pack."""

    def test_nonzero_exit_returns_an_error_not_silence(self, tmp_path, monkeypatch):
        class _P:
            returncode = 2
            stderr = "ref must be a 40-hex commit SHA"
            stdout = ""

        monkeypatch.setattr(crp.subprocess, "run", lambda *a, **k: _P())
        facts, err = crp.scan(tmp_path / "t", "https://x/y")
        assert facts == []
        assert err and "40-hex" in err

    def test_errored_repo_is_not_counted_as_scanned(self):
        """aggregate() must not treat an errored repo as a clean scan —
        otherwise a systematically failing run reports 0 findings across
        N repos and looks like a pack that finds nothing."""
        rows = [
            {
                "repo": "a",
                "scanned": True,
                "tp_locations": ["x"],
                "rediscovery": [{"rule_id": "r", "path": "p"}],
                "novel": [],
            },
            {"repo": "b", "error": "run_opengrep exit 2"},
        ]
        t = crp.aggregate(rows)["totals"]
        assert t["repos"] == 2 and t["scanned"] == 1


class TestLangFilter:
    """--langs lets one language be calibrated at a time. Rust's crypto
    slice is 2 repos (below the gate) while its all-CWE slice is 12, so
    without this flag a per-language run is not expressible."""

    def _corpus(self):
        return [
            {
                "repo": "https://x/r",
                "commit": "a" * 40,
                "locations": ["src/main.rs"],
                "cwe": "CWE-295",
                "cwes": ["CWE-295"],
                "language": "rust",
                "title": "t",
            },
            {
                "repo": "https://x/g",
                "commit": "b" * 40,
                "locations": ["main.go"],
                "cwe": "CWE-295",
                "cwes": ["CWE-295"],
                "language": "go",
                "title": "t",
            },
        ]

    def test_restricts_to_named_language(self):
        t = crp.select_targets(self._corpus(), "crypto", langs={"rust"})
        assert list(t) == [("https://x/r", "a" * 40)]

    def test_none_means_every_pack_language(self):
        assert len(crp.select_targets(self._corpus(), "crypto")) == 2

    def test_rust_and_csharp_are_pack_languages(self):
        """Regression: these were wrongly described as uncalibratable."""
        for lang in ("rust", "c", "cpp", "csharp"):
            assert lang in crp.PACK_LANGS


class TestGateReachability:
    """A run whose ground truth cannot possibly clear the gate must be
    labelled untestable, never reported as a negative verdict. This is
    the 2026-08-06 Rust run: 0 of 35 rules cleared, but the only Rust
    CWEs spanning >=3 repos were ones the crypto pack has no rules for."""

    @staticmethod
    def _t(*pairs):
        return {
            (repo, "c" * 40): {"cwes": set(cwes), "locations": {"f"}, "count": 1}
            for repo, cwes in pairs
        }

    def test_reports_the_widest_cwe_span(self):
        t = self._t(("r1", ["CWE-295"]), ("r2", ["CWE-295"]), ("r3", ["CWE-306"]))
        assert crp.gate_reachability(t) == (2, "CWE-295")

    def test_span_at_the_gate_is_reachable(self):
        t = self._t(("r1", ["CWE-295"]), ("r2", ["CWE-295"]), ("r3", ["CWE-295"]))
        span, cwe = crp.gate_reachability(t)
        assert span >= crp.REDISCOVERY_GATE and cwe == "CWE-295"

    def test_dispersed_cwes_are_unreachable_despite_many_repos(self):
        """12 repos with 32 distinct CWEs is what Rust actually looked
        like — plenty of repos, no shared CWE to rediscover."""
        t = self._t(*[(f"r{i}", [f"CWE-{i}"]) for i in range(12)])
        span, _ = crp.gate_reachability(t)
        assert len(t) == 12 and span == 1

    def test_empty_targets(self):
        assert crp.gate_reachability({}) == (0, None)


class TestGateReachabilityAgainstPackCwes:
    """Reachability must intersect with the CWEs the pack targets. The
    first version of this check counted raw CWE spans and reported the
    impossible Rust run as reachable — CWE-532 spanned 4 repos, and the
    crypto pack has no CWE-532 rule."""

    @staticmethod
    def _t(*pairs):
        return {
            (repo, "c" * 40): {"cwes": set(cwes), "locations": {"f"}, "count": 1}
            for repo, cwes in pairs
        }

    def test_span_in_an_uncovered_cwe_does_not_count(self):
        t = self._t(
            ("r1", ["CWE-532"]), ("r2", ["CWE-532"]), ("r3", ["CWE-532"]), ("r4", ["CWE-295"])
        )
        assert crp.gate_reachability(t) == (3, "CWE-532")  # naive
        span, cwe = crp.gate_reachability(t, covered={"CWE-295"})
        assert (span, cwe) == (1, "CWE-295")  # pack-aware

    def test_no_overlap_at_all_reports_zero(self):
        t = self._t(("r1", ["CWE-306"]), ("r2", ["CWE-306"]))
        assert crp.gate_reachability(t, covered={"CWE-327"}) == (0, None)

    def test_pack_cwes_returns_empty_for_unpinned_source(self):
        """No ref -> cannot resolve a cache dir -> caller must skip."""
        assert crp.pack_cwes("https://github.com/x/y") == set()
