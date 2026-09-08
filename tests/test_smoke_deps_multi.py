#!/usr/bin/env python3
"""smoke_deps_multi.py tests — a tiny temp-db portfolio graph with Go + npm
edges and a temp language cache, exercising each tripwire."""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import smoke_deps_multi as S
from traust_engine.portfolio import graph as G


def _repo(org, name):
    return {
        "id": f"repo:github.com/{org}/{name}",
        "type": "repo",
        "label": f"{org}/{name}",
        "attrs": {"host": "github.com", "org": org, "name": name},
    }


# repo-a: Go + npm edges. repo-b: Go module dep only. repo-c: JS language but
# NO npm edge (coverage shortfall). repo-npm: npm-only, dep on shared name.
SPINE = {
    "nodes": [
        {"id": "product:p1", "type": "product", "label": "P1", "attrs": {}},
        _repo("org", "repo-a"),
        _repo("org", "repo-b"),
        _repo("org", "repo-c"),
        _repo("org", "npmapp"),
        _repo("org", "goapp"),
    ],
    "edges": [
        {"from": "product:p1", "to": "repo:github.com/org/repo-a", "rel": "ships"},
    ],
}


def _seed(con):
    """Attach Go + npm edges by hand (no network), mirroring build_deps /
    build_deps_multi output shapes."""
    # Go deps: repo-a & repo-b both require golang.org/x/net; goapp requires
    # a Go module literally named `foo` (collision partner for npm `foo`).
    for rid in ("repo:github.com/org/repo-a", "repo:github.com/org/repo-b"):
        G.upsert_node(con, "module:golang.org/x/net", "module", "golang.org/x/net", internal=0)
        G.upsert_edge(
            con, rid, "module:golang.org/x/net", "depends_on", version="v0.17.0", indirect=0
        )
    G.upsert_node(con, "module:foo", "module", "foo", internal=0)
    G.upsert_edge(
        con, "repo:github.com/org/goapp", "module:foo", "depends_on", version="v1.0.0", indirect=0
    )
    # npm deps: repo-a depends on left-pad; npmapp depends on npm pkg `foo`
    # (same bare name as the Go module -> collision test).
    G.upsert_node(con, "pkg:npm/left-pad", "package", "left-pad", ecosystem="npm", internal=0)
    G.upsert_edge(
        con,
        "repo:github.com/org/repo-a",
        "pkg:npm/left-pad",
        "depends_on",
        version="1.3.0",
        indirect=0,
        ecosystem="npm",
    )
    G.upsert_node(con, "pkg:npm/foo", "package", "foo", ecosystem="npm", internal=0)
    G.upsert_edge(
        con,
        "repo:github.com/org/npmapp",
        "pkg:npm/foo",
        "depends_on",
        version="1.0.0",
        indirect=0,
        ecosystem="npm",
    )
    con.commit()


class SmokeBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "graph.db"
        self.con = G.db_connect(self.db)
        spine = self.tmp / "spine.json"
        spine.write_text(json.dumps(SPINE))
        G.build_spine(self.con, spine)
        _seed(self.con)
        self.con.close()
        # language cache: repo-a JS+Go, repo-c JS (no npm edge -> shortfall),
        # npmapp JS, goapp Go, repo-b Go.
        self.lang = self.tmp / "lang.jsonl"
        self.lang.write_text(
            json.dumps({"repo": "org/repo-a", "languages": {"JavaScript": 900, "Go": 100}})
            + "\n"
            + json.dumps({"repo": "org/repo-c", "languages": {"JavaScript": 500}})
            + "\n"
            + json.dumps({"repo": "org/npmapp", "languages": {"JavaScript": 300}})
            + "\n"
        )
        self.snapshot = self.tmp / "snap.json"

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, extra):
        out, err = io.StringIO(), io.StringIO()
        argv = [
            "--db",
            str(self.db),
            "--lang-cache",
            str(self.lang),
            "--snapshot",
            str(self.snapshot),
            *extra,
        ]
        with redirect_stdout(out), redirect_stderr(err):
            rc = S.main(argv)
        return rc, out.getvalue(), err.getvalue()


class TestCoverageFloor(SmokeBase):
    def test_shortfall_fails_and_names_repo(self):
        # First capture a snapshot so the Go check passes in isolation.
        rc, _, _ = self.run_cli(["--make-snapshot"])
        self.assertEqual(rc, 0)
        # npm: repos_with_lang = {repo-a, repo-c, npmapp} = 3;
        # repos_with_edges = {repo-a, npmapp} = 2 -> ratio 0.67 (>=0.5 PASS).
        # Raise the floor so the shortfall (repo-c) trips the check.
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--floor", "0.9"])
        self.assertEqual(rc, 1)
        self.assertIn("COVERAGE npm", out)
        self.assertIn("[FAIL]", out)
        self.assertIn("org/repo-c", err)  # the shortfall repo is named

    def test_within_floor_passes(self):
        self.run_cli(["--make-snapshot"])
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--floor", "0.5"])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("COVERAGE npm", out)


class TestPresenceGap(SmokeBase):
    def test_requested_ecosystem_with_zero_edges_fails(self):
        self.run_cli(["--make-snapshot"])
        # pypi is requested but the graph has zero pypi edges -> loud FAIL.
        rc, out, _err = self.run_cli(["--ecosystems", "npm,pypi"])
        self.assertEqual(rc, 1)
        self.assertIn("PRESENCE pypi", out)
        self.assertIn("silent-gap tripwire", out)

    def test_present_ecosystem_reports_pkg_nodes(self):
        self.run_cli(["--make-snapshot"])
        _rc, out, _ = self.run_cli(["--ecosystems", "npm"])
        self.assertIn("PRESENCE npm:", out)


class TestGoSnapshotRoundTrip(SmokeBase):
    def test_make_then_check_passes(self):
        rc, out, _ = self.run_cli(["--make-snapshot", "--go-modules", "golang.org/x/net"])
        self.assertEqual(rc, 0)
        self.assertTrue(self.snapshot.is_file())
        snap = json.loads(self.snapshot.read_text())
        self.assertEqual(
            snap["golang.org/x/net"], ["repo:github.com/org/repo-a", "repo:github.com/org/repo-b"]
        )
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--go-modules", "golang.org/x/net"])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("GO NO-REGRESS golang.org/x/net", out)
        self.assertIn("unchanged", out)

    def test_missing_snapshot_fails_loudly(self):
        rc, out, _err = self.run_cli(["--ecosystems", "npm", "--go-modules", "golang.org/x/net"])
        self.assertEqual(rc, 1)
        self.assertIn("snapshot missing", out)
        self.assertIn("--make-snapshot", out)

    def test_go_blast_change_fails_with_diff(self):
        self.run_cli(["--make-snapshot", "--go-modules", "golang.org/x/net"])
        # simulate a regression: a new repo now depends on x/net.
        con = sqlite3.connect(self.db)
        G.upsert_edge(
            con,
            "repo:github.com/org/repo-c",
            "module:golang.org/x/net",
            "depends_on",
            version="v0.17.0",
            indirect=0,
        )
        con.commit()
        con.close()
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--go-modules", "golang.org/x/net"])
        self.assertEqual(rc, 1)
        self.assertIn("blast radius CHANGED", out)
        self.assertIn("+ repo:github.com/org/repo-c", err)


class TestCollision(SmokeBase):
    def test_shared_name_reported_isolated(self):
        self.run_cli(["--make-snapshot"])
        _rc, out, _err = self.run_cli(["--ecosystems", "npm"])
        # module:foo (goapp) and pkg:npm/foo (npmapp) share the bare name.
        self.assertIn("COLLISION: 1 shared name(s) checked", out)
        self.assertIn("isolated", out)
        # blast radii do not cross-contaminate
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(S.blast_repos(con, "module:foo"), {"repo:github.com/org/goapp"})
            self.assertEqual(S.blast_repos(con, "pkg:npm/foo"), {"repo:github.com/org/npmapp"})
        finally:
            con.close()


class TestDenominatorHonesty(SmokeBase):
    """The coverage denominator is the builder's persisted repos_with_manifest
    (manifest-based, authoritative) when deps-multi-stats.json is present next
    to the db; otherwise it falls back to the gh-language-cache count, clearly
    labelled as an overcount."""

    def _write_stats(self, npm_manifest):
        # deps-multi-stats.json lives next to the db (self.db = tmp/graph.db)
        (self.tmp / "deps-multi-stats.json").write_text(
            json.dumps(
                {
                    "repos_tree_ok": 3,
                    "repos_with_any_manifest": 2,
                    "repos_with_zero_manifests": 1,
                    "truncated_fallback": 0,
                    "loud_fail": [],
                    "npm": {
                        "repos_with_manifest": npm_manifest,
                        "manifests_fetched_ok": npm_manifest,
                        "absent": 0,
                        "parse_empty": 0,
                        "pkg_nodes": 1,
                        "dep_edges": 2,
                        "manifest_paths_sample": ["package-lock.json"],
                    },
                }
            )
        )

    def test_authoritative_denominator_used_when_stats_present(self):
        # lang cache carries npm for 3 repos (repo-a, repo-c, npmapp) — the
        # overcount. Stats say only 2 repos actually have an npm manifest.
        self._write_stats(npm_manifest=2)
        self.run_cli(["--make-snapshot"])
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--floor", "0.9"])
        # authoritative ratio = repos_with_edges(2) / repos_with_manifest(2)
        # = 100% (PASS at floor 0.9); the lang-based 2/3=67% would FAIL.
        self.assertEqual(rc, 0, out + err)
        self.assertIn("manifest-based (authoritative)", out)
        self.assertIn("2/2 repos = 100%", out)
        # both denominators reported when both are available
        self.assertIn("also language-based (overcounts): 2/3", out)
        # summary marks the basis
        self.assertIn("manifest (authoritative)", out)

    def test_fallback_to_language_when_stats_absent(self):
        # no deps-multi-stats.json → language-based overcount denominator.
        self.run_cli(["--make-snapshot"])
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--floor", "0.5"])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("language-based (overcounts)", out)
        self.assertIn("2/3 repos = 67%", out)
        self.assertNotIn("manifest-based (authoritative)", out)

    def test_authoritative_shortfall_fails_without_lang_shortfall_list(self):
        # stats say 3 repos have an npm manifest but only 2 carry an edge →
        # authoritative ratio 67% FAILS a 0.9 floor via the manifest count.
        self._write_stats(npm_manifest=3)
        self.run_cli(["--make-snapshot"])
        rc, out, err = self.run_cli(["--ecosystems", "npm", "--floor", "0.9"])
        self.assertEqual(rc, 1)
        self.assertIn("2/3 repos = 67%", out)
        self.assertIn("manifest-based (authoritative)", out)
        self.assertIn("have no npm edge", err)


class TestUniversalSurfaces(SmokeBase):
    """docker/actions/helm are path-discovered: a language coverage floor is
    meaningless. They are checked by PRESENCE only (>=1 pkg node + >=1 edge)
    and never fail on a coverage floor."""

    def _add_docker_edge(self):
        con = sqlite3.connect(self.db)
        G.upsert_node(con, "pkg:docker/golang", "package", "golang", ecosystem="docker", internal=0)
        G.upsert_edge(
            con,
            "repo:github.com/org/repo-a",
            "pkg:docker/golang",
            "depends_on",
            version="1.22",
            indirect=0,
            ecosystem="docker",
        )
        con.commit()
        con.close()

    def test_universal_with_edges_passes_and_skips_floor(self):
        self._add_docker_edge()
        self.run_cli(["--make-snapshot"])
        # an absurd floor must NOT fail a universal surface — it carries none.
        rc, out, err = self.run_cli(["--ecosystems", "docker", "--floor", "0.99"])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("PRESENCE docker", out)
        self.assertIn("presence-only", out)
        self.assertNotIn("coverage:docker", out)

    def test_universal_requested_with_zero_edges_fails_presence(self):
        # no docker edges seeded → the silent-gap tripwire fires on presence.
        self.run_cli(["--make-snapshot"])
        rc, out, _err = self.run_cli(["--ecosystems", "docker"])
        self.assertEqual(rc, 1)
        self.assertIn("PRESENCE docker", out)
        self.assertIn("silent-gap tripwire", out)


class TestDbMissing(unittest.TestCase):
    def test_missing_db_exits_2(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = S.main(["--db", "/nonexistent/graph.db"])
        self.assertEqual(rc, 2)
        self.assertIn("not found", err.getvalue())


if __name__ == "__main__":
    unittest.main()
