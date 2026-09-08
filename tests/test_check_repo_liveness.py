#!/usr/bin/env python3
"""check_repo_liveness.py tests — classification, ratchet, sweep (mocked)."""

import json
import tempfile
import unittest
from pathlib import Path

import check_repo_liveness as L

SPINE = {
    "nodes": [
        {
            "id": "repo:github.com/org/live",
            "type": "repo",
            "attrs": {
                "url": "https://github.com/org/live",
                "host": "github.com",
                "org": "org",
                "name": "live",
            },
        },
        {
            "id": "repo:github.com/org/dead",
            "type": "repo",
            "attrs": {
                "url": "https://github.com/org/dead",
                "host": "github.com",
                "org": "org",
                "name": "dead",
            },
        },
        {
            "id": "repo:github.com/org/old",
            "type": "repo",
            "attrs": {
                "url": "https://github.com/org/old",
                "host": "github.com",
                "org": "org",
                "name": "old",
            },
        },
        {
            "id": "repo:github.com/org/relocated",
            "type": "repo",
            "attrs": {
                "url": "https://github.com/org/relocated",
                "host": "github.com",
                "org": "org",
                "name": "relocated",
            },
        },
        {
            "id": "repo:gitlab.example/x/y",
            "type": "repo",
            "attrs": {
                "url": "https://gitlab.example/x/y",
                "host": "gitlab.example.com",
                "org": "x",
                "name": "y",
            },
        },
    ],
    "edges": [],
}

FAKE_API = {
    "org/live": {
        "ok": True,
        "full_name": "org/live",
        "archived": False,
        "pushed_at": "2026-07-01T00:00:00Z",
    },
    "org/dead": {"ok": False, "error": "404"},
    "org/old": {
        "ok": True,
        "full_name": "org/old",
        "archived": True,
        "pushed_at": "2023-01-05T00:00:00Z",
    },
    "org/relocated": {
        "ok": True,
        "full_name": "neworg/relocated",
        "archived": False,
        "pushed_at": "2026-06-01T00:00:00Z",
    },
}


def fake_fetch(org, name):
    return FAKE_API[f"{org}/{name}"]


class TestClassify(unittest.TestCase):
    def test_states(self):
        self.assertEqual(L.classify("org/live", FAKE_API["org/live"])["status"], "active")
        self.assertEqual(L.classify("org/dead", FAKE_API["org/dead"])["status"], "missing")
        self.assertEqual(L.classify("org/old", FAKE_API["org/old"])["status"], "archived")
        moved = L.classify("org/relocated", FAKE_API["org/relocated"])
        self.assertEqual(moved["status"], "moved")
        self.assertEqual(moved["moved_to"], "neworg/relocated")

    def test_moved_and_archived(self):
        out = L.classify("a/b", {"ok": True, "full_name": "c/b", "archived": True})
        self.assertEqual(out["status"], "moved-archived")

    def test_case_insensitive_rename_is_not_moved(self):
        out = L.classify("Org/Repo", {"ok": True, "full_name": "org/repo", "archived": False})
        self.assertEqual(out["status"], "active")


class TestSweepAndRatchet(unittest.TestCase):
    def _run(self, out_path):
        with tempfile.TemporaryDirectory() as d:
            spine = Path(d) / "spine.json"
            spine.write_text(json.dumps(SPINE))
            return L.sweep(spine, out_path, jobs=2, limit=None, fetch=fake_fetch)

    def test_sweep_counts_and_unknown_host(self):
        with tempfile.TemporaryDirectory() as d:
            artifact = self._run(Path(d) / "liveness.json")
            self.assertEqual(
                artifact["counts"],
                {"active": 1, "archived": 1, "missing": 1, "moved": 1, "unknown": 1},
            )
            gitlab = artifact["repos"]["https://gitlab.example/x/y"]
            self.assertEqual(gitlab["status"], "unknown")
            self.assertEqual(gitlab["host"], "gitlab.example.com")

    def test_status_since_ratchets_across_runs(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "liveness.json"
            self._run(out)
            # simulate an older prior observation
            prior = json.loads(out.read_text())
            prior["repos"]["https://github.com/org/old"]["status_since"] = "2026-01-01"
            out.write_text(json.dumps(prior))
            second = self._run(out)
            self.assertEqual(
                second["repos"]["https://github.com/org/old"]["status_since"], "2026-01-01"
            )
            # a status CHANGE resets the date: previous said active
            prior = json.loads(out.read_text())
            prior["repos"]["https://github.com/org/old"].update(
                {"status": "active", "status_since": "2026-01-01"}
            )
            out.write_text(json.dumps(prior))
            third = self._run(out)
            self.assertNotEqual(
                third["repos"]["https://github.com/org/old"]["status_since"], "2026-01-01"
            )

    def test_md_lists_non_active(self):
        with tempfile.TemporaryDirectory() as d:
            artifact = self._run(Path(d) / "liveness.json")
            md = L.render_md(artifact)
            self.assertIn("github.com/org/old | archived", md)
            self.assertIn("neworg/relocated", md)
            self.assertNotIn("github.com/org/live |", md)


if __name__ == "__main__":
    unittest.main()
