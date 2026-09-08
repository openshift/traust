#!/usr/bin/env python3
"""Unit tests for traust.cli.build_symbol_index and traust.cli.query_index."""

import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest

from traust.cli.build_symbol_index import build_index, detect_ref, find_universal_ctags
from traust.cli.query_index import cmd_defs, cmd_file_symbols, cmd_info, cmd_refs

GO_FILE = """package reconciler

const MaxRetries = 5

var (
\tdefaultRegistry = "quay.io/ambient_code/"
\tallowInsecure   = false
)

type KubeReconciler struct{}

func (r *KubeReconciler) mergeAgentEnvironment(base map[string]string) map[string]string {
\treturn base
}

func isAllowedRegistry(image string) bool {
\treturn len(image) > 0
}
"""

PY_FILE = '''"""Runner auth helpers."""

TOKEN_HEADER = "X-Ambient-Token"


class CredentialBroker:
    def issue_token(self, scope):
        return scope


def redact_secrets(text):
    return text
'''

TS_FILE = """export interface PreviewBridge {
  origin: string;
}

export function requestCapture(target: string): void {
}

export const sendFeedback = async (payload: string) => {
  return payload;
};
"""


def _repo(tmp: str) -> Path:
    repo = Path(tmp) / "clone"
    (repo / "internal").mkdir(parents=True)
    (repo / "runner").mkdir()
    (repo / "ui" / "src").mkdir(parents=True)
    (repo / "vendor" / "dep").mkdir(parents=True)
    (repo / "internal" / "reconciler.go").write_text(GO_FILE, encoding="utf-8")
    (repo / "runner" / "auth.py").write_text(PY_FILE, encoding="utf-8")
    (repo / "ui" / "src" / "bridge.ts").write_text(TS_FILE, encoding="utf-8")
    # vendored code must be excluded
    (repo / "vendor" / "dep" / "dep.go").write_text(
        "package dep\n\nfunc VendoredFn() {}\n", encoding="utf-8"
    )
    return repo


class TestBuiltinEngine(unittest.TestCase):
    def _build(self, tmp: str):
        repo = _repo(tmp)
        db = Path(tmp) / "idx.db"
        meta = build_index(repo, db, engine="builtin")
        return repo, db, meta

    def test_builds_and_reports_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, db, meta = self._build(tmp)
            self.assertEqual(meta["engine"], "builtin")
            self.assertTrue(db.is_file())
            self.assertGreater(int(meta["symbols"]), 5)

    def test_go_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, db, _ = self._build(tmp)
            con = sqlite3.connect(db)
            names = {r[0] for r in con.execute("SELECT name FROM symbols")}
        for expected in (
            "KubeReconciler",
            "mergeAgentEnvironment",
            "isAllowedRegistry",
            "MaxRetries",
            "defaultRegistry",
        ):
            self.assertIn(expected, names)

    def test_python_and_ts_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, db, _ = self._build(tmp)
            con = sqlite3.connect(db)
            names = {r[0] for r in con.execute("SELECT name FROM symbols")}
        for expected in (
            "CredentialBroker",
            "issue_token",
            "redact_secrets",
            "TOKEN_HEADER",
            "PreviewBridge",
            "requestCapture",
            "sendFeedback",
        ):
            self.assertIn(expected, names)

    def test_vendor_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, db, _ = self._build(tmp)
            con = sqlite3.connect(db)
            names = {r[0] for r in con.execute("SELECT name FROM symbols")}
            files = {r[0] for r in con.execute("SELECT path FROM files")}
        self.assertNotIn("VendoredFn", names)
        self.assertFalse(any(p.startswith("vendor/") for p in files))

    def test_rebuild_replaces_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, db, _ = self._build(tmp)
            n1 = sqlite3.connect(db).execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
            build_index(repo, db, engine="builtin")
            n2 = sqlite3.connect(db).execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
            self.assertEqual(n1, n2)


class TestQueries(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = _repo(self._tmp.name)
        self.db = Path(self._tmp.name) / "idx.db"
        build_index(self.repo, self.db, engine="builtin")
        self.con = sqlite3.connect(self.db)

    def tearDown(self):
        self.con.close()
        self._tmp.cleanup()

    def test_defs_exact(self):
        out = cmd_defs(self.con, "isAllowedRegistry")
        self.assertEqual(out["mode"], "exact")
        self.assertEqual(out["defs"][0]["path"], "internal/reconciler.go")
        self.assertEqual(out["defs"][0]["language"], "Go")

    def test_defs_fuzzy_fallback(self):
        out = cmd_defs(self.con, "AllowedRegistry")
        self.assertEqual(out["mode"], "fuzzy")
        self.assertTrue(any(d["name"] == "isAllowedRegistry" for d in out["defs"]))

    def test_refs_word_boundary_and_def_marking(self):
        out = cmd_refs(self.con, self.repo, "isAllowedRegistry")
        self.assertGreaterEqual(out["total"], 1)
        def_refs = [r for r in out["refs"] if r["is_def"]]
        self.assertEqual(len(def_refs), 1)
        self.assertEqual(def_refs[0]["path"], "internal/reconciler.go")

    def test_file_symbols(self):
        out = cmd_file_symbols(self.con, "runner/auth.py")
        names = {s["name"] for s in out["symbols"]}
        self.assertIn("CredentialBroker", names)
        self.assertIn("issue_token", names)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=test",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _git_repo(tmp: str, branch: str) -> Path:
    """Fixture clone with one commit on the named branch."""
    repo = _repo(tmp)
    _git(repo, "init", "-b", branch)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "fixture", "--no-gpg-sign")
    return repo


class TestRefMeta(unittest.TestCase):
    """Branch-awareness Phase 1: the meta table records the
    checked-out ref; older ref-less indexes stay fully queryable."""

    @pytest.mark.requires_git
    def test_ref_recorded_for_branch_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(tmp, "release-4.19")
            db = Path(tmp) / "idx.db"
            meta = build_index(repo, db, engine="builtin")
            self.assertEqual(meta["ref"], "release-4.19")
            self.assertNotEqual(meta["sha"], "nosha")
            con = sqlite3.connect(db)
            stored = dict(con.execute("SELECT key, value FROM meta"))
            con.close()
            self.assertEqual(stored["ref"], "release-4.19")

    @pytest.mark.requires_git
    def test_ref_detached_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(tmp, "main")
            _git(repo, "checkout", "--detach")
            self.assertEqual(detect_ref(repo), "detached")
            meta = build_index(repo, Path(tmp) / "idx.db", engine="builtin")
            self.assertEqual(meta["ref"], "detached")

    def test_ref_unknown_outside_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)  # no .git at all
            self.assertEqual(detect_ref(repo), "unknown")
            meta = build_index(repo, Path(tmp) / "idx.db", engine="builtin")
            self.assertEqual(meta["ref"], "unknown")
            self.assertEqual(meta["sha"], "nosha")

    def test_old_index_without_ref_still_queryable(self):
        """Pre-Phase-1 indexes never wrote a ref row — queries must keep
        working and --info must report the ref as unknown, not error."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            db = Path(tmp) / "idx.db"
            build_index(repo, db, engine="builtin")
            con = sqlite3.connect(db)
            con.execute("DELETE FROM meta WHERE key = 'ref'")
            con.commit()
            out = cmd_defs(con, "isAllowedRegistry")
            self.assertEqual(out["mode"], "exact")
            info = cmd_info(con, db)
            con.close()
            self.assertEqual(info["ref"], "unknown")
            self.assertEqual(info["engine"], "builtin")
            self.assertEqual(info["index"], str(db))

    @pytest.mark.requires_git
    def test_info_surfaces_recorded_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(tmp, "stable-2.x")
            db = Path(tmp) / "idx.db"
            build_index(repo, db, engine="builtin")
            con = sqlite3.connect(db)
            info = cmd_info(con, db)
            con.close()
            self.assertEqual(info["ref"], "stable-2.x")


@unittest.skipUnless(find_universal_ctags(), "universal-ctags not installed")
class TestCtagsEngine(unittest.TestCase):
    def test_ctags_build_finds_core_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            db = Path(tmp) / "idx-ctags.db"
            meta = build_index(repo, db, engine="ctags")
            self.assertEqual(meta["engine"], "ctags")
            con = sqlite3.connect(db)
            names = {r[0] for r in con.execute("SELECT name FROM symbols")}
            self.assertIn("isAllowedRegistry", names)
            self.assertIn("CredentialBroker", names)


class TestEngineErrors(unittest.TestCase):
    def test_ctags_engine_without_binary_errors(self):
        if find_universal_ctags():
            self.skipTest("universal-ctags is installed")
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            with self.assertRaises(RuntimeError):
                build_index(repo, Path(tmp) / "x.db", engine="ctags")


if __name__ == "__main__":
    unittest.main()
