#!/usr/bin/env python3
"""
Build a per-run symbol index for a target repo clone.

The index is derived data keyed by (repo, sha): audits and triage runs always
operate on an immutable clone pinned to one commit, so the index is built once
after clone and is structurally incapable of going stale — a new SHA means a
new clone and a new index. Nothing here requires manual freshness management.

Engines:
  ctags    — universal-ctags (preferred when installed; full language coverage)
  builtin  — pure-Python regex extractors for Go / Python / TypeScript /
             JavaScript / Shell; zero dependencies, definitions only
  auto     — ctags if a Universal Ctags binary is found, else builtin (default)

The index is an accelerator, not a gatekeeper: consumers (verifier agents via
query_index.py) fall back to grep when a symbol is missing, so extractor
imperfection can never suppress a finding.

Usage:
  python3 -m traust.cli.build_symbol_index --repo /tmp/target-clone
  python3 -m traust.cli.build_symbol_index --repo /tmp/clone --out /tmp/idx.db --engine builtin
"""

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "vendor",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "testdata",
    ".idea",
    ".vscode",
}

LANG_BY_EXT = {
    ".go": "Go",
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".sh": "Sh",
    ".bash": "Sh",
}

# Definition-site regexes for the builtin engine. Deliberately conservative:
# misses are acceptable (consumers fall back to grep); false definitions are
# not, because they would misdirect verifiers.
BUILTIN_PATTERNS = {
    "Go": [
        (re.compile(r"^func\s+([A-Za-z_]\w*)\s*[(\[]"), "func"),
        (re.compile(r"^func\s+\(\s*\w+\s+\*?([A-Za-z_]\w*)\s*\)\s*([A-Za-z_]\w*)\s*\("), "method"),
        (re.compile(r"^type\s+([A-Za-z_]\w*)\s"), "type"),
        (re.compile(r"^(?:var|const)\s+([A-Za-z_]\w*)\s"), "variable"),
        # grouped `var (` / `const (` block members are handled contextually
        # in extract_builtin
    ],
    "Python": [
        (re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\("), "function"),
        (re.compile(r"^\s*class\s+([A-Za-z_]\w*)\s*[(:]"), "class"),
        (re.compile(r"^([A-Z_][A-Z0-9_]{2,})\s*="), "constant"),
    ],
    "TypeScript": [
        (
            re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$]\w*)"),
            "function",
        ),
        (re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$]\w*)"), "class"),
        (re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$]\w*)"), "interface"),
        (re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$]\w*)\s*="), "type"),
        (
            re.compile(
                r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)"
                r"\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\()"
            ),
            "function",
        ),
        (re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)\s*="), "variable"),
    ],
    "Sh": [
        (re.compile(r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{"), "function"),
    ],
}
BUILTIN_PATTERNS["JavaScript"] = BUILTIN_PATTERNS["TypeScript"]


def detect_sha(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "nosha"


def detect_ref(repo: Path) -> str:
    """Branch the clone is checked out on, for meta-table provenance only
    (branch-awareness Phase 1). `git rev-parse --abbrev-ref
    HEAD` prints the literal branch name, or "HEAD" when detached — which
    is recorded as "detached". Outside a git checkout: "unknown". The
    index identity key stays (repo, sha); the filename convention
    (`<dir>-<sha>.db`) is deliberately unchanged."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if out.returncode == 0:
            name = out.stdout.strip()
            if name:
                return "detached" if name == "HEAD" else name
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def default_index_path(repo: Path, sha: str) -> Path:
    # per-user 0700 cache — a shared predictable /tmp name lets any
    # local user plant a DB that feeds fabricated symbol locations to
    # triage verifiers (audit B4, plan P1.7)
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "symbol-index"
    cache.mkdir(parents=True, exist_ok=True)
    cache.chmod(0o700)
    if cache.stat().st_uid != os.getuid():
        raise SystemExit(f"refusing cache dir not owned by uid: {cache}")
    return cache / f"{repo.resolve().name}-{sha}.db"


def find_universal_ctags() -> str | None:
    """Locate a Universal Ctags binary (macOS ships BSD ctags, which lacks
    JSON output and recursion — it must not be used)."""
    import shutil

    for name in ("ctags", "uctags", "universal-ctags"):
        path = shutil.which(name)
        if not path:
            continue
        try:
            ver = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
            if "Universal Ctags" in ver.stdout:
                return path
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def iter_source_files(repo: Path):
    for p in sorted(repo.rglob("*")):
        # file symlinks can point outside the untrusted checkout —
        # following them exfiltrates host content into the index
        # (audit B5, plan P1.7)
        if p.is_symlink() or not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts):
            continue
        lang = LANG_BY_EXT.get(p.suffix)
        if lang:
            yield p, lang


def extract_builtin(repo: Path):
    """Yield (name, relpath, line, kind, language) tuples."""
    for path, lang in iter_source_files(repo):
        rel = str(path.relative_to(repo))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_go_group = False
        for i, line in enumerate(text.splitlines(), start=1):
            if lang == "Go":
                # track grouped `var (` / `const (` blocks
                if re.match(r"^(?:var|const)\s*\($", line.strip()):
                    in_go_group = True
                    continue
                if in_go_group:
                    if line.strip() == ")":
                        in_go_group = False
                        continue
                    m = re.match(r"^\s+([A-Za-z_]\w*)\s*(?:=|\s)", line)
                    if m:
                        yield m.group(1), rel, i, "variable", lang
                    continue
            for pattern, kind in BUILTIN_PATTERNS[lang]:
                m = pattern.match(line)
                if m:
                    if kind == "method":
                        # receiver type and method name are both useful
                        yield m.group(1), rel, i, "type-receiver", lang
                        yield m.group(2), rel, i, "method", lang
                    else:
                        yield m.group(1), rel, i, kind, lang
                    break


def extract_ctags(repo: Path, ctags_bin: str):
    """Yield (name, relpath, line, kind, language) tuples via universal-ctags."""
    # --options=NONE: never load ./.ctags.d/* from the untrusted repo
    # cwd (audit C4, plan P1.7)
    cmd = [ctags_bin, "--options=NONE", "--output-format=json", "--fields=+nKl", "-R", "-f", "-"]
    cmd += [f"--exclude={d}" for d in sorted(SKIP_DIRS)]
    cmd.append(".")
    proc = subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"ctags failed: {proc.stderr[:500]}")
    for raw in proc.stdout.splitlines():
        try:
            tag = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if tag.get("_type") != "tag":
            continue
        name, path, line = tag.get("name"), tag.get("path"), tag.get("line")
        if not (name and path and line):
            continue
        rel = path[2:] if path.startswith("./") else path
        yield name, rel, int(line), tag.get("kind", ""), tag.get("language", "")


def build_index(repo: Path, out: Path, engine: str = "auto") -> dict:
    ctags_bin = find_universal_ctags() if engine in ("auto", "ctags") else None
    if engine == "ctags" and not ctags_bin:
        raise RuntimeError(
            "engine=ctags requested but no Universal Ctags binary found "
            "(macOS /usr/bin/ctags is BSD ctags and is not usable; "
            "install with: brew install universal-ctags)"
        )
    used = "ctags" if ctags_bin else "builtin"

    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    con = sqlite3.connect(out)
    con.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE symbols (name TEXT, path TEXT, line INTEGER,
                              kind TEXT, language TEXT);
        CREATE TABLE files (path TEXT PRIMARY KEY, language TEXT);
        CREATE INDEX idx_symbols_name ON symbols(name);
    """)

    rows = extract_ctags(repo, ctags_bin) if used == "ctags" else extract_builtin(repo)
    n = 0
    for name, rel, line, kind, lang in rows:
        con.execute("INSERT INTO symbols VALUES (?, ?, ?, ?, ?)", (name, rel, line, kind, lang))
        n += 1
    for path, lang in iter_source_files(repo):
        con.execute(
            "INSERT OR IGNORE INTO files VALUES (?, ?)", (str(path.relative_to(repo)), lang)
        )
    nfiles = con.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    sha = detect_sha(repo)
    meta = {
        "repo": str(repo.resolve()),
        "sha": sha,
        "ref": detect_ref(repo),
        "engine": used,
        "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "symbols": str(n),
        "files": str(nfiles),
    }
    con.executemany("INSERT INTO meta VALUES (?, ?)", meta.items())
    con.commit()
    con.close()
    return {**meta, "out": str(out)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--repo", required=True, help="target repo clone (read-only)")
    parser.add_argument(
        "--out", help="index DB path (default: $TMPDIR/symbol-index/<repo>-<sha>.db)"
    )
    parser.add_argument("--engine", choices=("auto", "ctags", "builtin"), default="auto")
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"ERROR: --repo {args.repo} is not a directory", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else default_index_path(repo, detect_sha(repo))
    try:
        meta = build_index(repo, out, args.engine)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(
        f"Symbol index built: {meta['symbols']} symbols across {meta['files']} "
        f"files (engine={meta['engine']}, sha={meta['sha']}, "
        f"ref={meta['ref']})\n  -> {meta['out']}"
    )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["build", "symbol-index", *sys.argv[1:]]))
