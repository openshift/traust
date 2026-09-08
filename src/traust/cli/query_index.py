#!/usr/bin/env python3
"""
Query the per-run symbol index built by build_symbol_index.py.

Designed for verifier agents: one lookup replaces a chain of exploratory
greps. If no index exists for the repo yet, one is built automatically, so
`query_index.py --repo <clone> --defs Foo` always works in one call.

The index is an accelerator, not a gatekeeper: if a symbol is not in the
index (exotic syntax, unindexed language), fall back to grep — a miss here
must never be treated as evidence the symbol does not exist.

Usage:
  python3 -m traust.cli.query_index --repo /tmp/clone --defs TSLAnd
  python3 -m traust.cli.query_index --repo /tmp/clone --refs mergeAgentEnvironment
  python3 -m traust.cli.query_index --repo /tmp/clone --file-symbols pkg/rbac/scope.go
  python3 -m traust.cli.query_index --index /tmp/idx.db --defs Foo --json
  python3 -m traust.cli.query_index --index /tmp/idx.db --info

Output (text mode):
  --defs:          path:line:  kind  language  name
  --refs:          path:line:  source line   (definition sites marked [def])
  --file-symbols:  line:  kind  name
  --info:          key: value  (index meta table — repo, sha, ref, engine, …;
                   pre-branch-awareness indexes never recorded a ref, which
                   is reported as "unknown")
"""

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

# import sibling module for auto-build / default path resolution
from traust.cli.build_symbol_index import build_index, default_index_path, detect_sha

REFS_CAP = 200
FUZZY_CAP = 20


def open_index(args) -> tuple[sqlite3.Connection, Path]:
    if args.index:
        db = Path(args.index)
        if not db.is_file():
            print(f"ERROR: index not found: {db}", file=sys.stderr)
            sys.exit(2)
    else:
        if not args.repo:
            print("ERROR: provide --index or --repo", file=sys.stderr)
            sys.exit(2)
        repo = Path(args.repo)
        db = default_index_path(repo, detect_sha(repo))
        if not db.is_file():
            meta = build_index(repo, db)
            print(
                f"[auto-built index: {meta['symbols']} symbols, engine={meta['engine']}]",
                file=sys.stderr,
            )
    return sqlite3.connect(db), db


def cmd_defs(con: sqlite3.Connection, name: str) -> dict:
    rows = con.execute(
        "SELECT name, path, line, kind, language FROM symbols WHERE name = ? ORDER BY path, line",
        (name,),
    ).fetchall()
    fuzzy = False
    if not rows:
        fuzzy = True
        rows = con.execute(
            "SELECT name, path, line, kind, language FROM symbols "
            "WHERE name LIKE ? ORDER BY path, line LIMIT ?",
            (f"%{name}%", FUZZY_CAP),
        ).fetchall()
    return {
        "query": name,
        "mode": "fuzzy" if fuzzy else "exact",
        "defs": [
            {"name": n, "path": p, "line": ln, "kind": k, "language": g} for n, p, ln, k, g in rows
        ],
    }


def cmd_refs(con: sqlite3.Connection, repo: Path, name: str) -> dict:
    """Textual (word-boundary) references across indexed source files.

    This is deliberately language-agnostic and includes comments/strings —
    it narrows the search space for the verifier, it does not build a call
    graph. Definition sites from the index are marked so callers stand out.
    """
    def_sites = {
        (path, line)
        for path, line in con.execute("SELECT path, line FROM symbols WHERE name = ?", (name,))
    }
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    refs, total = [], 0
    for (relpath,) in con.execute("SELECT path FROM files ORDER BY path"):
        f = repo / relpath
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                total += 1
                if len(refs) < REFS_CAP:
                    refs.append(
                        {
                            "path": relpath,
                            "line": i,
                            "is_def": (relpath, i) in def_sites,
                            "text": line.strip()[:200],
                        }
                    )
    return {"query": name, "total": total, "capped_at": REFS_CAP, "refs": refs}


def cmd_info(con: sqlite3.Connection, db: Path) -> dict:
    """Index meta table (build provenance). Older indexes predate the
    `ref` key (branch-awareness Phase 1) — missing means
    unknown, never an error, so every existing index stays queryable."""
    meta = dict(con.execute("SELECT key, value FROM meta"))
    meta.setdefault("ref", "unknown")
    return {"index": str(db), **meta}


def cmd_file_symbols(con: sqlite3.Connection, relpath: str) -> dict:
    rows = con.execute(
        "SELECT name, line, kind FROM symbols WHERE path = ? ORDER BY line", (relpath,)
    ).fetchall()
    return {"query": relpath, "symbols": [{"name": n, "line": ln, "kind": k} for n, ln, k in rows]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--repo", help="target repo clone (used for auto-build and --refs)")
    parser.add_argument("--index", help="explicit index DB path")
    parser.add_argument("--defs", metavar="NAME", help="find definition sites of NAME")
    parser.add_argument("--refs", metavar="NAME", help="find textual references to NAME")
    parser.add_argument(
        "--file-symbols", metavar="PATH", help="list symbols defined in a repo-relative file"
    )
    parser.add_argument(
        "--info", action="store_true", help="print the index meta table (repo, sha, ref, engine, …)"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    chosen = [x for x in (args.defs, args.refs, args.file_symbols, args.info) if x]
    if len(chosen) != 1:
        print(
            "ERROR: exactly one of --defs / --refs / --file-symbols / --info required",
            file=sys.stderr,
        )
        return 2
    if args.refs and not args.repo:
        print("ERROR: --refs requires --repo (files are read from the clone)", file=sys.stderr)
        return 2

    con, db = open_index(args)

    if args.info:
        out = cmd_info(con, db)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            for k, v in out.items():
                print(f"{k}: {v}")
    elif args.defs:
        out = cmd_defs(con, args.defs)
        if args.json:
            print(json.dumps(out, indent=2))
        elif not out["defs"]:
            print(f"no definitions for {args.defs!r} in index — fall back to grep")
        else:
            if out["mode"] == "fuzzy":
                print(f"[no exact match; fuzzy matches for {args.defs!r}]")
            for d in out["defs"]:
                print(f"{d['path']}:{d['line']}:  {d['kind']}  {d['language']}  {d['name']}")
    elif args.refs:
        out = cmd_refs(con, Path(args.repo), args.refs)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            shown = len(out["refs"])
            print(
                f"{out['total']} reference line(s) for {args.refs!r}"
                + (f" (showing first {shown})" if out["total"] > shown else "")
            )
            for r in out["refs"]:
                mark = " [def]" if r["is_def"] else ""
                print(f"{r['path']}:{r['line']}:{mark} {r['text']}")
    else:
        out = cmd_file_symbols(con, args.file_symbols)
        if args.json:
            print(json.dumps(out, indent=2))
        elif not out["symbols"]:
            print(f"no indexed symbols in {args.file_symbols!r} (check the path is repo-relative)")
        else:
            for s in out["symbols"]:
                print(f"{s['line']}:  {s['kind']}  {s['name']}")

    con.close()
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["admin", "query-index", *sys.argv[1:]]))
