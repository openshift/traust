#!/usr/bin/env python3
"""Diff-mode context packet — the deterministic evidence bundle the
review agents judge instead of exploring the checkout.

The 50-repo pilot (2026-07-27) measured that a diff scan's cost tracks
repo size and fixed exploration overhead, not diff size: the median run
reviewed 640 changed lines yet cost $6.67, mostly agent turns spent
re-deriving scope (recon reads, symbol lookups, baseline cross-checks)
that a script derives deterministically for free. This builder folds
all of that into ONE artifact:

  per cluster (from the resolver's scope package):
    - the changed hunks themselves (`git diff -U<ctx> <anchor>..HEAD`,
      per first-party file, byte-capped with an explicit `omitted`
      ledger — no silent truncation)
    - direct callers of symbols defined in the changed files (symbol
      index: `traust build symbol-index` + `traust admin query-index`), each with
      a few lines of surrounding context from the working tree
    - the baseline findings touching the cluster's files (from the
      scope package — the ALREADY-IN-BASELINE block, pre-sliced)

Consumes: the resolver's scope package (resolve_baseline.py --out; a
refusal is rejected here — a packet must never widen past a refusal).
Emits: <repo>-diff-packet.json for /vuln-scan --diff to hand its
cluster subagents. Routes attention and carries evidence only — it
never authors a finding, and agents remain free to Read the checkout
to verify anything the packet shows them.

Usage:
    python3 build_diff_packet.py --scope <repo>-diff-scope.json \
        [--repo DIR] [--out FILE] [--context-lines 10] \
        [--max-file-bytes 20000] [--max-total-bytes 400000] \
        [--max-callers 40] [--no-callers]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Harness root: the directory holding VERSION, found by walking up rather
# than counting parents, so nesting this skill under a stage directory
# (skill-usability plan 1.2) cannot silently repoint it.
HARNESS_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())

MAX_SYMBOLS_PER_FILE = 10  # exported symbols queried per changed file
CALLER_CONTEXT_LINES = 3


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=120
    )


def file_hunks(repo: Path, anchor: str, path: str, ctx: int, max_bytes: int) -> tuple[str, bool]:
    """Unified diff for one file; (text, truncated)."""
    r = _git(repo, "diff", f"-U{ctx}", f"{anchor}..HEAD", "--", path)
    if r.returncode != 0:
        return f"(diff failed: {r.stderr.strip()[:200]})", False
    text = r.stdout
    if len(text.encode("utf-8", "replace")) > max_bytes:
        clipped = text.encode("utf-8", "replace")[:max_bytes].decode("utf-8", "replace")
        return (
            clipped + f"\n... [truncated at {max_bytes} bytes — Read the file for the rest]"
        ), True
    return text, False


def build_index(repo: Path) -> Path | None:
    """Build the per-run symbol index; None when the builder fails
    (callers section is then honestly empty with a reason)."""
    out = Path(tempfile.mkdtemp(prefix="diff-packet-idx-")) / "index.db"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli.build_symbol_index",
            "--repo",
            str(repo),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    return out if r.returncode == 0 and out.is_file() else None


def _query(index: Path, repo: Path, *args: str) -> list | dict | None:
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli.query_index",
            "--index",
            str(index),
            "--repo",
            str(repo),
            "--json",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def _context_snippet(repo: Path, path: str, line: int) -> str:
    try:
        lines = (repo / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(0, line - 1 - CALLER_CONTEXT_LINES)
    hi = min(len(lines), line + CALLER_CONTEXT_LINES)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _symbol_names(doc) -> list[str]:
    """query_index --file-symbols shape: {query, symbols:[{name,...}]}"""
    names = []
    for row in (doc or {}).get("symbols") or []:
        name = row.get("name")
        if name and name not in names:
            names.append(name)
    return names


def callers_for(
    index: Path, repo: Path, changed: set[str], max_callers: int
) -> tuple[list[dict], list[str]]:
    """Reference sites OUTSIDE the changed set for symbols defined in
    changed files. Capped with an explicit omission ledger."""
    callers, omitted = [], []
    for path in sorted(changed):
        rows = _query(index, repo, "--file-symbols", path)
        names = _symbol_names(rows)
        if len(names) > MAX_SYMBOLS_PER_FILE:
            omitted.append(
                f"{path}: {len(names) - MAX_SYMBOLS_PER_FILE} "
                f"symbol(s) beyond the per-file cap unqueried"
            )
            names = names[:MAX_SYMBOLS_PER_FILE]
        for name in names:
            doc = _query(index, repo, "--refs", name) or {}
            for ref in doc.get("refs") or []:
                rfile = ref.get("path") or ""
                rline = int(ref.get("line") or 0)
                if not rfile or rfile in changed or ref.get("is_def"):
                    continue
                if len(callers) >= max_callers:
                    omitted.append(
                        f"caller cap ({max_callers}) reached at "
                        f"{path}:{name} — remaining references "
                        f"unlisted; use query_index.py --refs"
                    )
                    return callers, omitted
                callers.append(
                    {
                        "symbol": name,
                        "defined_in": path,
                        "file": rfile,
                        "line": rline,
                        "context": _context_snippet(repo, rfile, rline),
                    }
                )
    return callers, omitted


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--scope", required=True, type=Path, help="resolver scope package (resolve_baseline.py)"
    )
    ap.add_argument(
        "--repo", type=Path, default=None, help="target checkout (default: scope's `target`)"
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output path (default: <repo>-diff-packet.json beside the scope file)",
    )
    ap.add_argument("--context-lines", type=int, default=10)
    ap.add_argument("--max-file-bytes", type=int, default=20_000)
    ap.add_argument("--max-total-bytes", type=int, default=400_000)
    ap.add_argument("--max-callers", type=int, default=40)
    ap.add_argument("--no-callers", action="store_true", help="skip the symbol-index caller pass")
    args = ap.parse_args(argv)

    try:
        scope = json.loads(args.scope.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read scope package: {e}", file=sys.stderr)
        return 2
    if scope.get("refuse"):
        print(
            "error: the scope package is a REFUSAL — a packet must "
            "never widen past it; run the recommended full audit",
            file=sys.stderr,
        )
        return 3

    repo = args.repo or Path(scope.get("target") or ".")
    if not (repo / ".git").exists():
        print(f"error: {repo} is not a git checkout", file=sys.stderr)
        return 2
    anchor = scope.get("anchor")
    if not anchor:
        print("error: scope package has no anchor", file=sys.stderr)
        return 2

    changed_paths = [c["path"] for c in scope.get("changed_files") or []]
    changed_set = set(changed_paths)
    omitted: list[str] = []

    # hunks, per file, byte-capped per-file and in total
    hunks: dict[str, dict] = {}
    total = 0
    for c in scope.get("changed_files") or []:
        path = c["path"]
        if total >= args.max_total_bytes:
            omitted.append(
                f"{path}: total packet byte cap "
                f"({args.max_total_bytes}) reached — hunks "
                f"not embedded; run git diff to view"
            )
            continue
        text, truncated = file_hunks(repo, anchor, path, args.context_lines, args.max_file_bytes)
        total += len(text.encode("utf-8", "replace"))
        hunks[path] = {
            "diff": text,
            "truncated": truncated,
            "added": c.get("added"),
            "deleted": c.get("deleted"),
            "sensitive": c.get("sensitive"),
        }

    # callers via the symbol index (optional, honestly absent on failure)
    callers: list[dict] = []
    callers_note = None
    if args.no_callers:
        callers_note = "skipped: --no-callers"
    else:
        index = build_index(repo)
        if index is None:
            callers_note = (
                "skipped: symbol index build failed — enumerate callers manually per the SKILL"
            )
        else:
            callers, caller_omits = callers_for(index, repo, changed_set, args.max_callers)
            omitted.extend(caller_omits)

    by_file_callers: dict[str, list[dict]] = {}
    for cal in callers:
        by_file_callers.setdefault(cal["defined_in"], []).append(cal)

    baseline_rows = scope.get("baseline_findings_for_changed_files") or []
    clusters = []
    for cl in scope.get("clusters") or []:
        files = cl.get("files") or []
        clusters.append(
            {
                "name": cl.get("name"),
                "files": [{"path": p, **hunks.get(p, {})} for p in files],
                "callers": [c for p in files for c in by_file_callers.get(p, [])],
                "baseline_findings": [
                    b for b in baseline_rows if any(bp in files for bp in b.get("paths") or [])
                ],
            }
        )

    doc = {
        "artifact": "diff-packet",
        "target": str(repo),
        "repo_url": scope.get("repo_url"),
        "baseline_report": scope.get("baseline_report"),
        "anchor": anchor,
        "resolution_source": scope.get("resolution_source"),
        "C": scope.get("C"),
        "sensitive_lines": scope.get("sensitive_lines"),
        "deps_manifests_changed": scope.get("deps_manifests_changed"),
        "clusters": clusters,
        "callers_note": callers_note,
        "omitted": omitted,
        "stats": {
            "changed_files": len(changed_paths),
            "files_embedded": len(hunks),
            "hunk_bytes": total,
            "callers": len(callers),
        },
    }
    out = args.out or args.scope.with_name(args.scope.name.replace("-diff-scope", "-diff-packet"))
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(
        f"diff packet: {len(changed_paths)} changed file(s), "
        f"{len(callers)} caller site(s), {total} hunk bytes → {out}"
        + (f" ({len(omitted)} omission(s) listed)" if omitted else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
