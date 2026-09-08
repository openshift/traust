#!/usr/bin/env python3
"""
Citation gate: deterministic pre-verification check for triage findings.

Runs between triage Phase 2 (dedup) and Phase 3 (verification). For each
finding it verifies that the cited file exists under the target repo, that
the cited line is in range, and that an extractable anchor (backtick-quoted
symbol or snippet from the finding text) actually appears near the cited
line. Findings with fabricated or drifted citations are tagged so the triage
orchestrator can route them to fewer verifier votes instead of burning a
full adversarial panel on them.

This tool routes; it never concludes. Tags map to vote routing only:

  ok                -> full votes
  line_drifted      -> full votes (annotated; anchor found elsewhere in file)
  anchor_absent     -> single vote (no extracted anchor appears in the file)
  file_missing      -> skip verification (emit verdict "undetermined" with
                       needs_manual_test / confidence 0 — never a false
                       positive: inaccessible material proves nothing)

Usage:
  python3 -m traust.cli.check_citations phase1.json --repo /tmp/target-clone
  python3 -m traust.cli.check_citations report.json --repo /tmp/clone --json-out gate.json

Input formats accepted:
  - triage phase1 checkpoint: {"findings": [{"id", "file", "line", "title",
    "description", ...}]}
  - a bare JSON list of such finding objects
  - audit reports whose findings carry "locations": [{"path", "lines"}] —
    each location is checked and the worst tag wins.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Tags ordered worst-first so multi-location findings keep the worst result.
TAG_ORDER = ["file_missing", "anchor_absent", "line_drifted", "ok"]

ROUTE = {
    "ok": "full_votes",
    "line_drifted": "full_votes",
    "anchor_absent": "single_vote",
    "file_missing": "skip_verification",
}

# Prefixes commonly prepended (or dropped) by scanners relative to the repo
# root. Mirrors the resolution ladder in the triage skill's Phase 1c.
STRIP_PREFIXES = ("./", "src/", "app/")

BACKTICK_SPAN = re.compile(r"`([^`\n]{2,120})`")
# path-with-line spans like foo/bar.go:123 are locations, not anchors
PATH_LINE_SPAN = re.compile(r"^[\w./-]+:\d+(?:-\d+)?$")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def resolve_path(repo: Path, cited: str) -> Path | None:
    """Resolve a cited path under the repo, tolerating common prefix skew."""
    if not cited or cited == ".":
        return None
    candidates = [cited]
    for pre in STRIP_PREFIXES:
        if cited.startswith(pre):
            candidates.append(cited[len(pre) :])
    # cited path may embed the repo's own basename ("myrepo/pkg/x.go")
    base = repo.name + "/"
    if cited.startswith(base):
        candidates.append(cited[len(base) :])
    for cand in candidates:
        p = (repo / cand).resolve()
        try:
            p.relative_to(repo.resolve())
        except ValueError:
            continue  # escaped the repo root; not acceptable
        if p.is_file():
            return p
    # absolute path already inside the repo
    p = Path(cited)
    if p.is_absolute() and p.is_file():
        try:
            p.resolve().relative_to(repo.resolve())
            return p
        except ValueError:
            return None
    return None


def extract_anchors(finding: dict) -> list[str]:
    """Pull checkable anchors out of the finding text.

    Only backtick-quoted spans and explicit symbol/anchor fields are used —
    free prose is too noisy to treat as a citation. Spans that are just
    file:line locations are skipped (they are checked positionally instead).
    """
    anchors: list[str] = []
    for key in ("symbol", "anchor"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            anchors.append(v.strip())
    text = f"{finding.get('title', '')}\n{finding.get('description', '')}"
    for span in BACKTICK_SPAN.findall(text):
        span = span.strip()
        if PATH_LINE_SPAN.match(span):
            continue
        if "/" in span and " " not in span:
            continue  # bare path, checked positionally
        anchors.append(span)
    # Deduplicate, preserve order
    seen: set[str] = set()
    out = []
    for a in anchors:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def _anchor_terms(anchor: str) -> list[str]:
    """Reduce an anchor to searchable identifier terms.

    A snippet like ``params.Set("search", v)`` reduces to its identifiers so
    minor formatting differences between the finding text and the source do
    not cause false anchor_absent tags.
    """
    idents = [t for t in IDENTIFIER.findall(anchor) if t not in ("the", "and", "not", "for")]
    return idents or [anchor]


def check_one(repo: Path, file: str, line, finding: dict, window: int) -> dict:
    resolved = resolve_path(repo, file)
    if resolved is None:
        return {
            "tag": "file_missing",
            "resolved": None,
            "matched_anchor": None,
            "detail": f"cited path not found under repo: {file!r}",
        }

    try:
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return {
            "tag": "file_missing",
            "resolved": str(resolved),
            "matched_anchor": None,
            "detail": f"unreadable: {e}",
        }

    nlines = len(lines)
    try:
        lineno = int(line) if line is not None else None
    except (TypeError, ValueError):
        lineno = None
    line_valid = lineno is not None and 1 <= lineno <= nlines

    anchors = extract_anchors(finding)
    rel = str(resolved.relative_to(repo.resolve()))

    if not anchors:
        # Nothing checkable beyond position. An out-of-range line with no
        # anchor is drift, not fabrication.
        if lineno is not None and not line_valid:
            return {
                "tag": "line_drifted",
                "resolved": rel,
                "matched_anchor": None,
                "detail": f"line {lineno} > {nlines}-line file; no anchor to check",
            }
        return {
            "tag": "ok",
            "resolved": rel,
            "matched_anchor": None,
            "detail": "no anchor extractable; file/line check only",
        }

    def find_terms(text: str) -> str | None:
        for anchor in anchors:
            terms = _anchor_terms(anchor)
            if all(t in text for t in terms):
                return anchor
        return None

    if line_valid:
        lo = max(0, lineno - 1 - window)
        hi = min(nlines, lineno + window)
        hit = find_terms("\n".join(lines[lo:hi]))
        if hit:
            return {
                "tag": "ok",
                "resolved": rel,
                "matched_anchor": hit,
                "detail": f"anchor within ±{window} lines of {lineno}",
            }

    hit = find_terms("\n".join(lines))
    if hit:
        where = f"line {lineno}" if lineno is not None else "no line cited"
        return {
            "tag": "line_drifted",
            "resolved": rel,
            "matched_anchor": hit,
            "detail": f"anchor found in file but not near cited {where}",
        }

    return {
        "tag": "anchor_absent",
        "resolved": rel,
        "matched_anchor": None,
        "detail": f"none of {len(anchors)} anchor(s) found anywhere in file",
    }


def iter_locations(finding: dict):
    """Yield (file, line) pairs for a finding in either supported format."""
    locs = finding.get("locations")
    if isinstance(locs, list) and locs:
        for loc in locs:
            if isinstance(loc, dict):
                lines = str(loc.get("lines", "")).strip()
                m = re.match(r"^(\d+)", lines)
                yield loc.get("path", ""), (int(m.group(1)) if m else None)
        return
    yield finding.get("file", ""), finding.get("line")


def gate(findings: list[dict], repo: Path, window: int) -> dict:
    results = []
    for f in findings:
        worst = None
        for file, line in iter_locations(f):
            r = check_one(repo, file or "", line, f, window)
            if worst is None or TAG_ORDER.index(r["tag"]) < TAG_ORDER.index(worst["tag"]):
                worst = {**r, "file": file, "line": line}
        worst = worst or {
            "tag": "file_missing",
            "file": None,
            "line": None,
            "resolved": None,
            "matched_anchor": None,
            "detail": "finding has no location",
        }
        results.append({"id": f.get("id"), **worst, "route": ROUTE[worst["tag"]]})
    summary = {t: sum(1 for r in results if r["tag"] == t) for t in TAG_ORDER}
    summary["total"] = len(results)
    return {"summary": summary, "results": results}


def load_findings(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        return doc["findings"]
    raise ValueError("input must be a findings list or an object with a 'findings' array")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("findings", help="findings JSON (triage phase1.json or audit report)")
    parser.add_argument("--repo", required=True, help="path to the target repo clone (read-only)")
    parser.add_argument(
        "--window",
        type=int,
        default=15,
        help="±lines around the cited line to search for anchors (default 15)",
    )
    parser.add_argument("--json-out", help="write full results JSON to this path")
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"ERROR: --repo {args.repo} is not a directory", file=sys.stderr)
        return 2
    try:
        findings = load_findings(Path(args.findings))
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot load findings: {e}", file=sys.stderr)
        return 2

    out = gate(findings, repo, args.window)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    s = out["summary"]
    print(
        f"Citation gate: {s['total']} finding(s) — "
        f"{s['ok']} ok, {s['line_drifted']} line_drifted, "
        f"{s['anchor_absent']} anchor_absent, {s['file_missing']} file_missing"
    )
    for r in out["results"]:
        if r["tag"] != "ok":
            print(
                f"  {r['tag']:>13}  {r['id']}  {r['file']}:{r['line']}  -> {r['route']}"
                f"  ({r['detail']})"
            )
    if not args.json_out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "citations", *sys.argv[1:]]))
