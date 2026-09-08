#!/usr/bin/env python3
"""
Lint the citations inside triage VERDICTS (post-vote), catching hallucinated
refutation evidence.

check_citations.py gates the SCANNER's citations before votes are spent;
this tool checks the VERIFIERS' citations after tallying: every file:line in
a finding's `first_links` and `rationale` must resolve under the target repo
and be in range. A false_positive or hardening verdict resting on evidence
that does not exist is the most dangerous triage failure mode — a real
vulnerability dismissed on hallucinated grounds.

This tool routes; it never concludes. Per-finding actions:

  ok                    -> nothing to do
  re_vote_recommended   -> false_positive/hardening verdict cites broken
                           evidence: spawn one fresh verifier vote and
                           re-tally before accepting the dismissal
  review_recommended    -> true_positive (or other) verdict cites broken
                           evidence: flag for reviewer attention (the
                           finding stays on the action list)

Usage:
  python scripts/lint_verdict_citations.py TRIAGE.json --repo /tmp/clone
  python scripts/lint_verdict_citations.py .triage-state/phase3.json \\
      --repo /tmp/clone --json-out lint.json

Accepts any JSON document with a `findings` array (TRIAGE.json or a triage
phase-3 checkpoint) or a bare list of finding objects.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from traust.cli.check_citations import resolve_path

# file:line spans like pkg/rbac/scope.go:37 or handler.py:112-118 — requires
# an extension so bare ratios ("3:1") and clock times don't match.
CITE_RE = re.compile(
    r"(?<![\w/])([\w.\-]+(?:/[\w.\-]+)*\.[A-Za-z]{1,6}[a-z0-9]?):(\d{1,6})(?:-\d{1,6})?"
)

LINTED_VERDICTS = {"false_positive", "hardening"}
SKIP_TOKENS = ("http://", "https://", "none found", "n/a")


def extract_citations(finding: dict) -> list[tuple[str, int, str]]:
    """Return (file, line, origin) citations from first_links and rationale."""
    cites: list[tuple[str, int, str]] = []
    for link in finding.get("first_links") or []:
        link = str(link).strip()
        if not link or any(t in link.lower() for t in SKIP_TOKENS):
            continue
        m = CITE_RE.search(link)
        if m:
            cites.append((m.group(1), int(m.group(2)), "first_links"))
    for m in CITE_RE.finditer(str(finding.get("rationale") or "")):
        cites.append((m.group(1), int(m.group(2)), "rationale"))
    # dedupe, preserve order
    seen: set[tuple[str, int]] = set()
    out = []
    for file, line, origin in cites:
        if (file, line) not in seen:
            seen.add((file, line))
            out.append((file, line, origin))
    return out


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
}


def build_file_index(repo: Path) -> dict[str, list[Path]]:
    """Map basename -> files, for lenient suffix resolution.

    Verifier prose routinely cites paths relative to a component or package
    root ("pkg/rbac/scope.go:37" inside a monorepo). The lint must be
    lenient in resolution and strict only when NOTHING in the repo matches
    — a false broken-citation claim burns a re-vote, so precision of the
    lint itself matters more than completeness.
    """
    index: dict[str, list[Path]] = {}
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts):
            continue
        index.setdefault(p.name, []).append(p)
    return index


def _suffix_candidates(index: dict[str, list[Path]], repo: Path, file: str) -> list[Path]:
    parts = Path(file).parts
    name = Path(file).name
    cands = index.get(name, [])
    if cands:
        return [c for c in cands if c.relative_to(repo).parts[-len(parts) :] == parts]
    # Verifier prose often abbreviates hyphenated filenames
    # ("jwt-args-patch.yaml" for "ambient-api-server-jwt-args-patch.yaml");
    # accept a hyphen-boundary tail match on the basename, still requiring
    # any cited directory components to line up.
    dir_parts = parts[:-1]
    out = []
    for basename, paths in index.items():
        if basename.endswith("-" + name):
            for c in paths:
                rel_dirs = c.relative_to(repo).parts[:-1]
                if not dir_parts or rel_dirs[-len(dir_parts) :] == dir_parts:
                    out.append(c)
    return out


def _line_count(path: Path) -> int | None:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return None


def check_citation(repo: Path, index: dict[str, list[Path]], file: str, line: int) -> str | None:
    """Return None if the citation plausibly resolves, else a defect."""
    resolved = resolve_path(repo, file)
    candidates = [resolved] if resolved else _suffix_candidates(index, repo, file)
    if not candidates:
        return f"{file}:{line} — file not found anywhere under repo"
    counts = [n for n in (_line_count(c) for c in candidates) if n is not None]
    if not counts:
        return f"{file}:{line} — unreadable"
    if line > max(counts):
        where = "" if resolved else f" (best suffix match of {len(candidates)})"
        return f"{file}:{line} — line out of range ({max(counts)}-line file{where})"
    return None


def lint(findings: list[dict], repo: Path) -> dict:
    index = build_file_index(repo)
    results = []
    for f in findings:
        verdict = f.get("verdict")
        if verdict == "duplicate":
            continue
        cites = extract_citations(f)
        broken = []
        for file, line, origin in cites:
            defect = check_citation(repo, index, file, line)
            if defect:
                broken.append({"origin": origin, "defect": defect})
        if broken:
            action = "re_vote_recommended" if verdict in LINTED_VERDICTS else "review_recommended"
            status = "broken_citations"
        else:
            action, status = "none", "ok"
        results.append(
            {
                "id": f.get("id"),
                "verdict": verdict,
                "citations_checked": len(cites),
                "broken": broken,
                "status": status,
                "action": action,
            }
        )
    summary = {
        "findings_linted": len(results),
        "citations_checked": sum(r["citations_checked"] for r in results),
        "broken_citations": sum(len(r["broken"]) for r in results),
        "re_vote_recommended": sum(1 for r in results if r["action"] == "re_vote_recommended"),
        "review_recommended": sum(1 for r in results if r["action"] == "review_recommended"),
    }
    return {"summary": summary, "results": results}


def load_findings(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        return doc["findings"]
    raise ValueError("input must be a findings list or an object with a 'findings' array")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("findings", help="TRIAGE.json, a phase-3 checkpoint, or a findings list")
    parser.add_argument("--repo", required=True, help="target repo clone (read-only)")
    parser.add_argument("--json-out", help="write full results JSON to this path")
    args = parser.parse_args()

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"ERROR: --repo {args.repo} is not a directory", file=sys.stderr)
        return 2
    try:
        findings = load_findings(Path(args.findings))
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot load findings: {e}", file=sys.stderr)
        return 2

    out = lint(findings, repo)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    s = out["summary"]
    print(
        f"Verdict-citation lint: {s['findings_linted']} finding(s), "
        f"{s['citations_checked']} citation(s) checked, "
        f"{s['broken_citations']} broken — "
        f"{s['re_vote_recommended']} re-vote, {s['review_recommended']} review"
    )
    for r in out["results"]:
        if r["status"] != "ok":
            print(f"  {r['action']:>20}  {r['id']} ({r['verdict']})")
            for b in r["broken"]:
                print(f"{'':24}{b['origin']}: {b['defect']}")
    if not args.json_out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
