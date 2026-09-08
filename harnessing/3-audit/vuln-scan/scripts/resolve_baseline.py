#!/usr/bin/env python3
"""Resolve the /vuln-scan --diff baseline and emit the scope package.

Deterministic helper (stdlib + sqlite3 only) for the vuln-scan skill's
diff mode (progress-tracker/plans/vuln-scan-diff-mode-plan.md). Given an
EXISTING target checkout directory it:

  1. identifies the repository (`git -C <dir> remote get-url origin`
     normalized via corpus.normalize_repo_url — ssh remotes are
     converted to their https spelling first);
  2. resolves the baseline: the newest valid HEAD code-audit report for
     that URL in findings.db (report_kind='code-audit',
     is_branch_audit=0, deduped by normalized URL, freshest audit_date
     wins — the same query shape as `traust build rescan-worklist`).
     `--baseline <audit.json>` / `--since <commit>` override resolution
     and are recorded as resolution_source: override (auto otherwise);
  3. extracts the anchor SHA from the baseline report's
     metadata.commit (prose-tolerant parse_pinned_sha, shared with the
     router / build_verify_sweep.py);
  4. verifies the anchor is reachable in the clone and computes
     `git diff --numstat <anchor>..HEAD`, applying the SAME first-party
     filter and narrow sensitive matcher as the rescan router (imported
     from build_rescan_worklist — a diverging matcher between router
     and scanner is a bug; tests assert identity);
  5. REFUSES (exit 3, {"refuse": true, "recommend": "full-audit", ...})
     when the diff invalidates the baseline: >30% of first-party files
     changed, C >= 8,000 first-party changed lines, no baseline
     resolvable, or the anchor unreachable in the clone. It NEVER falls
     back to whole-repo scope — the middle lane must not silently
     substitute for a full audit;
  6. on success emits the scope package JSON (stdout, or --out):
     baseline_report / anchor / resolution_source, changed_files with
     per-file added/deleted/sensitive, 1-5 path clusters (top-level
     dir/component grouping), C, sensitive_lines,
     deps_manifests_changed, and the baseline findings that touch the
     changed files (fingerprint + title + paths) for dedupe.

This is a SCOPING tool, never a finder: it routes the diff mode's
attention and authors no finding or verdict
(docs/deterministic-inferential-mix.md).

Git safety: every git invocation is list-argv (no shell), read-only,
and local-only — the target dir is operator-supplied and this script
performs NO network fetching of any kind (it works on the existing
clone; findings.db is opened read-only).

Usage:
    python3 resolve_baseline.py <target-dir>
        [--db FILE] [--baseline <audit.json>] [--since <commit>]
        [--out FILE]

Exit codes: 0 scope package emitted; 2 usage/operational error;
3 refusal (JSON verdict emitted, recommend: full-audit).
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

# Same sys.path pattern as harnessing/8-verify/verify-remediation/scripts/build_verify_sweep.py
from traust_engine.corpus.resolver import normalize_repo_url

# Shared with the continuous-operations router — imported, not copied, so
# router and scanner can never disagree on what "first-party" or
# "sensitive" means (tests/test_resolve_baseline.py asserts identity).
from traust.cli.build_rescan_worklist import (
    CHURN_FULL_LINES,
    SENSITIVE_RX,
    is_deps_manifest,
    is_first_party,
    parse_pinned_sha,
)
from traust.context import (
    add_config_home_arg,
    findings_db,
    load_engine,
)

MAX_CHANGED_FILE_RATIO = 0.30  # refusal rule: >30% first-party files
MAX_CLUSTERS = 5

_SHA_ARG_RX = re.compile(r"^[0-9a-f]{7,40}$")
_SSH_REMOTE_RX = re.compile(r"^(?:ssh://)?git@([^:/]+)[:/](.+)$")
# `git diff --numstat -M` rename spellings: "a/{old => new}/b" or
# "old => new"
_RENAME_BRACE_RX = re.compile(r"\{[^{}]*=> ?([^{}]*)\}")

# Same query shape as build_rescan_worklist._REPOS_SQL (HEAD code-audit
# population).
_REPOS_SQL = """
SELECT repo_key, repo_url, report_path, audit_date
FROM repos WHERE report_kind = 'code-audit' AND is_branch_audit = 0
"""


# ---------------------------------------------------------------------------
# git (list argv only, read-only, local-only)
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=timeout
    )


def is_git_checkout(repo: Path) -> bool:
    proc = _git(repo, "rev-parse", "--git-dir")
    return proc.returncode == 0


_URL_USERINFO_RX = re.compile(r"^(https?://)[^/@]+@")


def repo_origin_url(repo: Path) -> str | None:
    """Normalized https URL of the checkout's origin remote, or None.

    Userinfo is ALWAYS stripped: clones made with a token-in-URL remote
    (https://oauth2:<token>@host/...) would otherwise leak the live
    credential into the scope package, every refusal message, and the
    findings.db lookup (which stores clean URLs, so the lookup also
    fails — observed on the 2026-07-27 re-pilot's engagement row)."""
    proc = _git(repo, "remote", "get-url", "origin")
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    m = _SSH_REMOTE_RX.match(raw)
    if m:  # ssh spelling -> https spelling before corpus normalization
        raw = f"https://{m.group(1)}/{m.group(2)}"
    raw = _URL_USERINFO_RX.sub(r"\1", raw)
    return normalize_repo_url(raw)


def anchor_reachable(repo: Path, sha: str) -> bool:
    if not _SHA_ARG_RX.fullmatch(sha or ""):
        return False
    return _git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def _normalize_numstat_path(path: str) -> str:
    """Collapse rename spellings to the NEW path."""
    if "=>" in path:
        path = _RENAME_BRACE_RX.sub(lambda m: m.group(1), path)
        if "=>" in path:  # whole-path rename: "old => new"
            path = path.split("=>", 1)[1].strip()
        path = path.replace("//", "/").lstrip("/")
    return path


def diff_numstat(repo: Path, anchor: str) -> list[dict]:
    """[{path, added, deleted}] for anchor..HEAD; binary files count 0."""
    proc = _git(repo, "diff", "--numstat", "-M", f"{anchor}..HEAD", timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()[:200]}")
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added_s, deleted_s, path = parts
        added = int(added_s) if added_s.isdigit() else 0
        deleted = int(deleted_s) if deleted_s.isdigit() else 0
        rows.append({"path": _normalize_numstat_path(path), "added": added, "deleted": deleted})
    return rows


def count_first_party_files(repo: Path) -> int:
    """First-party file count at HEAD (the 30%-rule denominator)."""
    proc = _git(repo, "ls-files", "-z", timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {proc.stderr.strip()[:200]}")
    return sum(1 for p in proc.stdout.split("\0") if p and is_first_party(p))


# ---------------------------------------------------------------------------
# baseline resolution (findings.db, read-only)
# ---------------------------------------------------------------------------


def resolve_from_db(db_path: Path, url: str) -> dict | None:
    """Newest valid HEAD code-audit row for `url`.

    Same population and dedupe semantics as the router: normalized-URL
    match, freshest audit_date wins, strict-greater keeps the earlier
    row on ties. Exact normalized match first, case-insensitive
    fallback second (checkout remotes sometimes differ from report
    metadata in case only)."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(_REPOS_SQL).fetchall()
    finally:
        con.close()
    best_exact, best_ci = None, None
    for repo_key, repo_url, report_path, audit_date in rows:
        norm = normalize_repo_url(repo_url)
        if norm is None or not report_path:
            continue
        rec = {
            "repo_key": repo_key,
            "repo_url": norm,
            "report_path": report_path,
            "audit_date": audit_date,
        }
        if norm == url:
            if best_exact is None or ((rec["audit_date"] or "") > (best_exact["audit_date"] or "")):
                best_exact = rec
        elif norm.lower() == url.lower() and (
            best_ci is None or ((rec["audit_date"] or "") > (best_ci["audit_date"] or ""))
        ):
            best_ci = rec
    return best_exact or best_ci


def load_report(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# scope-package pieces (pure, unit-testable)
# ---------------------------------------------------------------------------


def cluster_paths(paths: list[str]) -> list[dict]:
    """Group changed paths by top-level dir/component into 1-5 clusters.

    Root-level files group under "(root)". When more than MAX_CLUSTERS
    top-level groups exist, the largest MAX_CLUSTERS-1 stay named and
    the remainder merge into an "other" cluster — the diff mode fans
    out one review subagent per cluster, so the cap bounds the fan-out.
    """
    groups: dict[str, list[str]] = {}
    for p in paths:
        top = p.split("/", 1)[0] if "/" in p else "(root)"
        groups.setdefault(top, []).append(p)
    items = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    if len(items) > MAX_CLUSTERS:
        head, tail = items[: MAX_CLUSTERS - 1], items[MAX_CLUSTERS - 1 :]
        other = sorted(f for _, fs in tail for f in fs)
        items = [*head, ("other", other)]
    return [{"name": name, "files": sorted(files)} for name, files in items]


def _norm_rel(path: str) -> str:
    return path.removeprefix("./").lstrip("/")


def _paths_match(loc_path: str, changed: str) -> bool:
    a, b = _norm_rel(loc_path), _norm_rel(changed)
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def baseline_findings_for(report: dict | None, changed_paths: list[str]) -> list[dict]:
    """Baseline findings whose locations touch any changed file:
    fingerprint (may be null — fingerprints are unstable across runs,
    so the skill also fuzzy-matches on title/path) + title + paths."""
    if not report or not changed_paths:
        return []
    out = []
    for f in report.get("findings") or []:
        touched = sorted(
            {
                loc.get("path")
                for loc in (f.get("locations") or [])
                if loc.get("path") and any(_paths_match(loc["path"], c) for c in changed_paths)
            }
        )
        if touched:
            out.append(
                {
                    "id": f.get("id"),
                    "fingerprint": f.get("fingerprint"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "paths": touched,
                }
            )
    return out


# ---------------------------------------------------------------------------
# emit / main
# ---------------------------------------------------------------------------


def _emit(doc: dict, out: Path | None) -> None:
    text = json.dumps(doc, indent=2) + "\n"
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"[+] wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _refuse(reason: str, out: Path | None, **details) -> int:
    doc = {"refuse": True, "recommend": "full-audit", "reason": reason}
    doc.update(details)
    _emit(doc, out)
    return 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Resolve the /vuln-scan --diff baseline and emit "
        "the scope package (refuses with recommend: "
        "full-audit when the diff invalidates the baseline)"
    )
    add_config_home_arg(ap)
    ap.add_argument("target", type=Path, help="existing target checkout directory (read-only)")
    ap.add_argument(
        "--db", type=Path, default=None, help="findings.db projection (default: configured)"
    )
    ap.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="explicit baseline *-security-audit.json (overrides findings.db resolution)",
    )
    ap.add_argument(
        "--since",
        default=None,
        metavar="COMMIT",
        help="explicit anchor commit (overrides the baseline report's metadata.commit)",
    )
    ap.add_argument("--out", type=Path, default=None, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    args.db = args.db or findings_db(engine)

    target = args.target
    if not target.is_dir():
        print(f"error: not a directory: {target}", file=sys.stderr)
        return 2
    if args.since and not _SHA_ARG_RX.fullmatch(args.since.lower()):
        print(f"error: --since must be a 7-40 char hex SHA, got {args.since!r}", file=sys.stderr)
        return 2
    if not is_git_checkout(target):
        return _refuse(
            "target is not a git checkout — no diff is computable against any baseline", args.out
        )

    # --- resolve the baseline report -----------------------------------
    override = bool(args.baseline or args.since)
    resolution_source = "override" if override else "auto"
    baseline_path: str | None = None
    baseline_report: dict | None = None
    repo_url = repo_origin_url(target)

    if args.baseline:
        baseline_report = load_report(args.baseline)
        if baseline_report is None:
            return _refuse(
                f"--baseline {args.baseline} is missing or unparseable",
                args.out,
                resolution_source=resolution_source,
            )
        baseline_path = str(args.baseline)
    else:
        row = None
        if repo_url and args.db.is_file():
            row = resolve_from_db(args.db, repo_url)
        if row:
            baseline_path = row["report_path"]
            baseline_report = load_report(Path(baseline_path))
        if baseline_report is None and not args.since:
            if repo_url is None:
                return _refuse(
                    "cannot identify the repository (no origin remote "
                    "URL) and no --baseline/--since override given",
                    args.out,
                    resolution_source=resolution_source,
                )
            if not args.db.is_file():
                return _refuse(
                    f"findings.db not found at {args.db} — no baseline "
                    f"resolvable (run `traust corpus findings-db`, or "
                    f"pass --baseline/--since)",
                    args.out,
                    resolution_source=resolution_source,
                    repo_url=repo_url,
                )
            return _refuse(
                f"no valid HEAD code-audit baseline resolvable for {repo_url} in {args.db}",
                args.out,
                resolution_source=resolution_source,
                repo_url=repo_url,
            )

    # --- resolve the anchor SHA ----------------------------------------
    if args.since:
        anchor = args.since.lower()
    else:
        meta = (baseline_report or {}).get("metadata") or {}
        anchor = parse_pinned_sha(meta.get("commit"))
        if not anchor:
            return _refuse(
                f"baseline report {baseline_path} has no parseable pinned SHA in metadata.commit",
                args.out,
                resolution_source=resolution_source,
                baseline_report=baseline_path,
            )
    if not anchor_reachable(target, anchor):
        return _refuse(
            f"anchor {anchor} is not reachable in the clone — the "
            f"checkout does not contain the audited commit",
            args.out,
            resolution_source=resolution_source,
            baseline_report=baseline_path,
            anchor=anchor,
        )

    # --- diff + metrics (router-identical filter/matcher) --------------
    try:
        numstat = diff_numstat(target, anchor)
        total_fp_files = count_first_party_files(target)
    except (RuntimeError, subprocess.SubprocessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    deps_manifests_changed = any(is_deps_manifest(r["path"]) for r in numstat)
    changed_files = []
    C = 0
    sensitive_lines = 0
    for r in numstat:
        if not is_first_party(r["path"]):
            continue
        sensitive = bool(SENSITIVE_RX.search(r["path"]))
        lines = r["added"] + r["deleted"]
        C += lines
        if sensitive:
            sensitive_lines += lines
        changed_files.append(
            {
                "path": r["path"],
                "added": r["added"],
                "deleted": r["deleted"],
                "sensitive": sensitive,
            }
        )

    ratio = (
        len(changed_files) / total_fp_files if total_fp_files else (1.0 if changed_files else 0.0)
    )
    if ratio > MAX_CHANGED_FILE_RATIO:
        return _refuse(
            f"{len(changed_files)}/{total_fp_files} "
            f"({ratio:.0%}) of first-party files changed since the "
            f"anchor — the diff invalidates the baseline",
            args.out,
            resolution_source=resolution_source,
            baseline_report=baseline_path,
            anchor=anchor,
            changed_first_party_files=len(changed_files),
            total_first_party_files=total_fp_files,
        )
    if C >= CHURN_FULL_LINES:
        return _refuse(
            f"C={C} first-party changed lines >= {CHURN_FULL_LINES} "
            f"(rescan rule-2 threshold) — the diff invalidates the "
            f"baseline",
            args.out,
            resolution_source=resolution_source,
            baseline_report=baseline_path,
            anchor=anchor,
            C=C,
        )

    changed_paths = [c["path"] for c in changed_files]
    doc = {
        "refuse": False,
        "target": str(target),
        "repo_url": repo_url,
        "baseline_report": baseline_path,
        "anchor": anchor,
        "resolution_source": resolution_source,
        "changed_files": changed_files,
        "clusters": cluster_paths(changed_paths),
        "C": C,
        "sensitive_lines": sensitive_lines,
        "deps_manifests_changed": deps_manifests_changed,
        "baseline_findings_for_changed_files": baseline_findings_for(
            baseline_report, changed_paths
        ),
        "total_first_party_files": total_fp_files,
        "changed_first_party_ratio": round(ratio, 4),
    }
    _emit(doc, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
