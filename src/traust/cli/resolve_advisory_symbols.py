#!/usr/bin/env python3
"""Resolve an advisory's VULNERABLE SYMBOLS from its fix commit — the
missing input that keeps every non-Go reachability tier at the manifest
ceiling.

WHY THIS EXISTS (measured 2026-08-11, harness v0.261.0). /impact-analysis
promotes a repo to `affected` only on `evidence_level == "symbol"`, which
requires a Joern call-site hit against a `kind: "symbol"` pattern, which
exists only when `--symbols` is supplied. Nothing supplied it outside Go:
0 of 289 fleet-OSV worklist commands carried `--symbols`, because OSV
publishes per-symbol data (`ecosystem_specific.imports`) for Go and
nothing else. Consequence: a full 52-advisory Maven sweep promoted 0 of
120 in-range pairs, even though the Java Joern tier fires and produces
real witnesses. The tier was never the problem; the query was empty.

METHOD (facts only — this script never classifies).

  1. Union the advisory's OSV record with its CVE aliases. GHSA-form
     records routinely lack what the CVE-form record carries
     (GHSA-24rp-q3w6-vc56 has no fix data; its alias CVE-2024-1597 leads
     to pgjdbc@06abfb78).
  2. Mine `references[].url` for `/commit/<sha>` (and `/pull/<n>` as a
     fallback). Do NOT use the `fixed` SHA in OSV GIT ranges: measured,
     those are release-tag commits ("[maven-release-plugin] prepare
     release jackson-databind-2.7.9.7"), whose diffs are release
     plumbing, not the patch. Coverage of a direct commit reference on
     the real Maven set: 22/25.
  3. Fetch the commit and extract method/function declarations touched by
     the diff, from hunk-header context and from changed declaration
     lines, skipping test paths.
  4. Qualify each symbol with the package derived from the FILE PATH
     (src/main/java/<pkg>/<Class>.java), because javasrc2cpg
     methodFullName is package-qualified — a bare `Class#method` cannot
     match a startsWith query.

KNOWN LIMIT, stated because it bounds the yield: when the fix is DATA
rather than code — a deny-list entry, a validation table, a dependency
bump — there is no changed method and this returns nothing. jackson's
CVE family is exactly this shape (CVE-2020-8840's fix adds three lines to
SubTypeValidator's deny-list; the real symbol is the entry point
`ObjectMapper.readValue`). Those advisories need the judged or curated
tier, not this one. `status` says which case a run hit, and a caller must
treat an empty result as "unresolved", never as "no vulnerable symbol".

A WRONG SYMBOL IS WORSE THAN NO SYMBOL: it fabricates `affected` with a
cited witness, the strongest claim the evidence ladder allows short of
execution. So every symbol carries its provenance (commit URL + file +
extraction rule) and `confidence`; consumers gate on those.

Usage:
    python3 -m traust.cli.resolve_advisory_symbols ADVISORY \
        [--ecosystem maven|npm|pypi|...] [--module group:artifact] \
        [--curated config/advisory-symbols.yaml] [--out FILE]

Exit 0 always writes an artifact: status "resolved", "no_fix_commit",
"no_symbols_in_diff" (the data-fix case), "curated", or
"error: <reason>" — the deterministic_steps honesty convention.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from traust.paths import HARNESS_ROOT
from traust.registry.osv_urls import osv_vuln_url

OSV_VULN = osv_vuln_url()

# GitHub, GitLab, and the cgit/gitweb shapes the C ecosystem actually uses.
# Measured 2026-08-14: of 8 distro CVEs only 2 carried a GitHub commit ref —
# but glibc, gnutls, libgcrypt and sqlite do not develop on GitHub at all, so
# a GitHub-only pattern understates recoverable fixes rather than measuring
# advisory quality.
_COMMIT_RX = re.compile(
    r"(?:github|gitlab)\.com/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+?)"
    r"/-?/?commit/([0-9a-f]{7,40})"
)
# cgit / gitweb: ?id=<sha> or ;h=<sha> against a repo path
_CGIT_RX = re.compile(
    r"https?://([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.~-]+)*?)"
    r"[/?]?(?:[?;&](?:id|h)=)([0-9a-f]{7,40})"
)
_PULL_RX = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(\d+)")

# Java/C-style declaration: modifiers, return type, name, open paren.
_JAVA_DECL = re.compile(
    r"\b(?:public|protected|private)\s+(?:static\s+|final\s+|synchronized\s+|"
    r"abstract\s+|native\s+)*[\w<>\[\],.\s?]+?\s+(\w+)\s*\("
)
_PY_DECL = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")
_JS_DECL = re.compile(
    r"(?:^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\()"
    r"|(?:^\s*(\w+)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>))"
)
_C_DECL = re.compile(r"^[A-Za-z_][\w\s*]*?\b(\w+)\s*\([^;]*$")

_NOT_A_METHOD = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "else",
    }
)
_TEST_PATH = re.compile(r"(^|/)(src/test|tests?|testdata|__tests__|spec)(/|$)", re.I)

_SRC_EXT = {
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".py": "python",
    ".js": "js",
    ".ts": "js",
    ".jsx": "js",
    ".tsx": "js",
}


def _get_json(url: str, timeout: int = 25) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as fh:
            return json.load(fh)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None


def osv_records(advisory: str) -> list[dict]:
    """The advisory's record plus ALL of its alias records (deduped).

    Alias traversal must run in BOTH directions, not just CVE-ward: the
    fix-commit reference lives on whichever form the ecosystem's curator
    populated. Measured 2026-08-11 — the GHSA record for Spring4Shell
    (GHSA-36p3-wjmg-h94x) carries spring-framework@002546b3 while its
    alias CVE-2022-22965 carries no commit reference at all, and
    GHSA-24rp-q3w6-vc56 is the reverse. A CVE-only walk silently returns
    `no_fix_commit` for advisories whose fix IS published.
    """
    out, seen = [], set()
    first = _get_json(OSV_VULN.format(vid=advisory))
    if not first:
        return out
    out.append(first)
    seen.add(first.get("id"))
    # ALIASES ONLY — an alias is the SAME vulnerability under another id,
    # so its fix commit is this advisory's fix commit. `related` is a
    # DIFFERENT vulnerability and must not contribute symbols: following it
    # pulled com.amazon.redshift SimpleParameterList#toString into
    # GHSA-24rp-q3w6-vc56 (pgjdbc) via CVE-2024-32888, and a foreign symbol
    # in a promotion query is exactly how a wrong `affected` gets minted.
    # `upstream` as well as `aliases`. Distro advisories (RHSA/DSA/USN) carry
    # their CVE ids in `upstream` and have NO `aliases` at all — measured
    # 2026-08-14: RHSA-2026:1334 has aliases=None, upstream=['CVE-2026-0861',
    # 'CVE-2026-0915']. Without this hop every distro advisory resolves to
    # nothing, which silently excludes the whole C/C++ surface.
    for al in (first.get("aliases") or []) + (first.get("upstream") or []):
        if not isinstance(al, str) or al in seen:
            continue
        seen.add(al)
        rec = _get_json(OSV_VULN.format(vid=al))
        if rec:
            out.append(rec)
    return out


def fix_commits(records: list[dict]) -> tuple[list[dict], list[dict]]:
    """(direct commit refs, pull-request refs) mined from references.

    Deliberately ignores `affected[].ranges[type=GIT].events[].fixed`:
    those SHAs are release commits, not the patch (verified 2026-08-11 on
    jackson-databind and spring-framework).
    """
    commits, pulls, seen = [], [], set()
    for rec in records:
        for ref in rec.get("references") or []:
            url = ref.get("url") or ""
            m = _COMMIT_RX.search(url) or _CGIT_RX.search(url)
            if m and (m.group(1), m.group(2)) not in seen:
                seen.add((m.group(1), m.group(2)))
                commits.append(
                    {"repo": m.group(1), "sha": m.group(2), "url": url, "ref_type": ref.get("type")}
                )
                continue
            m = _PULL_RX.search(url)
            if m:
                pulls.append(
                    {"repo": m.group(1), "pr": m.group(2), "url": url, "ref_type": ref.get("type")}
                )
    return commits, pulls


def _gh_api(path: str) -> dict | list | None:
    """GitHub API via the gh CLI (inherits its auth; token never in argv)."""
    try:
        p = subprocess.run(
            ["gh", "api", path],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if p.returncode != 0:
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return None


def _package_from_path(path: str, lang: str) -> str:
    """Package/module prefix implied by a source path.

    Java: .../src/main/java/org/springframework/beans/Foo.java ->
    org.springframework.beans. Python: pkg/sub/mod.py -> pkg.sub.mod.
    Returns "" when no prefix can be derived (C, bare paths).
    """
    parts = path.split("/")
    if lang == "java":
        for anchor in ("java", "kotlin", "scala"):
            if anchor in parts:
                i = len(parts) - 1 - parts[::-1].index(anchor)
                pkg = parts[i + 1 : -1]
                if pkg:
                    return ".".join(pkg)
        return ""
    if lang == "python":
        pkg = [p for p in parts[:-1] if p not in ("src", "lib")]
        return ".".join(pkg)
    return ""


def symbols_from_commit(repo: str, sha: str) -> tuple[list[dict], dict]:
    """Declarations touched by the commit, package-qualified where the
    language allows it. Returns (symbols, stats)."""
    data = _gh_api(f"repos/{repo}/commits/{sha}")
    stats = {"files_total": 0, "files_source": 0, "files_skipped_test": 0}
    if not isinstance(data, dict):
        return [], {**stats, "error": "commit fetch failed"}
    files = data.get("files") or []
    stats["files_total"] = len(files)
    stats["commit_subject"] = ((data.get("commit") or {}).get("message") or "").splitlines()[:1]
    out: list[dict] = []
    for f in files:
        fn = f.get("filename") or ""
        lang = _SRC_EXT.get("." + fn.rsplit(".", 1)[-1] if "." in fn else "")
        if not lang:
            continue
        if _TEST_PATH.search(fn) or fn.endswith(("Tests.java", "Test.java")):
            stats["files_skipped_test"] += 1
            continue
        stats["files_source"] += 1
        patch = f.get("patch") or ""
        cls = fn.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        pkg = _package_from_path(fn, lang)
        names: list[tuple[str, str]] = []
        decl = {"java": _JAVA_DECL, "c": _C_DECL, "python": _PY_DECL, "js": _JS_DECL}[lang]
        # (a) enclosing declaration in the hunk header context
        for m in re.finditer(r"^@@[^@]*@@\s*(.+)$", patch, re.M):
            mm = decl.search(m.group(1))
            if mm:
                nm = next((g for g in mm.groups() if g), None)
                if nm and nm not in _NOT_A_METHOD:
                    names.append((nm, "hunk_context"))
        # (b) changed lines that ARE declarations
        for line in patch.splitlines():
            if line[:1] not in "+-" or line[1:2] in "+-":
                continue
            mm = decl.search(line[1:])
            if mm:
                nm = next((g for g in mm.groups() if g), None)
                if nm and nm not in _NOT_A_METHOD:
                    names.append((nm, "changed_declaration"))
        seen = set()
        for nm, rule in names:
            if lang == "java":
                qual = f"{pkg}.{cls}#{nm}" if pkg else f"{cls}#{nm}"
            elif lang == "python":
                qual = f"{pkg}.{nm}" if pkg else nm
            else:
                qual = nm
            if qual in seen:
                continue
            seen.add(qual)
            out.append(
                {
                    "symbol": qual,
                    "language": lang,
                    "file": fn,
                    "extraction_rule": rule,
                    "confidence": "high" if rule == "changed_declaration" else "medium",
                    "package_qualified": bool(pkg) or lang == "c",
                }
            )
    return out, stats


def load_curated(path: Path, advisory: str) -> list[str] | None:
    if not path or not path.is_file():
        return None
    try:
        import yaml
    except ImportError:
        return None
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    entry = (doc.get("advisories") or {}).get(advisory)
    if isinstance(entry, dict):
        return entry.get("symbols") or None
    if isinstance(entry, list):
        return entry or None
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("advisory")
    ap.add_argument("--ecosystem", default=None)
    ap.add_argument("--module", default=None)
    ap.add_argument(
        "--curated", type=Path, default=HARNESS_ROOT / "config" / "advisory-symbols.yaml"
    )
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--print-symbols",
        action="store_true",
        help="print resolved symbols one per line (for argv construction by a caller)",
    )
    args = ap.parse_args(argv)

    doc: dict = {
        "artifact": "advisory-symbols",
        "advisory": args.advisory,
        "ecosystem": args.ecosystem,
        "module": args.module,
        "tool": "resolve_advisory_symbols.py",
        "soundness": {
            "empty_result": "means UNRESOLVED, never 'no vulnerable "
            "symbol exists' — a data-shaped fix "
            "(deny-list, validation table, "
            "dependency bump) yields no changed "
            "method",
            "wrong_symbol": "fabricates `affected` with a cited "
            "witness; gate promotion on "
            "`confidence` and `source`",
        },
    }

    curated = load_curated(args.curated, args.advisory)
    if curated:
        doc.update(
            status="curated",
            source="curated",
            symbols=[{"symbol": s, "source": "curated", "confidence": "high"} for s in curated],
        )
    else:
        records = osv_records(args.advisory)
        if not records:
            doc.update(status="error: advisory not found in OSV", symbols=[])
        else:
            doc["osv_ids"] = [r.get("id") for r in records]
            commits, pulls = fix_commits(records)
            doc["fix_commits"] = commits
            doc["pull_refs"] = pulls
            if not commits:
                doc.update(
                    status="no_fix_commit",
                    symbols=[],
                    note="no /commit/<sha> reference on the advisory or its "
                    "CVE aliases"
                    + (
                        f"; {len(pulls)} PR ref(s) present — resolve PR commits to extend coverage"
                        if pulls
                        else ""
                    ),
                )
            else:
                raw, stats = [], []
                for c in commits[:4]:
                    s, st = symbols_from_commit(c["repo"], c["sha"])
                    for x in s:
                        x["from_commit"] = c["url"]
                    raw += s
                    stats.append({**st, "commit": c["url"]})
                doc["extraction"] = stats
                # global dedupe: the same symbol often appears in several
                # backport commits (and via both extraction rules) — keep
                # one entry, at its strongest observed confidence
                best: dict[str, dict] = {}
                for x in raw:
                    cur = best.get(x["symbol"])
                    if cur is None or (cur["confidence"] == "medium" and x["confidence"] == "high"):
                        best[x["symbol"]] = x
                syms = sorted(best.values(), key=lambda x: x["symbol"])
                if syms:
                    doc.update(status="resolved", source="fix_commit", symbols=syms)
                else:
                    doc.update(
                        status="no_symbols_in_diff",
                        symbols=[],
                        note="fix commit found but no changed method "
                        "declaration — likely a data/config fix "
                        "(deny-list, validation table, dependency "
                        "bump). Route to the judged or curated tier.",
                    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    if args.print_symbols:
        for s in doc.get("symbols") or []:
            print(s["symbol"])
    else:
        print(
            f"advisory-symbols: {doc['status']} "
            f"({len(doc.get('symbols') or [])} symbol(s))" + (f" → {args.out}" if args.out else "")
        )
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["impact", "resolve-advisory-symbols", *sys.argv[1:]]))
