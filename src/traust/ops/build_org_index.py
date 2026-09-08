#!/usr/bin/env python3
"""
Build the GitHub/GitLab org -> findings cross-reference index.

The findings tree is organized by product/service (matching the
the inputs inventory inventories), so a single source org's repos
scatter across many product folders. This script inverts that layout:
it reads `metadata.repository` from every audit report and emits an
org -> repo -> findings-locations index so reviewers can navigate the
same artifacts by source org.

Reads:  <results-root>/findings/**/*-security-audit.json
        <results-root>/findings/**/*-cloud-config-audit.json
        <results-root>/oss-findings/**  (same patterns, tagged "oss")

Writes: <results-root>/findings/_index/org-index.json
        <results-root>/findings/_index/ORG-INDEX.md

Usage:
  python3 -m traust.cli.build_org_index                       # sibling analysis-results
  python3 -m traust.cli.build_org_index --results-root PATH
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

from traust.context import add_config_home_arg, resolve_results_root

REPORT_SUFFIXES = ("-security-audit.json", "-cloud-config-audit.json")
SKIP_DIRS = {"_manifest", "_index", "_orgs"}

ARTIFACT_TAGS = [
    ("-security-audit.json", "audit"),
    ("-cloud-config-audit.json", "cloud-config-audit"),
    ("-threat-model.md", "threat-model"),
    ("-triage.json", "triage"),
    ("-findings-current.json", "findings-current"),
    ("-remediation-verification.json", "remediation-verification"),
    ("-validation.json", "validation"),
]

SEVERITIES = ["critical", "high", "medium", "low", "informational"]


_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")  # incl. leading dot (".github")
_HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def parse_org_repo(url: str):
    """Return (org, repo) from a GitHub/GitLab repository URL, or None.

    Strict: host and every path segment must look like real identifiers —
    free-text or angle-bracket-wrapped `metadata.repository` values are
    rejected (they would otherwise mint junk orgs in the index and farm).
    """
    if not url:
        return None
    url = url.strip().strip("<>")  # markdown autolink wrapping
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2 or not _HOST_RE.match(host):
        return None
    parts[-1] = parts[-1].removesuffix(".git")
    if not all(_NAME_RE.match(p) and any(c.isalnum() for c in p) for p in parts):
        return None
    repo = parts[-1]
    # GitLab namespaces nest; keep host + full namespace as the "org".
    org = f"{host}/{'/'.join(parts[:-1])}" if host != "github.com" else parts[0]
    return org, repo


def severity_counts(report: dict) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for row in report.get("findings_summary") or []:
        sev = row.get("severity")
        if sev in counts:
            counts[sev] = row.get("count", 0)
    return counts


def artifact_inventory(directory: Path) -> list[str]:
    tags = []
    names = {p.name for p in directory.iterdir() if not p.name.startswith(".")}
    for suffix, tag in ARTIFACT_TAGS:
        if any(n.endswith(suffix) for n in names):
            tags.append(tag)
    return tags


def is_symlinked(path: Path, root: Path) -> bool:
    """True if the report path traverses a symlink below root."""
    current = path
    while current != root:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def collect(results_root: Path):
    # GitHub org/repo names are case-insensitive; group case-insensitively and
    # display the casing seen most often across reports.
    index = defaultdict(lambda: defaultdict(list))
    spellings = defaultdict(lambda: defaultdict(int))
    warnings = []
    roots = [
        ("findings", results_root / "findings"),
        ("oss", results_root / "oss-findings"),
        ("cloud-config", results_root / "cloud-config"),
    ]
    for cut, root in roots:
        if not root.is_dir():
            continue
        for report_path in sorted(root.rglob("*.json")):
            if not report_path.name.endswith(REPORT_SUFFIXES):
                continue
            if SKIP_DIRS & set(p.name for p in report_path.parents):
                continue
            try:
                report = json.loads(report_path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                warnings.append(
                    f"unparseable report: {report_path.relative_to(results_root)} ({exc})"
                )
                continue
            meta = report.get("metadata") or {}
            org_repo = parse_org_repo(meta.get("repository", ""))
            if org_repo is None:
                resolution = str((meta.get("additional") or {}).get("repo_resolution") or "")
                if not resolution.startswith("org-url-stub"):
                    warnings.append(
                        f"no metadata.repository: {report_path.relative_to(results_root)}"
                    )
                continue
            org, repo = org_repo
            spellings["org"][org] += 1
            spellings["repo"][repo] += 1
            org, repo = org.lower(), repo.lower()
            rel_dir = report_path.parent.relative_to(results_root)
            entry = {
                "path": str(rel_dir),
                "product": rel_dir.parts[1] if len(rel_dir.parts) > 1 else rel_dir.parts[0],
                "cut": cut,
                "report": report_path.name,
                "kind": "cloud-config-audit"
                if report_path.name.endswith("-cloud-config-audit.json")
                else "security-audit",
                "commit": (meta.get("commit") or "")[:7] or None,
                "ref": meta.get("ref"),
                "date": meta.get("date"),
                "severity_counts": severity_counts(report),
                "artifacts": artifact_inventory(report_path.parent),
                "symlink": is_symlinked(report_path, results_root),
            }
            index[org][repo].append(entry)

    def display(kind: str, lowered: str) -> str:
        candidates = [(n, c) for n, c in spellings[kind].items() if n.lower() == lowered]
        return max(candidates, key=lambda nc: nc[1])[0] if candidates else lowered

    index = {
        display("org", org): {display("repo", repo): entries for repo, entries in repos.items()}
        for org, repos in index.items()
    }
    return index, warnings


def render_markdown(index: dict, warnings: list[str], results_root: Path) -> str:
    total_repos = sum(len(repos) for repos in index.values())
    lines = [
        "# Findings Index by Source Org",
        "",
        f"Generated {date.today().isoformat()} by `traust.ops.build_org_index`"
        "— do not edit by hand.",
        "",
        "The findings tree is organized **by product**; this index maps the same",
        "reports **by source org/repo** so coverage can be navigated both ways.",
        f"Machine-readable form: [`org-index.json`](org-index.json). "
        f"{len(index)} orgs, {total_repos} repos indexed under `{results_root.name}/`.",
        "",
        "Severity columns show C/H/M/L/I counts from the report's `findings_summary`.",
        "",
        "## Orgs",
        "",
    ]
    for org in sorted(index, key=lambda o: (-len(index[o]), o)):
        anchor = org.lower().replace("/", "").replace(".", "")
        lines.append(f"- [`{org}`](#{anchor}) — {len(index[org])} repos")
    for org in sorted(index, key=lambda o: (-len(index[o]), o)):
        lines += ["", f"## {org}", ""]
        lines.append("| Repo | Filed under | Severities (C/H/M/L/I) | Artifacts | Ref | Date |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for repo in sorted(index[org]):
            for e in index[org][repo]:
                sev = e["severity_counts"]
                sev_str = "/".join(str(sev[s]) for s in SEVERITIES)
                link = f"[`{e['path']}`](../../{e['path']}/)"
                note = " (symlink)" if e["symlink"] else ""
                kind = "" if e["kind"] == "security-audit" else " *(cloud-config)*"
                lines.append(
                    f"| {repo}{kind} | {link}{note} | {sev_str} | "
                    f"{', '.join(e['artifacts'])} | {e['ref'] or e['commit'] or ''}"
                    f" | {e['date'] or ''} |"
                )
    if warnings:
        lines += ["", "## Indexing warnings", ""]
        lines += [f"- {w}" for w in warnings]
    lines.append("")
    return "\n".join(lines)


ORGS_README = """# findings/_orgs — browse findings by source org

Generated by `traust.ops.build_org_index` — do not edit by hand; every
entry is a relative symlink to the canonical filing location (product
folder or cloud-config tree). One directory per source org; a repo with
multiple filings gets `<repo>` (canonical) plus `<repo>__<product>`
aliases. Symlink aliases are excluded by the corpus resolver, so nothing
here is double-counted. Tabular equivalent: [`../_index/ORG-INDEX.md`](../_index/ORG-INDEX.md).
"""


def emit_org_symlinks(index: dict, results_root: Path) -> tuple[int, int]:
    """Materialize findings/_orgs/<org>/<alias> -> canonical filing dirs.

    Regenerates the whole farm: stale symlinks are pruned, real files are
    never touched. Only non-symlink (canonical) filings are linked.
    Returns (links written, stale links removed).
    """
    orgs_root = results_root / "findings" / "_orgs"
    orgs_root.mkdir(parents=True, exist_ok=True)
    wanted = {}  # (org_slug, alias) -> target rel path
    for org, repos in index.items():
        org_slug = org.replace("/", "__")
        for repo, entries in repos.items():
            canonical = [e for e in entries if not e["symlink"]]
            # bare name goes to the richest artifact set; ties to the
            # oldest filing (the original audit), then path for stability
            canonical.sort(key=lambda e: (-len(e["artifacts"]), e["date"] or "9999", e["path"]))
            for i, e in enumerate(canonical):
                alias = repo if i == 0 else f"{repo}__{e['product']}"
                if (org_slug, alias) in wanted:
                    alias = f"{repo}__{e['product']}__{e['cut']}"
                wanted[(org_slug, alias)] = e["path"]
    written = 0
    for (org_slug, alias), rel_path in sorted(wanted.items()):
        org_dir = orgs_root / org_slug
        org_dir.mkdir(exist_ok=True)
        link = org_dir / alias
        target = Path(os.path.relpath(results_root / rel_path, org_dir))
        if link.is_symlink() and link.readlink() == target:
            continue
        if link.is_symlink():
            link.unlink()
        elif link.exists():
            continue  # never clobber a real file
        link.symlink_to(target)
        written += 1
    pruned = 0
    for link in orgs_root.rglob("*"):
        if link.is_symlink():
            key = (link.parent.name, link.name)
            if key not in wanted:
                link.unlink()
                pruned += 1
    for d in orgs_root.iterdir():
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()
    (orgs_root / "README.md").write_text(ORGS_README)
    return written, pruned


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results root (default: configured analysis-results)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output directory (default: <results-root>/findings/_index)",
    )
    args = ap.parse_args()

    results_root = resolve_results_root(args)
    if not (results_root / "findings").is_dir():
        print(f"error: {results_root}/findings not found", file=sys.stderr)
        return 1
    out_dir = args.out_dir or results_root / "findings" / "_index"
    out_dir.mkdir(parents=True, exist_ok=True)

    index, warnings = collect(results_root)
    payload = {
        "generated": date.today().isoformat(),
        "generator": "traust.ops.build_org_index",
        "results_root": str(results_root),
        "org_count": len(index),
        "repo_count": sum(len(r) for r in index.values()),
        "orgs": {org: dict(repos) for org, repos in sorted(index.items())},
        "warnings": warnings,
    }
    (out_dir / "org-index.json").write_text(json.dumps(payload, indent=2) + "\n")
    (out_dir / "ORG-INDEX.md").write_text(render_markdown(index, warnings, results_root))
    written, pruned = emit_org_symlinks(index, results_root)
    print(
        f"indexed {payload['repo_count']} repos across {payload['org_count']} orgs "
        f"({len(warnings)} warnings) -> {out_dir}; "
        f"_orgs symlink farm: +{written} / -{pruned}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
