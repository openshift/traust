#!/usr/bin/env python3
"""Re-path findings whose location is a repo-root marker (item 4b).

A location of `.` canonicalises to nothing, so the ledger fingerprint collapses to
`(repo, "", cwe)` and unrelated findings in one repo become one identity. Measured
2026-08-21: **2,795 findings**, 1,791 distinct degenerate fingerprints.

Most such findings DO have an artifact — an absent `SECURITY.md` is still
`SECURITY.md`, and a missing file's path is both a stable key and a hint to the
remediator. Keyword rules cover **2,375 (85%)**. The remaining **420 are left alone
and listed**: they imply real artifacts a keyword cannot name (`.gitlab-ci.yml
absent`, a stale `Dockerfile.openshift`, `hack/cp-plugin`), and guessing would put
prose in a field that feeds identity.

**The cascade, which is why this is bigger than items 9 and 10.** Changing a location
changes the fingerprint, so per affected repo:
  report location -> report fingerprint -> layer `audit_report_sha256`
  -> the layer's format-3 signature -> event fingerprints stamped by item 6d
**429 events currently carry a degenerate fingerprint** and are refreshed here. That
overwrite is deliberate and is the one place `attach_identity`'s "never overwrite" rule
must not apply: a degenerate fingerprint is a defect, not a historical observation.

    python3 -m traust.migrations.repath_repo_root_findings <root> \
        [--apply] [--pubkey PATH] [--report-unmatched FILE]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

from traust_engine.ledger import (
    LedgerError,
    canon_path,
    fingerprint,
    stamp_report_reference,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}

# Ordered: first match wins. Deliberately conservative — a rule earns its place by
# naming an artifact that certainly exists (or certainly should), never by guessing.
RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"security\.md|vulnerability[- ]disclosure|security policy", re.I), "SECURITY.md"),
    (re.compile(r"scorecard", re.I), "repo:scorecard-onboarding"),
    (re.compile(r"branch protection|unprotected branch", re.I), "repo:branch-protection"),
    (re.compile(r"dependabot|renovate|dependency[- ]update", re.I), ".github/dependabot.yml"),
    (re.compile(r"unmaintained|archived|abandoned|stale repo", re.I), "repo:maintenance"),
    (re.compile(r"codeowners", re.I), "CODEOWNERS"),
    (re.compile(r"\blicense\b", re.I), "LICENSE"),
    (re.compile(r"contributing", re.I), "CONTRIBUTING.md"),
    (re.compile(r"signed commits|commit signing|\bgpg\b", re.I), "repo:provenance"),
    (re.compile(r"release process|no releases|tagging", re.I), "repo:release-process"),
    (
        re.compile(r"access control|repository permissions|admin access", re.I),
        "repo:access-control",
    ),
    # ── Second wave, 2026-09-02 (A5) ──────────────────────────────────────────
    # The 420 the first wave left alone are overwhelmingly repo-scoped: the finding
    # is about the repository, not a file, and often about a file's ABSENCE ("No CI
    # pipeline", "No NetworkPolicy"). No path can be named honestly, so these use the
    # `repo:<subject>` convention the rules above already established — it says
    # "repo-scoped, subject X" without claiming a file exists, survives canon_path,
    # and satisfies fingerprint(strict=True).
    #
    # **This is deliberately coarse and does not fully separate them.** Measured
    # before adoption: it takes the colliding set from 214 findings to 71, with the
    # residue being same-repo, same-CWE, same-subject — e.g. 9 secrets-handling
    # CWE-798 findings in csi-external-provisioner. Separating those needs a real
    # location per finding, which is per-finding review, not a rule. The alternative
    # considered and rejected was keying identity on the title: titles are reworded
    # on re-audit, and identity must not move when prose does. Severity was rejected
    # for the same reason — /countersign can upgrade an informational finding, so a
    # rule keyed on severity changes under it.
    (re.compile(r"networkpolicy|network policy", re.I), "repo:networkpolicy"),
    (
        re.compile(
            r"\bci\b|ci/cd|pipeline|workflow|github action|tekton|prow|travis|jenkins", re.I
        ),
        "repo:ci-pipeline",
    ),
    (
        re.compile(r"resources?\.?(limits|requests)|cpu/memory|memory limit", re.I),
        "repo:resource-limits",
    ),
    (
        re.compile(
            r"clusterrole|\brbac\b|apigroups|wildcard|serviceaccount|sa token|automount", re.I
        ),
        "repo:rbac-scope",
    ),
    (
        re.compile(r":latest|floating (builder )?(base )?tag|image tag|digest pin", re.I),
        "repo:image-tags",
    ),
    (
        re.compile(r"privileged|runasnonroot|securitycontext|capabilit|read-only root", re.I),
        "repo:container-hardening",
    ),
    (re.compile(r"secret|credential|token leak|kubeconfig", re.I), "repo:secrets-handling"),
    (re.compile(r"dependenc|\bcve\b|vulnerab|outdated|stale", re.I), "repo:dependency-hygiene"),
    (re.compile(r"\btests?\b|coverage|fuzz", re.I), "repo:test-coverage"),
]


def classify(finding: dict) -> str | None:
    text = f"{finding.get('title') or ''} {(finding.get('description') or '')[:200]}"
    for rx, path in RULES:
        if rx.search(text):
            return path
    return None


def is_degenerate(finding: dict) -> bool:
    return not {c for loc in (finding.get("locations") or []) if (c := canon_path(loc.get("path")))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--pubkey", type=Path, default=None)
    ap.add_argument(
        "--report-unmatched",
        type=Path,
        default=None,
        help="write the findings needing human classification to this file",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()

    tally: Counter[str] = Counter()
    by_path: Counter[str] = Counter()
    unmatched: list[dict] = []
    problems: list[str] = []
    started = time.monotonic()

    for report_path in sorted(results_root.rglob("*-security-audit.json")):
        if STATE_DIRS.intersection(report_path.relative_to(results_root).parts):
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable report"] += 1
            continue
        repo = (report.get("metadata") or {}).get("repository")
        changed: dict[str, str] = {}  # finding id -> old fingerprint

        for f in report.get("findings") or []:
            if not is_degenerate(f):
                continue
            tally["degenerate findings seen"] += 1
            path = classify(f)
            if not path:
                tally["needs human classification"] += 1
                unmatched.append(
                    {
                        "report": str(report_path.relative_to(results_root)),
                        "id": f.get("id"),
                        "title": f.get("title"),
                    }
                )
                continue
            by_path[path] += 1
            old_fp = f.get("fingerprint")
            locs = f.get("locations") or [{}]
            locs[0] = {**locs[0], "path": path}
            f["locations"] = locs
            new_fp = fingerprint(f, repo)
            f["fingerprint"] = new_fp
            if old_fp and old_fp != new_fp:
                changed[old_fp] = new_fp
            tally["re-pathed"] += 1

        if not changed and not tally["re-pathed"]:
            continue
        if not changed:
            continue
        tally["reports touched"] += 1
        if not args.apply:
            continue

        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        # Cascade: digest -> signature -> event stamps, for every layer beside it.
        for layer_path in report_path.parent.glob("*-findings-layer.json"):
            try:
                layer = json.loads(layer_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (layer.get("metadata") or {}).get("audit_report") != report_path.name:
                continue
            refreshed = 0
            for e in layer.get("events") or []:
                nf = changed.get(e.get("fingerprint"))
                if nf:
                    e["fingerprint"] = nf  # deliberate overwrite; see docstring
                    refreshed += 1
            tally["event stamps refreshed"] += refreshed
            stamp_report_reference(layer, report_path)  # new digest; drops the signature
            svc = engine.ledger.service(data_dir=layer_path.parent)
            svc.store_layer(layer_path, layer)
            try:
                svc.sign(layer_path)
            except LedgerError as exc:
                tally["sign failed — layer NOT written"] += 1
                problems.append(f"{layer_path.name}: {exc}")
                continue
            if args.pubkey:
                layer = engine.ledger.service(data_dir=layer_path.parent).read_layer_file(
                    layer_path
                )
                if [
                    x
                    for x in verify_merkle_signature(layer, str(args.pubkey))
                    if x.severity.name == "ERROR"
                ]:
                    tally["fresh signature failed to verify — NOT written"] += 1
                    continue
            tally["layers re-signed"] += 1

    if args.report_unmatched and unmatched:
        args.report_unmatched.write_text(json.dumps(unmatched, indent=1) + "\n")
        print(f"  wrote {len(unmatched):,} unmatched to {args.report_unmatched}")

    print(f"{'APPLY' if args.apply else 'DRY RUN'} · {time.monotonic() - started:.0f}s")
    for k, v in tally.most_common():
        print(f"  {k:44} {v:,}")
    print("  paths assigned:")
    for p, c in by_path.most_common():
        print(f"     {c:6,}  {p}")
    for p in problems[:10]:
        print(f"    ! {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
