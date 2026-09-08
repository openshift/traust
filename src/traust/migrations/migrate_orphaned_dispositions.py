#!/usr/bin/env python3
"""Re-run the sanctioned rebaseline on layers a re-audit left inconsistent.

This is an ORCHESTRATOR, not a migration engine. `finding_identity.py
rebaseline` already owns the whole job — tiered matching (fingerprint auto,
weaker tiers queued), the `metadata.finding_aliases` table that
build_cumulative resolves at replay, and claim-pin migration. This script
only finds the affected layers and feeds that tool the right inputs.

WHY IT EXISTS (measured 2026-08-13/14). Campaign ids embed the audited sha,
so a re-audit re-issues every id. A bulk batch (`week-1 full-audit batch: 110
churn-triggered re-audits`) left layers pointing at superseded ids. Corrected
fleet sweep over 8,107 layer/audit pairs — resolving through finding_aliases
exactly as build_cumulative does:

  * 102 repos / 1,268 STALE CLAIM PINS -> build_cumulative refuses
    ("baselined finding missing from the audit report"). 900 of those pins
    belong to old ids that ALREADY have a confirmed alias, so no
    disposition is at risk and no human adjudication is needed — only the
    pins were never migrated.
  * 27 repos / 387 events genuinely detached (no alias at all). Residue
    that needs the old generation recovered from git.

An earlier measurement of 111 repos / 2,332 events was WRONG: it compared
raw finding_refs without resolving aliases, so correctly-rebaselined layers
counted as broken.

THE FILENAME IS LOAD-BEARING. `finding_identity.py` namespaces alias keys by
the old report's FILE NAME (`old-thanos-security-audit.json` ->
`old-thanos:FIND-001`) and migrates a stale pin only when the id is
`covered` — either mapped in this run, or carrying an existing alias whose
`from_report` equals the filename passed in. So the old generation must be
written under the EXACT name recorded in `from_report`:

  * right name  -> same namespace, pins migrate, run is idempotent;
  * wrong name  -> a SECOND namespace, bare `FIND-001` becomes ambiguous
    across two entries, and resolution that used to work PARKS instead.
    (Observed live: naming the extract `old-audit.json` broke thanos, whose
    aliases were keyed `old-thanos:`. Reverted.)

DRY RUN IS THE DEFAULT.

Usage:
    python3 -m traust.migrations.migrate_orphaned_dispositions [--root DIR]
        [--repo SUBSTR ...] [--pins-only] [--apply] [--out report.json]
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    resolve_results_root,
    workspace_dir,
)

REBASELINE_MOD = "traust_engine._util.finding_identity"


def _git(analysis_repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(analysis_repo), *args],
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def _resolver(meta: dict):
    """build_cumulative's alias resolution, mirrored (see its _alias_for /
    resolve): bare key first, then an UNAMBIGUOUS namespaced key, and only
    `confirmed` aliases resolve."""
    raw = meta.get("finding_aliases") or {}
    ns: dict[str, list] = {}
    for k, v in raw.items():
        if ":" in k:
            ns.setdefault(k.split(":", 1)[1], []).append(v)

    def alias_for(ref):
        a = raw.get(ref)
        if a is not None:
            return a
        c = ns.get(ref) or []
        return c[0] if len(c) == 1 else None

    def resolve(ref, seen=None):
        seen = seen or set()
        a = alias_for(ref)
        if not a or not a.get("confirmed") or ref in seen:
            return ref
        seen.add(ref)
        return resolve(a["new_id"], seen)

    return raw, alias_for, resolve


def inspect(lay_p: Path, findings_root: Path) -> dict | None:
    aud_p = Path(str(lay_p).replace("-findings-layer.json", "-security-audit.json"))
    if not aud_p.is_file():
        return None
    try:
        lay = json.loads(lay_p.read_text(encoding="utf-8"))
        aud = json.loads(aud_p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    ids = {f.get("id") for f in (aud.get("findings") or [])}
    meta = lay.get("metadata") or {}
    raw, alias_for, resolve = _resolver(meta)

    stale = sorted(c for c in (meta.get("claim_hashes") or {}) if c not in ids)
    stale_aliased = [c for c in stale if alias_for(c)]
    pending = {
        i.get("suggested_finding_ref")
        for i in (lay.get("needs_review") or [])
        if i.get("status") == "pending"
    }
    detached = collections.Counter()
    for e in lay.get("events") or []:
        r = e.get("finding_ref")
        if r and resolve(r) not in ids and r not in pending and alias_for(r) is None:
            detached[r] += 1
    if not stale and not detached:
        return None

    # the filename the existing aliases were built from; without it a
    # re-run would create a second namespace
    from_reports = collections.Counter(
        v.get("from_report") for v in raw.values() if v.get("from_report")
    )
    return {
        "layer": str(lay_p),
        "audit": str(aud_p),
        "repo": (
            str(lay_p.parent.relative_to(findings_root))
            if findings_root in lay_p.parents
            else str(lay_p.parent)
        ),
        "stale_pins": stale,
        "stale_pins_aliased": stale_aliased,
        "detached_ids": sorted(detached),
        "detached_events": sum(detached.values()),
        "from_report": (from_reports.most_common(1)[0][0] if from_reports else None),
        "from_report_ambiguous": len(from_reports) > 1,
    }


def old_generation(
    aud_p: Path, wanted: set[str], analysis_repo: Path
) -> tuple[str | None, str | None]:
    """(json text, commit) of the newest historical generation containing
    `wanted` ids, or (None, None)."""
    try:
        rel = str(aud_p.relative_to(analysis_repo))
    except ValueError:
        return None, None
    log = _git(analysis_repo, ["log", "--format=%H", "--", rel])
    for sha in log.stdout.split() if log.returncode == 0 else []:
        show = _git(analysis_repo, ["show", f"{sha}:{rel}"])
        if show.returncode != 0:
            continue
        try:
            doc = json.loads(show.stdout)
        except json.JSONDecodeError:
            continue
        have = {f.get("id") for f in (doc.get("findings") or [])}
        if wanted & have:
            return show.stdout, sha
    return None, None


def run_rebaseline(plan: dict, apply: bool, analysis_repo: Path, workspace: Path) -> dict:
    """Invoke the sanctioned tool with the old generation written under the
    filename its aliases were recorded from."""
    wanted = set(plan["stale_pins"]) | set(plan["detached_ids"])
    text, sha = old_generation(Path(plan["audit"]), wanted, analysis_repo)
    if text is None:
        return {"status": "skipped: no historical generation contains these ids"}
    name = plan["from_report"]
    if not name:
        # no prior aliases: choose a STABLE name derived from the commit, so
        # a re-run reuses the same namespace instead of multiplying them
        name = f"old-{(sha or 'unknown')[:12]}-security-audit.json"
    with tempfile.TemporaryDirectory(prefix="rebaseline-") as td:
        old_p = Path(td) / name
        old_p.write_text(text, encoding="utf-8")
        # NOT --no-review-queue. Only `fingerprint` matches auto-confirm;
        # weaker tiers (path_cwe/path_set/title) record UNCONFIRMED, so they
        # do not resolve until a human runs countersign `confirm_mapping`.
        # Suppressing the queue would leave those dispositions permanently
        # unresolved with nothing to review — the silent loss this whole
        # exercise exists to prevent. Measured on the pins-only subset: 284
        # fingerprint (auto) vs 88 weaker matches that need a signature.
        cmd = [
            sys.executable,
            "-m",
            REBASELINE_MOD,
            "rebaseline",
            str(old_p),
            plan["audit"],
            plan["layer"],
        ]
        if not apply:
            cmd.append("--dry-run")
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            stdin=subprocess.DEVNULL,
            cwd=str(workspace),
            check=False,
        )
    return {
        "status": "ran" if p.returncode == 0 else "error",
        "old_generation_commit": sha,
        "old_report_name": name,
        "output": (p.stdout or p.stderr).strip().splitlines()[-1:] or [],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--root", type=Path, default=None, help="findings tree (default: <results-root>/findings)"
    )
    ap.add_argument("--repo", action="append", default=[])
    ap.add_argument(
        "--pins-only",
        action="store_true",
        help="only layers whose every orphan already has a "
        "confirmed alias — no disposition at risk",
    )
    ap.add_argument("--apply", action="store_true")
    ap.add_argument(
        "--allow-ambiguous",
        action="store_true",
        help="run layers that already carry multiple alias\n "
        "namespaces (can BREAK working resolution)",
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    analysis_repo = resolve_results_root(args)
    workspace = workspace_dir(engine)
    findings_root = args.root or (analysis_repo / "findings")

    plans = []
    skipped_ambiguous: list[str] = []
    for p in sorted(findings_root.rglob("*-findings-layer.json")):
        if p.is_symlink():
            continue
        if args.repo and not any(s in str(p) for s in args.repo):
            continue
        pl = inspect(p, findings_root)
        if not pl:
            continue
        if args.pins_only and (
            pl["detached_ids"] or len(pl["stale_pins_aliased"]) != len(pl["stale_pins"])
        ):
            continue
        # AMBIGUITY GUARD. A layer that already carries MORE THAN ONE alias
        # namespace is skipped unless --allow-ambiguous. Alias keys are
        # namespaced by the old report's FILE NAME, so adding another
        # namespace makes a bare `FIND-001` match several entries, and
        # build_cumulative parks rather than guessing — breaking resolution
        # that currently WORKS. Observed live on rhobs/thanos, which had a
        # working `old-thanos:` namespace until a run under a different
        # filename made it ambiguous (reverted). Never trade working
        # resolution for coverage.
        if pl["from_report_ambiguous"] and not args.allow_ambiguous:
            skipped_ambiguous.append(pl["repo"])
            continue
        plans.append(pl)
        if args.limit and len(plans) >= args.limit:
            break

    tot = collections.Counter()
    for pl in plans:
        tot["repos"] += 1
        tot["stale_pins"] += len(pl["stale_pins"])
        tot["stale_pins_aliased"] += len(pl["stale_pins_aliased"])
        tot["detached_ids"] += len(pl["detached_ids"])
        tot["detached_events"] += pl["detached_events"]
        if pl["from_report_ambiguous"]:
            tot["ambiguous_namespace"] += 1
        if not pl["from_report"]:
            tot["no_prior_aliases"] += 1

    for pl in plans:
        pl["result"] = run_rebaseline(pl, args.apply, analysis_repo, workspace)
        tot[pl["result"]["status"].split(":")[0]] += 1

    print(f"{'APPLIED' if args.apply else 'DRY RUN'}: {tot['repos']} layer(s)")
    print(
        f"  stale claim pins        : {tot['stale_pins']} "
        f"({tot['stale_pins_aliased']} already aliased)"
    )
    print(
        f"  genuinely detached      : {tot['detached_ids']} ids / {tot['detached_events']} events"
    )
    print(f"  rebaseline ran / error / skipped : {tot['ran']} / {tot['error']} / {tot['skipped']}")
    if skipped_ambiguous:
        print(
            f"  SKIPPED {len(skipped_ambiguous)} layer(s) with multiple alias "
            f"namespaces (--allow-ambiguous to override):"
        )
        for r in skipped_ambiguous:
            print(f"      {r}")
    if tot["ambiguous_namespace"]:
        print(
            f"  WARNING {tot['ambiguous_namespace']} layer(s) already carry "
            f"MULTIPLE alias namespaces — resolution may be ambiguous there"
        )
    if tot["no_prior_aliases"]:
        print(
            f"  {tot['no_prior_aliases']} layer(s) had no prior aliases; a "
            f"commit-derived stable name was used"
        )
    if args.out:
        args.out.write_text(
            json.dumps(
                {
                    "artifact": "rebaseline-orchestration",
                    "mode": "applied" if args.apply else "dry-run",
                    "totals": dict(tot),
                    "layers": plans,
                },
                indent=1,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"  report → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
