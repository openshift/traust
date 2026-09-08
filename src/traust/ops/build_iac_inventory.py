#!/usr/bin/env python3
"""Portfolio-wide IaC discovery census — Phase 0 of the iac-lane
(progress-tracker/plans/router-lane-coverage-plan.md §3).

Walks the same deduped HEAD code-audit population the continuous-
scanning router uses (findings.db via build_rescan_worklist.
load_population), fetches each GitHub repo's file listing with ONE
recursive-tree API call, and classifies paths against the IaC pattern
classes the /cloud-config-audit lane will own (Terraform /
CloudFormation / ARM+Bicep). Helm charts and Dockerfiles are counted
separately as informational "SCA-covered" signals — secure-code-audit's
KHS arm already audits those, so they never trigger the lane.

Outputs (analysis-results/findings/_manifest/):
  iac-inventory.json          census block + per-repo classification
  iac-baseline-worklist.json  IaC-bearing repos ordered for the Phase-0
                              baseline sweep (exposure band, then
                              managed-services tenancy relevance, then
                              risk tier, then live crit/high)
  iac-baseline-worklist.md    human view of the same

ROUTES ATTENTION, NEVER SCANS: this is a file-listing census — no
clone, no checkout, no Checkov run, no verdict. Dispatching the
baseline sweep it proposes is a separate, budgeted decision.

Conventions inherited from the router (build_rescan_worklist.py):
population + URL dedup, exposure designations (externality axis is the
curated repository-exposure designation, NEVER the corpus ownership
tag), quota preflight with a hard floor, resume cache so re-runs are
incremental. GitLab-hosted repos are counted but not tree-walked in v1
(paginated tree API + VPN gating) — they surface as `gitlab-unchecked`
so the gap is visible, not silent.

Usage:
    python3 -m traust.cli.build_iac_inventory
        [--db <findings.db>] [--results-root <analysis-results>]
        [--inputs-root <inputs>]
        [--jobs 8] [--max-repos N] [--refresh] [--quota-floor 300]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

from traust.cli import build_rescan_worklist as brw
from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    inputs_dir,
    load_engine,
)
from traust.inventory import load_descriptor

# --- IaC pattern classes (lane triggers) -----------------------------------
# The lane owns what secure-code-audit does NOT cover. Path-only
# heuristics; `cloudformation` accepts *.template / cfn|cloudformation
# dirs and is flagged heuristic (template.yaml without content checks
# can false-positive on SAM/other templates — acceptable for a census).
IAC_CLASSES = {
    "terraform": re.compile(r"\.tf$|\.tfvars$|\.tf\.json$"),
    "cloudformation": re.compile(r"(^|/)(cloudformation|cfn)/[^ ]*\.(ya?ml|json)$"),
    # dir-based ONLY. Two census runs showed suffix rules are wrong in
    # this portfolio: bare *.template = nginx/values/md templates;
    # *.template.(yaml|json) = OpenShift Templates (k8s-native, the
    # SCA/KHS arm's territory). Content-only CFN (plain .yaml with
    # AWSTemplateFormatVersion) is an accepted false negative.
    "arm_bicep": re.compile(
        r"\.bicep$|(^|/)azuredeploy[^/]*\.json$"
        r"|(^|/)arm(-templates)?/[^ ]*\.json$"
    ),
}
# Informational only — covered by secure-code-audit's KHS/opengrep arms.
SCA_COVERED = {
    "helm_chart": re.compile(r"(^|/)Chart\.yaml$"),
    "dockerfile": re.compile(r"(^|/)(Dockerfile|Containerfile)([._-][^/]*)?$"),
}

EXPOSURE_RANK = {e: i for i, e in enumerate(brw.EXPOSURE_ORDER)}
# Router charset + optional leading dot: dot-named repos (.github org
# meta-repos) are real audit targets per the corpus doctrine.
_NAME_RE = re.compile(r"^\.?[A-Za-z0-9][A-Za-z0-9._-]*$")


def classify_paths(paths: list[str]) -> dict:
    """Count matches per class over one repo's blob paths."""
    out = {k: 0 for k in IAC_CLASSES}
    out.update({k: 0 for k in SCA_COVERED})
    samples: dict[str, str] = {}
    for p in paths:
        for name, rx in IAC_CLASSES.items():
            if rx.search(p):
                out[name] += 1
                samples.setdefault(name, p)
        for name, rx in SCA_COVERED.items():
            if rx.search(p):
                out[name] += 1
    out["iac_hit"] = any(out[k] for k in IAC_CLASSES)
    out["samples"] = samples
    return out


def fetch_github_paths(project: str) -> dict:
    """One recursive-tree call -> {ok, paths, truncated} (mirrors the
    router's gh_tree_fp_count; HEAD resolves the default branch)."""
    org, _, name = project.partition("/")
    if not (_NAME_RE.fullmatch(org) and _NAME_RE.fullmatch(name)):
        return {"ok": False, "error": f"unsafe org/name: {project}"}
    try:
        proc = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{org}/{name}/git/trees/HEAD?recursive=1",
                "--jq",
                '{truncated, paths: [.tree[] | select(.type=="blob") | .path]}',
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "error": str(e)[:120]}
    if proc.returncode != 0:
        err = proc.stderr.strip()[:120] or "api-error"
        kind = "unreachable" if "404" in err or "Not Found" in err else "error"
        return {"ok": False, "error": err, "kind": kind}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "unparseable"}
    return {
        "ok": True,
        "paths": payload.get("paths") or [],
        "truncated": bool(payload.get("truncated")),
    }


def risk_tier(live_crit_high: int) -> str:
    """Census-simplified tier: P0/P1/P2 from live crit/high only (the
    router's P3 dormancy needs stage-1 pushed_at, absent here)."""
    if live_crit_high >= brw.P0_MIN_LIVE:
        return "P0"
    return "P1" if live_crit_high >= 1 else "P2"


def load_services_urls(inputs_root: Path) -> set[str]:
    """Services inventory segment (tenancy-relevance default, plan
    open-decision 3 option B): normalized repo URLs from the URL-ish columns
    of every CSV under the first segment declared with kind `services` in
    <inputs>/inventory.yaml (traust.inventory). No such segment → empty."""
    urls: set[str] = set()
    seg = load_descriptor(inputs_root).first_of_kind("services")
    if seg is None:
        return urls
    svc = inputs_root / seg
    if not svc.is_dir():
        return urls
    url_rx = re.compile(r"https?://[^\s,\"']+")
    for csv_p in sorted(svc.rglob("*.csv")):
        try:
            text = csv_p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in url_rx.finditer(text):
            u = brw.normalize_repo_url(m.group(0))
            if u:
                urls.add(u)
    return urls


def priority_key(row: dict) -> tuple:
    return (
        EXPOSURE_RANK.get(row["exposure"], 9),
        0 if row["services_segment"] else 1,
        {"P0": 0, "P1": 1, "P2": 2}.get(row["tier"], 3),
        -row["live_crit_high"],
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument("--inputs-root", type=Path, default=None)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--max-repos", type=int, default=None)
    ap.add_argument("--refresh", action="store_true", help="ignore the resume cache and refetch")
    ap.add_argument(
        "--quota-floor",
        type=int,
        default=300,
        help="stop fetching when GitHub core quota drops to this floor (resume later)",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = args.results_root or analysis_results_dir(engine)
    inputs_root = args.inputs_root or inputs_dir(engine)

    db = args.db or results_root / "graph" / "findings.db"
    if not db.is_file():
        print(f"findings.db not found: {db}", file=sys.stderr)
        return 2
    manifest = results_root / "findings" / "_manifest"
    manifest.mkdir(parents=True, exist_ok=True)
    cache_p = manifest / "iac-census-cache-v3.jsonl"  # v3 stores
    # matched paths per class — future pattern NARROWING recomputes
    # from cache; only widening needs --refresh

    population = brw.load_population(db)
    designations = brw.load_designations(manifest / "exposure-designations.json")
    services = load_services_urls(inputs_root)

    cache: dict[str, dict] = {}
    if cache_p.is_file() and not args.refresh:
        for line in cache_p.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                cache[row["repo_url"]] = row
            except (json.JSONDecodeError, KeyError):
                continue

    todo, rows, gitlab_unchecked, no_url = [], [], 0, 0
    for rec in population:
        url = rec.get("repo_url")
        if not url:
            no_url += 1
            continue
        kind, _host, project = brw.split_repo_url(url)
        if kind == "gitlab":
            gitlab_unchecked += 1
            continue
        if kind != "github" or not project:
            continue
        if url in cache:
            rows.append({**cache[url], **_meta(rec, url, designations, services)})
            continue
        todo.append((rec, url, project))
    if args.max_repos:
        todo = todo[: args.max_repos]

    remaining = brw.gh_rate_remaining()
    print(
        f"population {len(population)} | cached {len(rows)} | "
        f"to fetch {len(todo)} | gitlab-unchecked {gitlab_unchecked} "
        f"| gh quota {remaining}",
        flush=True,
    )
    if remaining is not None and remaining < args.quota_floor:
        print("quota below floor — writing census from cache only", file=sys.stderr)
        todo = []

    stop = {"flag": False, "rl_streak": 0}
    fetched = 0

    def one(item):
        _rec, url, project = item
        if stop["flag"]:
            return {"repo_url": url, "status": "quota-deferred"}
        res = fetch_github_paths(project)
        if not res.get("ok"):
            err = res.get("error", "")
            # The rate_limit endpoint can keep reporting a full pool
            # while tree calls are rejected (observed 2026-07-28) —
            # the errors themselves are the reliable throttle signal.
            if "rate limit" in err.lower():
                stop["rl_streak"] += 1
                if stop["rl_streak"] >= 20:
                    stop["flag"] = True
                return {"repo_url": url, "status": "quota-deferred", "error": err[:80]}
            stop["rl_streak"] = 0
            return {"repo_url": url, "status": res.get("kind", "error"), "error": err}
        stop["rl_streak"] = 0
        fp_paths = [p for p in res["paths"] if brw.is_first_party(p)]
        cls = classify_paths(fp_paths)
        samples = cls.pop("samples")
        matched = {k: [p for p in fp_paths if IAC_CLASSES[k].search(p)][:50] for k in IAC_CLASSES}
        return {
            "repo_url": url,
            "status": "ok",
            "truncated": res["truncated"],
            "files": len(res["paths"]),
            **cls,
            "iac_samples": samples,
            "matched_paths": matched,
        }

    with (
        cache_p.open("a", encoding="utf-8") as cache_f,
        concurrent.futures.ThreadPoolExecutor(args.jobs) as pool,
    ):
        for i, out in enumerate(pool.map(one, todo), 1):
            rec, url, _project = todo[i - 1]
            if out["status"] == "ok":
                cache_f.write(json.dumps(out, sort_keys=True) + "\n")
                fetched += 1
            rows.append({**out, **_meta(rec, url, designations, services)})
            if i % 200 == 0:
                cache_f.flush()
                remaining = brw.gh_rate_remaining()
                print(f"[{i}/{len(todo)}] quota {remaining}", flush=True)
                if remaining is not None and remaining < args.quota_floor:
                    stop["flag"] = True

    hits = [r for r in rows if r.get("iac_hit")]
    enrich_visibility(hits, designations, args.jobs)
    hits.sort(key=priority_key)
    now = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    census = {
        "generated_at": now,
        "population": len(population),
        "github_checked": sum(1 for r in rows if r["status"] == "ok"),
        "gitlab_unchecked": gitlab_unchecked,
        "no_url": no_url,
        "errors": sum(1 for r in rows if r["status"] not in ("ok", "quota-deferred")),
        "quota_deferred": sum(1 for r in rows if r["status"] == "quota-deferred"),
        "fetched_this_run": fetched,
        "truncated_trees": sum(1 for r in rows if r.get("truncated")),
        "iac_bearing": len(hits),
        "by_class": {k: sum(1 for r in rows if r.get(k)) for k in IAC_CLASSES},
        "by_exposure": _count(hits, "exposure"),
        "by_tier": _count(hits, "tier"),
        "services_segment": sum(1 for r in hits if r["services_segment"]),
    }
    inv_p = manifest / "iac-inventory.json"
    if inv_p.is_file() and census["github_checked"] == 0:
        print(
            "refusing to overwrite existing inventory with a "
            "zero-checked run (throttled?) — no files written",
            file=sys.stderr,
        )
        return 3
    inv_p.write_text(
        json.dumps({"census": census, "repos": rows}, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    wl_p = manifest / "iac-baseline-worklist.json"
    wl_p.write_text(
        json.dumps(
            {
                "generated_at": now,
                "note": (
                    "Phase-0 iac-baseline candidates, priority-ordered "
                    "(exposure band > managed-services tenancy relevance > "
                    "tier > live crit/high). Dispatch = /cloud-config-audit "
                    "full run per repo; sweep budget is a user decision "
                    "(router-lane-coverage-plan.md open decision 1)."
                ),
                "worklist": [
                    {
                        k: r.get(k)
                        for k in (
                            "repo_key",
                            "repo_url",
                            "exposure",
                            "tier",
                            "services_segment",
                            "live_crit_high",
                            "terraform",
                            "cloudformation",
                            "arm_bicep",
                            "truncated",
                            "iac_samples",
                        )
                    }
                    for r in hits
                ],
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    md = [
        f"# IaC Baseline Worklist — Phase 0 census ({now})",
        "",
        f"Population {census['population']} | GitHub checked "
        f"{census['github_checked']} | IaC-bearing "
        f"**{census['iac_bearing']}** | gitlab-unchecked "
        f"{gitlab_unchecked} | errors {census['errors']}",
        "",
        "| # | Repo | Exposure | Tier | Svc | tf | cfn | arm |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(hits, 1):
        md.append(
            f"| {i} | {r['repo_url']} | {r['exposure']} | "
            f"{r['tier']} | {'Y' if r['services_segment'] else ''}"
            f" | {r.get('terraform', 0)} | "
            f"{r.get('cloudformation', 0)} | "
            f"{r.get('arm_bicep', 0)} |"
        )
    (manifest / "iac-baseline-worklist.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"iac-bearing: {census['iac_bearing']} (by class {census['by_class']}) -> {wl_p}")
    return 0


def enrich_visibility(hits: list[dict], designations, jobs: int) -> None:
    """The census's exposure default is visibility-blind (private).
    One repo-info call per IaC-BEARING repo (only ~hundreds) recovers
    the visibility/fork/parent axis so the worklist ordering matches
    the router's exposure semantics."""

    def one(row):
        _kind, _host, project = brw.split_repo_url(row["repo_url"])
        if not project:
            return
        info = brw.gh_repo_info(project)
        if not isinstance(info, dict) or info.get("ok") is False:
            return
        data = info.get("info") or info
        row["visibility"] = data.get("visibility")
        row["exposure"] = brw.exposure_class(
            {
                "designation": brw.lookup_designation(row["repo_url"], designations),
                "visibility": data.get("visibility"),
                "fork": data.get("fork"),
                "parent": data.get("parent"),
            }
        )

    with concurrent.futures.ThreadPoolExecutor(jobs) as pool:
        list(pool.map(one, hits))


def _meta(rec: dict, url: str, designations, services: set[str]) -> dict:
    designation = brw.lookup_designation(url, designations)
    exposure = brw.exposure_class(
        {"designation": designation, "visibility": None, "fork": False, "parent": None}
    )
    return {
        "repo_key": rec.get("repo_key"),
        "repo_url": url,
        "exposure": exposure,
        "tier": risk_tier(rec.get("live_crit_high", 0)),
        "live_crit_high": rec.get("live_crit_high", 0),
        "services_segment": url in services,
    }


def _count(rows: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return dict(sorted(out.items()))


if __name__ == "__main__":
    sys.exit(main())
