#!/usr/bin/env python3
# Migration utility archived 2026-08-11
"""Benchmark rule-candidate extractor — the post-scoring capture step.

Benchmark runs are contamination-isolated by design: their audit reports
never enter analysis-results/ or the disposition ledger, so /mine-ledger
never sees them — and every rule-expressible shape a benchmark audit
surfaces (a `protected-mode no` Redis default, `insecure_header_jwk =
true`, `--nogpgcheck`) used to evaporate when the run ended (gap named
2026-07-29 during the deep-fn Phase-A baseline).

This extractor closes that leak IDENTITY-ONLY: it reads the benchmark
runs directory's `*-security-audit.json` reports, routes each finding
through the sweep engine's deterministic rule-expressibility classifier
(scripts/sweep_engine.classify — the same router the ledger tier uses),
clusters expressible candidates by (CWE, language), marks which clusters
the traust opengrep pack already covers, and emits a rule-authoring input
artifact. It never writes findings, ledger events, or anything under
analysis-results/ — the candidates are pattern exemplars for a rule
author, not findings of record, and the artifact says so in its banner.

Consumers: the /mine-ledger rule-authoring backlog review (read this
beside rule-mining.md); terminal otherwise.

Usage:
    python3 extract_benchmark_rule_candidates.py --runs-dir DIR
        [--pack <rules-dir>] [--out-dir DIR] [--min-severity medium]
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections import defaultdict
from pathlib import Path

from traust_engine.sweep import mining as MINE
from traust_engine.sweep.engine import classify

from traust.context import add_config_home_arg, load_engine, progress_tracker_dir
from traust.paths import HARNESS_ROOT, skill_dir

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]

BANNER = (
    "BENCHMARK-DERIVED CANDIDATES — these findings exist only in "
    "contamination-isolated benchmark runs. They are NOT in any "
    "baseline or disposition ledger and MUST NOT be ingested as "
    "findings; they are pattern exemplars for opengrep rule "
    "authoring only."
)


def _findings(report: dict):
    yield from report.get("findings") or []


def extract(runs_dir: Path, pack: Path, min_severity: str) -> dict:
    floor = SEV_ORDER.index(min_severity)
    clusters: dict[tuple, dict] = defaultdict(lambda: {"candidates": [], "repos": set()})
    routed_out: dict[str, int] = defaultdict(int)
    scanned = []

    for report_path in sorted(runs_dir.glob("*/*-security-audit.json")):
        run_id = report_path.parent.name
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            routed_out["unreadable_report"] += 1
            continue
        repo = (report.get("metadata") or {}).get("repository") or run_id
        scanned.append(run_id)
        for f in _findings(report):
            sev = str(f.get("severity") or "informational").lower()
            if sev not in SEV_ORDER or SEV_ORDER.index(sev) < floor:
                routed_out["below_severity_floor"] += 1
                continue
            locs = f.get("locations") or []
            path0 = locs[0].get("path") if locs and isinstance(locs[0], dict) else None
            probe = {
                "cwe": (f.get("cwes") or [None])[0],
                "file": path0,
                "language": MINE.guess_language(locs),
            }
            ok, reason = classify(probe)
            if not ok:
                routed_out[reason.split(":")[0]] += 1
                continue
            key = (probe["cwe"], probe["language"])
            c = clusters[key]
            c["repos"].add(repo)
            if len(c["candidates"]) < 12:
                c["candidates"].append(
                    {
                        "run": run_id,
                        "repo": repo,
                        "finding_id": f.get("id"),
                        "severity": sev,
                        "title": str(f.get("title") or "")[:160],
                        "file": path0,
                    }
                )

    rows = []
    for (cwe, lang), c in clusters.items():
        covered = MINE.pack_rule_count(
            pack, MINE.PACK_DIR_FOR_LANG.get(lang, lang)
        ) > 0 and _cluster_covered(pack, cwe, lang)
        rows.append(
            {
                "cwe": cwe,
                "language": lang,
                "repos": sorted(c["repos"]),
                "candidate_count": len(c["candidates"]),
                "pack_covered": covered,
                "candidates": c["candidates"],
            }
        )
    rows.sort(key=lambda r: (r["pack_covered"], -len(r["repos"]), str(r["cwe"])))
    return {
        "artifact": "benchmark-rule-candidates",
        "banner": BANNER,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "runs_dir": str(runs_dir),
        "runs_scanned": scanned,
        "min_severity": min_severity,
        "clusters": rows,
        "routed_out": dict(routed_out),
    }


def _cluster_covered(pack: Path, cwe: str | None, lang: str) -> bool:
    """True when any traust rule in the language's pack dir names this CWE."""
    lang_dir = pack / MINE.PACK_DIR_FOR_LANG.get(lang, lang)
    if not lang_dir.is_dir():
        return False
    needle = str(cwe or "").upper()
    if not needle:
        return False
    return any(needle in json.dumps(rule).upper() for rule in MINE.load_pack_rules(lang_dir))


def render_md(data: dict) -> str:
    lines = [
        "# Benchmark Rule Candidates",
        "",
        f"> **{data['banner']}**",
        "",
        f"Generated {data['generated_at']} · harness "
        f"{data['harness_version']} · runs: "
        f"{', '.join(data['runs_scanned'])} · severity floor: "
        f"{data['min_severity']}",
        "",
        "| CWE | Language | Repos | Candidates | Pack covered? |",
        "|---|---|---|---|---|",
    ]
    for r in data["clusters"]:
        lines.append(
            f"| {r['cwe']} | {r['language']} | {len(r['repos'])} | "
            f"{r['candidate_count']} | "
            f"{'yes' if r['pack_covered'] else '**NO — backlog**'} |"
        )
    lines += ["", "## Exemplars (uncovered clusters first)", ""]
    for r in data["clusters"]:
        if r["pack_covered"]:
            continue
        lines.append(f"### {r['cwe']} / {r['language']}")
        for c in r["candidates"][:5]:
            lines.append(
                f"- `{c['finding_id']}` ({c['severity']}, {c['run']}) {c['title']} — `{c['file']}`"
            )
        lines.append("")
    ro = data["routed_out"]
    if ro:
        lines.append(
            "Routed out (recorded, never silent): "
            + ", ".join(f"{k}: {v}" for k, v in sorted(ro.items()))
        )
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--runs-dir", type=Path, required=True)
    ap.add_argument("--pack", type=Path, default=skill_dir("secure-code-audit") / "opengrep-rules")
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--min-severity", default="medium", choices=SEV_ORDER)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    out_dir = args.out_dir or (progress_tracker_dir(engine) / "metrics" / "rule-mining")

    if not args.runs_dir.is_dir():
        print(f"not a directory: {args.runs_dir}", file=sys.stderr)
        return 1
    data = extract(args.runs_dir.resolve(), args.pack.resolve(), args.min_severity)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "benchmark-rule-candidates.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "benchmark-rule-candidates.md").write_text(render_md(data), encoding="utf-8")
    uncovered = sum(1 for r in data["clusters"] if not r["pack_covered"])
    print(
        f"{len(data['clusters'])} expressible clusters "
        f"({uncovered} uncovered by the traust pack) from "
        f"{len(data['runs_scanned'])} runs -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
