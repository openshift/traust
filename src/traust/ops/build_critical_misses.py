#!/usr/bin/env python3
"""Centralized running critical-misses report (error-correction campaign).

Regenerates <results-root>/CRITICAL-MISSES.md — the single place to see
every Type-II CRITICAL (a critical-severity vulnerability the original
audit missed on an already-audited repo) discovered by the
scanning-skill error-correction campaign, with its triage verdict,
disposition-ledger status, and routing state.

Sources (all campaign artifacts under
<results-root>/scan-testing/sxs-2026-07/; every glob tolerates absence
so future waves are picked up automatically):

  b-lite/*-delta.json          0e-probe (arm B) critical delta candidates
  matrix/*-delta*.json         matrix-arm delta candidates (if any)
  **/*-triage.json             triage verdicts, matched to deltas by the
                               triage finding's `source` fragment
                               ("b-lite/<slug>-delta.json#<idx>") and to
                               baselines by `orig_id`
  cve-replay/candidates.json   ground-truth CVE replay: rows with
                               present_at_audit=true, audit_verdict=
                               "missed", severity critical

Ledger status is best-effort: the slug -> report map from the campaign's
*-sample.json files resolves each repo's *-security-audit.json baseline
and *-findings-current.json; a delta counts as INGESTED when a baseline
finding matches by triage orig_id or by location-path + CWE, and its
current disposition validity is reported. This script only reads and
renders — verdicts belong to /triage, state to the disposition ledger.

Usage:
    python3 -m traust.cli.build_critical_misses
        [--results-root <analysis-results>]
            (default: configured analysis_results from $TRAUST_CONFIG_HOME/locations.yaml)
        [--campaign-dir scan-testing/sxs-2026-07]
        [--out <file>]                # default <results-root>/CRITICAL-MISSES.md
        [--generated-at ISO8601]      # reproducible runs
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.paths import HARNESS_ROOT

DEFAULT_CAMPAIGN_DIR = "scan-testing/sxs-2026-07"
CWE_RE = re.compile(r"CWE-\d{1,5}")


def harness_version() -> str:
    try:
        v = (HARNESS_ROOT / "VERSION").read_text().strip()
    except OSError:
        return "unknown"
    try:
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        return f"{v}-{sha}"
    except (subprocess.SubprocessError, OSError):
        return v


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"WARN: unreadable JSON skipped: {path} ({e})", file=sys.stderr)
        return None


def _is_critical(severity) -> bool:
    """Severity strings vary ('critical', 'critical (CVSS 9.9)', ...)."""
    return str(severity or "").strip().lower().startswith("critical")


def _primary_cwe(text) -> str:
    m = CWE_RE.search(str(text or ""))
    return m.group(0) if m else "—"


# ---------------------------------------------------------------- deltas


def collect_delta_rows(campaign: Path) -> list[dict]:
    """Critical-severity delta candidates from probe + matrix arms."""
    rows = []
    sources = [("b-lite probe (arm B)", sorted(campaign.glob("b-lite/*-delta.json")))]
    matrix = sorted(campaign.glob("matrix/*-delta*.json"))
    if matrix:
        sources.append(("matrix", matrix))
    for instrument, paths in sources:
        for path in paths:
            doc = _read_json(path)
            if not isinstance(doc, dict):
                continue
            slug = doc.get("slug") or path.name.replace("-delta.json", "")
            for idx, delta in enumerate(doc.get("deltas") or []):
                if not _is_critical(delta.get("severity")):
                    continue
                rel = path.relative_to(campaign).as_posix()
                rows.append(
                    {
                        "instrument": instrument,
                        "slug": slug,
                        "title": str(delta.get("title") or "(untitled)"),
                        "cwe": delta.get("cwe") or _primary_cwe(json.dumps(delta)),
                        "file": delta.get("file"),
                        "source_key": f"{rel}#{idx}",
                        "evidence_path": f"{rel}#{idx}",
                    }
                )
    return rows


# ---------------------------------------------------------------- triage


def collect_triage_verdicts(campaign: Path) -> dict[str, dict]:
    """Map delta source fragment -> triage verdict info."""
    verdicts: dict[str, dict] = {}
    for path in sorted(campaign.rglob("*-triage.json")):
        doc = _read_json(path)
        if not isinstance(doc, dict):
            continue
        for f in doc.get("findings") or []:
            src = str(f.get("source") or "")
            if "#" not in src:
                continue
            vb = f.get("vote_breakdown") or {}
            votes = "-".join(str(vb.get(k, 0)) for k in ("true_positive", "false_positive"))
            label = str(f.get("verdict") or "untriaged")
            if vb:
                label += f" ({votes}"
                if f.get("confidence") is not None:
                    label += f", conf {f['confidence']}"
                label += ")"
            verdicts[src] = {
                "verdict": f.get("verdict"),
                "label": label,
                "orig_id": f.get("orig_id"),
                "triage_file": path.relative_to(campaign).as_posix(),
            }
    return verdicts


# ------------------------------------------------------------ cve-replay


def collect_cve_replay_rows(campaign: Path) -> list[dict]:
    doc = _read_json(campaign / "cve-replay" / "candidates.json")
    if not isinstance(doc, dict):
        return []
    rows = []
    for r in doc.get("rows") or []:
        if not (
            r.get("present_at_audit") is True
            and r.get("audit_verdict") == "missed"
            and _is_critical(r.get("severity"))
        ):
            continue
        ident = r.get("cve") or r.get("ghsa") or "(unidentified advisory)"
        rows.append(
            {
                "instrument": "cve-replay",
                "slug": str(r.get("slug") or "?"),
                "title": f"{ident}: {str(r.get('summary') or '').strip()}",
                "cwe": _primary_cwe(r.get("summary")),
                "ident": ident,
                "evidence_path": "cve-replay/candidates.json",
            }
        )
    return rows


# ---------------------------------------------------------------- ledger


def load_repo_reports(campaign: Path) -> dict[str, dict]:
    """slug -> {audit, current} paths from the campaign *-sample.json maps."""
    out: dict[str, dict] = {}
    for path in sorted(campaign.glob("*sample*.json")):
        doc = _read_json(path)
        if not isinstance(doc, list):
            continue
        for entry in doc:
            if not isinstance(entry, dict):
                continue
            slug, report = entry.get("slug"), entry.get("report")
            if not slug or not report:
                continue
            current = Path(report)
            audit = current.with_name(
                current.name.replace("-findings-current.json", "-security-audit.json")
            )
            out.setdefault(slug, {"audit": audit, "current": current})
    return out


def ledger_status(row: dict, verdict: dict | None, reports: dict[str, dict]) -> tuple[str, str]:
    """Return (ledger_status, countersign_routing_status) for one row."""
    repo = reports.get(row["slug"])
    if repo is None or not repo["audit"].is_file():
        return "not ingested (no baseline resolved)", "pending routing"

    audit = _read_json(repo["audit"]) or {}
    findings = audit.get("findings") or []
    matched = None

    orig_id = (verdict or {}).get("orig_id")
    if orig_id:
        matched = next((f for f in findings if f.get("id") == orig_id), None)
    if matched is None and row.get("file"):
        cwe = str(row.get("cwe") or "")
        for f in findings:
            paths = {loc.get("path") for loc in f.get("locations") or []}
            if row["file"] in paths and (not cwe or cwe in (f.get("cwes") or [])):
                matched = f
                break
    if matched is None and row.get("ident") and row["ident"] in json.dumps(findings):
        # CVE-replay rows: best-effort text match on the advisory id
        matched = {"id": "(text match)"}

    if matched is None:
        return "not ingested", "pending routing"

    status = f"ingested as {matched.get('id')}"
    signoff = "pending routing"
    current = _read_json(repo["current"]) if repo["current"].is_file() else None
    if isinstance(current, dict):
        cf = next(
            (f for f in (current.get("findings") or []) if f.get("id") == matched.get("id")), None
        )
        if cf:
            disp = cf.get("disposition") or {}
            validity = disp.get("validity") or cf.get("validation_status") or "not_verified"
            status += f"; ledger validity: {validity}"
            if validity == "confirmed":
                signoff = "no countersign required (confirmation); Jira not filed"
            elif disp.get("refuted_awaiting_signoff"):
                signoff = "refuted — awaiting human countersign"
    return status, signoff


# ---------------------------------------------------------------- report


def _md_escape(text: str, limit: int = 220) -> str:
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text[:limit] + ("…" if len(text) > limit else "")


def build_report(results_root: Path, campaign_rel: str, generated_at: str) -> tuple[str, dict]:
    campaign = results_root / campaign_rel
    delta_rows = collect_delta_rows(campaign)
    verdicts = collect_triage_verdicts(campaign)
    replay_rows = collect_cve_replay_rows(campaign)
    reports = load_repo_reports(campaign)

    header = (
        "| Repo | Finding | CWE | Discovered-by | Triage verdict | "
        "Ledger status | Countersign/routing status | Evidence path |"
    )
    sep = "|---|---|---|---|---|---|---|---|"

    sections: list[str] = []
    counts = {"delta_candidates": 0, "triage_confirmed": 0, "ingested": 0, "cve_replay_missed": 0}

    by_instrument: dict[str, list[dict]] = {}
    for row in delta_rows:
        by_instrument.setdefault(row["instrument"], []).append(row)

    for instrument in sorted(by_instrument):
        lines = [f"## Instrument: {instrument}", "", header, sep]
        for row in sorted(by_instrument[instrument], key=lambda r: (r["slug"], r["title"])):
            verdict = verdicts.get(row["source_key"])
            label = verdict["label"] if verdict else "untriaged (awaiting fast-track)"
            status, signoff = ledger_status(row, verdict, reports)
            counts["delta_candidates"] += 1
            if verdict and verdict.get("verdict") == "true_positive":
                counts["triage_confirmed"] += 1
            if status.startswith("ingested"):
                counts["ingested"] += 1
            lines.append(
                f"| {row['slug']} | {_md_escape(row['title'])} "
                f"| {row['cwe']} | {instrument} | {_md_escape(label)} "
                f"| {_md_escape(status)} | {_md_escape(signoff)} "
                f"| `{row['evidence_path']}` |"
            )
        sections.append("\n".join(lines))
    if "matrix" not in by_instrument:
        sections.append(
            "## Instrument: matrix\n\n_No matrix delta "
            "artifacts yet (matrix/*-delta*.json absent or "
            "empty)._"
        )

    lines = ["## Instrument: cve-replay (ground-truth misses)", "", header, sep]
    for row in sorted(replay_rows, key=lambda r: (r["slug"], r["title"])):
        status, _ = ledger_status(row, None, reports)
        counts["cve_replay_missed"] += 1
        lines.append(
            f"| {row['slug']} | {_md_escape(row['title'])} | {row['cwe']} "
            f"| cve-replay | n/a (ground-truth advisory replay) "
            f"| {_md_escape(status)} | measured — not yet routed "
            f"| `{row['evidence_path']}` |"
        )
    if not replay_rows:
        lines.append(
            "| — | _no critical present_at_audit/missed rows_ | — | cve-replay | — | — | — | — |"
        )
    sections.append("\n".join(lines))

    summary = "\n".join(
        [
            "## Summary",
            "",
            f"- Critical delta candidates (probe + matrix): **{counts['delta_candidates']}**",
            f"- Triage-confirmed true positives: **{counts['triage_confirmed']}**",
            f"- Ingested into baseline + disposition ledger: **{counts['ingested']}**",
            f"- CVE-replay ground-truth critical misses "
            f"(present_at_audit, audit_verdict=missed): "
            f"**{counts['cve_replay_missed']}**",
        ]
    )

    doc = (
        "\n\n".join(
            [
                "# Critical Misses — Error-Correction Campaign (running report)",
                "\n".join(
                    [
                        "**Scope.** Type-II CRITICALS: critical-severity "
                        "vulnerabilities that the original security audit missed on "
                        "already-audited repos, discovered by the scanning-skill "
                        "error-correction campaign (plan v2.0). Sources: the 0e "
                        "yield probe (arm B) delta files, matrix-arm deltas (when "
                        "present), fast-track triage verdicts, and the CVE-replay "
                        "ground-truth benchmark. This file is GENERATED — do not "
                        "edit by hand; verdicts belong to /triage and state to the "
                        "disposition ledger (/track-findings).",
                        "",
                        f"Campaign tree: `{campaign_rel}` under the results root.",
                    ]
                ),
                summary,
                *sections,
                "\n".join(
                    [
                        "---",
                        f"Generated: {generated_at} by "
                        f"`traust/scripts/build_critical_misses.py` "
                        f"(harness {harness_version()}). Regenerate with "
                        f"`python3 -m traust.cli.build_critical_misses`.",
                    ]
                ),
            ]
        )
        + "\n"
    )
    return doc, counts


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument(
        "--campaign-dir",
        default=DEFAULT_CAMPAIGN_DIR,
        help=f"campaign tree, relative to --results-root (default: {DEFAULT_CAMPAIGN_DIR})",
    )
    ap.add_argument(
        "--out", type=Path, default=None, help="default: <results-root>/CRITICAL-MISSES.md"
    )
    ap.add_argument(
        "--generated-at",
        default=None,
        help="override the timestamp (ISO 8601, for reproducible runs)",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results = (args.results_root or analysis_results_dir(engine)).resolve()
    campaign = results / args.campaign_dir
    if not campaign.is_dir():
        print(f"ERROR: campaign dir not found: {campaign}", file=sys.stderr)
        return 2
    generated_at = args.generated_at or dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc, counts = build_report(results, args.campaign_dir, generated_at)
    out = args.out or results / "CRITICAL-MISSES.md"
    out.write_text(doc, encoding="utf-8")
    print(f"wrote {out}")
    print("  " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
