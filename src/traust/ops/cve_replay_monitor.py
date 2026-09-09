#!/usr/bin/env python3
"""Standing CVE-replay false-negative monitor (model-external FN oracle).

When a NEW advisory publishes against a repo+ref the campaign has already
audited, this monitor deterministically checks whether the audit report
had caught it, and files misses as (a) rows in the append-only
`fn_cve_replay_missed` trends series and (b) benchmark ground-truth
CANDIDATES (a human-gated queue — this tool never admits anything to the
recall benchmark itself). It is the permanent successor of the Phase-0a
CVE-replay backfill (scanning-skill error-correction plan v2.0, §5 item 4).

Hit-check tiers (deterministic — this tool ROUTES, NEVER CONCLUDES):
  detected  the report's findings or negative_results NAME the advisory's
            CVE/GHSA id (id-match — the only deterministic positive tier)
  unclear   no id match, but the advisory's affected file/symbol area
            appears in the report (area-match is suggestive, never a
            verdict — recorded for human adjudication, never guessed up
            or down)
  missed    neither the id nor the affected area appears anywhere in the
            report — a false-negative candidate

Modes:
  --backfill CANDIDATES.json
      Ingest an adjudicated Phase-0a artifact (rows carry slug, cve/ghsa,
      published, severity, present_at_audit, audit_verdict) into the
      trends series and the ground-truth candidates queue. Idempotent:
      re-running never duplicates rows.
  (default) incremental
      Resolve the audited-report population (traust.cli.groups.corpus when
      importable, else a fallback walker with the same identity rules),
      derive each repo's OSV package identity (github.com/<org>/<repo>,
      ecosystem Go — the fork/module identity convention of
      run_fork_advisory_lag.py; non-GitHub repos are recorded as skipped,
      matching the 0a backfill), query https://api.osv.dev/v1/query for
      advisories published since the per-ecosystem watermark in the state
      file, run the hit-check against every audited ref of the repo, and
      append the results.

Outputs (all idempotent, keyed by (repo, ref, advisory-or-alias)):
  progress-tracker/metrics/trends/fn_cve_replay_missed.jsonl
      Append-only JSONL series (the metrics-history.jsonl convention):
      one row per MISS with {date, repo, ref, advisory, severity,
      verdict, ...}. Only verdict == "missed" rows enter the series.
  analysis-results/scan-testing/cve-replay-monitor/ground-truth-candidates.json
      Queue of benchmark ground-truth CANDIDATES (missed rows, plus
      unclear rows not already adjudicated absent-at-audit). Admission to
      the recall benchmark stays human-gated — the file's `role` header
      says so.

State (`--state`, default <candidates dir>/state.json): per-ecosystem
watermark = the max advisory published-date processed. Network failure is
tolerated: rows classified before the failure are still appended (safe —
idempotent), the state is NOT advanced, "network: error: ..." is printed,
and the exit code stays 0 so a cron wrapper never pages on OSV downtime.

Ops note — cron: the monitor is stdlib-only and self-contained; a daily
run from the workspace root is enough (advisory publishing cadence makes
anything faster pointless):

    17 6 * * *  cd $WS && python3 traust/scripts/cve_replay_monitor.py

First run establishes the watermark (today) and processes nothing — the
Phase-0a `--backfill` covers history. Review misses via the ground-truth
candidates queue; the trends series feeds the metrics ledger's
`fn_cve_replay_missed` series at re-measurement time (plan §7).

Usage:
    python3 -m traust.cli.cve_replay_monitor [--workspace-root WS]
        [--state FILE] [--since YYYY-MM-DD] [--offline]
        [--timeout SECONDS] [--osv-url URL]
    python3 -m traust.cli.cve_replay_monitor --backfill candidates.json
        [--workspace-root WS]

Exit 0 on a completed run (network or not); 1 on bad input.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from traust_engine import HarnessEngine
from traust_engine.corpus.resolver import normalize_repo_url

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
    progress_tracker_dir,
)
from traust.paths import HARNESS_ROOT
from traust.registry.osv_urls import osv_query_url

OSV_QUERY_URL = osv_query_url()

# Relative paths under workspace — kept for tests/helpers that anchor on ws root.
TRENDS_REL = Path("progress-tracker/metrics/trends/fn_cve_replay_missed.jsonl")
QUEUE_REL = Path("analysis-results/scan-testing/cve-replay-monitor/ground-truth-candidates.json")
TRENDS_SUFFIX = Path("metrics/trends/fn_cve_replay_missed.jsonl")
QUEUE_SUFFIX = Path("scan-testing/cve-replay-monitor/ground-truth-candidates.json")


def _output_paths(args, engine: HarnessEngine | None = None) -> tuple[Path, Path]:
    """Resolve trends/queue paths: explicit --workspace-root beats config."""
    if args.workspace_root is not None:
        ws = args.workspace_root.resolve()
        return ws / TRENDS_REL, ws / QUEUE_REL
    if engine is None:
        engine = load_engine(args.config_home)
    return (
        progress_tracker_dir(engine) / TRENDS_SUFFIX,
        analysis_results_dir(engine) / QUEUE_SUFFIX,
    )


CVE_RX = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA_RX = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)

# identity rules shared with traust.cli.groups.corpus (legacy slug fallback)
AUDIT_JSON_SUFFIX = "-security-audit.json"
REF_SUFFIX_RX = re.compile(r"__((?:release|openshift)-\d+\.\d+(?:\.\d+)?)$")
SKIP_DIR_NAMES = {
    "_manifest",
    ".git",
    ".claude",
    ".triage-state",
    ".threat-model-state",
    ".scratch",
}
SKIP_DIR_PREFIXES = (".cache", ".tmp", ".verify")

QUEUE_ROLE = (
    "QUEUE of benchmark ground-truth CANDIDATES from the standing "
    "CVE-replay FN monitor. ADMISSION to the recall benchmark stays "
    "HUMAN-GATED: nothing in this file is ground truth until a human "
    "adjudicates present_at_audit and the verdict and promotes the row "
    "via the recall-benchmark workflow. The monitor only appends; it "
    "never concludes."
)


def _today() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def harness_version():
    try:
        return (HARNESS_ROOT / "VERSION").read_text().strip()
    except OSError:
        return None


# --------------------------------------------------------------- discovery


def _skip_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.startswith(SKIP_DIR_PREFIXES)


def _walk_fallback(analysis_results: Path) -> list[dict]:
    """Discovery fallback: walk *-security-audit.json with corpus.py's
    identity rules (skip dirs, no symlinks, legacy `__release-X.Y` slug
    refs, findings-current layer preference)."""
    records = []
    for dirpath, dirnames, filenames in os.walk(analysis_results, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not _skip_dir(d) and not (dp / d).is_symlink()]
        for fname in sorted(filenames):
            if not fname.endswith(AUDIT_JSON_SUFFIX) or (dp / fname).is_symlink():
                continue
            base = fname[: -len(AUDIT_JSON_SUFFIX)]
            m = REF_SUFFIX_RX.search(base)
            slug, ref = (base[: m.start()], m.group(1)) if m else (base, None)
            current = dp / f"{base}-findings-current.json"
            report = current if current.is_file() else dp / fname
            repo_url = None
            try:
                doc = json.loads((dp / fname).read_text(encoding="utf-8"))
                md = doc.get("metadata") or {}
                repo_url = normalize_repo_url(md.get("repository"))
                if md.get("ref"):
                    ref = md["ref"]
            except (OSError, json.JSONDecodeError, AttributeError):
                pass
            records.append({"slug": slug, "ref": ref, "report": str(report), "repo_url": repo_url})
    return records


def discover(
    analysis_results: Path,
    engine: HarnessEngine | None = None,
    *,
    use_corpus: bool = True,
) -> list[dict]:
    """Audited-report population: [{slug, ref, report, repo_url}, ...].

    Uses the shared corpus resolver (code-audit records only, findings-current
    preferred) when *engine* is provided; else the fallback walker with the
    same identity rules.
    """
    if not use_corpus or engine is None:
        return _walk_fallback(analysis_results)
    res = engine.corpus.load_resolution(
        with_repo_urls=True, results_root=analysis_results.resolve()
    )
    records = []
    for rec in res.records:
        if rec.report_kind != "code-audit" or rec.is_md_only:
            continue
        report = rec.findings_current or rec.audit_json
        records.append(
            {
                "slug": rec.base_slug,
                "ref": rec.ref,
                "report": report,
                "repo_url": normalize_repo_url(rec.repo_url),
            }
        )
    return records


def osv_identity(repo_url):
    """repo URL -> (osv_package, ecosystem) or None.

    GitHub repos map to their Go module identity
    (github.com/<org>/<name>) — the dominant portfolio ecosystem and the
    same identity convention run_fork_advisory_lag.py queries OSV with.
    Non-GitHub hosts (self-hosted GitLab etc.) have no public OSV surface and
    are skipped, exactly as the 0a backfill skipped them.
    """
    if not repo_url:
        return None
    m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s]+?)/?$", repo_url.strip())
    if not m:
        return None
    return f"github.com/{m.group(1)}/{m.group(2)}", "Go"


# --------------------------------------------------------------- hit-check


def report_index(report_path) -> dict | None:
    """{ids, text} extracted from a report's findings + negative_results.

    ids  = every CVE/GHSA token named anywhere in a finding or a
           negative_results entry (uppercased)
    text = the lowercased JSON text of both sections, for area-matching
    """
    # Read stays a direct path read: this helper is also fed by _walk_fallback(),
    # which runs when the resolver is unavailable and therefore has no corpus root
    # to anchor a ref against. Converting it would mean either inventing a root or
    # dropping the fallback, and the fallback exists so the monitor still works
    # when traust_engine is not importable. Residual, tracked in the plan.
    try:
        doc = json.loads(Path(report_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    blob = json.dumps(
        {
            "findings": doc.get("findings") or [],
            "negative_results": doc.get("negative_results") or [],
        }
    )
    ids = {t.upper() for t in CVE_RX.findall(blob)}
    ids |= {t.upper() for t in GHSA_RX.findall(blob)}
    return {"ids": ids, "text": blob.lower()}


def advisory_ids(vuln: dict) -> set[str]:
    ids = {vuln.get("id") or ""} | set(vuln.get("aliases") or [])
    return {i.upper() for i in ids if i}


def advisory_areas(vuln: dict) -> list[str]:
    """Affected file/symbol tokens from OSV `affected` entries (Go
    vulndb-style ecosystem_specific imports + symbols). Module roots are
    excluded — matching the whole module proves nothing."""
    areas = []
    for aff in vuln.get("affected") or []:
        eco = aff.get("ecosystem_specific") or {}
        pkg = (aff.get("package") or {}).get("name") or ""
        for imp in eco.get("imports") or []:
            path = imp.get("path") or ""
            sub = path[len(pkg) :].strip("/") if path.startswith(pkg) else path
            if sub and sub != pkg:
                areas.append(sub)
            areas.extend(s for s in imp.get("symbols") or [] if s)
    return [a for a in dict.fromkeys(areas) if len(a) >= 4]


def classify(ids: set[str], areas: list[str], idx: dict) -> tuple[str, str]:
    """Deterministic hit-check -> (verdict, basis). Never guesses:
    id-match is the only 'detected' tier; area-match is 'unclear'."""
    named = ids & idx["ids"]
    if named:
        return "detected", f"id-match: {', '.join(sorted(named))}"
    for area in areas:
        if area.lower() in idx["text"]:
            return "unclear", f"area-match only: {area!r} appears in report; advisory id not named"
    return "missed", "no id or affected-area match in findings or negative_results"


# ----------------------------------------------------------------- outputs


def _row_ids(row: dict) -> set[str]:
    ids = {row.get("advisory") or ""} | set(row.get("aliases") or [])
    return {i.upper() for i in ids if i}


def _row_keys(row: dict) -> set[tuple]:
    ref = row.get("ref") or ""
    return {(row.get("repo"), ref, i) for i in _row_ids(row)}


def _existing_trend_keys(path: Path) -> set[tuple]:
    keys: set[tuple] = set()
    if not path.is_file():
        return keys
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            keys |= _row_keys(json.loads(line))
        except json.JSONDecodeError:
            continue
    return keys


def append_trends(path: Path, rows: list[dict]) -> int:
    """Append verdict=='missed' rows not already in the series (JSONL,
    metrics-history.jsonl convention). Returns rows appended."""
    misses = [r for r in rows if r.get("verdict") == "missed"]
    if not misses:
        return 0
    seen = _existing_trend_keys(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    added = 0
    with path.open("a", encoding="utf-8") as fh:
        for row in misses:
            keys = _row_keys(row)
            if keys & seen:
                continue
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            seen |= keys
            added += 1
    return added


def _queue_eligible(row: dict) -> bool:
    """Missed rows always queue; unclear rows queue unless already
    adjudicated absent at audit (backfill present_at_audit == False)."""
    if row.get("verdict") == "missed":
        return True
    return row.get("verdict") == "unclear" and row.get("present_at_audit") is not False


def append_queue(path: Path, rows: list[dict]) -> int:
    """Merge eligible rows into the ground-truth candidates queue
    (idempotent). Returns rows added."""
    eligible = [r for r in rows if _queue_eligible(r)]
    doc = {"artifact": "cve-replay-monitor-ground-truth-candidates", "role": QUEUE_ROLE, "rows": []}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                doc.update(loaded)
                doc["role"] = QUEUE_ROLE
        except json.JSONDecodeError:
            pass
    existing = doc.get("rows") or []
    seen: set[tuple] = set()
    for row in existing:
        seen |= _row_keys(row)
    added = 0
    for row in eligible:
        keys = _row_keys(row)
        if keys & seen:
            continue
        existing.append(row)
        seen |= keys
        added += 1
    if added or not path.is_file():
        doc["rows"] = existing
        doc["updated_at"] = _now_iso()
        doc["tool_version"] = harness_version()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return added


# ---------------------------------------------------------------- backfill


def backfill_rows(candidates_doc: dict) -> list[dict]:
    """0a candidates.json rows -> monitor row shape (verdicts and
    present_at_audit adjudications carried verbatim — never re-derived)."""
    campaign = candidates_doc.get("campaign") or "backfill"
    rows = []
    for r in candidates_doc.get("rows") or []:
        ident = r.get("cve") or r.get("ghsa")
        if not ident or not r.get("slug"):
            continue
        aliases = [x for x in (r.get("cve"), r.get("ghsa")) if x and x != ident]
        rows.append(
            {
                "date": r.get("published") or "",
                "repo": r["slug"],
                "ref": None,
                "advisory": ident,
                "aliases": aliases,
                "severity": r.get("severity") or "unknown",
                "verdict": r.get("audit_verdict") or "unclear",
                "present_at_audit": r.get("present_at_audit"),
                "published": r.get("published"),
                "detail": r.get("evidence") or "",
                "summary": r.get("summary") or "",
                "source": f"backfill:{campaign}",
            }
        )
    return rows


# -------------------------------------------------------------- OSV client


def _post_json(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_osv(package: str, ecosystem: str, url: str, timeout: int) -> list[dict]:
    """All advisories for a package (no version filter — the hit-check,
    not the range, decides). Raises on network failure."""
    vulns, page_token, pages = [], None, 0
    payload = {"package": {"name": package, "ecosystem": ecosystem}}
    while pages < 10:
        body = dict(payload)
        if page_token:
            body["page_token"] = page_token
        resp = _post_json(url, body, timeout)
        vulns += resp.get("vulns") or []
        page_token = resp.get("next_page_token")
        pages += 1
        if not page_token:
            break
    return vulns


def osv_severity(vuln: dict) -> str:
    db = vuln.get("database_specific") or {}
    if db.get("severity"):
        return str(db["severity"]).lower()
    for sev in vuln.get("severity") or []:
        score = str(sev.get("score") or "")
        m = re.search(r"/AV:", score)  # a CVSS vector, not a number
        if m:
            continue
        try:
            n = float(score)
        except ValueError:
            continue
        return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low"
    return "unknown"


# -------------------------------------------------------------- state file


def load_state(path: Path) -> dict:
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict):
                doc.setdefault("watermarks", {})
                return doc
        except json.JSONDecodeError:
            pass
    return {"artifact": "cve-replay-monitor-state", "watermarks": {}}


def save_state(path: Path, state: dict) -> None:
    state["last_run"] = _now_iso()
    state["tool_version"] = harness_version()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ------------------------------------------------------------- incremental


def run_incremental(
    records: list[dict],
    state: dict,
    *,
    since: str,
    offline: bool,
    osv_url: str,
    timeout: int,
    run_date: str,
) -> tuple[list[dict], str, dict]:
    """Query OSV per unique package and hit-check new advisories.

    Returns (rows, network_status, new_watermarks). On network error the
    caller must NOT persist watermarks (rows already classified are safe
    to append — every output is idempotent).
    """
    packages: dict[tuple[str, str], list[dict]] = {}
    for rec in records:
        ident = osv_identity(rec.get("repo_url"))
        if ident:
            packages.setdefault(ident, []).append(rec)

    watermarks = dict(state.get("watermarks") or {})
    new_watermarks = dict(watermarks)
    rows: list[dict] = []
    if offline:
        return rows, "skipped (--offline)", new_watermarks

    for (package, eco), recs in sorted(packages.items()):
        wm = watermarks.get(eco) or since
        try:
            vulns = query_osv(package, eco, osv_url, timeout)
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            OSError,
            TimeoutError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            return rows, f"error: {exc}", dict(watermarks)
        for vuln in vulns:
            pub = (vuln.get("published") or "")[:10]
            if not pub or pub <= wm:
                continue
            ids = advisory_ids(vuln)
            areas = advisory_areas(vuln)
            ident = (
                next((i for i in sorted(ids) if i.startswith("CVE-")), None) or vuln.get("id") or ""
            )
            sev = osv_severity(vuln)
            for rec in recs:
                idx = report_index(rec["report"])
                if idx is None:
                    continue
                verdict, basis = classify(ids, areas, idx)
                rows.append(
                    {
                        "date": run_date,
                        "repo": rec["slug"],
                        "ref": rec.get("ref"),
                        "advisory": ident,
                        "aliases": sorted(ids - {ident.upper()}),
                        "severity": sev,
                        "verdict": verdict,
                        "present_at_audit": None,  # human adjudication
                        "published": vuln.get("published"),
                        "detail": basis,
                        "summary": (vuln.get("summary") or (vuln.get("details") or "")[:200]),
                        "source": "incremental",
                    }
                )
            cur = new_watermarks.get(eco) or since
            new_watermarks[eco] = max(cur, pub)
        # a queried ecosystem with no new advisories keeps its watermark
        new_watermarks.setdefault(eco, wm)
    return rows, "ok", new_watermarks


# ------------------------------------------------------------------- main


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="workspace root; ASSUMES the default layout (analysis-results/ and "
        "progress-tracker/ as siblings). Omit to resolve both through "
        "locations.yaml in $TRAUST_CONFIG_HOME",
    )
    ap.add_argument(
        "--analysis-results", type=Path, default=None, help="override analysis-results/ location"
    )
    ap.add_argument(
        "--backfill",
        type=Path,
        default=None,
        help="ingest a Phase-0a candidates.json instead of querying OSV",
    )
    ap.add_argument(
        "--state",
        type=Path,
        default=None,
        help="watermark state file (default: <candidates dir>/state.json)",
    )
    ap.add_argument(
        "--since",
        default=None,
        help="first-run watermark (YYYY-MM-DD; default: today — backfill covers history)",
    )
    ap.add_argument(
        "--offline", action="store_true", help="never touch the network (state untouched)"
    )
    ap.add_argument("--timeout", type=int, default=30, help="per-request OSV timeout in seconds")
    ap.add_argument(
        "--osv-url", default=OSV_QUERY_URL, help="OSV query endpoint (default: api.osv.dev)"
    )
    ap.add_argument(
        "--no-corpus", action="store_true", help="force the fallback walker instead of corpus.py"
    )
    args = ap.parse_args(argv)
    run_date = _today()

    # ------------------------------------------------------- backfill mode
    if args.backfill:
        try:
            doc = json.loads(args.backfill.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: cannot read {args.backfill}: {exc}", file=sys.stderr)
            return 1
        engine = load_engine(args.config_home) if args.workspace_root is None else None
        trends_path, queue_path = _output_paths(args, engine)
        rows = backfill_rows(doc)
        t_added = append_trends(trends_path, rows)
        q_added = append_queue(queue_path, rows)
        print(f"backfill: {len(rows)} rows ingested from {args.backfill}")
        print(f"  trends  +{t_added} -> {trends_path}")
        print(f"  queue   +{q_added} -> {queue_path}")
        return 0

    # ---------------------------------------------------- incremental mode
    engine = load_engine(args.config_home)
    trends_path, queue_path = _output_paths(args, engine)
    analysis_results = (args.analysis_results or analysis_results_dir(engine)).resolve()
    if not analysis_results.is_dir():
        print(f"ERROR: analysis-results not found at {analysis_results}", file=sys.stderr)
        return 1
    state_path = args.state or queue_path.parent / "state.json"
    state = load_state(state_path)
    since = args.since or run_date

    records = discover(analysis_results, engine, use_corpus=not args.no_corpus)
    rows, network, new_watermarks = run_incremental(
        records,
        state,
        since=since,
        offline=args.offline,
        osv_url=args.osv_url,
        timeout=args.timeout,
        run_date=run_date,
    )

    t_added = append_trends(trends_path, rows)
    q_added = append_queue(queue_path, rows)

    verdicts = {}
    for r in rows:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
    queryable = {
        osv_identity(r.get("repo_url")) for r in records if osv_identity(r.get("repo_url"))
    }
    print(
        f"cve-replay monitor: {len(records)} audited reports, "
        f"{len(queryable)} OSV packages (network: {network})"
    )
    verdict_line = ", ".join(f"{k} {v}" for k, v in sorted(verdicts.items())) or "none"
    print(f"  new advisory checks: {len(rows)} ({verdict_line})")
    print(f"  trends  +{t_added} -> {trends_path}")
    print(f"  queue   +{q_added} -> {queue_path}")

    if network == "ok":
        state["watermarks"] = new_watermarks
        state["last_network"] = network
        save_state(state_path, state)
        print(f"  state   watermarks {new_watermarks} -> {state_path}")
    else:
        print(f"  state   NOT advanced (network: {network})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
