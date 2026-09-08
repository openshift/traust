#!/usr/bin/env python3
"""Fleet OSV sweep — /dependency-watch's bootstrap / full-baseline mode.

The skill's daily path is incremental (advisories since the last run).
This script answers the other question: "which currently-known
advisories touch the audited fleet AT ALL?" — needed for the first
pass, quarterly re-baselines, and after portfolio-graph rebuilds.

Clone-free: dependency (module, version) pairs come from the portfolio
graph's `depends_on` edges (the same inventory /impact-analysis walks),
queried against the OSV batch API, deduplicated by advisory display id
(CVE alias when present, else the OSV id — so CVE-less malicious-package
/ Shai-Hulud advisories are NOT dropped), and banded by advisory
severity (malware bands CRITICAL). Output is a persisted, reviewable
inventory artifact plus a staged worklist of ready-to-run
run_impact_analysis.py / route_impact_findings.py commands — this
script routes and inventories only; affectedness judgment stays with
/impact-analysis and filing with route_impact_findings.py.

Staging discipline (precision posture): CVEs whose in-range repo count
exceeds --deep-scan-cap get graph-only impact commands (--skip-scan;
exposure becomes dashboard-visible immediately) with deep scans left to
operator staging; bounded CVEs get deep-scan + filing commands.
Severity for filing is the advisory band — never invented here.

Usage (from the workspace root):
    python3 traust/harnessing/3-audit/dependency-watch/scripts/fleet_sweep.py
        [--graph-db analysis-results/graph/portfolio-graph.db]
        [--out analysis-results/impact/fleet-osv-worklist-<date>.json]
        [--min-severity critical|high|medium|low]
        [--deep-scan-cap 100] [--jobs 8]
        [--ecosystem all|Go,npm,pypi,maven,cargo,ruby,nuget,actions]
        # docker/helm are graph-only (blast-radius), never OSV-swept

Exit 0 on a completed sweep (per-pair API errors are counted, not
fatal); 2 on usage errors.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import re
import sqlite3
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root
from traust.registry.osv_urls import osv_batch_url, osv_vuln_url

OSV_BATCH = osv_batch_url()
OSV_VULN = osv_vuln_url()
BATCH_SIZE = 800
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# Internal ecosystem tag (as it appears on graph edges / pkg: URLs) ->
# the OSV canonical ecosystem name used in the batch-query payload.
OSV_ECOSYSTEM = {
    "Go": "Go",
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    # GitHub Actions advisories (owner/repo, pinned to a tag or commit SHA)
    # are OSV-covered — the same worm class that hits npm hits Actions too.
    "actions": "GitHub Actions",
}

# Blast-radius-only ecosystems: they carry depends_on edges in the
# portfolio graph (so /impact-analysis can compute exposure) but OSV has
# no by-name advisory coverage for them — a batch query would 404/miss.
# They are swept for blast radius, never OSV-queried; `all` excludes them.
GRAPH_ONLY_ECOSYSTEMS = {"docker", "helm"}


def pairs_from_graph(
    db_path: Path,
) -> tuple[
    dict[str, dict[tuple[str, str], set[str]]],
    dict[str, dict[tuple[str, str], dict[str, list[str]]]],
]:
    """(pairs_by_eco, prov_by_eco) from depends_on edges.

    pairs_by_eco is {eco: {(name, version): repo ids}}; prov_by_eco is the
    source-manifest provenance {eco: {(name, version): {repo id: [manifest
    paths]}}} carried from each edge's `manifest` attr (see
    build_portfolio_graph._manifest_attr). Provenance is kept PER-REPO — a
    (name, version) that appears in several repos keeps each repo's own
    manifest list, never flattened across repos — so a hit can name exactly
    where in which repo the dependency is declared.

    Go edges carry dst `module:<path>`, usually no ecosystem attr, and no
    `manifest` attr (Go provenance is implicitly `go.mod`); such edges get
    no prov entry. Non-Go edges carry dst `pkg:<eco>/<name>` (name may itself
    contain '/' for scoped npm like `@scope/x` — split only on the FIRST '/'
    after the `pkg:` prefix) plus `ecosystem` and `manifest` attrs. If
    neither prefix is present the `ecosystem` attr is the fallback and dst is
    the name. Rows without a version are dropped (as before)."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    out: dict[str, dict[tuple[str, str], set[str]]] = {}
    prov: dict[str, dict[tuple[str, str], dict[str, list[str]]]] = {}
    try:
        for src, dst, attrs in con.execute(
            "SELECT src, dst, attrs FROM edges WHERE rel='depends_on'"
        ):
            a = json.loads(attrs or "{}")
            v = a.get("version")
            man = a.get("manifest")  # list of repo-relative paths, or absent
            if dst.startswith("module:"):
                eco, name = "Go", dst.removeprefix("module:")
            elif dst.startswith("pkg:"):
                rest = dst.removeprefix("pkg:")
                eco, _, name = rest.partition("/")
            else:
                eco, name = a.get("ecosystem"), dst
            if v and name and eco:
                out.setdefault(eco, {}).setdefault((name, v), set()).add(src)
                if man:
                    prov.setdefault(eco, {}).setdefault((name, v), {})[src] = list(man)
    finally:
        con.close()
    return out, prov


def _build_batch_body(chunk: list[tuple[str, str]], ecosystem: str) -> dict:
    """The OSV batch-query payload. `ecosystem` is the OSV *canonical*
    name (caller maps via OSV_ECOSYSTEM). Leading-'v' version stripping
    is Go-only — npm/PyPI/crates.io/Maven/RubyGems/NuGet versions are
    used verbatim (their version grammars are not semver-with-v)."""
    strip_v = ecosystem == "Go"
    return {
        "queries": [
            {
                "package": {"name": m, "ecosystem": ecosystem},
                "version": (v.lstrip("v") if strip_v else v),
            }
            for m, v in chunk
        ]
    }


def _post_batch(chunk: list[tuple[str, str]], ecosystem: str, retries: int = 3) -> list[dict]:
    body = json.dumps(_build_batch_body(chunk, ecosystem)).encode()
    req = urllib.request.Request(OSV_BATCH, data=body, headers={"Content-Type": "application/json"})
    for attempt in range(retries):
        try:
            return json.loads(urllib.request.urlopen(req, timeout=60).read())["results"]
        except Exception:
            time.sleep(2 * (attempt + 1))
    return [{} for _ in chunk]


def query_osv_multi(pairs_by_eco: dict, jobs: int, post=_post_batch) -> dict[str, dict]:
    """vuln id -> {"ecosystem": <internal tag>, "pairs": {(name, ver)}}.

    Batches within each ecosystem (BATCH_SIZE), mapping the internal tag
    to the OSV canonical name for the query, and tags every hit with the
    ecosystem that produced it so the worklist rows stay ecosystem-aware.
    `post=` is an injectable seam (tests pass a network-free fake)."""
    hits: dict[str, dict] = {}
    for eco, pairs in pairs_by_eco.items():
        canonical = OSV_ECOSYSTEM.get(eco, eco)
        keys = list(pairs)
        chunks = [keys[i : i + BATCH_SIZE] for i in range(0, len(keys), BATCH_SIZE)]
        if not chunks:
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
            for chunk, results in zip(
                chunks, ex.map(lambda c, e=canonical: post(c, e), chunks), strict=False
            ):
                for (m, v), res in zip(chunk, results, strict=False):
                    for vuln in (res or {}).get("vulns") or []:
                        h = hits.setdefault(vuln["id"], {"ecosystem": eco, "pairs": set()})
                        h["pairs"].add((m, v))
    return hits


def query_osv(
    pairs: dict, ecosystem: str, jobs: int, post=_post_batch
) -> dict[str, set[tuple[str, str]]]:
    """Legacy single-ecosystem shim: vuln id -> hit (name, version) pairs.
    Reimplemented on query_osv_multi; kept for pre-multi-eco callers."""
    multi = query_osv_multi({ecosystem: pairs}, jobs, post=post)
    return {vid: h["pairs"] for vid, h in multi.items()}


def _fetch_vuln(vid: str, retries: int = 3) -> dict | None:
    for attempt in range(retries):
        try:
            return json.loads(urllib.request.urlopen(OSV_VULN.format(vid=vid), timeout=30).read())
        except Exception:
            time.sleep(1 + attempt)
    return None


def sev_band(vuln: dict, malicious: bool = False) -> str:
    """Severity band for an OSV advisory, never raising on missing data.

    Malicious-package advisories (the Shai-Hulud/worm class) carry no
    CVSS — malware is not scored — so they band CRITICAL outright. Else
    the band is OSV's stated database_specific.severity; a missing or
    unrecognised severity is UNKNOWN (the CVE-less-advisory case)."""
    if malicious:
        return "CRITICAL"
    ds = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    return (
        {"MODERATE": "MEDIUM"}.get(ds, ds)
        if ds in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW")
        else "UNKNOWN"
    )


def display_id(vid: str, vuln: dict) -> str:
    """Stable display id for an advisory: the CVE alias when present, else
    the OSV id itself (GHSA-/MAL-/PYSEC-…).

    The CVE-less advisories are exactly the malicious-package/Shai-Hulud
    class — they MUST keep a real id here rather than being dropped for
    lacking a CVE."""
    for a in vuln.get("aliases") or []:
        if isinstance(a, str) and a.startswith("CVE-"):
            return a
    return vid


_MALWARE_HINT = ("malware", "malicious")


def is_malicious(vid: str, vuln: dict) -> bool:
    """Conservative malicious-package (Shai-Hulud/worm class) detector.

    True when the OSV id is a `MAL-` advisory, OR OSV explicitly types the
    record as malware: `database_specific.type` (record-level) or an
    affected package's `ecosystem_specific`/`database_specific` naming
    'malware'/'malicious' (a string field, or an explicit malicious=true).
    Deliberately narrow — a CVSS band or a plain GHSA is NOT malware on
    its own, so a normal advisory never gets force-promoted to CRITICAL."""
    if isinstance(vid, str) and vid.startswith("MAL-"):
        return True
    ds = vuln.get("database_specific") or {}
    if any(h in str(ds.get("type") or "").lower() for h in _MALWARE_HINT):
        return True
    for aff in vuln.get("affected") or []:
        for blk_key in ("ecosystem_specific", "database_specific"):
            blk = aff.get(blk_key) or {}
            for val in (blk.get("type"), blk.get("malicious")):
                if val is True:
                    return True
                if isinstance(val, str) and any(h in val.lower() for h in _MALWARE_HINT):
                    return True
    return False


def fixed_range(
    vuln: dict, module: str, ecosystem: str | None = None
) -> tuple[str | None, str | None]:
    """(introduced, first fixed version) for the module, when stated.

    When `ecosystem` (an internal tag) is given, the affected package's
    OSV ecosystem must match too — an OSV record can carry multiple
    affected packages across ecosystems, and matching on name alone
    would cross-contaminate a same-named package in another ecosystem."""
    osv_eco = OSV_ECOSYSTEM.get(ecosystem, ecosystem) if ecosystem else None
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("name") != module:
            continue
        if osv_eco and pkg.get("ecosystem") and pkg["ecosystem"] != osv_eco:
            continue
        for r in aff.get("ranges", []):
            intro, fixed = None, None
            for e in r.get("events", []):
                intro = e.get("introduced", intro)
                fixed = e.get("fixed", fixed)
            if fixed:
                return intro, fixed
    return None, None


def dedupe_by_cve(details: dict[str, dict]) -> dict[str, tuple[str, dict]]:
    """Advisory dedup keyed by DISPLAY id -> (osv id, detail).

    Key = the CVE alias when the advisory carries one (so GO-/GHSA-
    records aliasing a single CVE collapse into one row), else the OSV id
    itself. Keying on the OSV id for the CVE-less case is the fix for the
    Shai-Hulud blind spot: this used to key on CVE only, so MAL-/CVE-less
    GHSA advisories produced no key and were silently dropped. Across
    collapsed records the highest severity band wins; a malicious-package
    advisory ranks CRITICAL. (Name retained for backward compatibility.)"""
    best: dict[str, tuple[str, dict]] = {}
    for vid, d in details.items():
        key = display_id(vid, d)
        rank = SEV_RANK[sev_band(d, is_malicious(vid, d))]
        cur = best.get(key)
        if cur is None or rank > SEV_RANK[sev_band(cur[1], is_malicious(cur[0], cur[1]))]:
            best[key] = (vid, d)
    return best


# Charset gates for values that end up in worklist argv (assessment
# 2026-07-31 H1): package names and versions from target manifests / OSV
# are attacker-influenceable, so they are gated to argv-hostile-safe
# charsets — NO shell metacharacters, spaces, quotes, backticks, $, ;,
# |, &, or newlines — BEFORE anything command-shaped is built. Per
# ecosystem, since each has its own legal name grammar (scoped npm,
# maven group:artifact, …). Rejected values are surfaced in the
# artifact's rejected_inputs, never silently dropped.
_NAME_RX = {
    "Go": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~/\-]*$"),
    "npm": re.compile(r"^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$"),
    "pypi": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    "maven": re.compile(r"^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$"),
    "cargo": re.compile(r"^[A-Za-z0-9_-]+$"),
    "ruby": re.compile(r"^[A-Za-z0-9._-]+$"),
    "nuget": re.compile(r"^[A-Za-z0-9._-]+$"),
    # GitHub Actions are addressed as owner/repo.
    "actions": re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$"),
}
# OSV advisory ids (CVE-/GHSA-/MAL-/PYSEC-…) become an argv positional and
# a filename component, so gate their charset too (H1): alnum-lead, then
# alnum/dot/underscore/hyphen. A hostile alias never reaches argv.
_ADVISORY_ID_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# A relaxed-but-still-shell-safe version superset covering PEP 440 epochs
# (1!2.3), Maven qualifiers (1.0.0.Final), and prereleases (1.0.0-rc.1) —
# no shell metacharacters, spaces, or quotes.
_VERSION_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!:_~\-]*$")


def _name_ok(ecosystem: str | None, name: str) -> bool:
    """True iff `name` is legal for `ecosystem` AND argv-hostile-safe.
    Unknown ecosystems fail closed."""
    rx = _NAME_RX.get(ecosystem)
    return bool(rx and rx.match(name))


def _version_ok(ecosystem: str | None, version: str) -> bool:
    """Argv-hostile-safe version check (charset superset across
    ecosystems). `ecosystem` is accepted for symmetry / future
    per-ecosystem tightening. The superset already admits GitHub Actions
    pins — semver tags, `v4`-style major tags, and 40-hex commit SHAs are
    all plain alnum(+dot) and pass."""
    return bool(_VERSION_RX.match(str(version)))


def build_worklist(
    by_cve: dict,
    hits: dict,
    pairs_by_eco: dict,
    min_rank: int,
    deep_cap: int,
    prov_by_eco: dict | None = None,
    *,
    results_root: Path | None = None,
) -> tuple[list[dict], list[dict]]:
    # `prov_by_eco` is the source-manifest provenance from pairs_from_graph
    # ({eco: {(name, version): {repo id: [manifest paths]}}}). It is metadata
    # only — a `manifest` field surfaced on each command and rejected_inputs
    # row so an escalation names exactly where the dependency is declared. It
    # is NEVER injected into impact_argv (argv stays argv-array-only, H1).
    # Optional so pre-provenance callers keep working.
    prov_by_eco = prov_by_eco or {}
    # Library callers (unit tests) may omit results_root; CLI always passes it.
    root = results_root or Path("analysis-results")
    graph_db = root / "graph" / "portfolio-graph.db"
    impact_dir = root / "impact"
    # Accept the legacy single-ecosystem shapes (a flat {(name,ver): repos}
    # `pairs` and hits values that are bare pair-sets) so pre-multi-eco
    # callers keep working; their ecosystem defaults to Go.
    if pairs_by_eco and all(isinstance(k, tuple) for k in pairs_by_eco):
        pairs_by_eco = {"Go": pairs_by_eco}
    rows = []
    rejected: list[dict] = []
    for disp, (vid, d) in by_cve.items():
        mal = is_malicious(vid, d)
        band = sev_band(d, mal)
        if SEV_RANK[band] < min_rank:
            continue
        # The display id itself becomes an argv positional and a filename
        # component (H1) — gate it before anything command-shaped exists.
        if not _ADVISORY_ID_RX.match(str(disp)):
            rejected.append(
                {"advisory": vid, "display_id": str(disp), "reason": "advisory id charset"}
            )
            continue
        raw = hits.get(vid)
        if isinstance(raw, dict) and "pairs" in raw:
            eco, pair_set = (raw.get("ecosystem") or "Go"), raw["pairs"]
        else:
            eco, pair_set = "Go", (raw or set())
        eco_pairs = pairs_by_eco.get(eco, {})
        eco_prov = prov_by_eco.get(eco, {})
        repos = set()
        for p in pair_set:
            repos.update(eco_pairs.get(p, set()))
        modules = sorted({m for m, _ in pair_set})
        cmds = []
        for m in modules:
            # Source-manifest provenance for THIS module, kept per-repo:
            # {repo id: [sorted manifest paths]}. Unioned across the (m, v)
            # pairs that hit for this module; each repo keeps its own paths
            # (never flattened across repos). Empty for Go (implicit go.mod).
            man_by_repo: dict[str, set] = {}
            for pn, pv in pair_set:
                if pn != m:
                    continue
                for repo, paths in eco_prov.get((pn, pv), {}).items():
                    man_by_repo.setdefault(repo, set()).update(paths)
            manifest = {repo: sorted(paths) for repo, paths in man_by_repo.items()}
            _intro, fixed = fixed_range(d, m, eco)
            # A CVSS advisory needs a fixed version to build a remediation
            # command; a malicious package has none (the fix is removal)
            # yet MUST still produce a row — never drop malware for lacking
            # a fixed version.
            if not fixed and not mal:
                continue
            # Charset validation before anything command-shaped exists
            # (assessment 2026-07-31 H1) — tagged with ecosystem so the
            # rejected_inputs row is attributable. A malicious package name
            # that fails the gate is rejected here, never emitted to argv.
            if not _name_ok(eco, m):
                rejected.append(
                    {
                        "cve": disp,
                        "ecosystem": eco,
                        "module": m,
                        "malicious": mal,
                        "manifest": manifest,
                        "reason": "module charset",
                    }
                )
                continue
            if fixed and not _version_ok(eco, fixed):
                rejected.append(
                    {
                        "cve": disp,
                        "ecosystem": eco,
                        "module": m,
                        "version": str(fixed),
                        "malicious": mal,
                        "manifest": manifest,
                        "reason": "version charset",
                    }
                )
                continue
            deep = len(repos) <= deep_cap
            if fixed:
                vuln_range = f"< {fixed}"
                fixed_args = ["--fixed-version", str(fixed)]
            else:
                # Malware has no fixed version — the whole package is
                # compromised, so flag every version and carry no target.
                vuln_range, fixed_args = "*", []
            impact_out = impact_dir / f"{disp.lower()}-impact-analysis.json"
            impact_argv = (
                [
                    sys.executable,
                    "-m",
                    "traust.cli",
                    "impact",
                    "analyze",
                    disp,
                    "--module",
                    m,
                    "--ecosystem",
                    eco,
                    "--vulnerable-range",
                    vuln_range,
                ]
                + fixed_args
                + [
                    "--feature-desc",
                    "malicious-package" if mal else "fleet-osv-sweep",
                    "--db",
                    str(graph_db),
                    "--out",
                    str(impact_out),
                    "--jobs",
                    "4",
                ]
                + ([] if deep else ["--skip-scan"])
            )
            route_argv = (
                [
                    "python3",
                    "-m",
                    "traust.cli.route_impact_findings",
                    str(impact_out),
                    "--severity",
                    band.lower(),
                ]
                if deep
                else None
            )
            # argv arrays ONLY — a consumer that joins these into a
            # shell string re-opens H1; run them with subprocess(list)
            # or safe_exec, never bash -c.
            cmds.append(
                {
                    "module": m,
                    "impact_argv": impact_argv,
                    "route_argv": route_argv,
                    "deep": deep,
                    # provenance metadata only — NOT in impact_argv
                    "manifest": manifest,
                }
            )
        if cmds:
            rows.append(
                {
                    "id": disp,
                    "cve": disp if str(disp).startswith("CVE-") else None,
                    "osv": vid,
                    "malicious": mal,
                    "severity": band,
                    "ecosystem": eco,
                    "summary": (d.get("summary") or "")[:160],
                    "modules": modules,
                    "in_range_repos": len(repos),
                    # row-level provenance rollup: {module: {repo: paths}}
                    "manifest": {c["module"]: c["manifest"] for c in cmds},
                    "commands": cmds,
                }
            )
    # Malicious rows sort to the TOP regardless of CVSS (malware has none),
    # then by severity band, then by blast radius.
    rows.sort(
        key=lambda r: (0 if r["malicious"] else 1, -SEV_RANK[r["severity"]], -r["in_range_repos"])
    )
    return rows, rejected


def _load_verify_dep():
    """Lazily load scripts/verify_dep_provenance.verify_dep. Kept out of the
    default (non-`--verify`) path so its import + the gh-api fetcher it wraps
    never load unless auto-verification is explicitly requested."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "verify_dep_provenance", Path(__file__).resolve().parent / "verify_dep_provenance.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.verify_dep


def verify_worklist(worklist: list[dict], hits: dict, verify=None) -> tuple[list[dict], list[dict]]:
    """Auto-verify each MALICIOUS worklist row against its recorded
    source-manifest provenance BEFORE emission (the alias/false-positive
    guard — e.g. an npm `"x":"npm:real@ver"` alias that OSV name-matched).

    Returns (kept, refuted). Each malicious row is checked per (repo, module)
    via verify_dep and annotated with `verification: {status, evidence,
    checks}`. Verdict rollup, fail-safe: a row with ANY confirmation stays
    actionable (`confirmed`); a row with NO confirmation and at least one
    positive `refuted` is moved to `refuted` with its reason (never emitted
    as a live finding, never silently dropped); anything else — including a
    malicious hit carrying no manifest provenance — stays actionable
    (`unverifiable`). Non-malicious rows pass through untouched. `verify=`
    is the injectable verify_dep seam (tests pass a network-free fake)."""
    if verify is None:
        verify = _load_verify_dep()
    kept: list[dict] = []
    refuted: list[dict] = []
    for row in worklist:
        if not row.get("malicious"):
            kept.append(row)
            continue
        eco = row.get("ecosystem") or "Go"
        raw = hits.get(row.get("osv"))
        pair_set = raw.get("pairs") if isinstance(raw, dict) and "pairs" in raw else (raw or set())
        ver_by_mod: dict[str, str] = {}
        for pn, pv in pair_set:
            ver_by_mod.setdefault(pn, pv)
        checks: list[dict] = []
        for module, per_repo in (row.get("manifest") or {}).items():
            for repo, paths in (per_repo or {}).items():
                res = verify(repo, eco, module, ver_by_mod.get(module, ""), paths)
                checks.append(
                    {
                        "repo": repo,
                        "module": module,
                        "status": res.get("status"),
                        "evidence": res.get("evidence"),
                        "manifest": res.get("manifest"),
                    }
                )
        statuses = {c["status"] for c in checks}
        if not checks:
            status, evidence = (
                "unverifiable",
                "no source-manifest provenance recorded for this malicious hit",
            )
        elif "confirmed" in statuses:
            status = "confirmed"
            evidence = next(c["evidence"] for c in checks if c["status"] == "confirmed")
        elif "refuted" in statuses:
            status = "refuted"
            evidence = next(c["evidence"] for c in checks if c["status"] == "refuted")
        else:
            status = "unverifiable"
            evidence = next((c["evidence"] for c in checks), "")
        row["verification"] = {"status": status, "evidence": evidence, "checks": checks}
        (refuted if status == "refuted" else kept).append(row)
    return kept, refuted


def main(argv=None, post=_post_batch) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root", type=Path, default=None, help="analysis-results dir (default: configured)"
    )
    ap.add_argument(
        "--graph-db",
        type=Path,
        default=None,
        help="portfolio graph (default: <results-root>/graph/portfolio-graph.db)",
    )
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--min-severity", default="critical", choices=["critical", "high", "medium", "low"]
    )
    ap.add_argument(
        "--deep-scan-cap",
        type=int,
        default=100,
        help="CVEs with more in-range repos than this get "
        "graph-only commands; deep scans are staged "
        "by the operator",
    )
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument(
        "--verify",
        action="store_true",
        help="auto-verify each MALICIOUS hit against its "
        "recorded source manifest(s) before emission "
        "(alias/false-positive guard); a refuted hit is "
        "moved to refuted_findings with a paper trail. "
        "Adds gh-api raw fetches (network) — off by "
        "default.",
    )
    ap.add_argument(
        "--ecosystem",
        default="all",
        help="Comma list (Go,npm,pypi,maven,cargo,ruby,"
        "nuget,actions) or 'all' — filters the "
        "ecosystems present in the graph. docker/helm "
        "are graph-only (blast-radius) and never "
        "OSV-swept; 'all' means the OSV-supported set.",
    )
    args = ap.parse_args(argv)

    results = resolve_results_root(args)
    graph_db = args.graph_db or results / "graph" / "portfolio-graph.db"
    today = datetime.date.today().isoformat()
    out = args.out or (results / "impact" / f"fleet-osv-worklist-{today}.json")

    pairs_by_eco, prov_by_eco = pairs_from_graph(graph_db)
    present = sorted(pairs_by_eco)
    if args.ecosystem.strip().lower() == "all":
        selected = present
    else:
        want = {e.strip().lower() for e in args.ecosystem.split(",") if e.strip()}
        selected = [e for e in present if e.lower() in want]
    # docker/helm carry blast-radius edges but have no OSV-by-name
    # coverage — an OSV query would 404/miss. Sweep them for exposure
    # only; never query. `all` therefore means the OSV-supported set.
    graph_only = [e for e in selected if e.lower() in GRAPH_ONLY_ECOSYSTEMS]
    if graph_only:
        print(
            "[i] docker/helm are graph-only (blast-radius), not "
            f"OSV-swept; skipping for OSV: {', '.join(sorted(graph_only))}",
            file=sys.stderr,
        )
    selected = [e for e in selected if e.lower() not in GRAPH_ONLY_ECOSYSTEMS]
    pairs_by_eco = {e: pairs_by_eco[e] for e in selected}
    prov_by_eco = {e: prov_by_eco[e] for e in selected if e in prov_by_eco}
    per_eco_counts = {e: len(pairs_by_eco[e]) for e in selected}
    total_pairs = sum(per_eco_counts.values())
    print(
        f"[+] {total_pairs} unique (name, version) pairs across "
        f"{len(selected)} ecosystem(s): " + " ".join(f"{e}:{n}" for e, n in per_eco_counts.items()),
        file=sys.stderr,
    )
    hits = query_osv_multi(pairs_by_eco, args.jobs, post=post)
    print(f"[+] {len(hits)} vulnerability records hit the fleet", file=sys.stderr)

    details = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for vid, v in zip(hits, ex.map(_fetch_vuln, list(hits)), strict=False):
            if v:
                details[vid] = v
    by_cve = dedupe_by_cve(details)
    bands = Counter(sev_band(d, is_malicious(vid, d)) for vid, d in by_cve.values())
    malicious_count = sum(1 for vid, d in by_cve.values() if is_malicious(vid, d))
    print(
        f"[+] {len(by_cve)} distinct advisories "
        f"({malicious_count} malicious-package) — "
        + " ".join(f"{k}:{v}" for k, v in sorted(bands.items(), key=lambda kv: -SEV_RANK[kv[0]])),
        file=sys.stderr,
    )

    min_rank = SEV_RANK[args.min_severity.upper()]
    worklist, rejected = build_worklist(
        by_cve,
        hits,
        pairs_by_eco,
        min_rank,
        args.deep_scan_cap,
        prov_by_eco=prov_by_eco,
        results_root=results,
    )
    refuted_findings: list[dict] = []
    if args.verify:
        worklist, refuted_findings = verify_worklist(worklist, hits)
        print(
            f"[+] --verify: {len(refuted_findings)} malicious hit(s) "
            f"refuted against source manifests (moved out of the "
            f"actionable worklist)",
            file=sys.stderr,
        )
    doc = {
        "artifact": "fleet-osv-worklist",
        "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "graph_db": str(graph_db),
        "ecosystems": selected,
        "graph_only_ecosystems": sorted(graph_only),
        "pairs_by_ecosystem": per_eco_counts,
        "pairs_queried": total_pairs,
        "distinct_advisories": len(by_cve),
        "distinct_cves": len(by_cve),
        "malicious_advisories": malicious_count,
        "severity_bands": dict(bands),
        "min_severity": args.min_severity,
        "deep_scan_cap": args.deep_scan_cap,
        "worklist": worklist,
        # malicious hits auto-refuted against their source manifests
        # (--verify) — false positives (e.g. npm aliases) dropped from the
        # actionable worklist WITH a paper trail, never silently
        "refuted_findings": refuted_findings,
        # rows dropped by the H1 charset gates — visible, never silent
        "rejected_inputs": rejected,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(
        f"[+] wrote {out} ({len(worklist)} worklist rows, "
        f"{len(refuted_findings)} refuted, "
        f"{len(rejected)} rejected inputs)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
