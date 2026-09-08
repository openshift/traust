#!/usr/bin/env python3
"""
build_executive_summary.py — Executive roll-up harness for security-audit reports.

Walks <results-root>/findings/ and <results-root>/oss-findings/, ingests every
*security-audit.json (preferred) or *security-audit.md (fallback), correlates
against <results-root>/findings/_manifest/gh-languages-cache.jsonl, and emits
under <results-root>/:

  • Executive-summary-findings.md   — leadership one-pager
  • Executive-summary-findings.html — self-contained dashboard (Chart.js CDN)

Re-runnable: idempotent, no external state beyond the two output files.

Usage:
  build_executive_summary.py [--results-root DIR] [--open]
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import csv
import datetime as _dt
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from traust_engine.escaping import json_script, md_cell

from traust.context import (
    add_config_home_arg,
    inputs_dir,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)
from traust.inventory import load_descriptor

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

SEVERITIES = ("critical", "high", "medium", "low", "informational")

# CWEs that indicate a secret / credential committed to or surfaced by code.
CREDENTIAL_CWES = {
    "CWE-798",  # Hard-coded credentials
    "CWE-259",  # Hard-coded password
    "CWE-321",  # Hard-coded crypto key
    "CWE-547",  # Hard-coded security-relevant constants
    "CWE-256",  # Plaintext storage of password
    "CWE-312",  # Cleartext storage of sensitive info
    "CWE-313",  # Cleartext storage in file/disk
    "CWE-522",  # Insufficiently protected credentials
    "CWE-540",  # Source code containing sensitive info
    "CWE-260",  # Password in config file
    "CWE-1392",  # Default credentials
}

CREDENTIAL_TITLE_RX = re.compile(
    r"(hard.?cod|default (?:cred|password)|committed (?:secret|cred|key|token)"
    r"|secret in |private key|api[- ]?key|access[- ]?token in"
    r"|credential leak|leaked (?:secret|token|cred)|\.env|kubeconfig committed"
    r"|password in (?:source|repo|code|config))",
    re.I,
)

# Theme buckets keyed on CWE → human label.
THEME_MAP = {
    # Injection / RCE
    "CWE-77": "Command / Code Injection",
    "CWE-78": "Command / Code Injection",
    "CWE-94": "Command / Code Injection",
    "CWE-1336": "Command / Code Injection",
    "CWE-89": "SQL / Query Injection",
    "CWE-943": "SQL / Query Injection",
    # Path / file
    "CWE-22": "Path Traversal & Arbitrary File Access",
    "CWE-23": "Path Traversal & Arbitrary File Access",
    "CWE-59": "Path Traversal & Arbitrary File Access",
    "CWE-73": "Path Traversal & Arbitrary File Access",
    # Secrets
    "CWE-798": "Hard-coded / Leaked Secrets",
    "CWE-259": "Hard-coded / Leaked Secrets",
    "CWE-321": "Hard-coded / Leaked Secrets",
    "CWE-522": "Hard-coded / Leaked Secrets",
    "CWE-540": "Hard-coded / Leaked Secrets",
    "CWE-256": "Hard-coded / Leaked Secrets",
    "CWE-312": "Hard-coded / Leaked Secrets",
    "CWE-1392": "Hard-coded / Leaked Secrets",
    # Crypto
    "CWE-327": "Weak / Broken Cryptography",
    "CWE-326": "Weak / Broken Cryptography",
    "CWE-338": "Weak / Broken Cryptography",
    "CWE-330": "Weak / Broken Cryptography",
    # AuthN/Z
    "CWE-287": "Broken Authentication",
    "CWE-306": "Broken Authentication",
    "CWE-862": "Missing / Broken Authorization",
    "CWE-863": "Missing / Broken Authorization",
    "CWE-269": "Missing / Broken Authorization",
    "CWE-284": "Missing / Broken Authorization",
    "CWE-639": "Missing / Broken Authorization",
    # SSRF / Deserialization
    "CWE-918": "SSRF",
    "CWE-502": "Insecure Deserialization",
    "CWE-915": "Insecure Deserialization",
    # TLS / transport
    "CWE-295": "TLS / Certificate Validation",
    "CWE-319": "TLS / Certificate Validation",
    "CWE-297": "TLS / Certificate Validation",
    # K8s / RBAC / supply-chain
    "CWE-250": "Excessive Privilege / RBAC",
    "CWE-266": "Excessive Privilege / RBAC",
    "CWE-732": "Insecure File / Resource Permissions",
    "CWE-1357": "Supply-Chain / CI-CD Hardening",
    "CWE-494": "Supply-Chain / CI-CD Hardening",
    "CWE-829": "Supply-Chain / CI-CD Hardening",
    "CWE-1104": "Supply-Chain / CI-CD Hardening",
    # XSS / web
    "CWE-79": "Cross-Site Scripting",
    "CWE-352": "CSRF",
    # Info disclosure / DoS
    "CWE-200": "Sensitive Information Disclosure",
    "CWE-209": "Sensitive Information Disclosure",
    "CWE-532": "Sensitive Data in Logs",
    "CWE-400": "Resource Exhaustion / DoS",
    "CWE-770": "Resource Exhaustion / DoS",
    "CWE-1333": "Resource Exhaustion / DoS",
}

REPO_URL_RX = re.compile(
    r"https?://(?:github\.com|gitlab\.com|gitlab\.cee\.redhat\.com)/([\w.\-]+)/([\w.\-]+)"
)

# ---------------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------------


def harness_version() -> str:
    """Return '<VERSION>-<short-sha>' for the traust checkout."""
    here = Path(__file__).resolve()
    for p in here.parents:
        vf = p / "VERSION"
        if vf.is_file():
            ver = vf.read_text(encoding="utf-8").strip()
            try:
                sha = subprocess.run(
                    ["git", "-C", str(p), "rev-parse", "--short", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
                return f"{ver}-{sha}"
            except (subprocess.CalledProcessError, FileNotFoundError):
                return ver
    return "unknown"


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def load_attack_coverage(dash) -> dict | None:
    """MITRE ATT&CK coverage roll-up (attack-coverage skill), if built.
    Reads the Navigator layer (structured, no markdown scraping) and
    resolves technique names/tactics from the pinned vendored table."""
    if not dash:
        return None
    p = Path(dash) / "attack-coverage" / "attack-navigator-layer.json"
    try:
        layer = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    techs = layer.get("techniques") or []
    meta = {m.get("name"): m.get("value") for m in layer.get("metadata") or []}
    names, tactics_of = {}, {}
    try:
        tt = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "attack-coverage"
                / "tables"
                / "attack-techniques.json"
            ).read_text(encoding="utf-8")
        )
        names = {k: v.get("name") for k, v in tt.get("techniques", {}).items()}
        tactics_of = {k: v.get("tactics", []) for k, v in tt.get("techniques", {}).items()}
    except (OSError, json.JSONDecodeError):
        pass
    observed = sorted(
        (t for t in techs if t.get("score") == 3), key=lambda t: t.get("techniqueID", "")
    )

    def _n(key, fallback):
        try:
            return int(meta[key])
        except (KeyError, TypeError, ValueError):
            return fallback

    return {
        # exact class counts come from the layer metadata (scores overlap
        # classes); score-based numbers are only the legacy-layer fallback
        "covered": _n("techniques_covered", len(techs)),
        "observed": [
            {
                "id": t["techniqueID"],
                "name": names.get(t["techniqueID"], ""),
                "comment": t.get("comment", ""),
            }
            for t in observed
        ],
        "modeled": _n("techniques_modeled", sum(1 for t in techs if t.get("score") == 2)),
        "derived": _n("techniques_derived", sum(1 for t in techs if t.get("score") == 1)),
        "tactics": _n(
            "tactics_covered",
            len({tac for t in techs for tac in tactics_of.get(t.get("techniqueID"), [])}),
        ),
        "attack_version": meta.get("attack_version", "?"),
    }


def load_pqc_readiness(dash) -> dict | None:
    """PQC readiness roll-up (pqc-readiness skill, plan v1.3 Phase 2).
    Reads the Phase-2 portfolio-rollup sidecar (structured, no markdown
    scraping) plus the sweep dashboard sidecar for coverage; returns None
    until the roll-up has been built."""
    if not dash:
        return None
    base = Path(dash) / "pqc"
    try:
        roll = json.loads((base / "pqc-portfolio-rollup.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    cov = {}
    with contextlib.suppress(OSError, json.JSONDecodeError):
        cov = json.loads((base / "pqc-dashboard.json").read_text(encoding="utf-8"))
    clock = roll.get("clock_2030") or []
    return {
        "reports": roll.get("reports", 0),
        "coverage_pct": cov.get("sweep_coverage_pct") or cov.get("coverage_pct"),
        "buckets": roll.get("buckets") or {},
        "median": roll.get("median_score"),
        "clock_2030_items": len(clock),
        "clock_2030_repos": len({r.get("repo") for r in clock}),
        "clock_2030_significant": [r for r in clock if r.get("effort") == "significant"],
        "clock_2035_items": roll.get("clock_2035_count", 0),
        "hndl": roll.get("hndl") or [],
        "hybrid_blockers": len(roll.get("hybrid_blockers") or []),
        "quickwins": len(roll.get("toolchain_quickwins") or []),
        "fips_matrix": roll.get("fips_matrix") or {},
        "blocked_external": roll.get("blocked_external") or [],
        "products": roll.get("products") or [],
    }


def load_least_priv(dash) -> dict | None:
    """Operator least-privilege posture roll-up (/operator-priv-profile,
    static tiers 1-2). POSTURE, not findings: privilege profiles are
    ratings of declared privilege and stay out of the finding counts
    (census remains the denominator authority); escalation-worthy
    violations promote individually via triage. Returns None until the
    roll-up has been built."""
    if not dash:
        return None
    path = Path(dash) / "operator-least-priv" / "priv-profile-rollup.json"
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(rows, list) or not rows:
        return None
    flags: dict[str, int] = {}
    for r in rows:
        for k, v in (r.get("rbac_risk_flags") or {}).items():
            flags[k] = flags.get(k, 0) + (v or 0)
    surplus_rows = [r for r in rows if isinstance(r.get("surplus"), int)]
    return {
        "profiles": len(rows),
        "privileged": sum(
            1
            for r in rows
            if r.get("privileged_containers") or r.get("privileged_or_host_workloads")
        ),
        "scc_requesting": sum(1 for r in rows if r.get("scc_requests")),
        "wildcard_repos": sum(1 for r in rows if r.get("wildcard_rules")),
        "wildcard_rules": sum(r.get("wildcard_rules") or 0 for r in rows),
        "flags": sorted(flags.items(), key=lambda kv: -kv[1]),
        "surplus_scored": len(surplus_rows),
        "top_surplus": sorted(surplus_rows, key=lambda r: -r["surplus"])[:10],
    }


def load_isolation(results_root: Path) -> dict | None:
    """Tenant-isolation posture reviews (/isolation-review, PEACH lens).
    POSTURE, not findings — dimension scores stay out of the finding
    counts; escalation-worthy gaps promote individually via triage.
    Returns None until reports land under analysis-results/isolation/."""
    root = results_root / "isolation"
    if not root.is_dir():
        return None
    services = []
    for rj in sorted(root.rglob("*-isolation-review.json")):
        if rj.is_symlink() or "_manifest" in rj.parts:
            continue
        try:
            rep = json.loads(rj.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        post = rep.get("posture") or {}
        services.append(
            {
                "service": (rep.get("metadata") or {}).get("service") or rj.parent.name,
                "overall": post.get("overall"),
                "interfaces": post.get("interfaces_reviewed") or len(rep.get("interfaces") or []),
                "gaps": len(rep.get("gaps") or []),
            }
        )
    if not services:
        return None
    scored = [s for s in services if isinstance(s["overall"], (int, float))]
    return {
        "services": services,
        "interfaces": sum(s["interfaces"] or 0 for s in services),
        "gaps": sum(s["gaps"] for s in services),
        "worst": sorted(scored, key=lambda s: s["overall"])[:5],
    }


def load_cloud_config(results_root: Path) -> dict | None:
    """Declared-layer IaC cloud-config audits (analysis-results/
    cloud-config/, /cloud-config-audit skill). A SEPARATE unit —
    hardening-class posture from IaC at rest, no live observation —
    rendered as its own labeled section, never merged into the
    code-audit totals above it."""
    root = results_root / "cloud-config"
    if not root.is_dir():
        return None
    out = {
        "reports": 0,
        "findings": 0,
        "suppressed": 0,
        "ledgered": 0,
        "by_severity": {},
        "targets": [],
    }
    for rj in sorted(root.rglob("*-cloud-config-audit.json")):
        if rj.is_symlink() or "_manifest" in rj.parts:
            continue
        try:
            rep = json.loads(rj.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out["reports"] += 1
        target = (rep.get("metadata") or {}).get("target") or rj.parent.name
        n = 0
        for f in rep.get("findings") or []:
            if f.get("status") == "suppressed":
                out["suppressed"] += 1
                continue
            n += 1
            sev = str(f.get("severity") or "informational").lower()
            out["by_severity"][sev] = out["by_severity"].get(sev, 0) + 1
        out["findings"] += n
        out["targets"].append((target, n))
        if (
            rj.parent / rj.name.replace("cloud-config-audit.json", "findings-layer.json")
        ).is_file():
            out["ledgered"] += 1
    if not out["reports"]:
        return None
    out["targets"].sort(key=lambda t: -t[1])
    return out


def load_language_cache(path: str) -> dict[str, str]:
    """repo 'org/name' (lowercased) → primary language."""
    cache: dict[str, str] = {}
    if not os.path.isfile(path):
        return cache
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            langs = rec.get("languages") or {}
            if not langs:
                continue
            primary = max(langs.items(), key=lambda kv: kv[1])[0]
            cache[rec["repo"].lower()] = primary
    return cache


def repo_slug(url: str | None) -> str | None:
    if not url:
        return None
    m = REPO_URL_RX.search(url)
    if not m:
        return None
    org, name = m.group(1), m.group(2)
    name = re.sub(r"\.git$", "", name)
    return f"{org}/{name}".lower()


# ---------------------------------------------------------------------------
# input-segment mapping (the inputs inventory — locations.inputs)
# ---------------------------------------------------------------------------

# When a repo ships in more than one segment, the breakdown assigns it to the
# FIRST matching segment in this order so segment totals stay additive
# (a partition, not a multi-count). Overlap counts are reported alongside.
# The order is the inventory descriptor's declaration order
# (<inputs>/inventory.yaml, see traust.inventory); undeclared segments follow
# by name. Set from the resolved inputs root in main().
SEGMENT_PRIORITY: list[str] = []


def set_segment_priority(inputs_root: Path | None, exclude: list[str] = ()) -> None:
    global SEGMENT_PRIORITY
    present = []
    if inputs_root and Path(inputs_root).is_dir():
        present = [
            d.name
            for d in Path(inputs_root).iterdir()
            if d.is_dir() and not d.name.startswith(".") and d.name not in exclude
        ]
    SEGMENT_PRIORITY = load_descriptor(inputs_root).priority(present)


UNMAPPED_SEGMENT = "unmapped"


def canon_repo(url: str | None) -> str | None:
    """host/org/repo canonical form (same normalisation as repo-graph)."""
    if not url or not url.strip():
        return None
    u = url.strip().rstrip("/").removesuffix(".git")
    m = re.match(r"https?://([^/]+)/([^/]+)/([^/?#]+)", u)
    if m:
        return f"{m.group(1)}/{m.group(2)}/{m.group(3)}".lower()
    m = re.match(r"git@([^:]+):([^/]+)/(.+)", u)
    if m:
        return f"{m.group(1)}/{m.group(2)}/{m.group(3)}".lower()
    return None


def resolve_inputs_root(cli_arg: str | None, engine) -> Path | None:
    for cand in (cli_arg, inputs_dir(engine)):
        if cand and Path(cand).is_dir():
            return Path(cand)
    return None


def load_segment_map(inputs_root: Path, exclude: list[str]) -> dict[str, list[str]]:
    """canonical repo URL -> sorted list of input segments it appears in.

    Walks every `*-repos.csv` under each top-level segment directory of
    the inputs inventory (owners*.csv skipped; excluded segments —
    ansible by default — skipped entirely)."""
    seg_map: dict[str, set[str]] = collections.defaultdict(set)
    for segdir in sorted(inputs_root.iterdir()):
        if not segdir.is_dir() or segdir.name.startswith(".") or segdir.name in exclude:
            continue
        for csvp in segdir.rglob("*-repos.csv"):
            if csvp.name.startswith("owners"):
                continue
            try:
                with csvp.open(newline="", encoding="utf-8") as fh:
                    for row in csv.DictReader(fh):
                        c = canon_repo(row.get("GitHub URL") or row.get("URL"))
                        if c:
                            seg_map[c].add(segdir.name)
            except (OSError, csv.Error) as e:
                print(f"[!] skipping unreadable {csvp}: {e}", file=sys.stderr)
    return {k: sorted(v) for k, v in seg_map.items()}


def primary_segment(segments: list[str]) -> str | None:
    for s in SEGMENT_PRIORITY:
        if s in segments:
            return s
    return segments[0] if segments else None


_FI = None


def _finding_identity():
    """Soft-load the traust_engine.ledger identity functions for fingerprint computation —
    findings-current ledgers predate the fingerprint backfill, so most
    lack the field and it must be recomputed exactly as the census does.
    Fail-soft: fingerprint dedup degrades to the (repo, title) fallback."""
    global _FI
    if _FI is None:
        try:
            import importlib

            _FI = importlib.import_module("traust_engine._util.finding_identity")
        except Exception as e:
            print(
                f"[!] finding_identity unavailable ({e}); fingerprint "
                f"dedup degrades to (repo, title)",
                file=sys.stderr,
            )
            _FI = False
    return _FI or None


def _fp(f: dict, meta: dict) -> str:
    fi = _finding_identity()
    if fi is None:
        return ""
    # computed even for location-less findings (paths=[]) — identical to
    # the census's fp_key so the two distinct headlines can never diverge
    return fi.fingerprint(f, meta.get("repository"))


def parse_json_report(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    meta = data.get("metadata", {}) or {}
    summ = data.get("executive_summary") or {}
    counts = summ.get("severity_counts") or {}
    findings_raw = data.get("findings") or []
    # Cumulative reports (*-findings-current.json from the track-findings
    # skill) carry per-finding disposition blocks: exclude human-refuted
    # false positives from all aggregates and track remediation progress.
    dispositioned = "disposition_summary" in data
    fp_excluded = 0
    hardening_count = 0
    hardening_findings = []
    resolution_counts = collections.Counter()
    remediations = []  # one entry per resolved/partially_resolved finding
    findings = []
    for f in findings_raw:
        if dispositioned and f.get("validation_status") == "false_positive":
            fp_excluded += 1
            continue
        if dispositioned and f.get("validation_status") == "hardening":
            # Risk-bearing posture debt (docs/disposition-ledger.md §7) —
            # tracked in its own bucket and λ-weighted by findings-trends,
            # but never counted as a confirmed vulnerability in the
            # leadership severity aggregates. Details are retained so the
            # dashboard can render a dedicated backlog section — posture
            # debt must stay visible, never silently vanish from the page.
            hardening_count += 1
            hardening_findings.append(
                {
                    "severity": (f.get("severity") or "").lower(),
                    "cwes": [c.upper() for c in (f.get("cwes") or [])],
                }
            )
            continue
        sev = (f.get("severity") or "").lower()
        disp = f.get("disposition") or {}
        if dispositioned:
            resolution_counts[disp.get("resolution") or "open"] += 1
            if disp.get("resolution") in ("resolved", "partially_resolved"):
                remediations.append(
                    {
                        "month": (disp.get("last_updated") or "")[:7],
                        "severity": sev,
                        "resolution": disp["resolution"],
                    }
                )
        srcs = f.get("source_findings") or []
        cve_ref = next((str(x) for x in srcs if str(x).startswith("CVE-")), None)
        findings.append(
            {
                "id": f.get("id") or "",
                "origin": f.get("origin"),
                "cve": cve_ref,
                "title": f.get("title") or "",
                "severity": sev,
                "cwes": [c.upper() for c in (f.get("cwes") or [])],
                "cvss": (f.get("cvss") or {}).get("score"),
                "resolution": disp.get("resolution"),
                "fingerprint": f.get("fingerprint") or _fp(f, meta),
                # disposition.validity is authoritative where present (older
                # cumulative files may lack the mirrored validation_status)
                "validation_status": disp.get("validity") or f.get("validation_status") or "",
            }
        )
    if dispositioned:
        # severity_counts predate dispositions — recompute without the FPs
        counts = collections.Counter(f["severity"] for f in findings if f["severity"])
    add = meta.get("additional") or {}
    rtype = add.get("resource_type") or ""
    return {
        "source": path,
        "repository": meta.get("repository"),
        "org": add.get("org"),
        "resource_type": rtype,
        "counts": {s: int(counts.get(s, 0) or 0) for s in SEVERITIES},
        "findings": findings,
        "dispositioned": dispositioned,
        "fp_excluded": fp_excluded,
        "hardening_count": hardening_count,
        "hardening_findings": hardening_findings,
        "resolution_counts": dict(resolution_counts),
        "remediations": remediations,
    }


# --- markdown fallback ------------------------------------------------------

_MD_FIND_HDR_RX = re.compile(r"^#{2,4}\s+(FIND-[\w./-]+)\s+[—–-]\s+(.+?)\s*$")
_MD_SEV_INLINE_RX = re.compile(
    r"\|\s*\**Severity\**\s*\|\s*\**\s*(Critical|High|Medium|Low|Informational)\b", re.I
)
_MD_SEV_BULLET_RX = re.compile(
    r"^[-*]\s*\**(?:Severity|CVSS[^:]*)\**\s*:?.*\b(Critical|High|Medium|Low|Informational)\b", re.I
)
_MD_CWE_RX = re.compile(r"CWE-\d{1,5}")
_MD_REPO_RX = re.compile(r"^\|?\s*\**Repository\**\s*\|?\s*[:|]?\s*(https?://\S+)", re.I)
_MD_LANG_ROW_RX = re.compile(
    r"^\|?\s*\**(?:Primary\s+)?Language(?:\s*/\s*framework)?\**\s*\|\s*([^|]+)\|", re.I
)
_MD_TOTALS_RX = re.compile(
    r"(\d+)\s*Critical\s*[·•|,]\s*(\d+)\s*High\s*[·•|,]\s*(\d+)\s*Medium\s*[·•|,]\s*(\d+)\s*Low"
    r"(?:\s*[·•|,]\s*(\d+)\s*Info\w*)?",
    re.I,
)
_MD_COUNT_ROW_RX = re.compile(
    r"^\|\s*\**\s*(Critical|High|Medium|Low|Informational)\s*\**\s*\|\s*(\d+)\s*\|", re.I
)


def parse_md_report(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    lines = text.splitlines()

    repository = None
    md_lang = None
    for ln in lines[:60]:
        if repository is None:
            m = _MD_REPO_RX.search(ln)
            if m:
                repository = m.group(1).strip().rstrip("|").strip()
        if md_lang is None:
            m = _MD_LANG_ROW_RX.search(ln)
            if m:
                # take the leading word(s) before the first '/', ',', digit or '('
                raw = m.group(1).strip()
                tok = re.split(r"[\s/(,]|[0-9]", raw, maxsplit=1)[0].strip()
                if tok:
                    md_lang = tok

    counts = {s: 0 for s in SEVERITIES}
    got_counts = False
    m = _MD_TOTALS_RX.search(text[:4000])
    if m:
        counts["critical"], counts["high"], counts["medium"], counts["low"] = (
            int(m.group(1)),
            int(m.group(2)),
            int(m.group(3)),
            int(m.group(4)),
        )
        if m.group(5):
            counts["informational"] = int(m.group(5))
        got_counts = True
    else:
        for ln in lines[:120]:
            m = _MD_COUNT_ROW_RX.match(ln)
            if m:
                counts[m.group(1).lower()] = int(m.group(2))
                got_counts = True

    findings: list[dict] = []
    cur = None
    for ln in lines:
        h = _MD_FIND_HDR_RX.match(ln)
        if h:
            if cur:
                findings.append(cur)
            cur = {
                "id": h.group(1),
                "title": h.group(2).strip(" *`"),
                "severity": "",
                "cwes": [],
                "cvss": None,
            }
            continue
        if cur is None:
            continue
        if not cur["severity"]:
            for rx in (_MD_SEV_INLINE_RX, _MD_SEV_BULLET_RX):
                m = rx.search(ln)
                if m:
                    cur["severity"] = m.group(1).lower()
                    break
        for cwe in _MD_CWE_RX.findall(ln):
            if cwe not in cur["cwes"] and len(cur["cwes"]) < 8:
                cur["cwes"].append(cwe)
        # heuristic stop: blank header for next section
        if ln.startswith("## ") and not ln.startswith("### "):
            findings.append(cur)
            cur = None
    if cur:
        findings.append(cur)

    if not got_counts:
        for f in findings:
            if f["severity"] in counts:
                counts[f["severity"]] += 1

    return {
        "source": path,
        "repository": repository,
        "org": None,
        "resource_type": "",
        "md_lang": md_lang,
        "counts": counts,
        "findings": findings,
    }


# --- triage fallback (opt-in via --include-triage) ---------------------------

_TRIAGE_SCORE_RX = re.compile(r"\((\d+(?:\.\d+)?)\)")


def parse_triage_report(triage_path: str, audit_path: str) -> dict | None:
    """Count a repo from unconfirmed /triage verdicts (--include-triage only).

    Early /triage runs over-marked false positives (unreachable repos,
    hardening issues misfiled as FP), so these verdicts are NOT trusted by
    default: counting "true positives only" silently trusts exactly those bad
    FP exclusions. When the user opts in, every figure derived from these
    repos is labeled as unconfirmed-triage in both outputs.

    Schema note: in *-triage.json, `severity` holds the label
    (critical/high/…) while `severity_label` holds the CVSS *vector string*
    with the score in parentheses — never feed `severity_label` to the
    severity bucketer.
    """
    try:
        with open(triage_path, encoding="utf-8") as fh:
            tri = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    meta = {}
    try:
        with open(audit_path, encoding="utf-8") as fh:
            meta = json.load(fh).get("metadata", {}) or {}
    except (OSError, json.JSONDecodeError):
        pass
    findings = []
    fp_excluded = hardening = undetermined = 0
    for f in tri.get("findings") or []:
        if f.get("duplicate_of"):
            continue
        v = f.get("verdict")
        if v == "false_positive":
            fp_excluded += 1
            continue
        if v == "hardening":
            hardening += 1
            continue
        if v != "true_positive":
            undetermined += 1
            continue
        sev = (f.get("severity") or "").lower()
        m = _TRIAGE_SCORE_RX.search(f.get("severity_label") or "")
        blob = " ".join(str(f.get(k) or "") for k in ("category", "title", "rationale"))
        srcs = f.get("source_findings") or []
        cve_ref = next((str(x) for x in srcs if str(x).startswith("CVE-")), None)
        findings.append(
            {
                "id": f.get("id") or "",
                "origin": f.get("origin"),
                "cve": cve_ref,
                "title": f.get("title") or "",
                "severity": sev,
                "cwes": sorted({c.upper() for c in _MD_CWE_RX.findall(blob)}),
                "cvss": float(m.group(1)) if m else None,
                "resolution": None,
            }
        )
    counts = collections.Counter(f["severity"] for f in findings if f["severity"])
    add = meta.get("additional") or {}
    return {
        "source": triage_path,
        "repository": meta.get("repository"),
        "org": add.get("org"),
        "resource_type": add.get("resource_type") or "",
        "counts": {s: int(counts.get(s, 0)) for s in SEVERITIES},
        "findings": findings,
        "dispositioned": False,
        "triage_counted": True,
        "fp_excluded": fp_excluded,
        "hardening_count": hardening,
        "triage_undetermined": undetermined,
        "resolution_counts": {},
        "remediations": [],
    }


def _audit_slug(path: str) -> str:
    """Component slug of a report path (basename minus the artifact suffix)."""
    b = Path(path).name
    for suf in (
        "-security-audit.json",
        "-security-audit.md",
        "-findings-current.json",
        "-triage.json",
    ):
        if b.endswith(suf):
            return b[: -len(suf)]
    return Path(b).stem


def _product_dir(path: str, roots: list[str]) -> str:
    """First-level product directory of a report path under its scan root."""
    for root in roots:
        try:
            rel = os.path.relpath(path, root)
        except ValueError:
            continue
        if not rel.startswith(".."):
            parts = rel.split(os.sep)
            return os.path.join(root, parts[0]) if len(parts) > 1 else root
    return os.path.dirname(path)


def discover_reports(
    roots: list[str], include_triage: bool = False, exclude_branch_variants: bool = False
) -> tuple[list[dict], dict]:
    reports: list[dict] = []
    stats = {
        "excluded_branch_variants": 0,
        "triage_counted": 0,
        "symlink_dirs_skipped": 0,
        "md_fallback_reports": 0,
    }
    seen_stems: set[str] = set()
    json_paths: list[str] = []
    md_paths: list[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if "_manifest" in dirnames:
                dirnames.remove("_manifest")
            # os.walk(followlinks=False) never descends into dir symlinks;
            # count them so the population block can report the skip.
            stats["symlink_dirs_skipped"] += sum(
                1 for d in dirnames if os.path.islink(os.path.join(dirpath, d))
            )
            for fn in filenames:
                if fn.endswith("security-audit.json"):
                    json_paths.append(os.path.join(dirpath, fn))
                elif fn.endswith("security-audit.md"):
                    md_paths.append(os.path.join(dirpath, fn))
    if exclude_branch_variants:
        # Drop a '__'-slugged release-branch re-audit ONLY when the same
        # product tree also carries the base-slug audit (the within-product
        # duplicate case). Products whose only audit for a component is a
        # branch audit (e.g. per-release payload dirs) keep counting —
        # release branches are tracked per-branch by design.
        base_index = {
            (_product_dir(p, roots), _audit_slug(p))
            for p in json_paths + md_paths
            if "__" not in _audit_slug(p)
        }

        def _is_dup_variant(p: str) -> bool:
            s = _audit_slug(p)
            if "__" not in s:
                return False
            return (_product_dir(p, roots), s.split("__", 1)[0]) in base_index

        # Count excluded REPORTS, not files: one report per json audit, plus
        # md audits that have no json sibling at all.
        all_json_stems = {p[: -len(".json")] for p in json_paths}
        json_kept = [p for p in json_paths if not _is_dup_variant(p)]
        md_kept = [p for p in md_paths if not _is_dup_variant(p)]
        n_json_dropped = len(json_paths) - len(json_kept)
        n_md_report_dropped = sum(
            1 for p in md_paths if _is_dup_variant(p) and p[: -len(".md")] not in all_json_stems
        )
        json_paths, md_paths = json_kept, md_kept
        stats["excluded_branch_variants"] = n_json_dropped + n_md_report_dropped
    for p in sorted(json_paths):
        # Prefer the cumulative report produced by the track-findings skill
        # when one sits next to the audit — it carries the current
        # validation_status and disposition of every finding.
        cur = p[: -len("security-audit.json")] + "findings-current.json"
        rep = None
        if Path(cur).is_file():
            rep = parse_json_report(cur) or parse_json_report(p)
        else:
            if include_triage:
                tri = p[: -len("security-audit.json")] + "triage.json"
                if Path(tri).is_file():
                    rep = parse_triage_report(tri, p)
                    if rep:
                        stats["triage_counted"] += 1
            if rep is None:
                rep = parse_json_report(p)
        if rep:
            reports.append(rep)
            seen_stems.add(p[:-5])  # strip .json
    for p in sorted(md_paths):
        stem = p[:-3]  # strip .md
        if stem in seen_stems:
            continue
        rep = parse_md_report(p)
        if rep:
            reports.append(rep)
            stats["md_fallback_reports"] += 1
    return reports, stats


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------

_LANG_CANON = {
    "golang": "Go",
    "go": "Go",
    "python": "Python",
    "py": "Python",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "node": "JavaScript",
    "node.js": "JavaScript",
    "ruby": "Ruby",
    "rust": "Rust",
    "java": "Java",
    "shell": "Shell",
    "bash": "Shell",
    "sh": "Shell",
    "c": "C",
    "c++": "C++",
    "cpp": "C++",
    "yaml": "YAML",
    "ansible": "Jinja",
    "helm": "Go Template",
    "dockerfile": "Dockerfile",
    "make": "Makefile",
    "makefile": "Makefile",
    "hcl": "HCL",
    "terraform": "HCL",
    "groovy": "Groovy",
    "perl": "Perl",
}


def _canon_lang(s: str) -> str:
    return _LANG_CANON.get(s.strip().lower(), s.strip())


def primary_language(report: dict, lang_cache: dict[str, str], roots: list[str]) -> str:
    slug = repo_slug(report.get("repository"))
    if slug and slug in lang_cache:
        return lang_cache[slug]
    # try directory-based slug: <root>/<org>/<repo>/...
    src = report.get("source") or ""
    for root in roots:
        root = root.rstrip(os.sep) + os.sep
        if src.startswith(root):
            rel = src[len(root) :].split(os.sep)
            if len(rel) >= 2:
                cand = f"{rel[0]}/{rel[1]}".lower()
                if cand in lang_cache:
                    return lang_cache[cand]
            break
    rt = report.get("resource_type") or ""
    if rt.startswith("oss/"):
        return _canon_lang(rt[4:])
    if report.get("md_lang"):
        return _canon_lang(report["md_lang"])
    return "Unknown"


def is_credential_leak(f: dict) -> bool:
    if any(c in CREDENTIAL_CWES for c in f.get("cwes", ())):
        return True
    return bool(CREDENTIAL_TITLE_RX.search(f.get("title", "")))


def _rel_source(path: str, roots: list[str]) -> str:
    for root in roots:
        root = root.rstrip(os.sep)
        parent = os.path.dirname(root)
        if path.startswith(parent + os.sep):
            return os.path.dirname(os.path.relpath(path, parent))
    return os.path.dirname(path)


def aggregate(
    reports: list[dict],
    lang_cache: dict[str, str],
    roots: list[str],
    segment_map: dict[str, list[str]] | None = None,
) -> dict:
    sev_totals = collections.Counter()
    per_segment = collections.defaultdict(lambda: collections.Counter())
    segment_repos = collections.Counter()
    segment_crit = collections.Counter()
    segment_high = collections.Counter()
    segment_overlap = 0
    per_lang = collections.defaultdict(lambda: collections.Counter())
    repos_per_lang = collections.Counter()
    cwe_counter = collections.Counter()
    theme_counter = collections.Counter()
    crit_high: list[dict] = []
    cred_leaks: list[dict] = []
    repos_with_crit = 0
    repos_with_high = 0
    dispositioned_repos = 0
    fp_excluded = 0
    hardening_total = 0
    resolution_totals = collections.Counter()
    remediated_by_sev = collections.Counter()
    remediation_trend = collections.defaultdict(collections.Counter)

    hardening_repos = collections.Counter()
    hardening_themes = collections.Counter()
    triage_repos = 0
    triage_fp_excluded = 0
    triage_undetermined = 0
    unique_repo_keys: set[str] = set()
    occ_products: dict = collections.defaultdict(set)
    occ_counts = collections.Counter()

    for rep in reports:
        lang = primary_language(rep, lang_cache, roots)
        repos_per_lang[lang] += 1
        # Unique-repo key: canonical repository URL when the report carries
        # one (identical across mirror products and branch re-audits), else
        # the component slug with any '__<branch>' suffix stripped.
        ukey = canon_repo(rep.get("repository"))
        if not ukey:
            ukey = "slug:" + _audit_slug(rep["source"]).split("__", 1)[0]
        unique_repo_keys.add(ukey)
        if rep.get("triage_counted"):
            triage_repos += 1
            triage_fp_excluded += rep.get("fp_excluded", 0)
            triage_undetermined += rep.get("triage_undetermined", 0)
            hardening_total += rep.get("hardening_count", 0)
        if rep.get("dispositioned"):
            dispositioned_repos += 1
            fp_excluded += rep.get("fp_excluded", 0)
            hardening_total += rep.get("hardening_count", 0)
            if rep.get("hardening_count"):
                hardening_repos[_short_repo(rep.get("repository") or rep["source"])] += rep[
                    "hardening_count"
                ]
            for hf in rep.get("hardening_findings") or []:
                themed = False
                for cwe in hf.get("cwes", ()):
                    theme = THEME_MAP.get(cwe)
                    if theme:
                        hardening_themes[theme] += 1
                        themed = True
                        break
                if not themed:
                    hardening_themes["Other / uncategorised"] += 1
            for k, v in (rep.get("resolution_counts") or {}).items():
                resolution_totals[k] += v
            for r in rep.get("remediations") or []:
                if r["resolution"] == "resolved":
                    remediated_by_sev[r["severity"]] += 1
                if r.get("month"):
                    remediation_trend[r["month"]][r["resolution"]] += 1
        c = rep["counts"]
        for s in SEVERITIES:
            sev_totals[s] += c.get(s, 0)
            per_lang[lang][s] += c.get(s, 0)
        if c.get("critical", 0) > 0:
            repos_with_crit += 1
        if c.get("high", 0) > 0:
            repos_with_high += 1
        repo = rep.get("repository") or _rel_source(rep["source"], roots)
        if segment_map is not None:
            segs = segment_map.get(canon_repo(rep.get("repository")) or "", [])
            if len(segs) > 1:
                segment_overlap += 1
            seg = primary_segment(segs) or UNMAPPED_SEGMENT
            segment_repos[seg] += 1
            for s in SEVERITIES:
                per_segment[seg][s] += c.get(s, 0)
            if c.get("critical", 0) > 0:
                segment_crit[seg] += 1
            if c.get("high", 0) > 0:
                segment_high[seg] += 1
        for f in rep["findings"]:
            for cwe in f.get("cwes", ()):
                cwe_counter[cwe] += 1
                theme = THEME_MAP.get(cwe)
                if theme:
                    theme_counter[theme] += 1
            entry = {
                "repo": repo,
                "lang": lang,
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "cvss": f.get("cvss"),
                "cwes": f.get("cwes", []),
                "resolution": f.get("resolution"),
                "fingerprint": f.get("fingerprint", ""),
            }
            if f.get("severity") in ("critical", "high") or is_credential_leak(f):
                # multiplicity metadata for the deduped tables: how many
                # occurrences, across how many distinct product trees, the
                # same defect (dedup key) was reported in
                dkey = entry["fingerprint"] or (
                    _short_repo(entry["repo"]),
                    entry["title"][:80].lower(),
                )
                occ_counts[dkey] += 1
                occ_products[dkey].add(os.path.basename(_product_dir(rep["source"], roots)))
            if f.get("severity") in ("critical", "high"):
                crit_high.append(entry)
            if is_credential_leak(f):
                cred_leaks.append(entry)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "": 5}

    def _sort_and_dedupe(entries: list[dict]) -> list[dict]:
        entries.sort(key=lambda e: (sev_rank.get(e["severity"], 9), -(e["cvss"] or 0)))
        out, seen = [], set()
        for e in entries:
            # fingerprint is the stable cross-scan identity (embeds the
            # canonical repo URL); md-parsed findings without one fall
            # back to the legacy (repo, title) key
            key = e.get("fingerprint") or (_short_repo(e["repo"]), e["title"][:80].lower())
            if key in seen:
                continue
            seen.add(key)
            e["occurrences"] = occ_counts.get(key, 1)
            e["ships_in"] = len(occ_products.get(key) or ()) or 1
            out.append(e)
        return out

    crit_high_unique = _sort_and_dedupe(list(crit_high))
    cred_leaks_unique = _sort_and_dedupe(list(cred_leaks))

    return {
        "n_reports": len(reports),
        "unique_repos": len(unique_repo_keys),
        "triage_repos": triage_repos,
        "triage_fp_excluded": triage_fp_excluded,
        "triage_undetermined": triage_undetermined,
        "sev_totals": dict(sev_totals),
        "per_lang": {k: dict(v) for k, v in per_lang.items()},
        "repos_per_lang": dict(repos_per_lang),
        "cwe_top": cwe_counter.most_common(15),
        "theme_top": theme_counter.most_common(12),
        "crit_high": crit_high_unique,
        "crit_high_raw": len(crit_high),
        "cred_leaks": cred_leaks_unique,
        "cred_leaks_raw": len(cred_leaks),
        "repos_with_crit": repos_with_crit,
        "repos_with_high": repos_with_high,
        "dispositioned_repos": dispositioned_repos,
        "fp_excluded": fp_excluded,
        "hardening_total": hardening_total,
        "hardening_themes": hardening_themes.most_common(10),
        "hardening_top_repos": hardening_repos.most_common(15),
        "resolution_totals": dict(resolution_totals),
        "remediated_by_sev": dict(remediated_by_sev),
        "remediation_trend": {m: dict(c) for m, c in sorted(remediation_trend.items())},
        "per_segment": (
            {k: dict(v) for k, v in per_segment.items()} if segment_map is not None else None
        ),
        "segment_repos": dict(segment_repos),
        "segment_crit": dict(segment_crit),
        "segment_high": dict(segment_high),
        "segment_overlap": segment_overlap,
    }


_REF_RX = re.compile(r"__((?:release|openshift)-\d+\.\d+(?:\.\d+)?)$")


def _tree_of(path: str, roots: list[str]) -> str:
    for r in roots:
        if path.startswith(str(r).rstrip("/") + "/"):
            return os.path.basename(str(r).rstrip("/"))
    return "?"


def distinct_metrics(reports: list[dict], roots: list[str]) -> dict:
    """Lens 2 post-pass — separate from aggregate() so the occurrence
    metrics above are untouched. Distinct vulnerabilities = unique finding
    fingerprints at HEAD (branch re-audits excluded), false positives and
    hardening excluded, severity = max across occurrences, open = any
    occurrence not resolved/risk-accepted. Branch re-audit findings whose
    fingerprint matches a HEAD finding count as CONFIRMATIONS on shipped
    releases (Lens 1 coverage), never as new exposure."""
    head, branch = [], []
    for rep in reports:
        # census parity: md-fallback reports (no fingerprintable JSON) and
        # symlink-aliased reports are outside the distinct population —
        # they remain fully counted in the occurrence totals above
        src = rep["source"]
        if src.endswith(".md") and not rep.get("dispositioned"):
            continue
        if os.path.islink(src):
            continue
        # a findings-current ledger sitting next to a SYMLINKED audit is an
        # alias-attached (frequently stale) duplicate of the canonical
        # repo's ledger — outside the distinct population, like the alias
        if src.endswith("-findings-current.json") and os.path.islink(
            src[: -len("-findings-current.json")] + "-security-audit.json"
        ):
            continue
        slug = _audit_slug(rep["source"])
        parent = os.path.basename(os.path.dirname(rep["source"]))
        is_branch = bool(_REF_RX.search(slug) or _REF_RX.search(parent))
        (branch if is_branch else head).append(rep)

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    distinct: dict[str, dict] = {}
    head_fps: dict[str, set] = collections.defaultdict(set)
    fp_present = fp_total = 0
    for rep in head:
        tree = _tree_of(rep["source"], roots)
        d = distinct.setdefault(tree, {})
        for f in rep["findings"]:
            if f.get("validation_status") in ("false_positive", "hardening"):
                continue  # non-dispositioned audits keep these in findings[]
            fp_total += 1
            key = f.get("fingerprint")
            if key:
                fp_present += 1
                head_fps[tree].add(key)
            else:  # md-parsed/legacy findings — stable fallback identity
                key = (
                    f"t:{_short_repo(rep.get('repository') or rep['source'])}"
                    f":{f['title'][:80].lower()}"
                )
            e = d.setdefault(key, {"sev": f["severity"] or "informational", "open": False})
            if sev_rank.get(f["severity"], 0) > sev_rank.get(e["sev"], 0):
                e["sev"] = f["severity"]
            if f.get("resolution") not in ("resolved", "risk_accepted"):
                e["open"] = True

    confirmations = branch_findings = 0
    for rep in branch:
        tree = _tree_of(rep["source"], roots)
        for f in rep["findings"]:
            if f.get("validation_status") in ("false_positive", "hardening"):
                continue
            branch_findings += 1
            if f.get("fingerprint") and f["fingerprint"] in head_fps[tree]:
                confirmations += 1

    out = {}
    for tree, d in distinct.items():
        out[tree] = {
            "total": len(d),
            "open": sum(e["open"] for e in d.values()),
            "by_severity": dict(collections.Counter(e["sev"] for e in d.values())),
            "open_by_severity": dict(
                collections.Counter(e["sev"] for e in d.values() if e["open"])
            ),
        }
    return {
        "distinct": out,
        "branch_reports": len(branch),
        "branch_findings": branch_findings,
        "branch_confirmations": confirmations,
        "fingerprint_coverage": (100.0 * fp_present / fp_total) if fp_total else 0.0,
    }


# Compact per-release row set (branch-awareness Phase 4):
# how many refs the ref-coverage tables show before folding the tail.
REF_COVERAGE_TOP_N = 10


def _top_refs(rc: dict | None) -> list[tuple[str, int]]:
    """Top refs by report count from the corpus resolver's per-ref
    aggregate (aggregates()['totals']['refs']) — count desc, name asc."""
    refs = (rc or {}).get("refs") or {}
    return sorted(refs.items(), key=lambda kv: (-kv[1], kv[0]))[:REF_COVERAGE_TOP_N]


def _segment_rows(agg: dict) -> list[tuple[str, dict]]:
    """Segments in priority order, then any others, unmapped last."""
    present = list((agg.get("per_segment") or {}).keys())
    ordered = [s for s in SEGMENT_PRIORITY if s in present]
    ordered += sorted(s for s in present if s not in ordered and s != UNMAPPED_SEGMENT)
    if UNMAPPED_SEGMENT in present:
        ordered.append(UNMAPPED_SEGMENT)
    return [(s, agg["per_segment"][s]) for s in ordered]


# ---------------------------------------------------------------------------
# rendering — markdown
# ---------------------------------------------------------------------------


def _short_repo(url: str) -> str:
    s = repo_slug(url)
    return s if s else url


def load_dependency_exposure(reports: list[dict], results_root: Path) -> list[dict] | None:
    """Per-CVE fleet cut for advisory-driven dependency findings
    (/dependency-watch + route_impact_findings direct entry): joins the
    impact artifacts (affectedness analysis) with the findings actually
    filed (origin: impact-analysis), so leadership sees analysis AND
    accountability in one row."""
    import glob as _glob

    artifacts = sorted(_glob.glob(str(results_root / "impact" / "*-impact-analysis.json")))
    if not artifacts:
        return None
    filed: dict[str, list[dict]] = {}
    for rep in reports:
        for f in rep.get("findings", []):
            if f.get("origin") == "impact-analysis" and f.get("cve"):
                filed.setdefault(f["cve"], []).append(f)
    rows = []
    for ap in artifacts:
        try:
            art = json.loads(Path(ap).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cve = art.get("cve")
        if not cve:
            continue
        summ = art.get("summary") or {}
        ff = filed.get(cve, [])
        rows.append(
            {
                "cve": cve,
                "module": art.get("module") or "",
                "affected": summ.get("affected", 0),
                "likely": summ.get("likely_affected", 0),
                "filed": len(ff),
                "resolved": sum(
                    1 for f in ff if f.get("resolution") in ("resolved", "partially_resolved")
                ),
            }
        )
    rows.sort(key=lambda r: (-(r["affected"] + r["likely"]), r["cve"]))
    return rows or None


def render_markdown(agg: dict, roots: list[str], version: str) -> str:
    today = _dt.date.today().isoformat()
    sev = agg["sev_totals"]
    total_findings = sum(sev.get(s, 0) for s in SEVERITIES)
    lines: list[str] = []
    A = lines.append

    A("# Executive Summary — Security Audit Findings")
    A("")
    A(f"**Generated:** {today}  ")
    A(
        f"**Scope:** `{', '.join(roots)}` — {agg['n_reports']:,} reports across "
        f"{agg.get('unique_repos', agg['n_reports']):,} unique repositories, "
        f"{total_findings:,} findings total.  "
    )
    A(
        f"**Repositories with ≥1 Critical:** {agg['repos_with_crit']} · "
        f"**with ≥1 High:** {agg['repos_with_high']}"
    )
    if agg.get("trend_line"):
        A("")
        A(
            f"📈 *{agg['trend_line']}* — full history: "
            f"`progress-tracker/metrics/Executive-Trends.md`"
        )
    if agg.get("excluded_branch_variants"):
        A("")
        A(
            f"**Branch variants excluded:** {agg['excluded_branch_variants']:,} "
            f"within-product duplicate release-branch reports skipped "
            f"(`--exclude-branch-variants`); branch-only audits (per-release "
            f"payload products) still count."
        )
    if agg.get("triage_repos"):
        A("")
        A(
            f"⚠️ **Unconfirmed triage basis** (`--include-triage`): "
            f"{agg['triage_repos']:,} repositories without a disposition ledger "
            f"are counted from unconfirmed `/triage` verdicts — true positives "
            f"only; {agg['triage_fp_excluded']:,} machine-marked false positives "
            f"excluded and {agg['triage_undetermined']:,} undetermined findings "
            f"not counted. These verdicts are **not** execution-verified; early "
            f"/triage runs over-marked false positives."
        )
    # ---- Distinct vulnerabilities (Lens 2) — the canonical headline ----
    dist = agg.get("distinct") or {}
    owned, up = dist.get("findings"), dist.get("oss-findings")
    if owned:

        def _sevline(d):
            return "/".join(str(d.get(s, 0)) for s in SEVERITIES)

        A("")
        A("## Distinct Vulnerabilities")
        A("")
        A(
            f"**{owned['total']:,} distinct vulnerabilities "
            f"({owned['open']:,} open)** across Hybrid Platforms–owned code "
            f"(`findings/` at HEAD) — unique finding fingerprints, "
            f"disposition-adjusted, false positives excluded, hardening "
            f"tracked separately. Open by severity (C/H/M/L/I): "
            f"**{_sevline(owned['open_by_severity'])}**. "
            f"This is the canonical count of defects to fix; total exposure "
            f"surface remains **{total_findings:,} finding occurrences** "
            f"across all reports and products (severity table below) — the "
            f"same defect shipped in N products counts once here and N "
            f"times there."
        )
        if up:
            A("")
            A(
                f"*Upstream supply-chain exposure* (`oss-findings/`, adjacent "
                f"— never folded into the owned number): {up['total']:,} "
                f"distinct ({up['open']:,} open; C/H/M/L/I "
                f"{_sevline(up['open_by_severity'])})."
            )
        if agg.get("branch_reports"):
            A("")
            A(
                f"**Release-branch confirmations:** "
                f"{agg['branch_confirmations']:,} of "
                f"{agg['branch_findings']:,} findings restated by "
                f"{agg['branch_reports']:,} release-branch re-audits are "
                f"fingerprint-confirmations of a HEAD finding on shipped "
                f"releases — coverage evidence, not new exposure. "
                f"(Strict tier-1 matching; unmatched branch findings are an "
                f"upper bound pending the rebaseline ladder.)"
            )
            top_refs = _top_refs(agg.get("ref_coverage"))
            if top_refs:
                rc = agg["ref_coverage"]
                A("")
                A(
                    f"**Ref coverage** — reports per ref from the corpus "
                    f"resolver (`traust.cli.groups.corpus`: declared `metadata.ref` "
                    f"preferred, legacy `__`-slug fallback; "
                    f"{rc.get('declared', 0):,} report(s) declare "
                    f"`metadata.ref`). Top refs by report count:"
                )
                A("")
                A("| Ref | Reports |")
                A("| --- | ---: |")
                for ref, n in top_refs:
                    A(f"| `{ref}` | {n:,} |")
                rest = len(rc["refs"]) - len(top_refs)
                if rest > 0:
                    others = sum(rc["refs"].values()) - sum(n for _, n in top_refs)
                    A(f"| _…{rest} more refs_ | {others:,} |")
    A("")
    A("| Severity | Count | % of total |")
    A("| --- | ---: | ---: |")
    for s in SEVERITIES:
        n = sev.get(s, 0)
        pct = (100.0 * n / total_findings) if total_findings else 0.0
        A(f"| **{s.title()}** | {n:,} | {pct:.1f}% |")
    A("")

    # ---- Remediation status (from track-findings cumulative reports) ----
    if agg.get("dispositioned_repos"):
        rt = agg.get("resolution_totals", {})
        tracked = sum(rt.values())
        closed = rt.get("resolved", 0) + rt.get("risk_accepted", 0)
        A("## Remediation Status")
        A("")
        A(
            f"{agg['dispositioned_repos']:,} of {agg['n_reports']:,} repositories "
            f"carry a findings disposition ledger (`track-findings` skill). "
            f"Across their {tracked:,} tracked findings: "
            f"**{rt.get('resolved', 0):,} resolved**, "
            f"{rt.get('partially_resolved', 0):,} partially resolved, "
            f"{rt.get('fix_in_progress', 0):,} fix in progress, "
            f"{rt.get('risk_accepted', 0):,} risk accepted, "
            f"{rt.get('regression_introduced', 0):,} with regressions, "
            f"{rt.get('open', 0):,} open. "
            f"{agg.get('fp_excluded', 0):,} confirmed false positives are "
            f"excluded from every figure on this page. "
            f"{agg.get('hardening_total', 0):,} hardening findings "
            f"(accurate defense-in-depth/benchmark gaps, no exploit path) are "
            f"tracked as posture debt — λ-weighted in the findings-trends "
            f"risk index, never counted as confirmed vulnerabilities here."
        )
        if tracked:
            A("")
            A(f"**Closure rate (dispositioned repos):** {100.0 * closed / tracked:.1f}%")
        rsev = agg.get("remediated_by_sev", {})
        n_rem = sum(rsev.values())
        if n_rem:
            A("")
            A(
                f"**Findings remediated:** {n_rem:,} fully resolved — "
                + ", ".join(f"{rsev[s]:,} {s.title()}" for s in SEVERITIES if rsev.get(s))
            )
        trend = agg.get("remediation_trend", {})
        if trend:
            A("")
            A("**Remediation trend** (by month of last disposition event):")
            A("")
            A("| Month | Resolved | Partially resolved |")
            A("| --- | ---: | ---: |")
            for month, c in trend.items():
                A(f"| {month} | {c.get('resolved', 0):,} | {c.get('partially_resolved', 0):,} |")

    # ---- Hardening backlog (posture debt) — dedicated section so it never
    # gets lost in the remediation prose ----
    if agg.get("hardening_total"):
        A("")
        A("## Hardening Backlog (Posture Debt)")
        A("")
        A(
            f"**{agg['hardening_total']:,} hardening findings** — accurate "
            f"defense-in-depth/benchmark gaps with **no demonstrated exploit "
            f"path**. Never counted as vulnerabilities above, never dropped: "
            f"absent hardening degrades posture and amplifies co-located "
            f"vulnerabilities (see the findings-trends λ-weighted hardening "
            f"risk index and Unhardened Blast Radius). File as regular "
            f"engineering work via `/file-security-defect --hardening`."
        )
        if agg.get("hardening_themes"):
            A("")
            A("| Hardening theme | Findings |")
            A("| --- | ---: |")
            for theme, n in agg["hardening_themes"]:
                A(f"| {theme} | {n:,} |")
        if agg.get("hardening_top_repos"):
            A("")
            A(
                "**Largest per-repo backlogs:** "
                + ", ".join(f"`{r}` ({n:,})" for r, n in agg["hardening_top_repos"][:10])
            )
        A("")
    cc = agg.get("cloud_config")
    if cc:
        A("## Cloud Configuration — Declared Layer (IaC at Rest)")
        A("")
        sev = cc["by_severity"]
        A(
            f"**{cc['findings']:,} declared-layer IaC misconfigurations "
            f"across {cc['reports']:,} audited IaC targets** "
            f"(`/cloud-config-audit`, pinned offline Checkov; "
            f"C/H/M/L/I "
            f"{sev.get('critical', 0)}/{sev.get('high', 0)}/"
            f"{sev.get('medium', 0)}/{sev.get('low', 0)}/"
            f"{sev.get('informational', 0)}; "
            f"{cc['ledgered']}/{cc['reports']} with disposition ledgers). "
            f"**Separate unit from every count above**: these are "
            f"hardening-class posture gaps read from IaC at rest — no "
            f"live environment was observed, and drift applied outside "
            f"IaC is not visible here."
        )
        if cc["targets"]:
            A("")
            A(
                "**Largest per-target backlogs:** "
                + ", ".join(f"`{t}` ({n:,})" for t, n in cc["targets"][:10])
            )
        A("")
    dep = agg.get("dependency_exposure")
    if dep:
        A("## Dependency Exposure by CVE (advisory-driven)")
        A("")
        A(
            "Analysis vs accountability per advisory: `affected` comes "
            "from `/impact-analysis` reachability; `filed` are the "
            "campaign findings routed into baselines + ledgers "
            "(`/dependency-watch` → `route_impact_findings.py`), which is "
            "where owners, SLA clocks, and Jira live. affected > filed "
            "means unaudited repos or a pending routing run."
        )
        A("")
        A("| CVE | Module | Affected | Likely | Filed | Resolved |")
        A("|---|---|---:|---:|---:|---:|")
        for r in dep[:20]:
            A(
                f"| {r['cve']} | `{r['module']}` | {r['affected']} | "
                f"{r['likely']} | {r['filed']} | {r['resolved']} |"
            )
        if len(dep) > 20:
            A("")
            A(f"(+{len(dep) - 20} more CVEs in the artifact directory)")
        A("")
    A("---")
    A("")

    # ---- Critical / High ----
    ac = agg.get("attack_coverage")
    if ac:
        A("## MITRE ATT&CK Coverage")
        A("")
        A(
            f"**{ac['covered']} techniques across {ac['tactics']} tactics** "
            f"(ATT&CK v{ac['attack_version']}, pinned) — "
            f"**{len(ac['observed'])} observed** in confirmed live-validation "
            f"attack chains, {ac['modeled']:,} modeled in threat models, "
            f"{ac['derived']:,} weakness-derived candidates from finding "
            f"categories. The three evidence classes are never blended. "
            f"Full roll-up + Navigator layer: "
            f"`metrics/dashboards/attack-coverage/`."
        )
        if ac["observed"]:
            A("")
            A("| Technique | Name | Evidence |")
            A("| --- | --- | --- |")
            for t in ac["observed"]:
                A(f"| {t['id']} | {t['name']} | {t['comment']} |")
        A("")
        A("*MITRE ATT&CK® © The MITRE Corporation, used with attribution.*")
        A("")

    # ---- PQC readiness (pqc-readiness Phase-2 roll-up) ----
    pq = agg.get("pqc")
    if pq:
        b = pq["buckets"]
        A("## Post-Quantum Cryptography Readiness (NIST IR 8547)")
        A("")
        A(
            f"**{pq['reports']:,} repos assessed** — "
            f"{b.get('ready', 0):,} ready / {b.get('partial', 0):,} partial / "
            f"{b.get('not-ready', 0):,} not-ready / "
            f"{b.get('blocked-external', 0):,} blocked-external / "
            f"{b.get('not-applicable', 0):,} not-applicable "
            f"(scored median {pq['median']:g}). Full roll-up + CSV exports: "
            f"`metrics/dashboards/pqc/`."
        )
        A("")
        A("| KPI | Value | Reading |")
        A("| --- | ---: | --- |")
        A(
            f"| 2030-clock items (112-bit deprecated) | "
            f"{pq['clock_2030_items']} across {pq['clock_2030_repos']} repos "
            f"| urgent burndown; "
            f"{len(pq['clock_2030_significant'])} significant-effort |"
        )
        A(
            f"| 2035-clock items (classical PK disallowed) | "
            f"{pq['clock_2035_items']:,} | bulk migration, mostly "
            f"delegated/ecosystem |"
        )
        A(
            f"| HNDL-priority repos | {len(pq['hndl'])} | harvest-now/"
            f"decrypt-later exposure ranking |"
        )
        A(
            f"| Hybrid-TLS blockers | {pq['hybrid_blockers']} | first-party "
            f"group/KEX pins blocking ML-KEM negotiation |"
        )
        A(f"| Toolchain quick wins | {pq['quickwins']} | go.mod <1.24 one-line bumps |")
        if pq["clock_2030_significant"]:
            A("")
            A("Top significant-effort 2030-clock items:")
            A("")
            for r in pq["clock_2030_significant"][:8]:
                A(f"- **{r['repo']}** ({r.get('overall')}) — {(r.get('primitive') or '')[:140]}")
        if pq["blocked_external"]:
            A("")
            A(
                "Vendor/ecosystem-blocked: "
                + ", ".join(f"`{r}`" for r in pq["blocked_external"][:15])
            )
        A("")

    # ---- Posture tiles (ratings, deliberately NOT findings) ----
    lp = agg.get("least_priv")
    if lp:
        A("## Operator Least-Privilege Posture (static, tiers 1–2)")
        A("")
        A(
            f"**{lp['profiles']:,} operator privilege profiles** — posture "
            f"ratings, not findings (kept out of the totals above). "
            f"{lp['privileged']:,} run privileged/host-touching workloads; "
            f"{lp['scc_requesting']:,} request SCCs; "
            f"{lp['wildcard_repos']:,} carry wildcard RBAC rules "
            f"({lp['wildcard_rules']:,} rules); RBAC surplus statically "
            f"derivable for {lp['surplus_scored']:,}. Full rollup: "
            f"`metrics/dashboards/operator-least-priv/`."
        )
        if lp["top_surplus"]:
            A("")
            A("Top RBAC surplus (granted vs. statically required):")
            A("")
            for r in lp["top_surplus"][:8]:
                fl = ", ".join(
                    f"{k}×{v}"
                    for k, v in sorted(
                        (r.get("rbac_risk_flags") or {}).items(), key=lambda kv: -kv[1]
                    )[:3]
                )
                A(f"- **{r['repo']}** — surplus {r['surplus']:,}" + (f" ({fl})" if fl else ""))
        A("")
    iso = agg.get("isolation")
    if iso:
        A("## Tenant-Isolation Posture (PEACH)")
        A("")
        A(
            f"**{len(iso['services'])} multi-tenant service reviews** — "
            f"posture scores, not findings. {iso['interfaces']:,} "
            f"customer-facing interfaces inventoried; {iso['gaps']:,} "
            f"isolation gaps recorded (escalation-worthy gaps promote to "
            f"findings individually via triage). Reports: "
            f"`analysis-results/isolation/`."
        )
        if iso["worst"]:
            A("")
            A("| Service | Overall | Interfaces | Gaps |")
            A("| --- | ---: | ---: | ---: |")
            for s in iso["worst"]:
                A(f"| `{s['service']}` | {s['overall']} | {s['interfaces']} | {s['gaps']} |")
        A("")

    A("## Top Critical & High Findings")
    A("")
    crit = [e for e in agg["crit_high"] if e["severity"] == "critical"]
    high = [e for e in agg["crit_high"] if e["severity"] == "high"]
    A(
        f"**{len(crit)} unique Critical** and **{len(high)} unique High** findings "
        f"({agg['crit_high_raw']} total occurrences across overlapping product audits). "
        f"Top items by CVSS:"
    )
    A("")
    A("| Sev | CVSS | Repository | Finding | CWE | Ships in | Status |")
    A("| --- | ---: | --- | --- | --- | ---: | --- |")
    for e in agg["crit_high"][:25]:
        cvss = f"{e['cvss']:.1f}" if isinstance(e["cvss"], (int, float)) else "—"
        cwes = ", ".join(e["cwes"][:2]) or "—"
        status = (e.get("resolution") or "—").replace("_", " ")
        ships = f"{e.get('ships_in', 1)} products" if e.get("ships_in", 1) > 1 else "1 product"
        A(
            f"| {e['severity'].title()} | {cvss} | `{_short_repo(e['repo'])}` "
            f"| {md_cell(e['title'][:90])} | {cwes} | {ships} | {status} |"
        )
    if len(agg["crit_high"]) > 25:
        A(f"| … | | | *{len(agg['crit_high']) - 25} more — see per-repo reports* | | |")
    A("")
    A("---")
    A("")

    # ---- Credential leaks ----
    A("## Credential & Secret Leaks in Code")
    A("")
    leaks = agg["cred_leaks"]
    by_sev = collections.Counter(e["severity"] for e in leaks)
    A(
        f"**{len(leaks)} unique** findings ({agg['cred_leaks_raw']} total occurrences) flagged as "
        f"hard-coded / committed credentials, keys, or tokens "
        f"(CWE-798/259/321/522/540 et al.) — "
        f"{by_sev.get('critical', 0)} Critical, {by_sev.get('high', 0)} High, "
        f"{by_sev.get('medium', 0)} Medium."
    )
    A("")
    if leaks:
        A("| Sev | Repository | Finding | CWE |")
        A("| --- | --- | --- | --- |")
        for e in leaks[:20]:
            cwes = ", ".join(e["cwes"][:2]) or "—"
            A(
                f"| {e['severity'].title() or '—'} | `{_short_repo(e['repo'])}` "
                f"| {md_cell(e['title'][:90])} | {cwes} |"
            )
        if len(leaks) > 20:
            A(f"| … | | *{len(leaks) - 20} more* | |")
    A("")
    A("---")
    A("")

    # ---- Themes ----
    A("## Common Risk Themes")
    A("")
    A("Derived from CWE clustering across all findings (any severity):")
    A("")
    A("| # | Theme | Findings |")
    A("| ---: | --- | ---: |")
    for i, (theme, n) in enumerate(agg["theme_top"], 1):
        A(f"| {i} | {theme} | {n:,} |")
    A("")
    A("**Top individual CWEs:** " + "; ".join(f"{c} ({n})" for c, n in agg["cwe_top"][:10]))
    A("")
    A("---")
    A("")

    # ---- Per-segment (optional, --by-segment) ----
    if agg.get("per_segment"):
        A("## Findings by Input Segment")
        A("")
        A(
            "Repositories mapped against the inputs inventory "
            "inventories (ansible excluded). A repo shipping in more than one "
            "segment is counted once, in the first matching segment "
            f"(priority: {' → '.join(SEGMENT_PRIORITY)}); "
            f"{agg['segment_overlap']:,} repos appear in multiple segments. "
            "`unmapped` covers repos absent from the input inventories "
            "(including `oss-findings/`)."
        )
        A("")
        A(
            "| Segment | Repos | Critical | High | Medium | Low | Info | Total "
            "| Repos ≥1 Crit | Repos ≥1 High |"
        )
        A("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for seg, c in _segment_rows(agg):
            tot = sum(c.get(s, 0) for s in SEVERITIES)
            A(
                f"| {seg} | {agg['segment_repos'].get(seg, 0):,} "
                f"| {c.get('critical', 0):,} | {c.get('high', 0):,} "
                f"| {c.get('medium', 0):,} | {c.get('low', 0):,} "
                f"| {c.get('informational', 0):,} | **{tot:,}** "
                f"| {agg['segment_crit'].get(seg, 0):,} "
                f"| {agg['segment_high'].get(seg, 0):,} |"
            )
        A("")
        A("---")
        A("")

    # ---- Per-language ----
    A("## Findings by Primary Language")
    A("")
    A(
        "Primary language resolved via GitHub Linguist byte-count "
        "(`gh-languages-cache.jsonl`); falls back to `resource_type` where uncached."
    )
    A("")
    A("| Language | Repos | Critical | High | Medium | Low | Info | Total |")
    A("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    rows = []
    for lang, c in agg["per_lang"].items():
        tot = sum(c.get(s, 0) for s in SEVERITIES)
        rows.append((tot, lang, c))
    rows.sort(reverse=True)
    for tot, lang, c in rows:
        A(
            f"| {lang} | {agg['repos_per_lang'].get(lang, 0)} "
            f"| {c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} "
            f"| {c.get('low', 0)} | {c.get('informational', 0)} | **{tot}** |"
        )
    A("")
    A("---")
    A("")
    A(
        f"*Generated by traust `{version}` "
        "(`harnessing/executive-summary-findings/scripts/build_executive_summary.py`). "
        "Re-run via the `/executive-summary-findings` skill.*"
    )
    A("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# rendering — html dashboard
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "critical": "#cc0000",
    "high": "#ec7a08",
    "medium": "#f0ab00",
    "low": "#3e8635",
    "informational": "#6a6e73",
}


def render_html(agg: dict, roots: list[str], version: str) -> str:
    today = _dt.date.today().isoformat()
    sev = agg["sev_totals"]
    total_findings = sum(sev.get(s, 0) for s in SEVERITIES)

    sev_labels = [s.title() for s in SEVERITIES]
    sev_data = [sev.get(s, 0) for s in SEVERITIES]
    sev_colors = [_SEV_COLORS[s] for s in SEVERITIES]

    # language stacked-bar (top 12 by total)
    lang_rows = []
    for lang, c in agg["per_lang"].items():
        tot = sum(c.get(s, 0) for s in SEVERITIES)
        lang_rows.append((tot, lang, c))
    lang_rows.sort(reverse=True)
    lang_rows = lang_rows[:12]
    lang_labels = [r[1] for r in lang_rows]
    lang_datasets = []
    for s in SEVERITIES:
        lang_datasets.append(
            {
                "label": s.title(),
                "data": [r[2].get(s, 0) for r in lang_rows],
                "backgroundColor": _SEV_COLORS[s],
            }
        )

    theme_labels = [t for t, _ in agg["theme_top"][:10]]
    theme_data = [n for _, n in agg["theme_top"][:10]]

    def esc(s):
        return html.escape(str(s))

    def table(headers, rows):
        out = ["<table><thead><tr>"]
        out += [f"<th>{esc(h)}</th>" for h in headers]
        out.append("</tr></thead><tbody>")
        for r in rows:
            out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
        out.append("</tbody></table>")
        return "".join(out)

    crit_high_rows = []
    for e in agg["crit_high"][:25]:
        cvss = f"{e['cvss']:.1f}" if isinstance(e["cvss"], (int, float)) else "—"
        sev_badge = (
            f'<span class="badge" style="background:{_SEV_COLORS.get(e["severity"], "#888")}">'
            f"{esc(e['severity'].title())}</span>"
        )
        ships = e.get("ships_in", 1)
        crit_high_rows.append(
            [
                sev_badge,
                cvss,
                f"<code>{esc(_short_repo(e['repo']))}</code>",
                esc(e["title"][:110]),
                esc(", ".join(e["cwes"][:2]) or "—"),
                f"{ships} product{'s' if ships != 1 else ''}",
                esc((e.get("resolution") or "—").replace("_", " ")),
            ]
        )

    leak_rows = []
    for e in agg["cred_leaks"][:20]:
        sev_badge = (
            f'<span class="badge" style="background:{_SEV_COLORS.get(e["severity"], "#888")}">'
            f"{esc(e['severity'].title() or '—')}</span>"
        )
        leak_rows.append(
            [
                sev_badge,
                f"<code>{esc(_short_repo(e['repo']))}</code>",
                esc(e["title"][:110]),
                esc(", ".join(e["cwes"][:2]) or "—"),
            ]
        )

    triage_note = ""
    if agg.get("triage_repos"):
        triage_note = (
            f'<div class="card" style="border-left:4px solid #f0ab00">'
            f"<h2>⚠️ Unconfirmed Triage Basis (--include-triage)</h2>"
            f'<p style="font-size:13px">{agg["triage_repos"]:,} repositories '
            f"without a disposition ledger are counted from unconfirmed "
            f"<code>/triage</code> verdicts — true positives only; "
            f"{agg['triage_fp_excluded']:,} machine-marked false positives "
            f"excluded and {agg['triage_undetermined']:,} undetermined "
            f"findings not counted. These verdicts are <b>not</b> "
            f"execution-verified; early /triage runs over-marked false "
            f"positives.</p></div>"
        )

    variant_note = ""
    if agg.get("excluded_branch_variants"):
        variant_note = (
            f" {agg['excluded_branch_variants']:,} within-product duplicate "
            f"release-branch reports excluded (--exclude-branch-variants); "
            f"branch-only audits still count."
        )

    triage_kpi = ""
    if agg.get("triage_repos"):
        triage_kpi = (
            f'<div class="kpi"><div class="n" style="color:#f0ab00">'
            f"{agg['triage_repos']:,}</div>"
            f'<div class="l">Repos on unconfirmed triage</div></div>'
        )

    distinct_kpi = ""
    distinct_note = ""
    _owned = (agg.get("distinct") or {}).get("findings")
    if _owned:
        distinct_kpi = (
            f'<div class="kpi"><div class="n" style="color:#0066cc">'
            f"{_owned['total']:,}</div>"
            f'<div class="l">Distinct vulns (owned)</div></div>'
        )
        _up = (agg.get("distinct") or {}).get("oss-findings")
        _upline = (
            f" Upstream supply-chain exposure (oss-findings/, "
            f"adjacent — never folded in): {_up['total']:,} distinct "
            f"({_up['open']:,} open)."
            if _up
            else ""
        )
        _bline = (
            f" Release-branch re-audits: "
            f"{agg.get('branch_confirmations', 0):,} fingerprint-"
            f"confirmations of HEAD findings on shipped releases — "
            f"coverage, not new exposure."
            if agg.get("branch_reports")
            else ""
        )
        _ref_tbl = ""
        _top = _top_refs(agg.get("ref_coverage")) if agg.get("branch_reports") else []
        if _top:
            _rc = agg["ref_coverage"]
            _rows = "".join(
                f"<tr><td><code>{esc(ref)}</code></td><td style='text-align:right'>{n:,}</td></tr>"
                for ref, n in _top
            )
            _rest = len(_rc["refs"]) - len(_top)
            if _rest > 0:
                _others = sum(_rc["refs"].values()) - sum(n for _, n in _top)
                _rows += (
                    f"<tr><td><i>…{_rest} more refs</i></td>"
                    f"<td style='text-align:right'>{_others:,}</td>"
                    f"</tr>"
                )
            _ref_tbl = (
                f'\n  <details style="max-width:1280px;margin:6px auto 0;'
                f'padding:0 28px;font-size:13px;color:#6a6e73">'
                f"<summary>Ref coverage — reports per ref (top "
                f"{len(_top)}; corpus resolver: declared metadata.ref "
                f"preferred, legacy __-slug fallback; "
                f"{_rc.get('declared', 0):,} report(s) declare "
                f"metadata.ref)</summary>"
                f'<table style="max-width:420px"><thead><tr><th>Ref</th>'
                f"<th>Reports</th></tr></thead>"
                f"<tbody>{_rows}</tbody></table></details>"
            )
        distinct_note = (
            f'<div style="max-width:1280px;margin:12px auto 0;padding:0 '
            f'28px;font-size:13px;color:#6a6e73"><b>Distinct '
            f"vulnerabilities (owned):</b> {_owned['total']:,} "
            f"({_owned['open']:,} open) — unique finding fingerprints at "
            f"HEAD across findings/, disposition-adjusted; the canonical "
            f"exposure number.{_upline}{_bline}</div>{_ref_tbl}"
        )

    # Remediation status from track-findings cumulative reports
    disposition_kpi = ""
    disposition_note = ""
    rem_chart_card = ""
    rem_payload = None
    if agg.get("dispositioned_repos"):
        rt = agg.get("resolution_totals", {})
        tracked = sum(rt.values())
        closed = rt.get("resolved", 0) + rt.get("risk_accepted", 0)
        closure = f"{100.0 * closed / tracked:.0f}%" if tracked else "—"
        n_rem = sum(agg.get("remediated_by_sev", {}).values())
        disposition_kpi = (
            f'<div class="kpi"><div class="n" style="color:#3e8635">{n_rem:,}</div>'
            f'<div class="l">Findings remediated</div></div>'
            f'<div class="kpi"><div class="n">{closure}</div>'
            f'<div class="l">Closure rate (tracked)</div></div>'
        )
        if agg.get("hardening_total"):
            disposition_kpi += (
                f'<div class="kpi"><div class="n" style="color:#8476d1">'
                f"{agg['hardening_total']:,}</div>"
                f'<div class="l">Hardening backlog</div></div>'
            )
        if agg.get("cloud_config"):
            disposition_kpi += (
                f'<div class="kpi"><div class="n" style="color:#5b8dd1">'
                f"{agg['cloud_config']['findings']:,}</div>"
                f'<div class="l">IaC config gaps (declared layer, '
                f"separate unit)</div></div>"
            )
        trend = agg.get("remediation_trend", {})
        if trend:
            rem_payload = {
                "labels": list(trend.keys()),
                "resolved": [c.get("resolved", 0) for c in trend.values()],
                "partial": [c.get("partially_resolved", 0) for c in trend.values()],
            }
            rem_chart_card = (
                '<div class="card"><h2>Remediation Trend</h2>'
                '<div class="chart-box"><canvas id="remChart"></canvas></div>'
                '<p style="font-size:12px;color:var(--muted)">Findings resolved '
                "per month, by the date of their last disposition event "
                "(track-findings ledgers).</p></div>"
            )
        disposition_note = (
            f'<div class="card"><h2>Remediation Status</h2>'
            f'<p style="font-size:13px">{agg["dispositioned_repos"]:,} of '
            f"{agg['n_reports']:,} repositories carry a findings disposition "
            f"ledger (track-findings). Across their {tracked:,} tracked "
            f"findings: <b>{rt.get('resolved', 0):,} resolved</b>, "
            f"{rt.get('partially_resolved', 0):,} partially resolved, "
            f"{rt.get('fix_in_progress', 0):,} fix in progress, "
            f"{rt.get('risk_accepted', 0):,} risk accepted, "
            f"{rt.get('regression_introduced', 0):,} with regressions, "
            f"{rt.get('open', 0):,} open. "
            f"{agg.get('fp_excluded', 0):,} confirmed false positives "
            f"are excluded from every figure on this page; "
            f"{agg.get('hardening_total', 0):,} hardening findings "
            f"(accurate posture gaps, no exploit path) are tracked "
            f"separately and λ-weighted in the findings-trends risk "
            f"index.</p></div>"
        )

    # ATT&CK coverage (attack-coverage skill roll-up)
    attack_kpi = attack_card = ""
    ac = agg.get("attack_coverage")
    if ac:
        attack_kpi = (
            f'<div class="kpi"><div class="n" style="color:#ec7a08">'
            f"{len(ac['observed'])}</div>"
            f'<div class="l">ATT&amp;CK techniques observed</div></div>'
        )
        obs_rows = "".join(
            f"<tr><td>{esc(t['id'])}</td><td>{esc(t['name'])}</td><td>{esc(t['comment'])}</td></tr>"
            for t in ac["observed"]
        )
        attack_card = (
            f'<div class="card"><h2>MITRE ATT&amp;CK Coverage</h2>'
            f'<p style="font-size:13px">{ac["covered"]} techniques across '
            f"{ac['tactics']} tactics (ATT&amp;CK v{esc(str(ac['attack_version']))}, "
            f"pinned): <b>{len(ac['observed'])} observed</b> in confirmed "
            f"live-validation chains, {ac['modeled']:,} modeled in threat "
            f"models, {ac['derived']:,} weakness-derived candidates. "
            f"Navigator layer: "
            f"<code>metrics/dashboards/attack-coverage/</code>.</p>"
            f"<details><summary>Observed techniques "
            f"({len(ac['observed'])})</summary>"
            f"<table><thead><tr><th>ID</th><th>Name</th><th>Evidence</th>"
            f"</tr></thead><tbody>{obs_rows}</tbody></table></details>"
            f'<p style="font-size:11px;color:var(--muted)">MITRE ATT&amp;CK® '
            f"© The MITRE Corporation, used with attribution.</p></div>"
        )

    # PQC readiness (pqc-readiness Phase-2 roll-up)
    pqc_kpi = pqc_card = ""
    pq = agg.get("pqc")
    if pq:
        b = pq["buckets"]
        pqc_kpi = (
            f'<div class="kpi"><div class="n" style="color:#5ba352">'
            f"{pq['clock_2030_items']}</div>"
            f'<div class="l">PQC 2030-clock items</div></div>'
        )
        sig_rows = "".join(
            f"<tr><td><code>{esc(r['repo'])}</code></td>"
            f"<td style='text-align:right'>{esc(str(r.get('overall')))}</td>"
            f"<td>{esc((r.get('primitive') or '')[:140])}</td></tr>"
            for r in pq["clock_2030_significant"][:12]
        )
        hndl_rows = "".join(
            f"<tr><td><code>{esc(r['repo'])}</code></td>"
            f"<td style='text-align:right'>{esc(str(r.get('overall')))}</td>"
            f"<td>{esc(r.get('bucket') or '')}</td></tr>"
            for r in pq["hndl"][:12]
        )
        pqc_card = (
            f'<div class="card" style="border-left:4px solid #5ba352">'
            f"<h2>Post-Quantum Cryptography Readiness (NIST IR 8547)</h2>"
            f'<p style="font-size:13px">{pq["reports"]:,} repos assessed: '
            f"<b>{b.get('ready', 0):,} ready</b> / "
            f"{b.get('partial', 0):,} partial / "
            f"<b>{b.get('not-ready', 0):,} not-ready</b> / "
            f"{b.get('blocked-external', 0):,} blocked-external / "
            f"{b.get('not-applicable', 0):,} n/a (scored median "
            f"{pq['median']:g}). "
            f"2030 clock: <b>{pq['clock_2030_items']}</b> items across "
            f"{pq['clock_2030_repos']} repos "
            f"({len(pq['clock_2030_significant'])} significant); "
            f"2035 clock: {pq['clock_2035_items']:,}. "
            f"HNDL-priority: {len(pq['hndl'])} repos. "
            f"Hybrid-TLS blockers: {pq['hybrid_blockers']} pins. "
            f"Toolchain quick wins: {pq['quickwins']} go.mod bumps. "
            f"Roll-up + CSVs: <code>metrics/dashboards/pqc/</code>.</p>"
            f"<details><summary>Significant-effort 2030-clock items "
            f"({len(pq['clock_2030_significant'])})</summary>"
            f"<table><thead><tr><th>Repo</th><th>Score</th><th>Primitive"
            f"</th></tr></thead><tbody>{sig_rows}</tbody></table></details>"
            f"<details><summary>HNDL priority ranking (top 12 of "
            f"{len(pq['hndl'])})</summary>"
            f"<table><thead><tr><th>Repo</th><th>Score</th><th>Bucket</th>"
            f"</tr></thead><tbody>{hndl_rows}</tbody></table></details>"
            f"</div>"
        )

    # Posture tiles (ratings, deliberately NOT findings)
    leastpriv_kpi = leastpriv_card = ""
    lp = agg.get("least_priv")
    if lp:
        leastpriv_kpi = (
            f'<div class="kpi"><div class="n" style="color:#c98a3d">'
            f"{lp['wildcard_repos']:,}</div>"
            f'<div class="l">Operators w/ wildcard RBAC</div></div>'
        )
        surplus_rows = "".join(
            f"<tr><td><code>{esc(r['repo'])}</code></td>"
            f"<td style='text-align:right'>{r['surplus']:,}</td>"
            f"<td>{esc(', '.join(f'{k}×{v}' for k, v in sorted((r.get('rbac_risk_flags') or {}).items(), key=lambda kv: -kv[1])[:3]))}</td></tr>"
            for r in lp["top_surplus"]
        )
        flag_summary = ", ".join(f"{k}×{v:,}" for k, v in lp["flags"][:5])
        leastpriv_card = (
            f'<div class="card" style="border-left:4px solid #c98a3d">'
            f"<h2>Operator Least-Privilege Posture (static, tiers 1–2)</h2>"
            f'<p style="font-size:13px">{lp["profiles"]:,} privilege '
            f"profiles — <b>posture ratings, not findings</b> (kept out "
            f"of the totals above). "
            f"<b>{lp['privileged']:,}</b> privileged/host-touching, "
            f"<b>{lp['scc_requesting']:,}</b> request SCCs, "
            f"<b>{lp['wildcard_repos']:,}</b> with wildcard RBAC "
            f"({lp['wildcard_rules']:,} rules). "
            f"Risk-flag totals: {esc(flag_summary)}. "
            f"Rollup: <code>metrics/dashboards/operator-least-priv/"
            f"</code>.</p>"
            f"<details><summary>Top RBAC surplus "
            f"({len(lp['top_surplus'])})</summary>"
            f"<table><thead><tr><th>Repo</th><th>Surplus</th>"
            f"<th>Top risk flags</th></tr></thead>"
            f"<tbody>{surplus_rows}</tbody></table></details></div>"
        )
    isolation_card = ""
    iso = agg.get("isolation")
    if iso:
        worst_rows = "".join(
            f"<tr><td><code>{esc(s['service'])}</code></td>"
            f"<td style='text-align:right'>{esc(str(s['overall']))}</td>"
            f"<td style='text-align:right'>{s['interfaces']}</td>"
            f"<td style='text-align:right'>{s['gaps']}</td></tr>"
            for s in iso["worst"]
        )
        isolation_card = (
            f'<div class="card" style="border-left:4px solid #3d8ac9">'
            f"<h2>Tenant-Isolation Posture (PEACH)</h2>"
            f'<p style="font-size:13px">{len(iso["services"])} '
            f"multi-tenant service reviews — <b>posture scores, not "
            f"findings</b>. {iso['interfaces']:,} customer-facing "
            f"interfaces inventoried; {iso['gaps']:,} isolation gaps "
            f"recorded (escalation-worthy gaps promote individually via "
            f"triage). Reports: <code>analysis-results/isolation/"
            f"</code>.</p>"
            f"<details><summary>Lowest-scoring services</summary>"
            f"<table><thead><tr><th>Service</th><th>Overall</th>"
            f"<th>Interfaces</th><th>Gaps</th></tr></thead>"
            f"<tbody>{worst_rows}</tbody></table></details></div>"
        )

    hardening_card = ""
    if agg.get("hardening_total"):
        theme_rows_h = "".join(
            f"<tr><td>{esc(t)}</td><td style='text-align:right'>{n:,}</td></tr>"
            for t, n in agg.get("hardening_themes") or []
        )
        repo_rows_h = "".join(
            f"<tr><td><code>{esc(r)}</code></td><td style='text-align:right'>{n:,}</td></tr>"
            for r, n in (agg.get("hardening_top_repos") or [])[:10]
        )
        hardening_card = (
            f'<div class="card" style="border-left:4px solid #8476d1">'
            f"<h2>Hardening Backlog (Posture Debt) — "
            f"{agg['hardening_total']:,} findings</h2>"
            f'<p style="font-size:13px">Accurate defense-in-depth/benchmark '
            f"gaps with <b>no demonstrated exploit path</b> — never counted "
            f"as vulnerabilities above, never dropped: absent hardening "
            f"amplifies co-located vulnerabilities (λ-weighted in the "
            f"findings-trends risk index). File as regular engineering work "
            f"via <code>/file-security-defect --hardening</code>.</p>"
            f'<div class="grid">'
            f"<div><table><thead><tr><th>Theme</th><th>Findings</th></tr>"
            f"</thead><tbody>{theme_rows_h}</tbody></table></div>"
            f"<div><table><thead><tr><th>Largest per-repo backlogs</th>"
            f"<th>Findings</th></tr></thead><tbody>{repo_rows_h}</tbody>"
            f"</table></div></div></div>"
        )

    lang_table_rows = []
    for tot, lang, c in sorted(
        ((sum(c.get(s, 0) for s in SEVERITIES), lang, c) for lang, c in agg["per_lang"].items()),
        reverse=True,
    ):
        lang_table_rows.append(
            [
                esc(lang),
                agg["repos_per_lang"].get(lang, 0),
                c.get("critical", 0),
                c.get("high", 0),
                c.get("medium", 0),
                c.get("low", 0),
                c.get("informational", 0),
                f"<b>{tot}</b>",
            ]
        )

    seg_card = ""
    seg_payload = None
    if agg.get("per_segment"):
        seg_rows_data = _segment_rows(agg)
        seg_labels = [s for s, _ in seg_rows_data]
        seg_datasets = [
            {
                "label": s.title(),
                "data": [c.get(s, 0) for _, c in seg_rows_data],
                "backgroundColor": _SEV_COLORS[s],
            }
            for s in SEVERITIES
        ]
        seg_payload = {"labels": seg_labels, "datasets": seg_datasets}
        seg_table_rows = []
        for seg, c in seg_rows_data:
            tot = sum(c.get(s, 0) for s in SEVERITIES)
            seg_table_rows.append(
                [
                    esc(seg),
                    f"{agg['segment_repos'].get(seg, 0):,}",
                    c.get("critical", 0),
                    c.get("high", 0),
                    c.get("medium", 0),
                    c.get("low", 0),
                    c.get("informational", 0),
                    f"<b>{tot:,}</b>",
                    agg["segment_crit"].get(seg, 0),
                    agg["segment_high"].get(seg, 0),
                ]
            )
        seg_card = (
            '<div class="card"><h2>Findings by Input Segment</h2>'
            '<div class="chart-box"><canvas id="segChart"></canvas></div>'
            + table(
                [
                    "Segment",
                    "Repos",
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Info",
                    "Total",
                    "Repos ≥1 Crit",
                    "Repos ≥1 High",
                ],
                seg_table_rows,
            )
            + '<p style="font-size:12px;color:var(--muted)">Repositories '
            "mapped against the inputs inventories "
            "(ansible excluded). Multi-segment repos count once, priority "
            f"{esc(' → '.join(SEGMENT_PRIORITY))} "
            f"({agg['segment_overlap']:,} repos overlap); "
            "“unmapped” = absent from the input inventories "
            "(including oss-findings/).</p></div>"
        )

    payload = {
        "sev": {"labels": sev_labels, "data": sev_data, "colors": sev_colors},
        "lang": {"labels": lang_labels, "datasets": lang_datasets},
        "theme": {"labels": theme_labels, "data": theme_data},
        "rem": rem_payload,
        "seg": seg_payload,
    }

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit — Executive Summary</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {{ --rh-red:#ee0000; --fg:#151515; --muted:#6a6e73; --border:#d2d2d2; }}
  body {{ font-family: "Red Hat Text", -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
          margin:0; color:var(--fg); background:#fafafa; }}
  header {{ background:#151515; color:#fff; padding:20px 28px; border-bottom:4px solid var(--rh-red); }}
  header h1 {{ margin:0 0 4px 0; font-size:22px; }}
  header .sub {{ color:#d2d2d2; font-size:13px; }}
  main {{ max-width:1280px; margin:0 auto; padding:24px 28px 60px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:28px; }}
  .kpi {{ background:#fff; border:1px solid var(--border); border-radius:8px; padding:14px 16px; }}
  .kpi .n {{ font-size:28px; font-weight:700; }}
  .kpi .l {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:24px; }}
  @media (max-width: 960px) {{ .grid {{ grid-template-columns:1fr; }} }}
  .card {{ background:#fff; border:1px solid var(--border); border-radius:8px; padding:18px 20px; margin-bottom:24px; }}
  .card h2 {{ margin:0 0 12px 0; font-size:16px; }}
  .chart-box {{ position:relative; height:300px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #eee; }}
  th {{ font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted);
        border-bottom:1px solid var(--border); }}
  tbody tr:hover {{ background:#f5f5f5; }}
  code {{ font-family: "Red Hat Mono", SFMono-Regular, Menlo, monospace; font-size:12px; }}
  .badge {{ display:inline-block; min-width:54px; text-align:center; color:#fff;
            font-size:11px; font-weight:600; padding:2px 8px; border-radius:10px; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:32px; }}
</style>
</head><body>
<header>
  <h1>Hybrid Platforms — Security Audit Executive Summary</h1>
  <div class="sub">Generated {esc(today)} · {agg["n_reports"]:,} reports ·
    {agg.get("unique_repos", agg["n_reports"]):,} unique repositories ·
    {total_findings:,} findings · scope: {esc(", ".join(roots))}</div>
</header>
<main>
  {
        (
            "<div style='max-width:1280px;margin:12px auto 0;padding:0 28px;"
            "font-size:13px;color:#6a6e73'>📈 " + esc(agg["trend_line"]) + "</div>"
        )
        if agg.get("trend_line")
        else ""
    }
  <section class="kpis">
    <div class="kpi"><div class="n">{agg["n_reports"]:,}</div><div class="l">Reports</div></div>
    <div class="kpi"><div class="n">{
        agg.get("unique_repos", agg["n_reports"]):,}</div><div class="l">Unique repos</div></div>
    <div class="kpi"><div class="n">{
        total_findings:,}</div><div class="l">Total findings</div></div>
    {distinct_kpi}
    <div class="kpi"><div class="n" style="color:{_SEV_COLORS["critical"]}">{
        sev.get("critical", 0):,}</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="n" style="color:{_SEV_COLORS["high"]}">{
        sev.get("high", 0):,}</div><div class="l">High</div></div>
    <div class="kpi"><div class="n">{
        agg["cred_leaks_raw"]:,}</div><div class="l">Credential leaks</div></div>
    <div class="kpi"><div class="n">{
        agg["repos_with_crit"]
    }</div><div class="l">Repos w/ Critical</div></div>
    {triage_kpi}
    {disposition_kpi}
    {attack_kpi}
    {pqc_kpi}
    {leastpriv_kpi}
  </section>
  {distinct_note}
  {triage_note}
  {disposition_note}

  <section class="grid">
    <div class="card"><h2>Findings by Severity</h2>
      <div class="chart-box"><canvas id="sevChart"></canvas></div></div>
    <div class="card"><h2>Top Risk Themes (CWE clusters)</h2>
      <div class="chart-box"><canvas id="themeChart"></canvas></div></div>
  </section>

  {seg_card}

  {hardening_card}

  <div class="card"><h2>Findings by Primary Language — top 12</h2>
    <div class="chart-box" style="height:360px"><canvas id="langChart"></canvas></div></div>

  {rem_chart_card}

  {attack_card}

  {pqc_card}

  {leastpriv_card}

  {isolation_card}

  <div class="card"><h2>Top Critical &amp; High Findings</h2>
    {table(["Sev", "CVSS", "Repository", "Finding", "CWE", "Ships in", "Status"], crit_high_rows)}
    <p style="font-size:12px;color:var(--muted)">
      Showing top {len(crit_high_rows)} of {len(agg["crit_high"])} unique Critical/High findings
      ({agg["crit_high_raw"]} total occurrences), ranked by severity then CVSS.</p>
  </div>

  <div class="card"><h2>Credential &amp; Secret Leaks in Code</h2>
    {table(["Sev", "Repository", "Finding", "CWE"], leak_rows)}
    <p style="font-size:12px;color:var(--muted)">
      Showing top {len(leak_rows)} of {len(agg["cred_leaks"])} unique credential-leak findings
      ({agg["cred_leaks_raw"]} total occurrences;
       CWE-798/259/321/522/540/256/312/1392 or title heuristic).</p>
  </div>

  <div class="card"><h2>Findings by Primary Language — full table</h2>
    {
        table(
            ["Language", "Repos", "Critical", "High", "Medium", "Low", "Info", "Total"],
            lang_table_rows,
        )
    }
  </div>

  <footer>Generated by traust <code>{esc(version)}</code>
    (<code>harnessing/executive-summary-findings/scripts/build_executive_summary.py</code>).
    Re-run via the <code>/executive-summary-findings</code> skill.{variant_note}</footer>
</main>
<script>
const D = {json_script(payload)};
new Chart(document.getElementById('sevChart'), {{
  type:'doughnut',
  data:{{labels:D.sev.labels, datasets:[{{data:D.sev.data, backgroundColor:D.sev.colors,
         borderWidth:1, borderColor:'#fff'}}]}},
  options:{{responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{position:'right'}}}}}}
}});
new Chart(document.getElementById('themeChart'), {{
  type:'bar',
  data:{{labels:D.theme.labels, datasets:[{{label:'Findings', data:D.theme.data,
         backgroundColor:'#0066cc'}}]}},
  options:{{indexAxis:'y', responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}}, scales:{{x:{{beginAtZero:true}}}}}}
}});
new Chart(document.getElementById('langChart'), {{
  type:'bar',
  data:{{labels:D.lang.labels, datasets:D.lang.datasets}},
  options:{{responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom'}}}},
    scales:{{x:{{stacked:true}}, y:{{stacked:true, beginAtZero:true}}}}}}
}});
if (D.seg) {{
  new Chart(document.getElementById('segChart'), {{
    type:'bar',
    data:{{labels:D.seg.labels, datasets:D.seg.datasets}},
    options:{{responsive:true, maintainAspectRatio:false,
      plugins:{{legend:{{position:'bottom'}}}},
      scales:{{x:{{stacked:true}}, y:{{stacked:true, beginAtZero:true}}}}}}
  }});
}}
if (D.rem) {{
  new Chart(document.getElementById('remChart'), {{
    type:'bar',
    data:{{labels:D.rem.labels, datasets:[
      {{label:'Resolved', data:D.rem.resolved, backgroundColor:'#3e8635'}},
      {{label:'Partially resolved', data:D.rem.partial, backgroundColor:'#f0ab00'}}
    ]}},
    options:{{responsive:true, maintainAspectRatio:false,
      plugins:{{legend:{{position:'bottom'}}}},
      scales:{{x:{{stacked:true}}, y:{{stacked:true, beginAtZero:true,
        ticks:{{precision:0}}}}}}}}
  }});
}}
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _metrics_ledger(config_home):
    """Soft-load the shared metrics ledger; None when unavailable."""
    try:
        import importlib

        mod = importlib.import_module("traust_engine.metrics.history")
        ws = workspace_dir(load_engine(config_home))
        return mod, ws
    except SystemExit:
        return None, None
    except Exception as e:  # pragma: no cover — trends are best-effort
        print(f"[!] metrics ledger unavailable: {e}", file=sys.stderr)
    return None, None


TREND_KEYS = [
    "findings_total",
    "sev_critical",
    "sev_high",
    "credential_findings",
    "hardening_backlog",
    "resolved_findings",
    "dispositioned_repos",
]


def _corpus_module():
    """Load traust_engine.corpus.resolver — discovery/identity authority."""
    import importlib

    return importlib.import_module("traust_engine.corpus.resolver")


def _ref_coverage(roots):
    """Per-ref report counts for the scanned trees, straight from
    corpus.py aggregates()['totals']['refs'] (branch-awareness Phase 4). The resolver owns ref identity — declared `metadata.ref`
    preferred, legacy `__release-X.Y` slug fallback — this builder never
    re-parses slugs. Reporting only: no pre-existing number is derived
    from it; None (section skipped) when the corpus is unavailable or
    the roots are not registered trees."""
    try:
        corpus = _corpus_module()
        cfg = corpus.load_config()
        trees = [os.path.basename(os.path.normpath(r)) for r in roots]
        analysis_results = Path(os.path.normpath(roots[0])).parent
        res = corpus.resolve(analysis_results, cfg, trees=trees)
        agg = corpus.aggregates(res)
        return {
            "refs": agg["totals"]["refs"],
            "declared": sum(1 for r in res.records if r.ref_source == "metadata"),
            "reports": agg["totals"]["reports"],
        }
    except Exception as e:  # pragma: no cover — best-effort, additive
        print(f"[!] ref coverage unavailable: {e}", file=sys.stderr)
        return None


def _population_lines(roots, agg, disc_stats):
    """Standard population block (traust.cli.groups.corpus); None when unavailable.

    Reporting only — describes exactly what this run already scanned; the
    builder's discovery, filters and units are unchanged."""
    try:
        corpus = _corpus_module()
        cfg = corpus.load_config()
        trees = [os.path.basename(os.path.normpath(r)) for r in roots]
        return corpus.population_block_lines(
            tool="executive-summary-findings",
            roots=corpus.roots_description(cfg, trees),
            unit="findings (severity_counts occurrences per report)",
            filters=(
                "false positives and hardening excluded where a "
                "disposition ledger (findings-current) exists; plain "
                "audits counted raw (config findings included)"
            ),
            denominator="directory walk of the roots (reports on disk)",
            counts={
                "Reports scanned": f"{agg['n_reports']:,}",
                "Unique repositories": f"{agg.get('unique_repos', agg['n_reports']):,}",
                "Reports with disposition ledger": f"{agg.get('dispositioned_repos', 0):,}",
                "Symlinked dirs not traversed": f"{disc_stats.get('symlink_dirs_skipped', 0):,}",
                "Reports parsed from md fallback (no JSON sibling)": f"{disc_stats.get('md_fallback_reports', 0):,}",
                # branch-awareness Phase 4: make "HEAD or
                # branch-inclusive?" answerable from the header block
                "Ref scope": "occurrence totals are branch-INCLUSIVE (HEAD audits "
                "+ release-branch re-audits); the Distinct "
                "Vulnerabilities headline is HEAD-only (per-ref rows "
                "under Release-branch confirmations)",
            },
        )
    except Exception as e:  # pragma: no cover — block is best-effort
        print(f"[!] population block unavailable: {e}", file=sys.stderr)
        return None


def _dashboards_home(config_home):
    try:
        engine = load_engine(config_home)
        dashboards = progress_tracker_dir(engine) / "metrics" / "dashboards"
        dashboards.mkdir(parents=True, exist_ok=True)
        return dashboards
    except SystemExit:
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (contains findings/ and "
        "oss-findings/). Default: $AUDIT_RESULTS_ROOT or "
        "locations.yaml.",
    )
    ap.add_argument(
        "--roots",
        nargs="*",
        default=None,
        help="Override directories to scan for *security-audit.{json,md} "
        "(default: <results-root>/findings, <results-root>/oss-findings)",
    )
    ap.add_argument(
        "--lang-cache",
        default=None,
        help="Path to gh-languages-cache.jsonl "
        "(default: <results-root>/findings/_manifest/gh-languages-cache.jsonl)",
    )
    ap.add_argument(
        "--out-md",
        default=None,
        help="Output Markdown path (default: <results-root>/Executive-summary-findings.md)",
    )
    ap.add_argument(
        "--out-html",
        default=None,
        help="Output HTML path (default: <results-root>/Executive-summary-findings.html)",
    )
    ap.add_argument(
        "--open",
        action="store_true",
        help="Open the HTML dashboard in the default browser when done.",
    )
    ap.add_argument(
        "--by-segment",
        action="store_true",
        help="Add a per-input-segment breakdown (openshift / "
        "operator-catalog / services from the inputs inventory; "
        "ansible excluded by default).",
    )
    ap.add_argument(
        "--inputs-root",
        default=None,
        help="inputs inventory directory (default: "
        "locations.inputs, else <workspace>/inputs; "
        "override with --inputs-root).",
    )
    ap.add_argument(
        "--exclude-segment",
        action="append",
        default=None,
        metavar="SEG",
        help="Input segment(s) to skip in --by-segment mode (repeatable; default: ansible).",
    )
    ap.add_argument(
        "--include-triage",
        action="store_true",
        help="For repos without a findings-current ledger, count "
        "from unconfirmed /triage verdicts (true positives "
        "only) instead of the raw audit. OFF by default: "
        "early /triage runs over-marked false positives, so "
        "these figures are labeled unconfirmed in both "
        "outputs.",
    )
    ap.add_argument(
        "--exclude-branch-variants",
        action="store_true",
        help="Skip '__'-slugged release-branch re-audits when the "
        "same product tree also carries the base-slug audit "
        "(within-product duplicates). Branch-only audits "
        "(per-release payload products) always count.",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = resolve_results_root(args)
    roots = args.roots or [str(results_root / "findings"), str(results_root / "oss-findings")]
    lang_cache_path = args.lang_cache or str(
        results_root / "findings" / "_manifest" / "gh-languages-cache.jsonl"
    )
    dash = _dashboards_home(args.config_home)
    out_md = args.out_md or str((dash or results_root) / "Executive-summary-findings.md")
    out_html = args.out_html or str((dash or results_root) / "Executive-summary-findings.html")

    version = harness_version()
    print(f"[+] harness version: {version}", file=sys.stderr)
    print(f"[+] results root: {results_root}", file=sys.stderr)

    roots_rel = [os.path.relpath(r, results_root) + "/" for r in roots]
    lang_cache = load_language_cache(lang_cache_path)
    print(
        f"[+] language cache: {len(lang_cache)} repos "
        f"({os.path.relpath(lang_cache_path, results_root)})",
        file=sys.stderr,
    )

    reports, disc_stats = discover_reports(
        roots,
        include_triage=args.include_triage,
        exclude_branch_variants=args.exclude_branch_variants,
    )
    print(f"[+] parsed {len(reports)} reports", file=sys.stderr)
    if args.exclude_branch_variants:
        print(
            f"[+] excluded {disc_stats['excluded_branch_variants']} "
            f"within-product duplicate branch-variant reports",
            file=sys.stderr,
        )
    if args.include_triage:
        print(
            f"[+] {disc_stats['triage_counted']} repos counted from unconfirmed triage verdicts",
            file=sys.stderr,
        )

    segment_map = None
    if args.by_segment:
        inputs_root = resolve_inputs_root(args.inputs_root, engine)
        if inputs_root is None:
            print(
                "[!] --by-segment: could not locate the inputs inventory "
                "(pass --inputs-root or set locations.inputs); "
                "skipping the segment breakdown",
                file=sys.stderr,
            )
        else:
            exclude = args.exclude_segment or ["ansible"]
            set_segment_priority(inputs_root, exclude)
            segment_map = load_segment_map(inputs_root, exclude)
            print(
                f"[+] segment map: {len(segment_map)} repos from "
                f"{inputs_root} (excluded: {', '.join(exclude)})",
                file=sys.stderr,
            )

    agg = aggregate(reports, lang_cache, roots, segment_map=segment_map)
    agg["attack_coverage"] = load_attack_coverage(dash)
    agg["cloud_config"] = load_cloud_config(results_root)
    agg["pqc"] = load_pqc_readiness(dash)
    agg["least_priv"] = load_least_priv(dash)
    agg["isolation"] = load_isolation(results_root)
    agg["dependency_exposure"] = load_dependency_exposure(reports, results_root)
    agg["excluded_branch_variants"] = disc_stats["excluded_branch_variants"]
    agg.update(distinct_metrics(reports, roots))
    agg["ref_coverage"] = _ref_coverage(roots)
    if agg["ref_coverage"]:
        rc = agg["ref_coverage"]
        print(
            f"[+] ref coverage (corpus resolver): {len(rc['refs'])} "
            f"distinct refs across {sum(rc['refs'].values()):,} of "
            f"{rc['reports']:,} reports; {rc['declared']:,} declare "
            f"metadata.ref",
            file=sys.stderr,
        )
    print(
        "[+] distinct vulnerabilities (Lens 2): "
        + ", ".join(
            f"{t}: {d['total']:,} ({d['open']:,} open)" for t, d in sorted(agg["distinct"].items())
        )
        + f"; branch confirmations: {agg['branch_confirmations']:,}"
        f" (fingerprint coverage {agg['fingerprint_coverage']:.1f}%)",
        file=sys.stderr,
    )

    ml, _ws = _metrics_ledger(args.config_home)
    if ml:
        sev = agg["sev_totals"]
        headline = {
            "repos_audited": agg["n_reports"],
            "unique_repos": agg.get("unique_repos"),
            "findings_total": sum(sev.get(s, 0) for s in SEVERITIES),
            "sev_critical": sev.get("critical", 0),
            "sev_high": sev.get("high", 0),
            "repos_with_critical": agg["repos_with_crit"],
            "repos_with_high": agg["repos_with_high"],
            "credential_findings": len(agg["cred_leaks"]),
            "hardening_backlog": agg.get("hardening_total"),
            "dispositioned_repos": agg.get("dispositioned_repos"),
            "resolved_findings": (agg.get("resolution_totals") or {}).get("resolved"),
            "distinct_vulns_owned": (agg["distinct"].get("findings") or {}).get("total"),
            "distinct_open_owned": (agg["distinct"].get("findings") or {}).get("open"),
            "branch_confirmations": agg.get("branch_confirmations"),
        }
        prev = ml.previous("executive-summary")
        agg["trend_line"] = ml.trend_line(headline, prev, TREND_KEYS)
        row = ml.append_if_changed("executive-summary", headline)
        if row:
            print(
                f"[+] metrics snapshot appended (row_sha {row['row_sha'][:12]}…)", file=sys.stderr
            )
    if agg.get("per_segment"):
        print(
            "[+] segments: "
            + ", ".join(
                f"{s}={agg['segment_repos'].get(s, 0)} repos" for s, _ in _segment_rows(agg)
            ),
            file=sys.stderr,
        )
    print(f"[+] totals: {agg['sev_totals']}", file=sys.stderr)
    print(
        f"[+] crit/high findings: {len(agg['crit_high'])}; "
        f"credential leaks: {len(agg['cred_leaks'])}",
        file=sys.stderr,
    )

    pop_lines = _population_lines(roots, agg, disc_stats)

    md = render_markdown(agg, roots_rel, version)
    if pop_lines:
        md = md.rstrip("\n") + "\n\n---\n\n" + "\n".join(pop_lines) + "\n"
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"[+] wrote {out_md}", file=sys.stderr)

    # Machine sidecar for the leadership-scoreboard collector
    # (collect_harness_metrics.py). Before this existed the collector
    # regex-parsed the markdown SENTENCES above — rewording the prose
    # silently blanked headline metrics (docs-verification 2026-07-31,
    # wiring c3). The sidecar is the contract; the prose is for humans.
    sev = agg["sev_totals"]
    rt = agg.get("resolution_totals", {})
    crit = [e for e in agg["crit_high"] if e["severity"] == "critical"]
    high = [e for e in agg["crit_high"] if e["severity"] == "high"]
    sidecar = {
        "generated": _dt.date.today().isoformat(),
        "harness_version": version,
        "repos_audited": agg["n_reports"],
        "unique_repos": agg.get("unique_repos", agg["n_reports"]),
        "findings_total": sum(sev.get(s, 0) for s in SEVERITIES),
        **{f"sev_{s}": sev.get(s, 0) for s in SEVERITIES},
        "unique_critical": len(crit),
        "unique_high": len(high),
        "repos_with_critical": agg["repos_with_crit"],
        "repos_with_high": agg["repos_with_high"],
        "credential_findings": len(agg["cred_leaks"]),
        "dispositioned_repos": agg.get("dispositioned_repos", 0),
        "resolved_findings": rt.get("resolved", 0),
        "hardening_backlog": agg.get("hardening_total", 0),
    }
    sidecar_path = Path(out_md).with_suffix("").as_posix() + ".metrics.json"
    Path(sidecar_path).write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")
    print(f"[+] wrote {sidecar_path}", file=sys.stderr)

    html_doc = render_html(agg, roots_rel, version)
    if pop_lines:
        pop_items = "".join(
            "<li>"
            + re.sub(
                r"\*\*(.+?):\*\*",
                r"<b>\1:</b>",
                html.escape(ln[2:] if ln.startswith("- ") else ln),
                count=1,
            )
            + "</li>"
            for ln in pop_lines
            if ln and ln != "## Population"
        )
        pop_panel = (
            f'<div class="card"><h2>Population</h2>'
            f'<ul style="font-size:13px">{pop_items}</ul></div>'
        )
        html_doc = html_doc.replace("<footer>", pop_panel + "\n\n  <footer>", 1)
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"[+] wrote {out_html}", file=sys.stderr)

    if args.open:
        import webbrowser

        webbrowser.open(f"file://{Path(out_html).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
