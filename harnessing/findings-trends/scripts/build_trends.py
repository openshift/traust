#!/usr/bin/env python3
"""
build_trends.py — portfolio findings trends by ledger replay.

Walks every *-security-audit.json under the findings roots, replays each
repo's *-findings-layer.json (track-findings disposition ledger) against a
series of time-bucket boundaries, and emits upward/downward trend series:

  analysis-results/trends/findings-trends.json   full time series
  analysis-results/trends/findings-trends.md     one-pager with arrows
  analysis-results/trends/findings-trends.html   self-contained charts

Semantics (agreed 2026-07-10):
  * Ledger-less repos count as OPEN ("Option A"): every audited finding
    without a closing event is open exposure. Ledger coverage is printed
    next to every headline so partial coverage can't masquerade as a trend.
  * risk_accepted is NOT remediation: accepted findings leave "open" but
    land in a standing Accepted Risk register (unfixed, unmitigated),
    reported with who accepted them and when.
  * Risk headline = OWASP Risk Rating Methodology: per-finding
    likelihood x impact derived from the CVSS 3.x vector, rolled up as a
    band distribution + % of open findings rated High/Critical. See
    docs/risk-rating-methodology.md. The legacy CVSS-sum "risk index"
    series (severity-band midpoints for score-less findings: critical
    9.5, high 8.0, medium 5.5, low 2.0, informational 0) remain in the
    JSON as history only.
  * Events bucket by occurred_at (source timestamp) when present, falling
    back to recorded_at, so late ingestion does not distort the series.
  * The false_positive human-countersign rule is honoured by reusing the
    track-findings merge engine (derive_disposition) for state replay.
"""

import argparse
import collections
import contextlib
import datetime as _dt
import html as _html
import json
import re
import sys
from pathlib import Path

from traust_engine.escaping import json_script, md_cell

from traust.cli.build_cumulative import (
    derive_disposition,
    event_class,
)
from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

# Fallback λ for hardening events that predate emission-time weight
# recording; events written by emit_triage_ledger_events.py always carry
# risk_weight.lambda, which wins.
HARDENING_LAMBDA_FALLBACK = 0.3

# Finding categories where a refuted-register entry is a natural fuzzing
# target (parsers, decoders, injection surfaces) — these entries are the
# priority queue for empirically falsifying FP assertions.
FUZZABLE_CATEGORIES = {
    "injection",
    "input-validation",
    "path-traversal",
    "ssrf",
    "cross-site-scripting",
    "cryptography",
}

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
# CVSS v3 rating-band midpoints for findings that carry no cvss.score.
SEV_FALLBACK_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "informational": 0.0}
SEV_COLORS = {
    "critical": "#a30000",
    "high": "#ee0000",
    "medium": "#f0ab00",
    "low": "#2b9af3",
    "informational": "#8a8d90",
}

# metric -> which direction is good
POLARITY_GOOD_DOWN = {
    "open",
    "risk_index",
    "new",
    "mttr",
    "fp_rate",
    "regressions",
    "accepted_risk_index",
    "hardening_risk_index",
    "risk_index_combined",
    "owasp_high_plus_pct",
}
POLARITY_GOOD_UP = {"velocity", "coverage"}

# Ownership sub-split ($TRAUST_CONFIG_HOME/corpus-config.yaml tree tags): findings/ is
# owned (Hybrid Platforms), oss-findings/ is upstream. Reported alongside
# the portfolio series for the latest bucket only — upstream is never
# folded into the owned headline, and the portfolio buckets are unchanged.
OWNERSHIP_CUT_LABELS = {
    "findings": "Owned (findings/, Hybrid Platforms)",
    "oss-findings": "Upstream (oss-findings/)",
    "cloud-config": "Cloud-config declared-layer IaC (cloud-config/, "
    "hardening-class — separate unit, never blended "
    "into code-audit backlog)",
}


def effective_date(event: dict) -> str:
    return event.get("occurred_at") or event.get("recorded_at") or ""


def bucket_key(iso: str, granularity: str) -> str:
    """ISO date/datetime -> bucket key. Keys sort lexically within a scheme."""
    d = _dt.date.fromisoformat(iso[:10])
    if granularity == "week":
        y, w, _ = d.isocalendar()
        return f"{y}-W{w:02d}"
    return iso[:7]


def enumerate_buckets(start_iso: str, end_iso: str, granularity: str) -> list[str]:
    """All bucket keys from start to end inclusive, in order."""
    keys: list[str] = []
    d = _dt.date.fromisoformat(start_iso[:10])
    end = _dt.date.fromisoformat(end_iso[:10])
    while d <= end:
        k = bucket_key(d.isoformat(), granularity)
        if not keys or keys[-1] != k:
            keys.append(k)
        d += _dt.timedelta(days=7 if granularity == "week" else 28)
    k = bucket_key(end.isoformat(), granularity)
    if keys[-1] != k:
        keys.append(k)
    return keys


def cvss_effective(finding: dict) -> float:
    score = (finding.get("cvss") or {}).get("score")
    if isinstance(score, (int, float)):
        return float(score)
    return SEV_FALLBACK_CVSS.get((finding.get("severity") or "").lower(), 0.0)


# ---------------------------------------------------------------------------
# OWASP Risk Rating Methodology
# (https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
#
# risk = likelihood x impact. Both factors score 0-9, bucket LOW/MEDIUM/
# HIGH, and combine on the OWASP 3x3 matrix into note/low/medium/high/
# critical. Findings carry CVSS 3.x vectors, so the factor scores derive
# deterministically from the vector: likelihood from the exploitability
# metrics (AV, AC, PR, UI), impact from the technical-impact metrics
# (C, I, A). The tables live in risk-rating-methodology.json next to this
# file — validated against contracts/schemas/risk-rating-methodology.schema.json by
# the test suite; rationale in docs/risk-rating-methodology.md. Edit the
# JSON (and bump its methodology_version), never inline constants.

_RR = json.loads(
    (Path(__file__).resolve().parents[1] / "risk-rating-methodology.json").read_text(
        encoding="utf-8"
    )
)
RR_METHODOLOGY_VERSION = _RR["methodology_version"]
_OWASP_LIKELIHOOD_FACTORS = _RR["likelihood_factors"]
_OWASP_IMPACT_FACTORS = _RR["impact_factors"]
_OWASP_MATRIX = {(lk, im): band for lk, row in _RR["matrix"].items() for im, band in row.items()}
_OWASP_SEV_FALLBACK_IMPACT = _RR["fallback"]["severity_impact"]
_OWASP_DEFAULT_LIKELIHOOD = _RR["fallback"]["default_likelihood"]
_RR_MEDIUM_MIN = _RR["bucket_thresholds"]["medium_min"]
_RR_HIGH_MIN = _RR["bucket_thresholds"]["high_min"]
OWASP_BANDS = _RR["bands"]
_TI_FACTOR = _RR.get("threat_intel_factor")

# exploitation-evidence feeds (EPSS/KEV) — populated by
# init_threat_intel() when the pull-through cache exists; absent feeds
# leave every rating exactly as before (factor contributes nothing).
_THREAT_INTEL = {"epss": None, "kev": None, "status": None}
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}")


def init_threat_intel(results_root: Path) -> dict | None:
    """Load the feeds cache (`traust feeds fetch`) if present."""
    if _TI_FACTOR is None:
        return None
    try:
        import importlib

        ff = importlib.import_module("traust.cli.fetch_feeds")
        cache = Path(results_root) / "feeds"
        _THREAT_INTEL["epss"] = ff.load_epss(cache)
        _THREAT_INTEL["kev"] = ff.load_kev(cache)
        _THREAT_INTEL["status"] = ff.feed_status(cache)
    except (OSError, json.JSONDecodeError, ImportError) as e:
        print(
            f"[!] threat-intel feeds unavailable ({e}) — OWASP likelihood uses CVSS factors only",
            file=sys.stderr,
        )
        _THREAT_INTEL["epss"] = _THREAT_INTEL["kev"] = None
        _THREAT_INTEL["status"] = None
    return _THREAT_INTEL["status"]


def threat_intel_score(finding: dict) -> float | None:
    """Exploitation-evidence likelihood factor for one finding, or None
    (no CVE id / feeds not loaded — rating falls back to CVSS-only)."""
    if _TI_FACTOR is None or _THREAT_INTEL["epss"] is None:
        return None
    cves = set(_CVE_RX.findall(json.dumps(finding)))
    if not cves:
        return None
    if any(c in _THREAT_INTEL["kev"] for c in cves):
        return float(_TI_FACTOR["kev_score"])
    epss = max((_THREAT_INTEL["epss"].get(c, {}).get("epss", -1.0) for c in cves), default=-1.0)
    if epss < 0:
        return None
    for band in _TI_FACTOR["epss_bands"]:
        if epss >= band["min_epss"]:
            return float(band["score"])
    return None


def _owasp_bucket(score: float) -> str:
    return "LOW" if score < _RR_MEDIUM_MIN else ("MEDIUM" if score < _RR_HIGH_MIN else "HIGH")


def owasp_rating(finding: dict, ti_score: float | None = None) -> str:
    """Overall OWASP Risk Rating band for one finding."""
    vector = (finding.get("cvss") or {}).get("vector") or ""
    parts = (
        dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
        if vector.startswith("CVSS:3")
        else {}
    )
    lk_scores = [
        table[parts[k]] for k, table in _OWASP_LIKELIHOOD_FACTORS.items() if parts.get(k) in table
    ]
    im_scores = [
        table[parts[k]] for k, table in _OWASP_IMPACT_FACTORS.items() if parts.get(k) in table
    ]
    if ti_score is not None:
        lk_scores.append(ti_score)
    sev = (finding.get("severity") or "informational").lower()
    likelihood = (sum(lk_scores) / len(lk_scores)) if lk_scores else _OWASP_DEFAULT_LIKELIHOOD
    impact = (
        (sum(im_scores) / len(im_scores)) if im_scores else _OWASP_SEV_FALLBACK_IMPACT.get(sev, 0.0)
    )
    return _OWASP_MATRIX[(_owasp_bucket(likelihood), _owasp_bucket(impact))]


# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------


def discover(roots: list[Path], product: str | None):
    """Yield per-repo records: audit findings + layer events + dates."""
    repos = []
    # (glob suffix, report kind) — declared-layer IaC audits replay
    # through the same ledger machinery but stay a distinct kind.
    suffixes = (
        ("-security-audit.json", "code-audit"),
        ("-cloud-config-audit.json", "cloud-config"),
    )
    for root in roots:
        if not root.is_dir():
            continue
        hits = [
            (aj, suffix, kind)
            for suffix, kind in suffixes
            for aj in sorted(root.rglob(f"*{suffix}"))
        ]
        for aj, suffix, kind in hits:
            if aj.is_symlink() or "_manifest" in aj.parts:
                continue
            rel = aj.parent.relative_to(root)
            prod = rel.parts[0] if rel.parts else ""
            if product and prod != product:
                continue
            try:
                audit = json.loads(aj.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            meta = audit.get("metadata") or {}
            date = str(meta.get("date") or meta.get("generated_at") or "")
            if not re.match(r"^\d{4}-\d{2}-\d{2}", date):
                continue
            lj = aj.parent / (aj.name[: -len(suffix)] + "-findings-layer.json")
            events_by_finding: dict[str, list] = collections.defaultdict(list)
            has_layer = False
            if lj.is_file():
                try:
                    layer = json.loads(lj.read_text(encoding="utf-8"))
                    has_layer = True
                    for e in layer.get("events", []):
                        events_by_finding[e["finding_ref"]].append(e)
                except (OSError, json.JSONDecodeError):
                    pass
            rj = aj.parent / (aj.name[: -len(suffix)] + "-refuted-register.json")
            register = []
            if rj.is_file():
                with contextlib.suppress(OSError, json.JSONDecodeError):
                    register = json.loads(rj.read_text(encoding="utf-8")).get("entries") or []
            repos.append(
                {
                    "dir": str(aj.parent),
                    "slug": aj.parent.name,
                    "base": aj.name[: -len(suffix)],
                    "kind": kind,
                    "tree": root.name,
                    "product": prod,
                    "repository": (audit.get("metadata") or {}).get("repository"),
                    "audit_date": date[:10],
                    "findings": audit.get("findings") or [],
                    "events": events_by_finding,
                    "register": register,
                    "has_layer": has_layer,
                    "layer_start": min(
                        (effective_date(e)[:10] for evs in events_by_finding.values() for e in evs),
                        default=None,
                    ),
                }
            )
    return repos


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def state_of(finding: dict, events: list, upto_key: str, granularity: str) -> str:
    """Finding state as of the end of bucket `upto_key`:
    open | hardening | resolved | accepted | false_positive."""
    if events:
        visible = [e for e in events if bucket_key(effective_date(e), granularity) <= upto_key]
        disp = derive_disposition(finding, visible, "1970-01-01T00:00:00+00:00")
        validity, resolution = disp["validity"], disp["resolution"]
    else:
        validity = finding.get("validation_status", "not_verified")
        resolution = "open"
    if validity == "false_positive":
        return "false_positive"
    if resolution == "resolved":
        return "resolved"
    if resolution == "risk_accepted":
        return "accepted"
    if validity == "hardening":
        return "hardening"  # open posture debt, λ-weighted in the risk index
    return "open"  # incl. fix_in_progress / partially_resolved / regression


def hardening_lambda(events: list, upto_key: str, granularity: str) -> float:
    """λ from the latest visible hardening event's emission-time record."""
    lams = [
        ((e.get("risk_weight") or {}).get("lambda"))
        for e in events
        if (e.get("disposition") or {}).get("validity") == "hardening"
        and bucket_key(effective_date(e), granularity) <= upto_key
    ]
    lams = [v for v in lams if isinstance(v, (int, float))]
    return float(lams[-1]) if lams else HARDENING_LAMBDA_FALLBACK


def close_date(events: list, upto_key: str, granularity: str, resolutions: tuple) -> str | None:
    """Effective date of the latest event <= bucket that set one of
    `resolutions`."""
    dates = [
        effective_date(e)
        for e in events
        if (e.get("disposition") or {}).get("resolution") in resolutions
        and bucket_key(effective_date(e), granularity) <= upto_key
    ]
    return max(dates)[:10] if dates else None


def build_series(repos: list[dict], granularity: str, since: str | None, as_of: str) -> dict:
    if not repos:
        return {"buckets": [], "accepted_register": [], "coverage": {}}
    start = min(r["audit_date"] for r in repos)
    if since:
        start = max(start, f"{since}-01")
    keys = enumerate_buckets(start, as_of, granularity)

    buckets = []
    prev_states: dict[tuple, str] = {}
    for key in keys:
        snap = {
            "key": key,
            "open_by_sev": collections.Counter(),
            "owasp_open": collections.Counter(),
            "accepted_by_sev": collections.Counter(),
            "open": 0,
            "accepted": 0,
            "hardening": 0,
            "resolved_total": 0,
            "false_positives_total": 0,
            "risk_index": 0.0,
            "accepted_risk_index": 0.0,
            "hardening_risk_index": 0.0,
            "risk_index_combined": 0.0,
            "discovered": 0,
            "resolved": 0,
            "accepted_new": 0,
            "fp_new": 0,
            "regressions": 0,
            "dispositions": 0,
            "mttr_days": {},
            "covered_repos": 0,
            "audited_repos": 0,
        }
        mttr_samples = collections.defaultdict(list)
        for r in repos:
            born_key = bucket_key(r["audit_date"], granularity)
            if born_key > key:
                continue
            snap["audited_repos"] += 1
            if (
                r["has_layer"]
                and r["layer_start"]
                and bucket_key(r["layer_start"], granularity) <= key
            ):
                snap["covered_repos"] += 1
            for e in (ev for evs in r["events"].values() for ev in evs):
                if bucket_key(effective_date(e), granularity) == key:
                    snap["dispositions"] += 1
                    if (e.get("disposition") or {}).get("resolution") == "regression_introduced":
                        snap["regressions"] += 1
            for f in r["findings"]:
                fid = (r["dir"], f.get("id"))
                events = r["events"].get(f.get("id"), [])
                state = state_of(f, events, key, granularity)
                prev = prev_states.get(fid)
                if born_key == key:
                    snap["discovered"] += 1
                sev = (f.get("severity") or "informational").lower()
                if state == "open":
                    snap["open"] += 1
                    snap["open_by_sev"][sev] += 1
                    snap["owasp_open"][owasp_rating(f, threat_intel_score(f))] += 1
                    snap["risk_index"] += cvss_effective(f)
                elif state == "hardening":
                    # Risk-bearing posture debt: λ-weighted, never excluded,
                    # never counted as a confirmed vulnerability.
                    snap["hardening"] += 1
                    snap["hardening_risk_index"] += hardening_lambda(
                        events, key, granularity
                    ) * cvss_effective(f)
                elif state == "accepted":
                    snap["accepted"] += 1
                    snap["accepted_by_sev"][sev] += 1
                    snap["accepted_risk_index"] += cvss_effective(f)
                    if prev != "accepted":
                        snap["accepted_new"] += 1
                elif state == "resolved":
                    snap["resolved_total"] += 1
                    if prev not in ("resolved",):
                        snap["resolved"] += 1
                        cd = close_date(events, key, granularity, ("resolved",))
                        if cd:
                            days = (
                                _dt.date.fromisoformat(cd) - _dt.date.fromisoformat(r["audit_date"])
                            ).days
                            mttr_samples[sev].append(max(days, 0))
                            mttr_samples["overall"].append(max(days, 0))
                elif state == "false_positive":
                    snap["false_positives_total"] += 1
                    if prev != "false_positive":
                        snap["fp_new"] += 1
                prev_states[fid] = state
        snap["fp_rate"] = snap["fp_new"] / snap["dispositions"] if snap["dispositions"] else 0.0
        snap["mttr_days"] = {k: round(sum(v) / len(v), 1) for k, v in mttr_samples.items() if v}
        snap["open_by_sev"] = dict(snap["open_by_sev"])
        snap["accepted_by_sev"] = dict(snap["accepted_by_sev"])
        snap["risk_index"] = round(snap["risk_index"], 1)
        snap["accepted_risk_index"] = round(snap["accepted_risk_index"], 1)
        snap["hardening_risk_index"] = round(snap["hardening_risk_index"], 1)
        snap["risk_index_combined"] = round(snap["risk_index"] + snap["hardening_risk_index"], 1)
        # CVSS v4.0: scores measure SEVERITY, not risk, and the spec gives
        # no basis for summing them. The mean (same CVSS-effective weights)
        # plus the qualitative-band counts are the headline presentation;
        # the sum series above are retained in the JSON as legacy history.
        snap["mean_cvss_open"] = (
            round(snap["risk_index"] / snap["open"], 2) if snap["open"] else 0.0
        )
        # OWASP Risk Rating distribution (likelihood x impact) over open
        # findings, plus the % rated High or Critical — the ratio-scale
        # headline for open risk.
        snap["owasp_open"] = dict(snap["owasp_open"])
        snap["owasp_high_plus_pct"] = (
            round(
                100
                * (snap["owasp_open"].get("critical", 0) + snap["owasp_open"].get("high", 0))
                / snap["open"],
                1,
            )
            if snap["open"]
            else 0.0
        )
        buckets.append(snap)

    # Standing accepted-risk register as of the final bucket
    register = []
    final_key = keys[-1]
    for r in repos:
        for f in r["findings"]:
            events = r["events"].get(f.get("id"), [])
            if not events:
                continue
            if state_of(f, events, final_key, granularity) != "accepted":
                continue
            acc = [
                e
                for e in events
                if (e.get("disposition") or {}).get("resolution") == "risk_accepted"
            ]
            last = acc[-1] if acc else None
            actor = ((last or {}).get("source") or {}).get("actor") or {}
            register.append(
                {
                    "finding": f.get("id"),
                    "title": f.get("title"),
                    "repo": r["repository"] or r["slug"],
                    "product": r["product"],
                    "severity": (f.get("severity") or "").lower(),
                    "cvss": cvss_effective(f),
                    "accepted_since": (effective_date(last)[:10] if last else None),
                    "accepted_by": actor.get("display_name") or actor.get("identity") or "unknown",
                    "rationale": ((last or {}).get("rationale") or "")[:160],
                }
            )
    register.sort(key=lambda e: -e["cvss"])
    return {
        "buckets": buckets,
        "accepted_register": register,
        "coverage": {
            "covered_repos": buckets[-1]["covered_repos"] if buckets else 0,
            "audited_repos": buckets[-1]["audited_repos"] if buckets else 0,
            "cohorts": coverage_cohorts(repos),
        },
        "ownership_cuts": compute_ownership_cuts(repos, final_key, granularity),
        "final_views": compute_final_views(repos, keys[-1], granularity),
    }


_BRANCH_REF_RX = re.compile(r"__((?:release|openshift)-\d+\.\d+(?:\.\d+)?)$")


def _has_live_ledger(r: dict) -> bool:
    """Same criterion as covered_repos: a ledger FILE is not coverage — an
    empty layer records no dispositions (branch re-audit dirs carry empty
    layers, which is what drags the blended percentage down)."""
    return bool(r.get("has_layer") and r.get("layer_start"))


def _is_branch_reaudit(r: dict) -> bool:
    # the ref suffix lives on the dir name OR the report filename base
    # (shared dirs hold many per-branch reports, e.g. openshift--thanos)
    return bool(
        _BRANCH_REF_RX.search(r.get("slug") or "") or _BRANCH_REF_RX.search(r.get("base") or "")
    )


def coverage_cohorts(repos: list[dict]) -> dict:
    """Ledger coverage split by cohort — the blended percentage hides that
    the owned HEAD backlog is nearly fully dispositioned while branch
    re-audits (confirmations, no triage cycle by design) and non-owned
    trees are not. Keys: '<tree>/HEAD' and '<tree>/branch'."""
    out: dict[str, dict] = {}
    for r in repos:
        kind = "branch" if _is_branch_reaudit(r) else "HEAD"
        c = out.setdefault(f"{r.get('tree') or 'findings'}/{kind}", {"covered": 0, "total": 0})
        c["total"] += 1
        if _has_live_ledger(r):
            c["covered"] += 1
    return out


def compute_ownership_cuts(repos: list[dict], final_key: str, granularity: str) -> dict:
    """Owned vs upstream sub-split of the LATEST bucket only: each repo's
    open/severity/risk contributions are bucketed by its root tree
    (findings/ = owned, oss-findings/ = upstream). The portfolio bucket
    series is untouched; upstream is never folded into the owned cut."""

    def _blank(tree):
        return {
            "label": OWNERSHIP_CUT_LABELS.get(tree, tree),
            "repos": 0,
            "open": 0,
            "open_critical": 0,
            "open_high": 0,
            "risk_index": 0.0,
        }

    cuts = {t: _blank(t) for t in OWNERSHIP_CUT_LABELS}
    for r in repos:
        tree = r.get("tree") or "findings"
        c = cuts.setdefault(tree, _blank(tree))
        if bucket_key(r["audit_date"], granularity) > final_key:
            continue
        c["repos"] += 1
        if _has_live_ledger(r):
            c["ledgered_repos"] = c.get("ledgered_repos", 0) + 1
        for f in r["findings"]:
            events = r["events"].get(f.get("id"), [])
            if state_of(f, events, final_key, granularity) != "open":
                continue
            c["open"] += 1
            sev = (f.get("severity") or "").lower()
            if sev == "critical":
                c["open_critical"] += 1
            elif sev == "high":
                c["open_high"] += 1
            c["risk_index"] += cvss_effective(f)
    for c in cuts.values():
        c["risk_index"] = round(c["risk_index"], 1)
        c["mean_cvss_open"] = round(c["risk_index"] / c["open"], 2) if c["open"] else 0.0
        c.setdefault("ledgered_repos", 0)
    return {"bucket": final_key, "cuts": cuts}


def _component_of(finding: dict) -> str:
    locs = finding.get("locations") or []
    path = (
        locs[0].get("path") if locs and isinstance(locs[0], dict) else finding.get("file")
    ) or ""
    parts = [p for p in str(path).split("/") if p]
    if not parts:
        return "(unknown)"
    if parts[0] in ("components", "pkg", "internal", "src") and len(parts) > 1:
        return "/".join(parts[:2])
    return parts[0]


def compute_final_views(repos: list[dict], final_key: str, granularity: str) -> dict:
    """Assurance views (claimed/verified/proven), delta metrics,
    FP-override accountability, and unhardened-blast-radius co-location —
    all derived from the one event stream, as of the final bucket."""
    claimed_risk = verified_risk = proven_risk = 0.0
    claimed_open = verified_open = proven_count = 0
    overrides = collections.Counter()
    fp_overridden_findings = []
    components: dict = collections.defaultdict(lambda: {"confirmed_open": 0, "hardening_open": 0})

    for r in repos:
        for f in r["findings"]:
            events = [
                e
                for e in r["events"].get(f.get("id"), [])
                if bucket_key(effective_date(e), granularity) <= final_key
            ]
            cvss = cvss_effective(f)

            # Claimed: the raw audit surface, no dispositions at all.
            claimed_risk += cvss
            claimed_open += 1

            # Verified: static evidence only (classes 2 and 3) — the
            # triage/human-adjusted picture before any execution proof.
            static_events = [e for e in events if event_class(e) != 1]
            vstate = state_of(f, static_events, final_key, granularity)
            if vstate == "open":
                verified_risk += cvss
                verified_open += 1
            elif vstate == "hardening":
                verified_risk += hardening_lambda(static_events, final_key, granularity) * cvss

            # Proven: execution evidence confirmed it and it is still open.
            full_state = state_of(f, events, final_key, granularity)
            exec_confirmed = any(
                event_class(e) == 1 and (e.get("disposition") or {}).get("validity") == "confirmed"
                for e in events
            )
            if exec_confirmed and full_state == "open":
                proven_risk += cvss
                proven_count += 1

            # FP-override accountability: an execution proof over a prior
            # human false-positive assertion, attributed to the asserter.
            if exec_confirmed:
                proofs = [
                    e
                    for e in events
                    if event_class(e) == 1
                    and (e.get("disposition") or {}).get("validity") == "confirmed"
                ]
                proof_date = max(effective_date(e) for e in proofs)
                for e in events:
                    if (
                        event_class(e) == 2
                        and (e.get("disposition") or {}).get("validity") == "false_positive"
                        and effective_date(e) <= proof_date
                    ):
                        actor = e["source"]["actor"]
                        who = actor.get("identity") or actor.get("display_name") or "unknown"
                        overrides[who] += 1
                        fp_overridden_findings.append(
                            {
                                "finding": f.get("id"),
                                "repo": r["repository"] or r["slug"],
                                "asserted_by": who,
                            }
                        )

            # Blast radius: open confirmed vulns co-located with open
            # hardening gaps amplify each other (annotation only).
            comp = (r["slug"], _component_of(f))
            if full_state == "open":
                components[comp]["confirmed_open"] += 1
            elif full_state == "hardening":
                components[comp]["hardening_open"] += 1

    blast = [
        {
            "repo": slug,
            "component": comp,
            "confirmed_open": v["confirmed_open"],
            "hardening_open": v["hardening_open"],
        }
        for (slug, comp), v in sorted(components.items())
        if v["confirmed_open"] and v["hardening_open"]
    ]

    # Refuted register: every FP assertion is a falsifiable claim; the
    # fuzzable subset is the standing priority queue for create-fuzzing.
    reg_entries = reg_repos = reg_fuzzable = 0
    reg_by_tier = collections.Counter()
    for r in repos:
        if r.get("register"):
            reg_repos += 1
            for e in r["register"]:
                reg_entries += 1
                reg_by_tier[e.get("tier") or "unknown"] += 1
                if (e.get("category") or "").lower() in FUZZABLE_CATEGORIES:
                    reg_fuzzable += 1

    return {
        "refuted_register": {
            "entries": reg_entries,
            "repos": reg_repos,
            "fuzzable": reg_fuzzable,
            "by_tier": dict(reg_by_tier),
        },
        "assurance": {
            "claimed": {"findings": claimed_open, "risk": round(claimed_risk, 1)},
            "verified": {"open": verified_open, "risk": round(verified_risk, 1)},
            "proven": {"findings": proven_count, "risk": round(proven_risk, 1)},
            "triage_compression_risk": round(claimed_risk - verified_risk, 1),
            "validation_gap_risk": round(verified_risk - proven_risk, 1),
        },
        "fp_overrides": {
            "total": sum(overrides.values()),
            "by_identity": dict(overrides.most_common()),
            "findings": fp_overridden_findings,
        },
        "blast_radius": blast,
    }


# ---------------------------------------------------------------------------
# trend classification
# ---------------------------------------------------------------------------


def classify(series: list[float], good_down: bool, dead_band: float = 0.10):
    """Last bucket vs mean of up-to-3 prior buckets, with a dead band."""
    if len(series) < 2:
        return {
            "arrow": "→",
            "label": "flat",
            "last": series[-1] if series else 0,
            "baseline": None,
            "pct": None,
        }
    last = series[-1]
    base_vals = series[max(0, len(series) - 4) : -1]
    base = sum(base_vals) / len(base_vals)
    pct = (0.0 if last == 0 else float("inf")) if base == 0 else (last - base) / base
    if pct != float("inf") and abs(pct) <= dead_band:
        return {
            "arrow": "→",
            "label": "flat",
            "last": last,
            "baseline": round(base, 2),
            "pct": round(pct * 100, 1),
        }
    rising = last > base
    good = (not rising) if good_down else rising
    return {
        "arrow": "↑" if rising else "↓",
        "label": "improving" if good else "worsening",
        "last": last,
        "baseline": round(base, 2),
        "pct": None if pct == float("inf") else round(pct * 100, 1),
    }


def compute_trends(buckets: list[dict]) -> dict:
    if not buckets:
        return {}

    def series(fn):
        return [fn(b) for b in buckets]

    return {
        "open": classify(series(lambda b: b["open"]), good_down=True),
        "mean_cvss_open": classify(series(lambda b: b.get("mean_cvss_open", 0.0)), good_down=True),
        "owasp_high_plus_pct": classify(
            series(lambda b: b.get("owasp_high_plus_pct", 0.0)), good_down=True
        ),
        "hardening": classify(series(lambda b: b["hardening"]), good_down=True),
        "accepted": classify(series(lambda b: b["accepted"]), good_down=True),
        "risk_index": classify(series(lambda b: b["risk_index"]), good_down=True),
        "hardening_risk_index": classify(
            series(lambda b: b["hardening_risk_index"]), good_down=True
        ),
        "risk_index_combined": classify(series(lambda b: b["risk_index_combined"]), good_down=True),
        "velocity": classify(series(lambda b: b["resolved"]), good_down=False),
        "new": classify(series(lambda b: b["discovered"]), good_down=True),
        "accepted_risk_index": classify(series(lambda b: b["accepted_risk_index"]), good_down=True),
        "regressions": classify(series(lambda b: b["regressions"]), good_down=True),
        "fp_rate": classify(series(lambda b: round(b["fp_rate"] * 100, 1)), good_down=True),
        "mttr": classify(
            [b["mttr_days"].get("overall", 0) for b in buckets] or [0], good_down=True
        ),
        "coverage": classify(
            series(
                lambda b: b["covered_repos"] / b["audited_repos"] * 100 if b["audited_repos"] else 0
            ),
            good_down=False,
        ),
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

# Headline presentation follows CVSS v4.0: scores are SEVERITY (not risk),
# the spec provides no basis for summing them, and the endorsed rendering
# is per-vulnerability scores + qualitative bands. Mean severity + band
# counts replace the former CVSS-sum "risk index" rows here; the sum
# series remain in the JSON purely as legacy history.
METRIC_LABELS = [
    ("open", "Open findings", "{:,.0f}"),
    ("owasp_high_plus_pct", "OWASP risk rating: High/Critical share of open (%)", "{:,.1f}"),
    ("mean_cvss_open", "Mean CVSS severity of open findings", "{:,.2f}"),
    ("hardening", "Hardening backlog (count, tracked separately)", "{:,.0f}"),
    ("velocity", "Remediation velocity (resolved/period)", "{:,.0f}"),
    ("new", "New findings", "{:,.0f}"),
    ("accepted", "Risk-accepted findings (count)", "{:,.0f}"),
    ("mttr", "MTTR overall (days)", "{:,.1f}"),
    ("regressions", "Regressions", "{:,.0f}"),
    ("fp_rate", "False-positive rate (%)", "{:,.1f}"),
    ("coverage", "Ledger coverage (%)", "{:,.1f}"),
]


def render_markdown(data: dict, trends: dict, granularity: str, version: str) -> str:
    buckets = data["buckets"]
    cov = data["coverage"]
    last = buckets[-1] if buckets else {}
    lines = []
    A = lines.append
    A("# Findings Trends")
    A("")
    A(
        f"**Period:** {buckets[0]['key']} → {buckets[-1]['key']} ({granularity}ly)  "
        if buckets
        else ""
    )
    A(
        f"**Ledger coverage:** {cov.get('covered_repos', 0)}/"
        f"{cov.get('audited_repos', 0)} audited repos — findings in repos "
        f"without a disposition ledger count as **open** (Option A), so "
        f"trends improve only through recorded dispositions."
    )
    cohorts = cov.get("cohorts") or {}
    if cohorts:

        def _pct(c):
            return (
                f"{c['covered']:,}/{c['total']:,} ({100 * c['covered'] / c['total']:.1f}%)"
                if c["total"]
                else "0/0"
            )

        A("")
        A(
            "**Coverage by cohort** (the blended figure above mixes "
            "populations that are dispositioned on different terms):"
        )
        A("")
        A("| Cohort | Ledgered | Meaning |")
        A("| --- | ---: | --- |")
        _MEANING = {
            "findings/HEAD": "**Hybrid Platforms owned backlog** — the "
            "population remediation tracking applies to",
            "findings/branch": "release-branch re-audits — confirmations "
            "of HEAD findings; no separate triage "
            "cycle by design",
            "oss-findings/HEAD": "upstream community code — not dispositioned by HP",
        }
        for name in sorted(cohorts):
            A(f"| `{name}` | {_pct(cohorts[name])} | {_MEANING.get(name, 'external/other tree')} |")
    A("")
    A(f"| Metric | Latest ({last.get('key', '—')}) | Baseline (prior avg) | Trend |")
    A("| --- | ---: | ---: | --- |")
    for key, label, fmt in METRIC_LABELS:
        t = trends.get(key) or {}
        lastv = t.get("last") or 0
        base = t.get("baseline")
        flag = " ⚠" if t.get("label") == "worsening" else ""
        A(
            f"| {label} | {fmt.format(lastv)} "
            f"| {fmt.format(base) if base is not None else '—'} "
            f"| {t.get('arrow', '→')} {t.get('label', 'flat')}{flag} |"
        )
    A("")

    oc = data.get("ownership_cuts") or {}
    if oc.get("cuts"):
        A("## Ownership cuts (latest bucket)")
        A("")
        A(
            f"Owned (findings/) vs upstream (oss-findings/) split of the "
            f"{oc.get('bucket', '—')} bucket — upstream is never folded into "
            f"the owned headline; the portfolio numbers above are unchanged."
        )
        A("")
        A("| Cut | Open findings | Open C | Open H | Mean CVSS (open) | Ledgered repos |")
        A("| --- | ---: | ---: | ---: | ---: | ---: |")
        for c in oc["cuts"].values():
            led = f"{c.get('ledgered_repos', 0):,}/{c['repos']:,}" if c.get("repos") else "—"
            A(
                f"| {c['label']} | {c['open']:,} | {c['open_critical']:,} "
                f"| {c['open_high']:,} | {c.get('mean_cvss_open', 0):,.2f} "
                f"| {led} |"
            )
        A("")

    A("## Open Findings by Severity (latest)")
    A("")
    obs = last.get("open_by_sev", {})
    A("| " + " | ".join(s.title() for s in SEVERITIES) + " |")
    A("|" + "---:|" * len(SEVERITIES))
    A("| " + " | ".join(f"{obs.get(s, 0):,}" for s in SEVERITIES) + " |")
    A("")

    A("## Open Findings by OWASP Risk Rating (latest)")
    A("")
    A(
        "Risk = likelihood × impact per the [OWASP Risk Rating Methodology]"
        "(https://owasp.org/www-community/OWASP_Risk_Rating_Methodology): "
        "likelihood from each finding's CVSS exploitability metrics "
        "(AV/AC/PR/UI), impact from its C/I/A metrics, combined on the "
        "OWASP 3×3 matrix. Unlike the severity table above, this rates "
        "how likely exploitation is, not just how bad it would be."
    )
    ti_status = _THREAT_INTEL.get("status")
    if ti_status:
        stale = [n for n, s in ti_status.items() if s.get("stale")]
        A(
            "Likelihood additionally weighs **exploitation evidence** for "
            "CVE-bearing findings: CISA KEV membership (CC0-1.0) and "
            "EPSS scores (see EPSS at https://www.first.org/epss) — "
            f"EPSS {ti_status['epss'].get('feed_version') or '?'}, "
            f"KEV {ti_status['kev'].get('feed_version') or '?'}"
            + (
                f" (**stale feeds: {', '.join(stale)}** — run `traust feeds fetch`)"
                if stale
                else ""
            )
            + "."
        )
    A("")
    ob = last.get("owasp_open", {})
    A("| " + " | ".join(b.title() for b in OWASP_BANDS) + " | High+ % |")
    A("|" + "---:|" * (len(OWASP_BANDS) + 1))
    A(
        "| "
        + " | ".join(f"{ob.get(b, 0):,}" for b in OWASP_BANDS)
        + f" | {last.get('owasp_high_plus_pct', 0):,.1f} |"
    )
    A("")

    fv = data.get("final_views") or {}
    asr = fv.get("assurance") or {}
    if asr:
        A("## Assurance Stages (latest)")
        A("")
        A("Three views over one event stream — nothing stored twice:")
        A("")
        A("| View | Findings | Risk (CVSS sum) | Meaning |")
        A("| --- | ---: | ---: | --- |")
        A(
            f"| Claimed | {asr['claimed']['findings']:,} "
            f"| {asr['claimed']['risk']:,.1f} | raw audit surface |"
        )
        A(
            f"| Verified | {asr['verified']['open']:,} open "
            f"| {asr['verified']['risk']:,.1f} | triage/human-adjusted "
            f"(hardening λ-weighted) |"
        )
        A(
            f"| Proven | {asr['proven']['findings']:,} "
            f"| {asr['proven']['risk']:,.1f} | execution-demonstrated, "
            f"still open |"
        )
        A("")
        A(
            f"**Triage compression:** {asr['triage_compression_risk']:,.1f} "
            f"risk removed by adversarial verification. "
            f"**Validation gap:** {asr['validation_gap_risk']:,.1f} verified "
            f"risk not yet empirically demonstrated — the fuzzing/"
            f"live-validation priority queue."
        )
        A("")

    rr = fv.get("refuted_register") or {}
    if rr.get("entries"):
        A(
            f"## Refuted Register — {rr['entries']:,} standing FP "
            f"assertion(s) across {rr['repos']:,} repo(s)"
        )
        A("")
        A(
            f"Every false-positive assertion is a falsifiable claim, not an "
            f"exclusion: these findings remain in fuzzing and live-validation "
            f"scope. **{rr['fuzzable']:,}** are in fuzzable classes "
            f"(parsers/decoders/injection surfaces) — the standing priority "
            f"queue for `/create-fuzzing`. Tiers: "
            + ", ".join(f"{v} {k}" for k, v in (rr.get("by_tier") or {}).items())
            + "."
        )
        A("")

    fpo = fv.get("fp_overrides") or {}
    if fpo.get("total"):
        A(
            f"## ⚡ FP Overrides — {fpo['total']} human false-positive "
            f"assertion(s) overturned by execution evidence"
        )
        A("")
        A("| Asserted by | Overridden |")
        A("| --- | ---: |")
        for who, n in (fpo.get("by_identity") or {}).items():
            A(f"| {who} | {n} |")
        A("")

    blast = fv.get("blast_radius") or []
    if blast:
        A(f"## 🧨 Unhardened Blast Radius — {len(blast)} component(s)")
        A("")
        A(
            "Open confirmed vulnerabilities co-located with open hardening "
            "gaps: the missing hardening amplifies what each vulnerability "
            "is worth (annotation only — finding severities are never "
            "rewritten). Fixing the hardening items de-risks the "
            "vulnerabilities they fail to shield."
        )
        A("")
        A("| Repository | Component | Confirmed open | Hardening open |")
        A("| --- | --- | ---: | ---: |")
        for b in blast[:25]:
            A(
                f"| `{b['repo']}` | `{b['component']}` "
                f"| {b['confirmed_open']} | {b['hardening_open']} |"
            )
        if len(blast) > 25:
            A(f"| … | *{len(blast) - 25} more in findings-trends.json* | | |")
        A("")

    reg = data.get("accepted_register") or []
    A(f"## Accepted Risk Register — {len(reg)} standing")
    A("")
    if reg:
        A(
            "Findings the owning teams formally accepted: **not fixed and not "
            "mitigated**. This risk does not decay — it stays on the register "
            "until remediated or re-triaged."
        )
        A("")
        A("| Sev | CVSS | Repository | Finding | Accepted | By |")
        A("| --- | ---: | --- | --- | --- | --- |")
        for e in reg[:25]:
            A(
                f"| {e['severity'].title()} | {e['cvss']:.1f} "
                f"| `{e['repo']}` | {e['finding']}: {md_cell((e['title'] or '')[:60])} "
                f"| {e['accepted_since'] or '—'} | {md_cell(e['accepted_by'])} |"
            )
        if len(reg) > 25:
            A(f"| … | | | *{len(reg) - 25} more in findings-trends.json* | | |")
    else:
        A("No findings currently carry a risk-accepted disposition.")
    A("")

    A("## Time Series")
    A("")
    A(
        "| Period | Open | Risk idx | New | Resolved | Accepted (new) "
        "| Regressions | FP rate | MTTR d | Coverage |"
    )
    A("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for b in buckets:
        covpct = 100.0 * b["covered_repos"] / b["audited_repos"] if b["audited_repos"] else 0
        A(
            f"| {b['key']} | {b['open']:,} | {b['risk_index']:,.0f} "
            f"| {b['discovered']:,} | {b['resolved']:,} | {b['accepted_new']:,} "
            f"| {b['regressions']:,} | {b['fp_rate'] * 100:.1f}% "
            f"| {b['mttr_days'].get('overall', 0):.0f} | {covpct:.0f}% |"
        )
    A("")
    A(
        f"*The final period may be partial. Generated by traust "
        f"`{version}` (`harnessing/findings-trends/scripts/build_trends.py`); re-run "
        f"via the `/findings-trends` skill.*"
    )
    A("")
    return "\n".join(lines)


def render_html(data: dict, trends: dict, granularity: str, version: str) -> str:
    buckets = data["buckets"]
    cov = data["coverage"]
    reg = data.get("accepted_register") or []
    esc = _html.escape
    payload = {
        "labels": [b["key"] for b in buckets],
        "open_by_sev": {s: [b["open_by_sev"].get(s, 0) for b in buckets] for s in SEVERITIES},
        "sev_colors": SEV_COLORS,
        "risk": [b["risk_index"] for b in buckets],
        "accepted_risk": [b["accepted_risk_index"] for b in buckets],
        "resolved": [b["resolved"] for b in buckets],
        "discovered": [b["discovered"] for b in buckets],
        "accepted_new": [b["accepted_new"] for b in buckets],
        "mttr": [b["mttr_days"].get("overall", 0) for b in buckets],
    }
    trend_rows = "".join(
        f"<tr><td>{esc(label)}</td>"
        f"<td style='text-align:right'>{fmt.format((trends.get(key) or {}).get('last') or 0)}</td>"
        f"<td>{esc((trends.get(key) or {}).get('arrow', '→'))} "
        f"{esc((trends.get(key) or {}).get('label', 'flat'))}"
        f"{' ⚠' if (trends.get(key) or {}).get('label') == 'worsening' else ''}</td></tr>"
        for key, label, fmt in METRIC_LABELS
    )
    oc = data.get("ownership_cuts") or {}
    cut_rows = "".join(
        f"<tr><td>{esc(c['label'])}</td>"
        f"<td style='text-align:right'>{c['open']:,}</td>"
        f"<td style='text-align:right'>{c['open_critical']:,}</td>"
        f"<td style='text-align:right'>{c['open_high']:,}</td>"
        f"<td style='text-align:right'>{c['risk_index']:,.1f}</td></tr>"
        for c in (oc.get("cuts") or {}).values()
    )
    cuts_card = (
        ""
        if not cut_rows
        else f"""
<div class="card"><h2>Ownership Cuts (latest bucket)</h2>
<p style="font-size:13px">Owned (findings/) vs upstream (oss-findings/) —
upstream is never folded into the owned headline; the portfolio numbers
above are unchanged.</p>
<table><thead><tr><th>Cut</th><th style="text-align:right">Open findings</th>
<th style="text-align:right">Open C</th><th style="text-align:right">Open H</th>
<th style="text-align:right">Risk index</th></tr></thead>
<tbody>{cut_rows}</tbody></table></div>"""
    )
    reg_rows = "".join(
        f"<tr><td>{esc(e['severity'].title())}</td>"
        f"<td style='text-align:right'>{e['cvss']:.1f}</td>"
        f"<td><code>{esc(e['repo'])}</code></td>"
        f"<td>{esc(e['finding'])}: {esc((e['title'] or '')[:70])}</td>"
        f"<td>{esc(e['accepted_since'] or '—')}</td>"
        f"<td>{esc(e['accepted_by'])}</td></tr>"
        for e in reg[:25]
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Findings Trends</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {{ --rh-red:#ee0000; --fg:#151515; --muted:#6a6e73; --border:#d2d2d2; }}
  body {{ font-family:"Red Hat Text",-apple-system,Segoe UI,Helvetica,Arial,sans-serif;
          margin:0; color:var(--fg); background:#fafafa; }}
  header {{ background:#151515; color:#fff; padding:20px 28px;
            border-bottom:4px solid var(--rh-red); }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  header .sub {{ color:#d2d2d2; font-size:13px; }}
  main {{ max-width:1200px; margin:0 auto; padding:24px; }}
  .card {{ background:#fff; border:1px solid var(--border); border-radius:8px;
           padding:18px 20px; margin-bottom:20px; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
  .chart-box {{ position:relative; height:280px; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; }}
  th,td {{ border-bottom:1px solid var(--border); padding:6px 8px; text-align:left; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:32px; }}
  .warn {{ background:#fdf4e5; border-left:4px solid #f0ab00; padding:10px 14px;
           font-size:13px; margin-bottom:20px; }}
</style></head><body>
<header><h1>Findings Trends</h1>
<div class="sub">{esc(buckets[0]["key"] if buckets else "—")} →
{esc(buckets[-1]["key"] if buckets else "—")} ({esc(granularity)}ly) ·
ledger coverage {cov.get("covered_repos", 0)}/{cov.get("audited_repos", 0)} repos</div>
</header><main>
<div class="warn">Findings in repos without a disposition ledger count as
<b>open</b> (Option A). Trends improve only through recorded dispositions —
coverage is part of the story on every chart below.</div>
<div class="card"><h2>Trend Summary</h2>
<table><thead><tr><th>Metric</th><th style="text-align:right">Latest</th>
<th>Trend</th></tr></thead><tbody>{trend_rows}</tbody></table></div>
{cuts_card}
<section class="grid">
  <div class="card"><h2>Open Findings Burndown (by severity)</h2>
    <div class="chart-box"><canvas id="burnChart"></canvas></div></div>
  <div class="card"><h2>Risk Index (CVSS sum)</h2>
    <div class="chart-box"><canvas id="riskChart"></canvas></div></div>
</section>
<section class="grid">
  <div class="card"><h2>Flow: New vs Resolved vs Accepted</h2>
    <div class="chart-box"><canvas id="flowChart"></canvas></div></div>
  <div class="card"><h2>Mean Time to Remediate (days)</h2>
    <div class="chart-box"><canvas id="mttrChart"></canvas></div></div>
</section>
<div class="card"><h2>Accepted Risk Register — {len(reg)} standing</h2>
<p style="font-size:13px">Formally accepted: <b>not fixed and not mitigated</b>.
Stays on the register until remediated or re-triaged.</p>
<table><thead><tr><th>Sev</th><th style="text-align:right">CVSS</th>
<th>Repository</th><th>Finding</th><th>Accepted</th><th>By</th></tr></thead>
<tbody>{reg_rows or "<tr><td colspan=6>None</td></tr>"}</tbody></table></div>
<footer>Generated by traust <code>{esc(version)}</code>
(<code>harnessing/findings-trends/scripts/build_trends.py</code>) —
re-run via <code>/findings-trends</code>. Final period may be partial.</footer>
</main><script>
const D = {json_script(payload)};
new Chart(document.getElementById('burnChart'), {{
  type:'line',
  data:{{labels:D.labels, datasets:Object.entries(D.open_by_sev).map(([s,v])=>({{
    label:s, data:v, fill:true, backgroundColor:D.sev_colors[s]+'66',
    borderColor:D.sev_colors[s], pointRadius:2, tension:.2}}))}},
  options:{{responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom'}}}},
    scales:{{y:{{stacked:true, beginAtZero:true}}}}}}
}});
new Chart(document.getElementById('riskChart'), {{
  type:'line',
  data:{{labels:D.labels, datasets:[
    {{label:'Open risk (CVSS sum)', data:D.risk, borderColor:'#ee0000',
      backgroundColor:'#ee000022', fill:true, pointRadius:2, tension:.2}},
    {{label:'Accepted risk (CVSS sum)', data:D.accepted_risk,
      borderColor:'#f0ab00', borderDash:[6,4], pointRadius:2, tension:.2}}
  ]}},
  options:{{responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom'}}}}, scales:{{y:{{beginAtZero:true}}}}}}
}});
new Chart(document.getElementById('flowChart'), {{
  type:'bar',
  data:{{labels:D.labels, datasets:[
    {{label:'New', data:D.discovered, backgroundColor:'#8a8d90'}},
    {{label:'Resolved', data:D.resolved, backgroundColor:'#3e8635'}},
    {{label:'Accepted', data:D.accepted_new, backgroundColor:'#f0ab00'}}
  ]}},
  options:{{responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom'}}}},
    scales:{{y:{{beginAtZero:true, ticks:{{precision:0}}}}}}}}
}});
new Chart(document.getElementById('mttrChart'), {{
  type:'line',
  data:{{labels:D.labels, datasets:[{{label:'MTTR (days)', data:D.mttr,
    borderColor:'#0066cc', pointRadius:2, tension:.2}}]}},
  options:{{responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}}, scales:{{y:{{beginAtZero:true}}}}}}
}});
</script></body></html>
"""


# ---------------------------------------------------------------------------


def harness_version() -> str:
    vf = Path(__file__).resolve().parent.parent.parent / "VERSION"
    try:
        return vf.read_text().strip()
    except OSError:
        return "unknown"


def _dashboards_home(config_home):
    try:
        engine = load_engine(config_home)
        dashboards = progress_tracker_dir(engine) / "metrics" / "dashboards"
        dashboards.mkdir(parents=True, exist_ok=True)
        return dashboards
    except SystemExit:
        return None


# --- standard population block (traust.cli.groups.corpus; best-effort) -----------


def _population_lines(roots: list[Path], data: dict):
    """Standard population block for cross-dashboard reconciliation.
    Reports only what this run already did; omitted (never fatal) when
    corpus.py or its config is unavailable."""
    try:
        import importlib

        corpus = importlib.import_module("traust_engine.corpus.resolver")
        cfg = corpus.load_config()
        cov = data.get("coverage") or {}
        audited = cov.get("audited_repos", 0)
        covered = cov.get("covered_repos", 0)
        pct = f"{100 * covered / audited:.1f}%" if audited else "n/a"
        counts = {
            "Audited repos": audited,
            "Repos with ledger": f"{covered} ({pct} coverage)",
        }
        rr = (data.get("final_views") or {}).get("refuted_register") or {}
        if rr:
            counts["Refuted-register FP assertions"] = rr.get("entries", 0)
        return corpus.population_block_lines(
            tool="findings-trends",
            roots=corpus.roots_description(cfg, [r.name for r in roots if r.is_dir()]),
            unit="open findings by disposition-ledger replay over time buckets",
            filters="false positives excluded via ledger replay "
            "(countersign honored); hardening in a separate "
            "λ-weighted bucket; repos without a ledger count "
            "fully open (Option A)",
            denominator="rglob of *-security-audit.json and "
            "*-cloud-config-audit.json under the roots "
            "(symlinks and _manifest skipped; cloud-config "
            "is a separate declared-layer kind)",
            counts=counts,
        )
    except Exception as exc:
        print(f"[!] population block omitted: {exc}", file=sys.stderr)
        return None


def _population_html_panel(lines: list[str]) -> str:
    """Same content as the markdown block, as a final html-escaped card."""
    items = []
    for ln in lines:
        if ln.startswith("- **"):
            label, _, val = ln[4:].partition(":**")
            items.append(f"<li><b>{_html.escape(label)}:</b>{_html.escape(val)}</li>")
        elif ln.startswith("- "):
            items.append(f"<li>{_html.escape(ln[2:])}</li>")
    return (
        '<div class="card"><h2>Population</h2>'
        '<ul style="font-size:13px">' + "".join(items) + "</ul></div>"
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (default: $AUDIT_RESULTS_ROOT or locations.yaml)",
    )
    ap.add_argument(
        "--roots",
        nargs="*",
        default=None,
        help="Override findings roots (default: <results-root>/{findings,oss-findings})",
    )
    ap.add_argument("--granularity", choices=["month", "week"], default="month")
    ap.add_argument("--since", metavar="YYYY-MM", help="Ignore buckets before this month")
    ap.add_argument("--product", help="Restrict to one product directory")
    ap.add_argument("--as-of", default=None, help="End of the series (ISO date; default today)")
    ap.add_argument(
        "--out-dir", default=None, help="Output directory (default <results-root>/trends)"
    )
    args = ap.parse_args(argv)

    results_root = resolve_results_root(args)
    roots = (
        [Path(r).expanduser().resolve() for r in args.roots]
        if args.roots
        else [
            results_root / "findings",
            results_root / "oss-findings",
            results_root / "cloud-config",
        ]
    )
    out_dir = (
        Path(args.out_dir).expanduser().resolve()
        if args.out_dir
        else ((_dashboards_home(args.config_home) or results_root) / "trends")
    )
    as_of = args.as_of or _dt.date.today().isoformat()

    ti_status = init_threat_intel(results_root)
    if ti_status:
        print(
            "[+] threat-intel feeds: "
            + ", ".join(
                f"{n} {'STALE' if s['stale'] else 'fresh'} ({s.get('feed_version') or '?'})"
                for n, s in ti_status.items()
            ),
            file=sys.stderr,
        )

    repos = discover(roots, args.product)
    print(
        f"[+] {len(repos)} audited repos ({sum(1 for r in repos if r['has_layer'])} with ledgers)",
        file=sys.stderr,
    )
    if not repos:
        print("No audit reports found.", file=sys.stderr)
        return 1

    data = build_series(repos, args.granularity, args.since, as_of)
    trends = compute_trends(data["buckets"])
    version = harness_version()

    out_dir.mkdir(parents=True, exist_ok=True)
    out = {
        "generated_at": as_of,
        "risk_rating_methodology": {
            "name": _RR["methodology"],
            "version": RR_METHODOLOGY_VERSION,
            "source": _RR["source"],
            "threat_intel_feeds": ti_status,
        },
        "granularity": args.granularity,
        "product": args.product,
        "coverage": data["coverage"],
        "trends": trends,
        "buckets": data["buckets"],
        "accepted_register": data["accepted_register"],
        "ownership_cuts": data.get("ownership_cuts", {}),
        "final_views": data.get("final_views", {}),
    }
    (out_dir / "findings-trends.json").write_text(
        json.dumps(out, indent=2) + "\n", encoding="utf-8"
    )
    md_text = render_markdown(data, trends, args.granularity, version)
    html_text = render_html(data, trends, args.granularity, version)
    pop = _population_lines(roots, data)
    if pop:
        md_text += "\n---\n\n" + "\n".join(pop) + "\n"
        html_text = html_text.replace("<footer>", _population_html_panel(pop) + "\n<footer>", 1)
    (out_dir / "findings-trends.md").write_text(md_text, encoding="utf-8")
    (out_dir / "findings-trends.html").write_text(html_text, encoding="utf-8")
    for name in ("findings-trends.json", "findings-trends.md", "findings-trends.html"):
        print(f"[+] wrote {out_dir / name}", file=sys.stderr)
    b = data["buckets"][-1]
    print(
        f"[+] latest ({b['key']}): open={b['open']} "
        f"risk_index={b['risk_index']} accepted={b['accepted']} "
        f"resolved(period)={b['resolved']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
