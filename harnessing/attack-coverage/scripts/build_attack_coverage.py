#!/usr/bin/env python3
"""build_attack_coverage.py — fleet MITRE ATT&CK coverage roll-up.

Deterministic join of the three places the harness records technique IDs —
no agent judgment anywhere in this pipeline:

  observed  validations/**/*validation*.json  attack_chains[].mitre_attack_refs
  modeled   findings roots **/*threat-model*.md / THREAT_MODEL.md
            section-4 rows' optional attack_refs column
  derived   findings roots **/*security-audit.json finding categories,
            mapped through tables/attack-mapping.json category_map
            (candidates an adversary COULD use against that weakness class
            — never counted as observed behavior)

Every technique ID is validated against the pinned vendored table
(tables/attack-techniques.json); invalid/revoked IDs are dropped AND
reported, never silently.

Outputs (progress-tracker/metrics/dashboards/attack-coverage/):
  attack-navigator-layer.json   ATT&CK Navigator layer (format 4.5)
  attack-coverage.md            tactic/technique coverage one-pager

Usage:
    python3 build_attack_coverage.py [--results-root DIR]
"""

import argparse
import collections
import datetime
import json
import re
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

SKILL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SKILL_DIR))
import attack_refs  # noqa: E402

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def _split_row(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def scan_threat_models(roots):
    """{technique: n_threat_rows}, plus file/row counts and dropped IDs."""
    counts = collections.Counter()
    files = rows_with_refs = 0
    dropped = collections.Counter()
    seen = set()
    for root in roots:
        for p in list(root.rglob("*threat-model*.md")) + list(root.rglob("THREAT_MODEL.md")):
            if p.resolve() in seen:
                continue
            seen.add(p.resolve())
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files += 1
            in4 = idx = None
            for line in text.splitlines():
                if re.match(r"##\s*4\.", line):
                    in4, idx = True, None
                    continue
                if in4 and re.match(r"##\s*\d", line):
                    break
                if not in4 or not line.lstrip().startswith("|"):
                    continue
                cells = _split_row(line)
                if idx is None:
                    idx = cells.index("attack_refs") if "attack_refs" in cells else -1
                    continue
                if idx < 0 or len(cells) <= idx or set("".join(cells)) <= set("-: "):
                    continue
                ids = [t for t in re.split(r"[,;]\s*", cells[idx]) if t]
                if not ids:
                    continue
                good = [t for t in ids if not attack_refs.validate_ids([t], TECH)]
                for t in set(ids) - set(good):
                    dropped[t] += 1
                if good:
                    rows_with_refs += 1
                    counts.update(set(good))
    return counts, files, rows_with_refs, dropped


def scan_validations(results):
    """{technique: n_chains}, split by chain verdict."""
    confirmed = collections.Counter()
    attempted = collections.Counter()
    n_reports = n_chains = 0
    dropped = collections.Counter()
    vdir = results / "validations"
    if not vdir.is_dir():
        return confirmed, attempted, 0, 0, dropped
    for p in vdir.rglob("*validation*.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        chains = d.get("attack_chains") or []
        if not isinstance(chains, list):
            continue
        n_reports += 1
        for c in chains:
            refs = c.get("mitre_attack_refs") or []
            if not refs:
                continue
            n_chains += 1
            good = [t for t in refs if not attack_refs.validate_ids([t], TECH)]
            for t in set(refs) - set(good):
                dropped[t] += 1
            bucket = (
                confirmed
                if (c.get("verdict") or "").lower() in ("confirmed", "partially_confirmed")
                else attempted
            )
            bucket.update(set(good))
    return confirmed, attempted, n_reports, n_chains, dropped


def scan_findings(roots):
    """{technique: n_findings} via category_map (weakness-derived candidates)."""
    cmap = attack_refs.category_map()
    counts = collections.Counter()
    n_reports = n_findings = 0
    for root in roots:
        for p in root.rglob("*security-audit.json"):
            if "_manifest" in p.parts:
                continue
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            n_reports += 1
            for f in d.get("findings") or []:
                cat = (f.get("category") or "").strip().lower()
                if cat in cmap:
                    n_findings += 1
                    counts.update(cmap[cat])
    return counts, n_reports, n_findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()
    results = resolve_results_root(args)
    roots = [r for r in (results / "findings", results / "oss-findings") if r.is_dir()]

    global TECH
    TECH = attack_refs.load_techniques()
    tt = TECH["techniques"]

    modeled, tm_files, tm_rows, tm_drop = scan_threat_models(roots)
    observed, attempted, val_reports, val_chains, val_drop = scan_validations(results)
    derived, audit_reports, _cat_findings = scan_findings(roots)

    if args.out_dir:
        out_dir = Path(args.out_dir).resolve()
    else:
        engine = load_engine(args.config_home)
        out_dir = progress_tracker_dir(engine) / "metrics" / "dashboards" / "attack-coverage"
    out_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.date.today().isoformat()

    all_ids = sorted(set(modeled) | set(observed) | set(attempted) | set(derived))
    tactics_hit = sorted({t for i in all_ids for t in tt[i]["tactics"]})

    # ---- Navigator layer (format 4.5) ----
    def comment(i):
        parts = []
        if observed.get(i):
            parts.append(f"observed in {observed[i]} confirmed validation chain(s)")
        if attempted.get(i):
            parts.append(f"in {attempted[i]} unconfirmed chain(s)")
        if modeled.get(i):
            parts.append(f"modeled in {modeled[i]} threat row(s)")
        if derived.get(i):
            parts.append(f"candidate for {derived[i]} finding(s) by weakness class")
        return "; ".join(parts)

    def score(i):
        # 3 = observed adversary behavior, 2 = modeled, 1 = weakness-derived
        return 3 if i in observed else (2 if (i in modeled or i in attempted) else 1)

    layer = {
        "name": f"Traust ATT&CK coverage ({today})",
        "versions": {
            "attack": TECH["attack_version"].split(".")[0],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Deterministic fleet coverage: observed (validated "
            "attack chains), modeled (threat-model attack_refs), "
            "weakness-derived candidates (finding categories via "
            "attack-mapping.json). " + TECH["attribution"]
        ),
        "techniques": [
            {"techniqueID": i, "score": score(i), "comment": comment(i)} for i in all_ids
        ],
        "gradient": {"colors": ["#8ec843", "#ffe766", "#ff6666"], "minValue": 1, "maxValue": 3},
        "legend": [
            {"label": "1 weakness-derived candidate", "color": "#8ec843"},
            {"label": "2 modeled / unconfirmed chain", "color": "#ffe766"},
            {"label": "3 observed (confirmed chain)", "color": "#ff6666"},
        ],
        "metadata": [
            {"name": "attack_version", "value": TECH["attack_version"]},
            {"name": "mapping_version", "value": attack_refs.load_mapping()["mapping_version"]},
            # exact evidence-class counts (scores overlap classes — e.g.
            # unconfirmed-chain-only techniques also score 2); downstream
            # dashboards read these, never re-derive from scores
            {"name": "techniques_covered", "value": str(len(all_ids))},
            {"name": "techniques_observed", "value": str(len(observed))},
            {"name": "techniques_modeled", "value": str(len(modeled))},
            {"name": "techniques_derived", "value": str(len(derived))},
            {"name": "tactics_covered", "value": str(len(tactics_hit))},
            {
                "name": "population",
                "value": (
                    f"{audit_reports} audit reports / {tm_files} threat "
                    f"models ({tm_rows} rows with attack_refs) / "
                    f"{val_reports} validation reports ({val_chains} "
                    f"chains with refs)"
                ),
            },
        ],
    }
    layer_path = out_dir / "attack-navigator-layer.json"
    layer_path.write_text(json.dumps(layer, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    # ---- markdown one-pager ----
    L = [
        "# MITRE ATT&CK Coverage — Traust",
        "",
        f"**Generated:** {today} · ATT&CK v{TECH['attack_version']} (pinned) "
        f"· mapping v{attack_refs.load_mapping()['mapping_version']}",
        "",
        "**Population:** "
        f"{audit_reports} audit reports · {tm_files} threat models "
        f"({tm_rows} threat rows carry `attack_refs`) · {val_reports} "
        f"validation reports ({val_chains} chains with technique refs). "
        "Three evidence classes, never blended: **observed** = technique in "
        "a confirmed live-validation chain; **modeled** = named in a threat "
        "model; **derived** = candidate implied by an audit finding's "
        "weakness category (mapping table, not narrative).",
        "",
    ]
    L += [
        "| Tactic | Observed | Modeled | Derived | Total techniques |",
        "|---|---:|---:|---:|---:|",
    ]
    for tac in TACTIC_ORDER:
        ids = [i for i in all_ids if tac in tt[i]["tactics"]]
        if not ids:
            continue
        L.append(
            f"| {tac} | {sum(1 for i in ids if i in observed)} "
            f"| {sum(1 for i in ids if i in modeled)} "
            f"| {sum(1 for i in ids if i in derived)} | {len(ids)} |"
        )
    L += ["", "## Techniques", "", "| ID | Name | Score | Evidence |", "|---|---|---:|---|"]
    for i in sorted(all_ids, key=lambda x: (-score(x), x)):
        L.append(f"| {i} | {tt[i]['name']} | {score(i)} | {comment(i)} |")
    drops = tm_drop + val_drop
    if drops:
        L += ["", "## Dropped references (invalid against the pinned table)", ""]
        L += [f"- `{t}` × {n}" for t, n in drops.most_common()]
    L += [
        "",
        f"**Navigator layer:** `{layer_path.name}` — load at "
        "https://mitre-attack.github.io/attack-navigator/ (File → Open "
        "Existing Layer).",
        "",
        f"*{TECH['attribution']}*",
        "",
    ]
    md_path = out_dir / "attack-coverage.md"
    md_path.write_text("\n".join(L), encoding="utf-8")

    # ---- shared metrics history (best-effort; never fail the build) ----
    try:
        engine = load_engine(args.config_home)
        engine.metrics.append_if_changed(
            "attack-coverage",
            {
                "attack_techniques_covered": len(all_ids),
                "attack_techniques_observed": len(observed),
                "attack_techniques_modeled": len(modeled),
                "attack_tactics_covered": len(tactics_hit),
            },
            note="",
        )
    except SystemExit:
        print("[!] metrics history append skipped: config not resolvable", file=sys.stderr)
    except Exception as e:
        print(f"[!] metrics history append skipped: {e}", file=sys.stderr)

    print(f"[+] wrote {layer_path}")
    print(f"[+] wrote {md_path}")
    print(
        f"[+] {len(all_ids)} techniques ({len(observed)} observed / "
        f"{len(modeled)} modeled / {len(derived)} derived) across "
        f"{len(tactics_hit)} tactics; dropped {sum(drops.values())} bad ref(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
