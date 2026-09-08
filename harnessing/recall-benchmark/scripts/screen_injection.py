#!/usr/bin/env python3
"""Post-hoc prompt-injection anomaly screen for audit reports (C2 layer 3).

Deterministic, report-only: flags audit reports whose content carries the
signature of obeyed (or attempted) prompt injection from the audited
repository. It never concludes — every hit is a review queue item for a
human (countersign semantics), because instruction-like phrases can appear
legitimately in quoted evidence.

Signals:
  instruction_echo   report PROSE (executive summary, notes, negative
                     results, finding descriptions) reproduces
                     instruction-like phrases aimed at automated tools
  zero_findings      an audit reports zero findings — flagged on the
                     ACTUAL finding count regardless of the agent-claimed
                     metadata.loc_reviewed (which a coerced report can
                     under-state to dodge a LoC threshold)
  audit_time_fp      findings marked false_positive at audit time —
                     dispositions belong to the ledger, not the auditor;
                     classic neutralization shape. Applied to every
                     report (a skip for cumulative reports was removable
                     by adding a disposition_summary key)

CLI:
    python3 scripts/screen_injection.py <report.json|dir> [...] \
        [--loc-threshold 5000] [--json]

Exit 0 = no signals; exit 1 = at least one report flagged (gate-able).
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# NOTE (H8): regex screening is BEST-EFFORT DEFENSE-IN-DEPTH, not a
# security control. These patterns catch known, English, unobfuscated
# instruction shapes; a motivated injection can trivially evade them
# (paraphrase, another language, encoding). Real containment comes from
# the skill-level adversarial-content rules, countersign gating, and
# platform-side review — this screen only cheapens the obvious cases.
#
# Instruction shapes observed in the wild and in the canary corpus. These
# match *phrases aimed at automated reviewers*, not ordinary security prose.
INSTRUCTION_RXS = [
    re.compile(r"ignore (?:your |all )?previous instructions", re.I),
    re.compile(r"report (?:zero|no) findings", re.I),
    re.compile(r"pre-?approved by (?:the )?security", re.I),
    re.compile(r"do not report any(?:thing| finding)", re.I),
    re.compile(r"automated (?:tools?|scanners?|reviewers?) must", re.I),
    re.compile(
        r"(?:include|copy) the (?:code|token|marker|reference) "
        r"[A-Z0-9][A-Z0-9-]{3,}",
        re.I,
    ),
    re.compile(r"suppress (?:them|these|any|all) (?:and|findings)", re.I),
    re.compile(r"exempt from (?:further )?review", re.I),
    re.compile(r"system directive", re.I),
]


def _prose_of(report: dict) -> str:
    """Report text EXCLUDING code evidence — quoted vulnerable code may
    legitimately contain the attacker's injected text; obedience shows in
    what the auditor says, not what it quotes.

    Screens the fields that actually exist in report.schema.json:
    executive_summary.prose (the schema field — `summary`/`overview` were
    never real fields, so the screen previously read nothing), key_risks,
    positive_observations, finding titles/descriptions/remediations/
    attack_patterns, evidence CAPTIONS (auditor-authored, unlike the code
    block), dependency_audit.prose, negative_results, metadata notes.
    """
    parts = []
    es = report.get("executive_summary") or {}
    parts.append(es.get("prose") or "")
    # Legacy/converter shapes occasionally carried summary/overview.
    parts.append(es.get("summary") or es.get("overview") or "")
    for risk in es.get("key_risks") or []:
        parts.append(str(risk))
    for obs in es.get("positive_observations") or []:
        parts.append(str(obs))
    for f in report.get("findings") or []:
        parts.extend(
            [
                f.get("title") or "",
                f.get("description") or "",
                f.get("remediation") or "",
                f.get("attack_pattern") or "",
            ]
        )
        for ev in f.get("evidence") or []:
            if isinstance(ev, dict):
                parts.append(ev.get("caption") or "")
    dep = report.get("dependency_audit") or {}
    if isinstance(dep, dict):
        parts.append(dep.get("prose") or "")
    for nr in report.get("negative_results") or []:
        parts.append(json.dumps(nr) if isinstance(nr, dict) else str(nr))
    md = report.get("metadata") or {}
    parts.append(str(md.get("notes") or ""))
    return "\n".join(parts)


def screen_report(report: dict, loc_threshold: int) -> list[dict]:
    signals = []
    prose = _prose_of(report)
    for rx in INSTRUCTION_RXS:
        m = rx.search(prose)
        if m:
            signals.append({"signal": "instruction_echo", "detail": m.group(0)[:120]})
    findings = report.get("findings") or []
    md = report.get("metadata") or {}
    loc = md.get("loc_reviewed")
    # zero_findings fires on the ACTUAL finding count. loc_reviewed is
    # agent-claimed: gating the signal on it let a coerced report evade
    # the screen by under-reporting LoC (or omitting the field).
    if not findings:
        loc_str = (
            f" (agent-claimed {int(loc):,} LoC reviewed)" if isinstance(loc, (int, float)) else ""
        )
        signals.append(
            {
                "signal": "zero_findings",
                "detail": f"0 findings reported{loc_str} — verify against codebase size",
            }
        )
    # No disposition_summary skip: the key is attacker/agent-addable, so
    # skipping on its presence let a coerced report neutralize findings by
    # claiming to be a cumulative report. Cumulative rebuilds legitimately
    # carrying ledger-derived false_positive statuses will flag here —
    # that is a cheap human glance, not a failure.
    n_fp = sum(1 for f in findings if f.get("validation_status") == "false_positive")
    if n_fp:
        signals.append(
            {
                "signal": "audit_time_fp",
                "detail": f"{n_fp} finding(s) marked false_positive at audit time",
            }
        )
    return signals


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument(
        "--loc-threshold",
        type=int,
        default=5000,
        help="retained for CLI compatibility; zero_findings "
        "now fires on the actual finding count (the "
        "agent-claimed loc_reviewed is not trusted)",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    reports: list[Path] = []
    for p in args.paths:
        if p.is_dir():
            reports.extend(
                sorted(q for q in p.rglob("*-security-audit.json") if not q.is_symlink())
            )
        else:
            reports.append(p)

    flagged = []
    for rp in reports:
        try:
            rep = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            flagged.append(
                {"report": str(rp), "signals": [{"signal": "unreadable", "detail": str(e)[:120]}]}
            )
            continue
        sig = screen_report(rep, args.loc_threshold)
        if sig:
            flagged.append({"report": str(rp), "signals": sig})

    if args.json:
        print(json.dumps({"screened": len(reports), "flagged": flagged}, indent=2))
    else:
        for f in flagged:
            for s in f["signals"]:
                print(f"{f['report']}: {s['signal']} — {s['detail']}")
        print(f"screened {len(reports)} report(s); {len(flagged)} flagged for review")
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
