#!/usr/bin/env python3
"""
Render a validated TRIAGE.json (contracts/schemas/triage.schema.json) to Markdown.

The JSON is the authoritative artifact; this renderer makes TRIAGE.md a
deterministic projection of it — same convention as render_report.py for
audit reports. Section order mirrors the triage skill's report contract:
Act on these -> Hardening backlog -> Undetermined -> Dropped.

Usage:
  python harnessing/4-triage/triage/scripts/render_triage.py TRIAGE.json              # stdout
  python harnessing/4-triage/triage/scripts/render_triage.py TRIAGE.json -o TRIAGE.md  # file
"""

import argparse
import json
import re
import sys
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# --- output escaping (H10) ---------------------------------------------------
# Triage content (titles, rationales, refute reasons) is authored under
# prompt-injection pressure from the audited repository. Strip control and
# bidi-override characters, collapse newlines in inline positions, and
# escape table pipes so hostile text cannot fabricate rows, headings, or
# raw HTML in the rendered markdown.

_CTRL_RX = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069]")


def _clean_inline(text) -> str:
    text = _CTRL_RX.sub("", str(text if text is not None else ""))
    return " ".join(text.split())


def _cell(text) -> str:
    return _clean_inline(text).replace("|", "\\|")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(_cell(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return "\n".join(lines)


def _loc(f: dict) -> str:
    # Backticks stripped: a backtick in a hostile path would close the
    # inline-code span and let the rest render as markup.
    file = _clean_inline(f.get("file") or "-").replace("`", "")
    line = f.get("line")
    return f"`{file}:{line}`" if line is not None else f"`{file}`"


def _votes(f: dict) -> str:
    vb = f.get("vote_breakdown")
    if not isinstance(vb, dict):
        return "-"
    return (
        f"{vb.get('true_positive', 0)}T/{vb.get('hardening', 0)}H/"
        f"{vb.get('false_positive', 0)}F/{vb.get('cannot_verify', 0)}C"
    )


def _first_sentence(text: str, limit: int = 220) -> str:
    text = " ".join((text or "").split())
    for stop in (". ", "; "):
        idx = text.find(stop)
        if 0 < idx < limit:
            return text[: idx + 1]
    return text[:limit] + ("…" if len(text) > limit else "")


def _by_verdict(report: dict, verdict: str) -> list[dict]:
    return [f for f in report.get("findings", []) if f.get("verdict") == verdict]


def render_header(report: dict) -> str:
    ctx = report.get("triage_context", {})
    s = report.get("summary", {})
    sev = s.get("by_severity", {})
    sev_line = " / ".join(f"{sev.get(k, 0)} {k}" for k in SEV_ORDER if sev.get(k) is not None)
    lines = [
        "# Triage Report",
        "",
        f"{s.get('input_count', 0)} in -> "
        f"{s.get('true_positives', 0)} confirmed ({sev_line}), "
        f"{s.get('hardening', 0)} hardening, "
        f"{s.get('undetermined', 0)} undetermined, "
        f"{s.get('duplicates', 0)} duplicates, "
        f"{s.get('false_positives', 0)} false positives",
        "",
        f"Context: {_clean_inline(ctx.get('mode', '?'))}; "
        f"environment = {_clean_inline(ctx.get('environment', '?'))}; "
        f"{_clean_inline(ctx.get('votes_per_finding', '?'))}-vote verification; "
        f"harness {_clean_inline(ctx.get('harness_version', '?'))}; "
        f"completed {_clean_inline(report.get('triage_completed', '?'))}",
    ]
    if ctx.get("reemitted"):
        lines.append(
            f"Re-emitted {_clean_inline(ctx['reemitted'])}: "
            f"{_clean_inline(ctx.get('reemit_method', ''))}".rstrip()
        )
    return "\n".join(lines) + "\n"


def render_confirmed(report: dict) -> str:
    tps = sorted(
        _by_verdict(report, "true_positive"),
        key=lambda f: (
            SEV_ORDER.get(str(f.get("severity")).lower(), 9),
            -(f.get("confidence") or 0),
        ),
    )
    out = ["## Act on these", ""]
    if not tps:
        out.append("_No confirmed findings._")
        return "\n".join(out) + "\n"
    for f in tps:
        sev = _clean_inline(str(f.get("severity", "?")).upper())
        out.append(f"### [{sev}] {_clean_inline(f.get('title'))}  ({_clean_inline(f.get('id'))})")
        claimed = f.get("claimed_severity")
        align = f.get("severity_alignment")
        meta = f"{_loc(f)} | {_clean_inline(f.get('category', '-'))}"
        if claimed:
            meta += f" | claimed {_clean_inline(claimed)}" + (
                f" (alignment {_clean_inline(align)})" if align is not None else ""
            )
        conf = f.get("confidence")
        if conf is not None:
            meta += f" | confidence {conf}/10"
        out.append(meta)
        if f.get("orig_id"):
            out.append(f"**Source finding:** {_clean_inline(f['orig_id'])}")
        if f.get("owner_hint"):
            out.append(f"**Owner:** {_clean_inline(f['owner_hint'])}")
        out.append(
            f"**Verdict:** "
            f"{_clean_inline(f.get('verify_verdict') or 'confirmed')}, "
            f"votes {_votes(f)}"
        )
        if f.get("preconditions"):
            out.append(
                "**Preconditions:** " + "; ".join(_clean_inline(p) for p in f["preconditions"])
            )
        if f.get("threat_match"):
            out.append(f"**Threat-model match:** {_clean_inline(f['threat_match'])}")
        if f.get("rationale"):
            out.append(f"**Why:** {_clean_inline(f['rationale'])}")
        if f.get("first_links"):
            out.append(
                "**Reachability evidence:** "
                + ", ".join(_clean_inline(link) for link in f["first_links"])
            )
        if f.get("verify_verdict") == "needs_manual_test":
            out.append("> Recommend a human build a PoC; static reasoning hit its limit.")
        out.append("")
    return "\n".join(out)


def render_hardening(report: dict) -> str:
    hd = sorted(_by_verdict(report, "hardening"), key=lambda f: -(f.get("confidence") or 0))
    out = [
        "## Hardening backlog",
        "",
        "Real gaps confirmed by verification, with no concrete exploit path "
        "(exclusion rule 13 — defense-in-depth and benchmark/best-practice "
        "deviations). Track as engineering hygiene / compliance work, not "
        "vulnerabilities. These are NOT false positives.",
        "",
    ]
    if not hd:
        out.append("_None._")
        return "\n".join(out) + "\n"
    rows = [
        [
            f.get("id"),
            f.get("title"),
            _loc(f),
            f.get("owner_hint") or "-",
            _first_sentence(f.get("rationale", "")),
        ]
        for f in hd
    ]
    out.append(_table(["id", "title", "location", "owner", "why hardening"], rows))
    return "\n".join(out) + "\n"


def render_undetermined(report: dict) -> str:
    und = _by_verdict(report, "undetermined")
    if not und:
        return ""
    out = [
        "## Undetermined",
        "",
        "Nothing was proven or refuted — cited material was missing/unreadable, "
        "or verification could not decide. Human review required; these are "
        "not false positives.",
        "",
    ]
    rows = [
        [
            f.get("id"),
            f.get("title"),
            _loc(f),
            _first_sentence(f.get("rationale", "") or ", ".join(f.get("refute_reasons", []))),
        ]
        for f in und
    ]
    out.append(_table(["id", "title", "location", "why undetermined"], rows))
    return "\n".join(out) + "\n"


def render_dropped(report: dict) -> str:
    fps = _by_verdict(report, "false_positive")
    dups = _by_verdict(report, "duplicate")
    out = ["## Dropped", ""]
    if not fps and not dups:
        out.append("_None._")
        return "\n".join(out) + "\n"
    rows = []
    for f in fps:
        why = ", ".join(f.get("refute_reasons", [])) or "refuted"
        if f.get("exclusion_rule") is not None:
            why += f" (rule {f['exclusion_rule']})"
        rows.append([f.get("id"), f.get("title"), _loc(f), why])
    for f in dups:
        rows.append([f.get("id"), f.get("title"), _loc(f), f"duplicate of {f.get('duplicate_of')}"])
    out.append(_table(["id", "title", "location", "why dropped"], rows))
    return "\n".join(out) + "\n"


def render_triage(report: dict) -> str:
    sections = [
        render_header(report),
        render_confirmed(report),
        render_hardening(report),
        render_undetermined(report),
        render_dropped(report),
    ]
    return "\n".join(s for s in sections if s).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("report", help="path to a schema-conformant TRIAGE.json")
    parser.add_argument("-o", "--output", help="write Markdown here (default: stdout)")
    args = parser.parse_args()

    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot load report: {e}", file=sys.stderr)
        return 2

    md = render_triage(report)
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
