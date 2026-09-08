#!/usr/bin/env python3
# Migration utility archived 2026-08-11
"""Deterministic repair of mechanical THREAT_MODEL.md contract violations.

Companion to traust_engine.reporting.lint (the threat-model lint), with the same discipline as
reemit_legacy_triage.py: purely mechanical transforms, no re-analysis, and
a file is rewritten ONLY when the repair strictly reduces its lint errors
without introducing any new one. Everything else is left untouched and
reported — judgment calls (coverage gaps, free-text actors with no
unambiguous enum meaning) belong to a /threat-model review pass, not to
this script.

Transforms:
1. Escape unescaped `|` inside inline-code spans within table rows whose
   cell count exceeds the section's column count (the row-fracture defect:
   regex alternations, `|| true`).
2. Normalize actor-cell separators (` / ` -> `, `) and remap unambiguous
   legacy actor synonyms onto the schema enum (see ACTOR_MAP).
3. Remap unambiguous legacy values for status (accepted -> risk_accepted),
   likelihood (certain -> almost_certain), and their kin (see the *_MAP
   tables). Values with no unambiguous mapping are left in place.

Usage:
    python3 repair_threat_model.py <path> [<path> ...] [--dry-run]
"""

import argparse
import re
import sys

from traust_engine.reporting.lint import (
    MITIG_COLUMNS,
    THREATS_COLUMNS,
    collect,
    lint_file,
    split_row,
)

# Unambiguous legacy synonym -> schema enum. Values NOT in this table
# (free text like "in-cluster (log reader)", "control_plane", "infra")
# are deliberately left for human/LLM review — mapping them here would be
# concluding, not routing.
ACTOR_MAP = {
    "adjacent": "adjacent_network",
    "adjacent_net": "adjacent_network",
    "adjacent_unauth": "adjacent_network",
    "adjacent-network": "adjacent_network",
    "adjacent_container": "adjacent_network",
    "in-cluster": "adjacent_network",
    "in_cluster": "adjacent_network",
    "local": "local_user",
    "local_priv": "local_admin",
    "tenant": "remote_auth",
    "tenant_admin": "remote_auth",
    "co-tenant": "remote_auth",
    "authenticated_low": "remote_auth",
    "authenticated_privileged": "remote_auth",
    "authenticated cluster user": "remote_auth",
    "external": "remote_unauth",
    "automated": "remote_unauth",
    "opportunistic": "remote_unauth",
}
STATUS_MAP = {
    "accepted": "risk_accepted",
    "accepted_risk": "risk_accepted",
    "accepted_by_design": "risk_accepted",
    "risk-accepted": "risk_accepted",
    "mitigated_by_archival": "mitigated",
    "partially-mitigated": "partially_mitigated",
    "partial": "partially_mitigated",
}
LIKELIHOOD_MAP = {
    "certain": "almost_certain",
    "almost-certain": "almost_certain",
    "very-rare": "very_rare",
}

CODE_SPAN = re.compile(r"`[^`]*`")


def escape_pipes_in_code_spans(line):
    """Escape unescaped pipes inside inline-code spans of a table row."""

    def fix(m):
        return re.sub(r"(?<!\\)\|", r"\\|", m.group(0))

    return CODE_SPAN.sub(fix, line)


def remap_actor_cell(cell):
    parts = re.split(r"\s*(?:,|/)\s*", cell.strip())
    mapped = [ACTOR_MAP.get(p.strip(), p.strip()) for p in parts if p.strip()]
    # dedupe, preserve order
    seen, out = set(), []
    for m in mapped:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return ", ".join(out)


def rebuild_row(cells):
    return "| " + " | ".join(cells) + " |"


def repair_text(text):
    """Apply mechanical transforms; return the repaired text."""
    out = []
    section = None
    for line in text.splitlines():
        m = re.match(r"^## (\d+)\.", line)
        if m:
            section = int(m.group(1))
            out.append(line)
            continue
        stripped = line.strip()
        if not stripped.startswith("|") or set(stripped) <= {"|", "-", " ", ":"}:
            out.append(line)
            continue

        expected = {4: len(THREATS_COLUMNS), 8: len(MITIG_COLUMNS)}.get(section)
        cells = split_row(stripped)

        # 1. row fracture: too many cells -> escape pipes inside code spans
        if expected and len(cells) > expected:
            line = escape_pipes_in_code_spans(line)
            cells = split_row(line.strip())

        # 2/3. enum remaps in section 4 data rows
        if section == 4 and len(cells) == len(THREATS_COLUMNS) and cells[0] != "id":
            cells[2] = remap_actor_cell(cells[2])
            cells[6] = LIKELIHOOD_MAP.get(cells[6], cells[6])
            cells[7] = STATUS_MAP.get(cells[7], cells[7])
            indent = line[: len(line) - len(line.lstrip())]
            line = indent + rebuild_row(cells)

        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def error_class(e):
    """Collapse an error message to its class (quoted values stripped),
    so a partial repair — e.g. actor 'accidental / in-cluster' becoming
    actor 'accidental' — is recognized as the same, shrinking, defect
    rather than a new one."""
    return re.sub(r"'[^']*'", "'…'", e)


def repair_file(path, dry_run=False):
    """Repair one file. Returns (status, before_count, after_count)."""
    before_errors, _ = lint_file(path)
    if not before_errors:
        return "clean", 0, 0

    original = path.read_text(encoding="utf-8")
    repaired = repair_text(original)
    if repaired == original:
        return "unrepairable", len(before_errors), len(before_errors)

    tmp = path.with_suffix(path.suffix + ".repair-tmp")
    tmp.write_text(repaired, encoding="utf-8")
    try:
        after_errors, _ = lint_file(tmp)
    finally:
        tmp.unlink()

    new_classes = {error_class(e) for e in after_errors} - {error_class(e) for e in before_errors}
    if len(after_errors) >= len(before_errors) or new_classes:
        return "unrepairable", len(before_errors), len(before_errors)

    if not dry_run:
        path.write_text(repaired, encoding="utf-8")
    return ("fixed" if not after_errors else "improved", len(before_errors), len(after_errors))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument(
        "--dry-run", action="store_true", help="report what would change without writing"
    )
    args = ap.parse_args()

    files = collect(args.paths)
    stats = {"clean": 0, "fixed": 0, "improved": 0, "unrepairable": 0}
    err_before = err_after = 0
    residual = []
    for f in files:
        try:
            status, before, after = repair_file(f, dry_run=args.dry_run)
        except Exception as exc:
            status, before, after = "unrepairable", 1, 1
            print(f"  ERROR repairing {f}: {exc}")
        stats[status] += 1
        err_before += before
        err_after += after
        if status == "improved":
            residual.append((f, after))
        if status in ("fixed", "improved"):
            print(f"  {status}: {f} ({before} -> {after} errors)")

    mode = "DRY RUN — no files written" if args.dry_run else "applied"
    print(
        f"\n{mode}: {stats['fixed']} fixed, {stats['improved']} improved, "
        f"{stats['unrepairable']} unrepairable, {stats['clean']} already clean "
        f"(of {len(files)} files)"
    )
    print(f"errors: {err_before} -> {err_after}")
    if residual:
        print(
            f"{len(residual)} file(s) improved but not clean — "
            f"remaining errors need review (/threat-model review)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
