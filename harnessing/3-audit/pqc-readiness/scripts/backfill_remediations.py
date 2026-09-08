#!/usr/bin/env python3
"""Backfill the structured `remediations` section into existing PQC
readiness reports (harness >= 0.153.0 schema addition).

PQC readiness reports are posture artifacts — they have no disposition
ledger, so backfill is a plain regenerate-in-place: the section is
DERIVED deterministically from material the report already carries.

Sources, in order:
  1. The Markdown companion's "What you need to do" sections
     ("### Fix now", "### Upgrade", "### Waiting on upstream") — the
     SKILL.md-mandated template, parsed tolerantly:
       - "`file:line` — description" bullet heads
       - "Action: ..." continuation lines
       - "Playbook: <path>" continuation lines (mapped to `recipe`)
       - "— blocked on <vendor>" tails (mapped to `blocked_on`)
  2. `clock_items[]` in the JSON — one `deadline` entry per clock item
     whose primitive is not already covered by an entry from (1),
     reusing its `remediation_effort` / `blast_radius`.
     Owner-facing remediations use `locations`; fact_ids stay on
     clock_items / scores only.

Idempotent: reports that already have a `remediations` key are skipped
unless --force. Every touched report is re-validated with
pqc_facts.validate_readiness before the write is kept (invalid result
rolls back and reports the error).

Usage:
    # one report
    python3 backfill_remediations.py --report <slug>-pqc-readiness.json
    # whole corpus
    python3 backfill_remediations.py [--results-root PATH] [--root DIR] [--force]
    # dry run
    python3 backfill_remediations.py --results-root PATH --dry-run
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pqc_facts

SECTION_CATEGORY = {
    "fix now": "fix-now",
    "upgrade": "upgrade",
    "waiting on upstream": "waiting-on-upstream",
}
_HEAD_RE = re.compile(r"^###\s+(.+?)\s*(?:\(|$)")
_BULLET_RE = re.compile(r"^-\s+(?:`(?P<loc>[^`]+)`\s*[—-]\s*)?(?P<desc>.+)$")
_ACTION_RE = re.compile(r"^\s+Action:\s*(?P<action>.+)$")
_PLAYBOOK_RE = re.compile(r"^\s+Playbook:\s*(?P<path>\S+)")
_BLOCKED_RE = re.compile(r"blocked on\s+(?P<vendor>[^.,;]+)", re.IGNORECASE)


def parse_md_sections(md_text):
    """Yield (category, entry-dict) parsed from the MD companion."""
    category = None
    entry = None
    for line in md_text.splitlines():
        head = _HEAD_RE.match(line)
        if head:
            key = head.group(1).strip().lower()
            category = None
            for prefix, cat in SECTION_CATEGORY.items():
                if key.startswith(prefix):
                    category = cat
                    break
            if entry:
                yield entry
                entry = None
            continue
        if category is None:
            continue
        bullet = _BULLET_RE.match(line)
        if bullet:
            if entry:
                yield entry
            desc = bullet.group("desc").strip()
            entry = {
                "category": category,
                "action": desc,  # refined by an Action: line when present
                "details": None,
                "locations": [bullet.group("loc")] if bullet.group("loc") else [],
                "recipe": None,
                "target": None,
                "deadline": None,
                "blocked_on": None,
            }
            if category == "waiting-on-upstream":
                m = _BLOCKED_RE.search(desc)
                if m:
                    entry["blocked_on"] = m.group("vendor").strip()
            continue
        if entry:
            act = _ACTION_RE.match(line)
            if act:
                entry["details"] = entry["action"]
                entry["action"] = act.group("action").strip()
                if entry["category"] == "upgrade" and entry["target"] is None:
                    entry["target"] = act.group("action").strip()
                continue
            pb = _PLAYBOOK_RE.match(line)
            if pb:
                entry["recipe"] = pb.group("path")
                continue
    if entry:
        yield entry


def id_prefix(report, slug):
    """Unique per-report id prefix, mirroring the /secure-code-audit
    finding-id convention: <SLUG_UPPER max 24>-<7-hex provenance>.

    Provenance component: metadata.commit's short sha when present;
    otherwise the first 7 hex of sha256(repository URL or slug) — still
    deterministic and repo-unique, flagged by the 'u' prefix so a reader
    can tell it is not a git sha.
    """
    slug_part = re.sub(r"[^A-Za-z0-9]", "_", slug).upper()[:24]
    commit = (report.get("metadata") or {}).get("commit") or ""
    if re.fullmatch(r"[0-9a-f]{7,40}", commit):
        prov = commit[:7]
    else:
        seed = (report.get("metadata") or {}).get("repository") or slug
        prov = "u" + hashlib.sha256(seed.encode()).hexdigest()[:6]
    return f"{slug_part}-{prov}"


def derive(report, md_text, slug=None):
    """Return the remediations array for one report (list of dicts)."""
    entries = []
    if md_text:
        entries.extend(parse_md_sections(md_text))
    covered_text = " ".join(
        (e.get("action") or "") + " " + (e.get("details") or "") for e in entries
    ).lower()
    for ci in report.get("clock_items") or []:
        prim = ci.get("primitive") or ""
        if prim and prim.lower() in covered_text:
            continue  # already covered by a fix-now/upgrade entry
        deadline = ci.get("disallowed_after") or ci.get("deprecated_after")
        if deadline not in (2030, 2035):
            continue
        entry = {
            "category": "deadline",
            "action": (
                f"Migrate off {prim} — "
                + (
                    "disallowed after"
                    if ci.get("disallowed_after")
                    else "deprecated for new use after"
                )
                + f" {deadline} (NIST IR 8547)"
            ),
            "details": None,
            "locations": [],
            "recipe": None,
            "target": None,
            "deadline": deadline,
            "blocked_on": None,
        }
        if ci.get("remediation_effort"):
            entry["remediation_effort"] = ci["remediation_effort"]
        if ci.get("blast_radius"):
            entry["blast_radius"] = ci["blast_radius"]
        entries.append(entry)
    prefix = id_prefix(report, slug or "unknown")
    for i, e in enumerate(entries, 1):
        e_clean = {k: v for k, v in e.items() if v not in (None, []) or k in ("action", "category")}
        e_clean["id"] = f"{prefix}-REM-{i:03d}"
        entries[i - 1] = e_clean
    # blocked_on is schema-required for waiting-on-upstream; degrade
    # unparseable vendor names to the raw description
    for e in entries:
        if e["category"] == "waiting-on-upstream" and not e.get("blocked_on"):
            e["blocked_on"] = (e.get("details") or e["action"])[:120]
    return entries


_CAT_LABEL = {
    "fix-now": "Fix now",
    "upgrade": "Upgrade",
    "waiting-on-upstream": "Waiting on upstream",
    "deadline": "Deadline",
}


def render_md_section(remediations):
    """Plain-language '## Remediations' MD section from the JSON entries."""
    if not remediations:
        return "## Remediations\n\nNone — no remediation actions identified.\n"
    lines = ["## Remediations", ""]
    for r in remediations:
        head = _CAT_LABEL.get(r.get("category"), r.get("category"))
        if r.get("category") == "deadline" and r.get("deadline"):
            head += f" — by {r['deadline']}"
        line = f"- **{r['id']}** ({head}): {r.get('action', '').strip()}"
        extras = []
        if r.get("target"):
            extras.append(f"target: {r['target']}")
        if r.get("remediation_effort"):
            extras.append(f"effort: {r['remediation_effort']}")
        if r.get("blocked_on"):
            extras.append(f"blocked on: {r['blocked_on']}")
        if extras:
            line += f" _({'; '.join(extras)})_"
        lines.append(line)
        locs = r.get("locations") or []
        if locs:
            lines.append(f"  Locations: `{', '.join(locs)}`")
        # recipe stays in JSON for /patch; never emit Playbook paths in MD
    lines.append("")
    return "\n".join(lines)


def strip_facts_columns(md_text):
    """Remove any 'Facts' column from MD tables (fact ids are JSON-side
    citations; the human page should not carry them)."""
    out = []
    drop_idx = None
    for line in md_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if drop_idx is None or not out or not out[-1].strip().startswith("|"):
                drop_idx = None  # new table: re-detect from its header
            if "Facts" in cells:
                drop_idx = cells.index("Facts")
            if drop_idx is not None and len(cells) > drop_idx:
                del cells[drop_idx]
                out.append("| " + " | ".join(cells) + " |")
                continue
        else:
            drop_idx = None
        out.append(line)
    return "\n".join(out) + ("\n" if md_text.endswith("\n") else "")


LEGEND_HEADING = "### What the domains mean"
LEGEND = f"""{LEGEND_HEADING}

| Domain | Question it answers | Scale |
|---|---|---|
| **VULN** (Vulnerability) | Is this repo using crypto a quantum computer could break? | 0 = fully exposed · 100 = no quantum-vulnerable crypto |
| **AGIL** (Agility) | How easy is it to swap the crypto when needed? | 0 = hardcoded everywhere · 100 = fully configurable |
| **PQCA** (PQC Adoption) | Has this repo already adopted post-quantum crypto? | 0 = no PQC · 100 = fully adopted |
| **HNDL** (Harvest risk) | Could traffic recorded today be decrypted by a future quantum computer? | 0 = high-value long-lived data exposed · 100 = no risk |

**Overall** combines these (VULN 40%, AGIL 25%, PQCA 20%, HNDL 15%) into
a 0–100 score — higher = more ready. Buckets: **ready** (≥80, no urgent
items) · **partial** (50–79) · **not-ready** (<50 or significant-effort
items) · **blocked-external** (waiting on vendor/upstream) ·
**not-applicable** (no crypto).
"""


def upsert_legend(md_text):
    """Idempotently place the domain legend on EVERY report: under
    '## Scores' when the section exists, appended otherwise (minimal
    ready/not-applicable pages included — user directive: all reports
    carry the legend)."""
    if LEGEND_HEADING in md_text:
        pre, _, rest = md_text.partition(LEGEND_HEADING)
        m = re.search(r"\n(#{2,3} (?!What the domains mean).+)", rest)
        tail = rest[m.start() :].lstrip("\n") if m else ""
        return pre.rstrip("\n") + "\n\n" + LEGEND + "\n" + tail
    if "## Scores" in md_text:
        pre, _, rest = md_text.partition("## Scores")
        return pre + "## Scores" + rest.rstrip("\n") + "\n\n" + LEGEND
    return md_text.rstrip("\n") + "\n\n" + LEGEND


def refresh_md(md_path, remediations):
    """Idempotently apply both user-requested MD fixes: drop Facts
    columns, upsert the '## Remediations' section (before '## Scores'
    when present, else appended)."""
    text = md_path.read_text() if md_path.is_file() else ""
    text = strip_facts_columns(text)
    text = upsert_legend(text)
    section = render_md_section(remediations)
    if "## Remediations" in text:
        pre, _, rest = text.partition("## Remediations")
        # find the next section heading (h2 or h3 — e.g. the domain
        # legend) after the old block
        m = re.search(r"\n(#{2,3} (?!Remediations).+)", rest)
        tail = rest[m.start() :].lstrip("\n") if m else ""
        text = pre.rstrip("\n") + "\n\n" + section + "\n" + tail
    elif "## Scores" in text:
        pre, _, rest = text.partition("## Scores")
        text = pre.rstrip("\n") + "\n\n" + section + "\n## Scores" + rest
    else:
        text = text.rstrip("\n") + "\n\n" + section
    md_path.write_text(text)


def backfill_one(json_path, force=False, dry_run=False):
    report = json.loads(json_path.read_text())
    if "remediations" in report and not force:
        return "skipped (already has remediations)"
    md_path = json_path.with_suffix(".md")
    md_text = md_path.read_text() if md_path.is_file() else ""
    slug = json_path.name[: -len("-pqc-readiness.json")]
    report["remediations"] = derive(report, md_text, slug=slug)
    if dry_run:
        return f"would write {len(report['remediations'])} entries"
    original = json_path.read_text()
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    rc = pqc_facts.validate_readiness(json_path)
    if rc != 0:
        json_path.write_text(original)  # roll back
        return "ERROR: post-backfill validation failed (rolled back)"
    return f"wrote {len(report['remediations'])} entries"


def refresh_md_one(json_path, dry_run=False):
    report = json.loads(json_path.read_text())
    md_path = json_path.with_suffix(".md")
    if not md_path.is_file():
        return "skipped (no md companion)"
    if dry_run:
        return "would refresh md"
    refresh_md(md_path, report.get("remediations") or [])
    return "refreshed md"


def main():
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--report", help="single *-pqc-readiness.json")
    g.add_argument(
        "--root",
        nargs="?",
        const="",
        metavar="DIR",
        help="batch corpus (default: <results-root>/pqc when DIR omitted)",
    )
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results dir for default batch corpus",
    )
    ap.add_argument(
        "--force", action="store_true", help="re-derive even when remediations already present"
    )
    ap.add_argument(
        "--refresh-md",
        action="store_true",
        help="refresh the .md companion instead of the JSON: "
        "drop Facts columns, upsert '## Remediations' "
        "rendered from the JSON section",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.report:
        targets = [Path(args.report)]
    else:
        corpus_root = resolve_results_root(args) / "pqc" if args.root == "" else Path(args.root)
        targets = sorted(corpus_root.rglob("*-pqc-readiness.json"))
    counts = {}
    for p in targets:
        try:
            if args.refresh_md:
                result = refresh_md_one(p, dry_run=args.dry_run)
            else:
                result = backfill_one(p, force=args.force, dry_run=args.dry_run)
        except Exception as exc:  # keep the sweep going; report at the end
            result = f"ERROR: {exc}"
        key = result.split("(")[0].split(":")[0].strip()
        counts[key] = counts.get(key, 0) + 1
        if result.startswith("ERROR"):
            print(f"{p}: {result}", file=sys.stderr)
    print(f"backfill over {len(targets)} reports: {counts}")
    return 1 if counts.get("ERROR") else 0


if __name__ == "__main__":
    raise SystemExit(main())
