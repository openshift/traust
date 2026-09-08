#!/usr/bin/env python3
# Migration utility archived 2026-08-11
"""
Re-emit pre-0.24.0 triage artifacts under the current verdict taxonomy and
triage.schema.json contract.

Legacy triage JSONs (June-era batches) use the binary taxonomy — rule-13
hardening gaps and unlocatable findings sit in the false_positive column —
and pre-schema shapes (boolean triage_completed, uppercase by_severity,
string vote breakdowns, free-text exclusion rules, no harness_version).
This tool converts them deterministically, WITHOUT re-verification: votes,
confidence, and rationales are preserved verbatim; only labels and shapes
are normalized.

Verdict remap (same rules as the 2026-07-11 agent-control-plane re-emit):
  false_positive whose PRIMARY exclusion rule is 13  -> hardening
  false_positive that was unlocatable (refute reason doesnt_exist with
    confidence 0/absent, or a "no source location" rationale) -> undetermined
  everything else unchanged

A file is rewritten ONLY if the converted document passes the triage schema
plus cross-validation with zero errors; failures are reported and the
original is left untouched. The Markdown sibling is re-rendered from the
converted JSON (render_triage). Already-conformant files (those carrying
triage_context.harness_version) are skipped.

Usage:
  python -m traust.migrations.reemit_legacy_triage
      (default: configured analysis_results from $TRAUST_CONFIG_HOME/locations.yaml)
  python -m traust.migrations.reemit_legacy_triage --results-root <analysis-results> \\
      [--dry-run] [--limit N] [--failures-out failures.json]
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.paths import skill_dir

_TRIAGE_SCRIPTS = skill_dir("triage") / "scripts"
if not _TRIAGE_SCRIPTS.is_dir():
    sys.exit(
        f"ERROR: harnessing/4-triage/triage/scripts not found at {_TRIAGE_SCRIPTS} "
        "(expected under traust repo root — "
        "parents[3] from src/traust/migrations/)"
    )
if str(_TRIAGE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_TRIAGE_SCRIPTS))

import jsonschema  # noqa: E402
from render_triage import render_triage  # noqa: E402
from traust_contracts.paths import schema_dir  # noqa: E402
from traust_engine.reporting.validate import (  # noqa: E402
    ValidationResult,
    build_registry,
    cross_validate_triage,
    load_schema,
)

SCHEMA_DIR = schema_dir()
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
VERIFY_VERDICTS = {
    "exploitable",
    "mitigated",
    "needs_manual_test",
    "confirmed",
    "refuted",
    "hardening",
}
FINDING_KEYS = {  # triage.schema.json $defs.finding properties
    "id",
    "orig_id",
    "source",
    "title",
    "file",
    "line",
    "category",
    "claimed_severity",
    "verdict",
    "verify_verdict",
    "confidence",
    "severity",
    "severity_label",
    "severity_alignment",
    "preconditions",
    "access_level",
    "threat_match",
    "rationale",
    "vote_breakdown",
    "refute_reasons",
    "exclusion_rule",
    "first_links",
    "duplicate_of",
    "absorbed",
    "owner_hint",
    "component",
    "missing_fields",
}
LIST_KEYS = {"preconditions", "refute_reasons", "first_links", "absorbed", "missing_fields"}
RULE_NUM = re.compile(r"(\d+)")
VB_STRING = re.compile(r"\b(TP|FP)\s*(\d+)\s*-\s*(\d+)")


def harness_version() -> str:
    root = Path(__file__).resolve().parent.parent
    semver = (root / "VERSION").read_text().strip()
    sha = (
        subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        or "0000000"
    )
    return f"{semver}-{sha}"


def git_dates(results_root: Path) -> dict[str, str]:
    """path -> last-commit date (YYYY-MM-DD), one streamed git-log pass."""
    dates: dict[str, str] = {}
    proc = subprocess.Popen(
        ["git", "-C", str(results_root), "log", "--format=\x01%as", "--name-only"],
        stdout=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    current = None
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line.startswith("\x01"):
            current = line[1:]
        elif line.endswith("-triage.json") and line not in dates and current:
            dates[line] = current
    proc.wait()
    return dates


def primary_rule(exclusion) -> str | None:
    """First rule number cited in a (possibly free-text) exclusion rule."""
    if exclusion is None:
        return None
    m = RULE_NUM.search(str(exclusion))
    return m.group(1) if m else None


def parse_vb(vb):
    """Normalize vote_breakdown to the 4-key object, or None."""
    if isinstance(vb, dict):
        return {
            "true_positive": int(vb.get("true_positive") or 0),
            "hardening": int(vb.get("hardening") or 0),
            "false_positive": int(vb.get("false_positive") or 0),
            "cannot_verify": int(vb.get("cannot_verify") or 0),
        }
    if isinstance(vb, str):
        m = VB_STRING.search(vb)
        if m:
            a, b = int(m.group(2)), int(m.group(3))
            tp, fp = (a, b) if m.group(1) == "TP" else (b, a)
            return {"true_positive": tp, "hardening": 0, "false_positive": fp, "cannot_verify": 0}
    return None


def is_unlocatable(f: dict) -> bool:
    reasons = f.get("refute_reasons") or []
    conf = f.get("confidence")
    rat = str(f.get("rationale") or "").lower()
    return (
        "doesnt_exist" in reasons or "unlocatable" in reasons or "no source location" in rat
    ) and (conf in (None, 0, 0.0))


def convert_finding(f: dict) -> dict:
    out = {k: v for k, v in f.items() if k in FINDING_KEYS}
    for k in LIST_KEYS:
        if k in out and not isinstance(out[k], list):
            out[k] = []
    verdict = out.get("verdict")

    # line: legacy artifacts carry ranges ("18-31") and "n/a"
    line = out.get("line")
    if isinstance(line, str):
        m = re.match(r"^\s*(\d+)", line)
        out["line"] = int(m.group(1)) if m else None
    elif not isinstance(line, (int, type(None))):
        out["line"] = None

    if verdict in ("cannot_verify", "needs_manual_test"):
        # legacy verdict values: nothing was determined
        out["verdict"] = "undetermined"
        out["verify_verdict"] = "needs_manual_test"
        out["confidence"] = 0
        out["exclusion_rule"] = None
        verdict = "undetermined"

    if verdict == "false_positive":
        if is_unlocatable(f):
            out["verdict"] = "undetermined"
            out["verify_verdict"] = "needs_manual_test"
            out["confidence"] = 0
            rr = [r for r in (out.get("refute_reasons") or []) if r != "doesnt_exist"]
            out["refute_reasons"] = ["unlocatable", *rr]
            out["exclusion_rule"] = None
        elif primary_rule(out.get("exclusion_rule")) == "13":
            out["verdict"] = "hardening"
            out["verify_verdict"] = "hardening"
            out["exclusion_rule"] = "13"
            vb = parse_vb(out.get("vote_breakdown"))
            if vb:  # rule-13 refutation votes were hardening votes
                vb["hardening"] += vb["false_positive"]
                vb["false_positive"] = 0
                out["vote_breakdown"] = vb
    verdict = out.get("verdict")

    # severity: lowercase enum on true positives only
    sev = str(out.get("severity") or "").strip().lower()
    out["severity"] = sev if (verdict == "true_positive" and sev in SEVERITIES) else None

    if ("vote_breakdown" in out and not isinstance(out["vote_breakdown"], dict)) or isinstance(
        out.get("vote_breakdown"), dict
    ):
        out["vote_breakdown"] = parse_vb(out["vote_breakdown"])

    vv = out.get("verify_verdict")
    if vv is not None and vv not in VERIFY_VERDICTS:
        out["verify_verdict"] = None
    conf = out.get("confidence")
    if isinstance(conf, (int, float)):
        out["confidence"] = min(10, max(0, conf))
    elif conf is not None:
        out["confidence"] = None
    if verdict == "false_positive" and not out.get("refute_reasons"):
        out["refute_reasons"] = ["not_actionable"]
    return out


def convert(doc: dict, fallback_date: str, hv: str) -> dict:
    ctx = dict(doc.get("triage_context") or {})
    votes = ctx.get("votes_per_finding")
    if not isinstance(votes, int) or votes < 1:
        sums = [
            sum(parse_vb(f.get("vote_breakdown")).values())
            for f in doc.get("findings", [])
            if parse_vb(f.get("vote_breakdown"))
        ]
        ctx["votes_per_finding"] = max(sums) if sums else 3
    if ctx.get("threat_model") is None:
        ctx.pop("threat_model", None)
    ctx.setdefault("environment", "(not recorded in legacy artifact)")
    if len(str(ctx.get("environment") or "")) < 10:
        ctx["environment"] = "(not recorded in legacy artifact)"
    ctx.setdefault("repo", "(not recorded)")
    ctx["harness_version"] = hv
    ctx["reemitted"] = datetime.now(UTC).date().isoformat()
    ctx["reemit_method"] = (
        "Deterministic legacy re-emission under the v0.24.0+ verdict "
        "taxonomy (harness reemit_legacy_triage.py): false positives whose "
        "primary exclusion rule was 13 re-labeled hardening (refutation "
        "votes counted as hardening votes); unlocatable refutations "
        "re-labeled undetermined; shapes normalized to triage.schema.json. "
        "No re-verification; votes, confidence, and rationales unchanged."
    )

    tc = doc.get("triage_completed")
    if not (isinstance(tc, str) and re.match(r"^\d{4}-\d{2}-\d{2}", str(tc))):
        tc = fallback_date
    else:
        tc = tc[:10]

    findings = [convert_finding(f) for f in doc.get("findings", [])]
    # Renumber non-conformant ids (e.g. legacy 'u001'), preserving the
    # original in `source` and keeping duplicate_of references intact.
    id_pat = re.compile(r"^f\d{3,}$")
    valid_nums = [int(f["id"][1:]) for f in findings if id_pat.match(str(f.get("id") or ""))]
    next_num = (max(valid_nums) + 1) if valid_nums else 1
    id_map = {}
    for f in findings:
        old = str(f.get("id") or "")
        if not id_pat.match(old):
            new_id = f"f{next_num:03d}"
            next_num += 1
            id_map[old] = new_id
            f["source"] = ((f.get("source") or "") + f" (legacy id {old})").strip()
            f["id"] = new_id
    if id_map:
        for f in findings:
            if f.get("duplicate_of") in id_map:
                f["duplicate_of"] = id_map[f["duplicate_of"]]
            if f.get("absorbed"):
                f["absorbed"] = [id_map.get(a, a) for a in f["absorbed"]]

    def verdict_count(v):
        return sum(1 for f in findings if f.get("verdict") == v)

    by_sev = {s: 0 for s in ("critical", "high", "medium", "low", "informational")}
    for f in findings:
        if f.get("verdict") == "true_positive" and f.get("severity"):
            by_sev[f["severity"]] += 1
    summary = {
        "input_count": len(findings),
        "true_positives": verdict_count("true_positive"),
        "hardening": verdict_count("hardening"),
        "false_positives": verdict_count("false_positive"),
        "undetermined": verdict_count("undetermined"),
        "duplicates": verdict_count("duplicate"),
        "needs_manual_test": sum(
            1 for f in findings if f.get("verify_verdict") == "needs_manual_test"
        ),
        "by_severity": by_sev,
    }
    return {"triage_completed": tc, "triage_context": ctx, "summary": summary, "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_config_home_arg(parser)
    parser.add_argument("--results-root", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--failures-out")
    args = parser.parse_args()

    engine = load_engine(args.config_home)
    root = (args.results_root or analysis_results_dir(engine)).resolve()
    schema = load_schema(SCHEMA_DIR / "triage.schema.json")
    registry = build_registry()
    validator = jsonschema.Draft202012Validator(
        schema, registry=registry, format_checker=jsonschema.FormatChecker()
    )
    hv = harness_version()
    print("[+] indexing git dates…", file=sys.stderr)
    dates = git_dates(root)

    files = []
    for sub in ("findings", "oss-findings"):
        base = root / sub
        if base.is_dir():
            files.extend(
                p
                for p in sorted(base.rglob("*-triage.json"))
                if not p.is_symlink() and "_manifest" not in p.parts
            )
    if args.limit:
        files = files[: args.limit]

    stats = {
        "converted": 0,
        "already_conformant": 0,
        "failed": 0,
        "hardening_relabels": 0,
        "undetermined_relabels": 0,
    }
    failures = []
    for i, path in enumerate(files, 1):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            stats["failed"] += 1
            failures.append({"file": str(path), "error": f"unreadable: {e}"})
            continue
        if (doc.get("triage_context") or {}).get("harness_version"):
            stats["already_conformant"] += 1
            continue

        rel = str(path.relative_to(root))
        fallback = dates.get(rel) or datetime.now(UTC).date().isoformat()
        new = convert(doc, fallback, hv)

        errors = [
            f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
            for e in validator.iter_errors(new)
        ]
        if not errors:
            result = ValidationResult(file_path=str(path))
            cross_validate_triage(new, result)
            errors = result.errors
        if errors:
            stats["failed"] += 1
            failures.append({"file": str(path), "error": errors[:3]})
            continue

        stats["hardening_relabels"] += new["summary"]["hardening"]
        stats["undetermined_relabels"] += new["summary"]["undetermined"]
        stats["converted"] += 1
        if not args.dry_run:
            path.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
            path.with_suffix("").with_suffix(".md")  # no-op clarity
            md_path = path.parent / path.name.replace(".json", ".md")
            md_path.write_text(render_triage(new), encoding="utf-8")
        if i % 500 == 0:
            print(f"  … {i}/{len(files)}", file=sys.stderr)

    print(
        f"Re-emission{' (dry run)' if args.dry_run else ''}: "
        f"{stats['converted']} converted, "
        f"{stats['already_conformant']} already conformant, "
        f"{stats['failed']} failed — "
        f"{stats['hardening_relabels']} findings re-labeled hardening, "
        f"{stats['undetermined_relabels']} re-labeled undetermined"
    )
    if failures:
        print("  first failures: " + "; ".join(f"{f['file']}" for f in failures[:5]))
        if args.failures_out:
            Path(args.failures_out).write_text(
                json.dumps(failures, indent=2) + "\n", encoding="utf-8"
            )
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
