#!/usr/bin/env python3
"""Compliance citation gate — a narrative verdict cannot ship.

Layered over contracts/schemas/compliance-assessment.schema.json (which already
makes evidence-free satisfied/not_satisfied unrepresentable), this
validator enforces what a JSON Schema can't:

1. **Verdict-source discipline** (amendment 1): a `deterministic`
   control's verdict must come from `check` (code-computed) or an
   attributed `human_override` — an agent-sourced verdict on a
   deterministic control is a hard failure.
2. **Evidence hash verification** (amendment 3): with --evidence-dir,
   every cited sha256 must exist in the bundle
   (<evidence-dir>/<sha256>.json) and re-hash to its filename via the
   canonicalizer; a citation to evidence that does not exist or does
   not match is a hard failure. Inline excerpts are additionally
   re-hashed when they carry the full canonical form.
3. **Coverage honesty** (FP hard requirement 3): the coverage block is
   recomputed from the results and must match exactly — and no key
   resembling a blended compliance percentage may appear.
4. **Framework preconditions**: PCI results require a declared
   cde_boundary; GDPR results require personal_data_stores; SOC 2
   results require trust_service_categories AND the point-in-time
   caveat string on the framework entry.

Exit 0 = gate passed; 1 = failures printed with paths.

Usage:
    python3 validate_compliance_assessment.py <assessment.json>
        [--evidence-dir <dir>] [--schema <path>]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

from traust_contracts.paths import schema_path

from traust.paths import skill_dir

SCHEMA = schema_path("compliance-assessment")

_SPEC = importlib.util.spec_from_file_location(
    "compliance_assert", skill_dir("compliance-check") / "scripts" / "compliance_assert.py"
)
ca = importlib.util.module_from_spec(_SPEC)
sys.modules["compliance_assert"] = ca
_SPEC.loader.exec_module(ca)

FORBIDDEN_SUMMARY_KEYS = (
    "compliance_pct",
    "percent_compliant",
    "compliance_score",
    "overall_compliance",
)


def schema_failures(doc: dict, schema_path: Path) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        import jsonschema
    except ImportError:
        return [
            "jsonschema not installed — cannot run the schema gate "
            "(install it; the gate is not optional)"
        ]
    v = jsonschema.Draft7Validator(schema)
    return [
        f"schema: {e.json_path}: {e.message[:160]}"
        for e in sorted(v.iter_errors(doc), key=lambda e: e.json_path)
    ]


def verdict_source_failures(doc: dict) -> list[str]:
    out = []
    for i, r in enumerate(doc.get("results") or []):
        ref = f"results[{i}] {r.get('framework')}:{r.get('control_id')}"
        if (
            r.get("classification") == "deterministic"
            and r.get("verdict") in ("satisfied", "not_satisfied")
            and r.get("verdict_source") == "agent"
        ):
            out.append(
                f"{ref}: deterministic control with agent-sourced "
                "verdict — verdicts come from the check or an "
                "attributed override (amendment 1)"
            )
        if r.get("classification") == "organizational" and r.get("verdict") in (
            "satisfied",
            "not_satisfied",
        ):
            out.append(
                f"{ref}: organizational control carries a "
                "satisfied/not_satisfied verdict — out of "
                "technical scope, must be not_assessed"
            )
    return out


def evidence_failures(doc: dict, evidence_dir: Path | None) -> list[str]:
    out = []
    for i, r in enumerate(doc.get("results") or []):
        ref = f"results[{i}] {r.get('framework')}:{r.get('control_id')}"
        for j, ev in enumerate(r.get("evidence") or []):
            sha = ev.get("sha256", "")
            if evidence_dir is not None:
                p = evidence_dir / f"{sha}.json"
                if not p.is_file():
                    out.append(
                        f"{ref}: evidence[{j}] cites {sha[:12]}… but the bundle has no such item"
                    )
                    continue
                try:
                    obj = json.loads(p.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    out.append(f"{ref}: evidence[{j}] bundle item is not JSON")
                    continue
                if ca.evidence_id(obj) != sha:
                    out.append(
                        f"{ref}: evidence[{j}] content does not "
                        f"hash to its id ({sha[:12]}…) — "
                        "tampered or non-canonical"
                    )
    return out


def coverage_failures(doc: dict) -> list[str]:
    out = []
    recomputed: dict[str, Counter] = {}
    for r in doc.get("results") or []:
        c = recomputed.setdefault(r.get("framework", "?"), Counter())
        c["total_in_scope"] += 1
        c[r.get("classification", "?")] += 1
        c[r.get("verdict", "?")] += 1
    declared = doc.get("coverage") or {}
    for fw, counts in sorted(recomputed.items()):
        d = declared.get(fw)
        if d is None:
            out.append(f"coverage: framework '{fw}' has results but no coverage block")
            continue
        for k in (
            "total_in_scope",
            "deterministic",
            "evidence_review",
            "organizational",
            "satisfied",
            "not_satisfied",
            "not_applicable",
            "not_assessed",
        ):
            if d.get(k, 0) != counts.get(k, 0):
                out.append(
                    f"coverage[{fw}].{k}: declared {d.get(k, 0)} "
                    f"but results contain {counts.get(k, 0)}"
                )
    for fw in declared:
        if fw not in recomputed:
            out.append(f"coverage: block for '{fw}' but no results")
    text = json.dumps(doc)
    for k in FORBIDDEN_SUMMARY_KEYS:
        if f'"{k}"' in text:
            out.append(
                f"blended compliance percentage key '{k}' — "
                "coverage honesty forbids a single compliance "
                "number (FP hard requirement 3)"
            )
    return out


def n_pass_failures(doc: dict) -> list[str]:
    """N-pass agreement rule (Phase 4, determinism amendment 5): an
    agent-sourced verdict on an evidence_review control exists only
    with a recorded agreement across >=2 passes; disagreement can never
    carry a satisfied/not_satisfied verdict."""
    out = []
    for i, r in enumerate(doc.get("results") or []):
        if r.get("verdict_source") != "agent" or r.get("verdict") not in (
            "satisfied",
            "not_satisfied",
        ):
            continue
        ref = f"results[{i}] {r.get('framework')}:{r.get('control_id')}"
        npa = r.get("n_pass_agreement")
        if not npa:
            out.append(
                f"{ref}: agent-sourced verdict without "
                "n_pass_agreement — judge at least twice and "
                "record it (amendment 5)"
            )
        elif not npa.get("agreed") or npa.get("passes", 0) < 2:
            out.append(
                f"{ref}: n_pass_agreement shows disagreement or "
                "<2 passes — the verdict must be not_assessed "
                "(unstable judgment, human review)"
            )
    return out


NON_CITABLE_ADR_STATUSES = ("superseded", "deprecated", "archived", "rejected")


def adr_citation_failures(doc: dict, adr_index: dict | None) -> list[str]:
    """Superseded-decision rule (compliance Phase 2c): a satisfied
    verdict may not cite a decision the index marks non-citable, nor a
    decision the index does not know."""
    if adr_index is None:
        return []
    status = {}
    for reg in adr_index.get("registers") or []:
        for d in reg.get("decisions") or []:
            status[f"{reg['name']}/{d['id']}"] = d.get("status", "unknown")
    out = []
    for i, r in enumerate(doc.get("results") or []):
        if r.get("verdict") != "satisfied":
            continue
        ref = f"results[{i}] {r.get('framework')}:{r.get('control_id')}"
        for j, ev in enumerate(r.get("evidence") or []):
            loc = ev.get("locator", "")
            if not loc.startswith("adr:"):
                continue
            key = loc[len("adr:") :]
            st = status.get(key)
            if st is None:
                out.append(
                    f"{ref}: evidence[{j}] cites unknown "
                    f"decision '{key}' — not in the ADR index "
                    "(stale index or bad citation)"
                )
            elif st in NON_CITABLE_ADR_STATUSES:
                out.append(
                    f"{ref}: evidence[{j}] cites {st} decision "
                    f"'{key}' — non-citable for satisfied "
                    "verdicts (superseded-ADR rule)"
                )
    return out


def precondition_failures(doc: dict) -> list[str]:
    out = []
    target = (doc.get("metadata") or {}).get("target") or {}
    fw_entries = {f.get("id"): f for f in (doc.get("metadata") or {}).get("frameworks") or []}
    fws_with_results = {r.get("framework") for r in doc.get("results") or []}
    if "pci-dss-v4" in fws_with_results and not target.get("cde_boundary"):
        out.append(
            "pci-dss-v4 results without a declared cde_boundary — "
            "PCI scope is human input, never inferred"
        )
    if "gdpr-technical" in fws_with_results and not target.get("personal_data_stores"):
        out.append("gdpr-technical results without declared personal_data_stores")
    if "soc2-tsc" in fws_with_results:
        if not target.get("trust_service_categories"):
            out.append("soc2-tsc results without declared trust_service_categories")
        caveat = (fw_entries.get("soc2-tsc") or {}).get("caveat", "")
        if "point-in-time" not in caveat:
            out.append(
                "soc2-tsc framework entry missing the mandatory "
                "point-in-time vs Type 2 period caveat"
            )
    return out


def validate(
    doc: dict, evidence_dir: Path | None, schema_path: Path, adr_index: dict | None = None
) -> list[str]:
    failures = schema_failures(doc, schema_path)
    if failures:
        return failures  # structural failures first; rest may mislead
    failures += verdict_source_failures(doc)
    failures += n_pass_failures(doc)
    failures += evidence_failures(doc, evidence_dir)
    failures += coverage_failures(doc)
    failures += precondition_failures(doc)
    failures += adr_citation_failures(doc, adr_index)
    return failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("assessment", type=Path)
    ap.add_argument("--evidence-dir", type=Path, default=None)
    ap.add_argument("--schema", type=Path, default=SCHEMA)
    ap.add_argument(
        "--adr-index",
        type=Path,
        default=None,
        help="adr-index.json (index_adrs.py) — enables the superseded-decision citation rule",
    )
    args = ap.parse_args(argv)
    try:
        doc = json.loads(args.assessment.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read assessment: {e}", file=sys.stderr)
        return 1
    adr_index = None
    if args.adr_index:
        try:
            adr_index = json.loads(args.adr_index.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read adr index: {e}", file=sys.stderr)
            return 1
    failures = validate(doc, args.evidence_dir, args.schema, adr_index)
    if not failures:
        n = len(doc.get("results") or [])
        print(f"✓ compliance citation gate passed ({n} control results)")
        return 0
    print(f"✗ {len(failures)} gate failure(s):")
    for f in failures:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
