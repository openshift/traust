#!/usr/bin/env python3
"""Deterministic assertion engine + canonical evidence for compliance.

Determinism amendments 1–3 live here:

1. **Code-computed verdicts.** `evaluate_check()` returns the verdict for
   a `deterministic` control — satisfied / not_satisfied /
   not_applicable / not_assessed(reason) — computed purely from the
   assertion record and the snapshot. No LLM in the loop; the agent may
   annotate the result, never change it.
2. **Checks are data.** The engine evaluates declarative assertion
   records ({path, operator, expected}, plus applies_when /
   parameter refs / a declared sampling rule) defined in the
   compliance-mapping registry and gated by
   contracts/schemas/compliance-mapping.schema.json. There is exactly one engine;
   per-check code does not exist.
3. **Canonical, content-addressed evidence.** `canonicalize()` sorts
   keys, strips volatile fields, and renders compact JSON;
   `evidence_id()` is its sha256. Two runs over the same environment
   produce byte-identical evidence, and every citation carries a hash
   the validator can verify.

Path semantics: dot-separated into dicts, `[*]` fans out over lists.
A fan-out assertion must hold for EVERY selected value — sampling only
via an explicit `sorted_first_N` rule (amendment 7). A path that
selects nothing: `exists`/`absent` decide; any other operator verdicts
not_assessed("path selected no values") rather than vacuously passing.

Library-first (imported by the Phase 3 skill runner and the validator);
CLI for fixture calibration:
    python3 compliance_assert.py --check <id> --registry <yaml> \
        --snapshot <json> [--org-parameters <yaml>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# fields stripped during canonicalization — volatile by construction,
# never load-bearing for a control verdict
VOLATILE_FIELDS = frozenset(
    (
        "resourceVersion",
        "uid",
        "creationTimestamp",
        "generation",
        "managedFields",
        "observedGeneration",
        "generated_at",
        "retrieved_at",
        "request_id",
        "etag",
    )
)


# --------------------------------------------------------------------------
# canonical evidence (amendment 3)
# --------------------------------------------------------------------------


def canonicalize(obj):
    """Stable canonical form: volatile fields out, keys sorted."""
    if isinstance(obj, dict):
        return {k: canonicalize(v) for k, v in sorted(obj.items()) if k not in VOLATILE_FIELDS}
    if isinstance(obj, list):
        return [canonicalize(v) for v in obj]
    return obj


def canonical_json(obj) -> str:
    return json.dumps(canonicalize(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def evidence_id(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# path selection
# --------------------------------------------------------------------------

_SEG_RX = re.compile(r"^([^\[\]]*)((?:\[\*\])*)$")


def select(snapshot, path: str) -> list:
    """Resolve a dot/[*] path to the list of selected values."""
    steps: list[tuple[str, int]] = []  # (key or "", fan-out depth)
    for seg in path.split("."):
        m = _SEG_RX.match(seg)
        if not m:
            return []
        key, stars = m.group(1), m.group(2).count("[*]")
        steps.append((key, stars))
    current = [snapshot]
    for key, stars in steps:
        if key:
            current = [node[key] for node in current if isinstance(node, dict) and key in node]
        for _ in range(stars):
            nxt = []
            for node in current:
                if isinstance(node, list):
                    nxt.extend(node)
            current = nxt
    return current


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------


def _cmp_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _holds(value, operator: str, expected) -> bool | None:
    """True/False, or None when the comparison is impossible."""
    if operator == "equals":
        return value == expected
    if operator == "not_equals":
        return value != expected
    if operator == "contains":
        try:
            return expected in value
        except TypeError:
            return None
    if operator == "not_contains":
        try:
            return expected not in value
        except TypeError:
            return None
    if operator == "regex":
        return re.search(str(expected), str(value)) is not None if value is not None else None
    if operator == "not_regex":
        return re.search(str(expected), str(value)) is None if value is not None else None
    if operator == "gte":
        a, b = _cmp_num(value), _cmp_num(expected)
        return None if a is None or b is None else a >= b
    if operator == "lte":
        a, b = _cmp_num(value), _cmp_num(expected)
        return None if a is None or b is None else a <= b
    if operator == "in":
        return value in (expected or [])
    if operator == "not_in":
        return value not in (expected or [])
    return None


def resolve_expected(expected, org_parameters: dict | None):
    """'param:<id>' indirection — undeclared parameter is a signal, not
    a default (amendment 4)."""
    if isinstance(expected, str) and expected.startswith("param:"):
        pid = expected[len("param:") :]
        params = (org_parameters or {}).get("parameters") or {}
        if pid not in params:
            return None, f"parameter undeclared: {pid}"
        return params[pid]["value"], None
    return expected, None


def eval_assertion(
    snapshot, assertion: dict, org_parameters: dict | None = None, sampling: str | None = None
) -> tuple[str, list, str]:
    """-> (outcome 'pass'|'fail'|'not_assessed', selected values, reason)."""
    path, op = assertion["path"], assertion["operator"]
    expected, perr = resolve_expected(assertion.get("expected"), org_parameters)
    if perr:
        return "not_assessed", [], perr
    values = select(snapshot, path)
    if op == "exists":
        return ("pass" if values else "fail"), values, ""
    if op == "absent":
        return ("fail" if values else "pass"), values, ""
    if not values:
        return "not_assessed", [], f"path selected no values: {path}"
    if sampling:
        n = int(sampling.rsplit("_", 1)[1])
        values = sorted(values, key=canonical_json)[:n]
    for v in values:
        h = _holds(v, op, expected)
        if h is None:
            return "not_assessed", values, (f"operator {op} not applicable to selected value type")
        if not h:
            return "fail", values, ""
    return "pass", values, ""


def evaluate_check(check: dict, snapshot: dict, org_parameters: dict | None = None) -> dict:
    """Code-computed verdict for one registry check (amendment 1)."""
    applies = check.get("applies_when")
    if applies:
        outcome, _, reason = eval_assertion(snapshot, applies, org_parameters)
        if outcome == "not_assessed":
            return {
                "check_id": check["id"],
                "verdict": "not_assessed",
                "reason": f"applicability undeterminable: {reason}",
                "evidence": [],
            }
        if outcome == "fail":
            return {
                "check_id": check["id"],
                "verdict": "not_applicable",
                "reason": "declared applicability condition not met",
                "evidence": [],
            }
    outcome, values, reason = eval_assertion(
        snapshot, check["assertion"], org_parameters, sampling=check.get("sampling")
    )
    if outcome == "not_assessed":
        return {
            "check_id": check["id"],
            "verdict": "not_assessed",
            "reason": reason,
            "evidence": [],
        }
    path = check["assertion"]["path"]
    if outcome == "fail" and values:
        # cite the VIOLATING values — and where the path addresses a
        # field of parent objects, cite the parent objects themselves
        # (a resource with its id beats a bare `false` as evidence)
        exp, _ = resolve_expected(check["assertion"].get("expected"), org_parameters)
        op = check["assertion"]["operator"]
        if op not in ("exists", "absent"):
            m = re.match(r"^(.+)\.([A-Za-z0-9_-]+)$", path)
            parents = select(snapshot, m.group(1)) if m else []
            violating_parents = (
                [
                    p
                    for p in parents
                    if isinstance(p, dict)
                    and m.group(2) in p
                    # mirror select(): objects without the key were never
                    # part of the assertion and are not violations
                    and _holds(p[m.group(2)], op, exp) is False
                ]
                if m
                else []
            )
            if violating_parents:
                values = violating_parents
                path = m.group(1)
            else:
                violating = [v for v in values if _holds(v, op, exp) is False]
                if violating:
                    values = violating
    if not values:
        # satisfied-by-absence (or failed `exists`): the evidence is the
        # scanned parent scope, proving the collector ran and the
        # asserted key/selection is genuinely absent — an absence claim
        # is never evidence-free.
        parent = re.sub(r"(\[\*\])+$", "", path)
        parent = parent.rsplit(".", 1)[0] if "." in parent else ""
        values = select(snapshot, parent) if parent else [snapshot]
        path = parent or "(snapshot root)"
    evidence = [
        {
            "sha256": evidence_id(v),
            "kind": "inventory_snapshot_excerpt",
            "locator": f"{check['collector']}:{path}",
            "excerpt": canonical_json(v)[:2000],
            "_value": v,
        }  # bundle material — the
        for v in values[:10]
    ]  # runner strips this key
    return {
        "check_id": check["id"],
        "verdict": "satisfied" if outcome == "pass" else "not_satisfied",
        "evidence": evidence,
    }


# --------------------------------------------------------------------------
# CLI — fixture calibration entry point
# --------------------------------------------------------------------------


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", required=True)
    ap.add_argument("--registry", required=True, type=Path)
    ap.add_argument("--snapshot", required=True, type=Path)
    ap.add_argument("--org-parameters", type=Path, default=None)
    args = ap.parse_args(argv)
    if yaml is None:
        sys.exit("PyYAML required")
    registry = yaml.safe_load(args.registry.read_text(encoding="utf-8"))
    check = next((c for c in registry.get("checks", []) if c["id"] == args.check), None)
    if check is None:
        sys.exit(f"check '{args.check}' not in registry")
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    params = (
        yaml.safe_load(args.org_parameters.read_text(encoding="utf-8"))
        if args.org_parameters
        else None
    )
    result = evaluate_check(check, snapshot, params)
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] in ("satisfied", "not_applicable") else 1


if __name__ == "__main__":
    sys.exit(main())
