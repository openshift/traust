#!/usr/bin/env python3
"""Semantic precedent-card compiler (deep-fn-technique-plan Phase D / D6
semantic tier — PROTOTYPE).

A **semantic precedent card** is a confirmed finding generalized into a
MACHINE-EXECUTABLE enumeration recipe: a weakness shape, one of the
shipped deterministic enumerators, a filter predicate over that
enumerator's actual output fields, and the one question a judge answers
per matched row. The compile target is the "no prose checklists" rule
made mechanical (plan §2 D6 risk / §3 Phase D acceptance): a card is
VALID only if its predicate is expressible over the enumerator's real
output schema — a card that is only prose (a checklist, a pattern-to-
spot, a field the enumerator never emits) is **REJECTED at compile
time**, never shipped as a hint.

Shipped enumerators (schemas hardcoded from the emitting scripts):

config-matrix     harnessing/3-audit/secure-code-audit/scripts/expand_config_matrix.py —
rows = `triples[]`
                (key, effective_default, source.*, sink.*, class,
                judgement_required, weak_default)
route-guards      harnessing/3-audit/secure-code-audit/scripts/enumerate_route_guards.py —
rows = `routes[]`
                (family, method, pattern, handler.*, guards,
                scope_guards, registration.*, judgement_required,
                unguard_markers, asymmetry)
sanitizer-probes  harnessing/3-audit/secure-code-audit/scripts/probe_sanitizers.py —
rows = `candidates[]`
                (--list, default) or `probes[]` (--run; EXECUTES repo
                code — a card must declare
                `enumerator_options.run: true` to use run-only
                fields, audit-sandbox doctrine)
symbol-index      traust admin query-index --json — rows = `defs[]` or
                `refs[]`; a card must declare
                `enumerator_options.query: {mode, name}`

Like the syntactic sweep engine, this NEVER files findings and NEVER
routes externally: the output, `sweep-candidates-semantic.json`, is the
same generic-candidate shape `sweep_engine.py emit` writes (per-row
repo/url/file/line/location/excerpt/rule_id/severity_hint/test_path/
source_finding_provenance), so /triage ingests it unchanged — every
match is a CANDIDATE whose verdict belongs to triage.

CLI:
    python3 -m traust.cli.compile_precedent_cards --cards <cards.yaml>
        --validate-only
    python3 -m traust.cli.compile_precedent_cards --cards <cards.yaml>
        --repo <checkout> [--card ID] [--out FILE]
        [--artifact NAME=PATH ...]

--artifact NAME=PATH reuses a pre-generated enumerator artifact instead
of running the enumerator (fixture/test path; NAME is the enumerator
name). Exit 0 when every card compiled or was an *expected* reject
(`expect_reject: true` — the pinned reject example); 1 on an unexpected
rejection or bad input.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from traust.paths import HARNESS_ROOT, skill_dir

SCRIPTS = skill_dir("secure-code-audit") / "scripts"

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    yaml = None

# ---------------------------------------------------------------------------
# enumerator output schemas — hardcoded from the emitting scripts (v1).
# Field values are type tags for documentation; validation checks path
# membership and op sanity. `run_only` fields exist only in probe --run
# output and require the card to acknowledge execution.
# ---------------------------------------------------------------------------

CONFIG_MATRIX_FIELDS = {
    "key": "str",
    "effective_default": "str",
    "class": "str",
    "judgement_required": "bool",
    "weak_default": "bool",
    "source.system": "str",
    "source.path": "str",
    "source.line": "int",
    "sink.status": "str",
    "sink.path": "str",
    "sink.line": "int",
    "sink.expr": "str",
    "sink.service": "str",
    "sink.container": "str",
}

ROUTE_GUARDS_FIELDS = {
    "family": "str",
    "method": "str",
    "pattern": "str",
    "handler.expr": "str",
    "handler.path": "str",
    "handler.line": "int",
    "handler.resolved.path": "str",
    "handler.resolved.line": "int",
    "guards": "list",
    "scope_guards": "list",
    "unguard_markers": "list",
    "registration.path": "str",
    "registration.line": "int",
    "judgement_required": "bool",
    "asymmetry": "bool",
}

SANITIZER_DISCOVERY_FIELDS = {
    "function": "str",
    "path": "str",
    "line": "int",
    "arg": "str",
    "is_method": "bool",
}
SANITIZER_RUN_FIELDS = {
    "outcome": "str",
    "survived": "int",
    "errors": "int",
    "reason": "str",
    "transcript": "list",
}

SYMBOL_INDEX_FIELDS = {
    "defs": {"name": "str", "path": "str", "line": "int", "kind": "str", "language": "str"},
    "refs": {"path": "str", "line": "int", "is_def": "bool", "text": "str"},
}

ENUMERATORS = {
    "config-matrix": {
        "script": "expand_config_matrix.py",
        "artifact": "config-matrix",
        "rows_key": "triples",
        "fields": CONFIG_MATRIX_FIELDS,
    },
    "route-guards": {
        "script": "enumerate_route_guards.py",
        "artifact": "route-guard-matrix",
        "rows_key": "routes",
        "fields": ROUTE_GUARDS_FIELDS,
    },
    "sanitizer-probes": {
        "script": "probe_sanitizers.py",
        "artifact": "sanitizer-probes",
        # rows_key depends on mode — resolved in rows_of()
        "rows_key": None,
        "fields": SANITIZER_DISCOVERY_FIELDS,
        "run_fields": SANITIZER_RUN_FIELDS,
    },
    "symbol-index": {
        "module": "traust.cli.query_index",
        "artifact": None,  # query output has no artifact stamp
        "rows_key": None,  # defs / refs, per query mode
        "fields": None,  # mode-dependent, resolved per card
    },
}

# predicate ops. VALUE_FREE take no `value`; the rest require one.
VALUE_FREE_OPS = {"empty", "not_empty", "truthy", "falsy"}
VALUE_OPS = {"eq", "ne", "in", "not_in", "contains", "not_contains", "matches", "gte", "lte"}
ALL_OPS = VALUE_FREE_OPS | VALUE_OPS

SEVERITY_ENUM = {"critical", "high", "medium", "low", "info"}

# prose-checklist smuggling: fields whose presence marks a card as a
# checklist wearing a card's clothes — rejected, not ignored
PROSE_FIELDS = {
    "checklist",
    "instructions",
    "steps",
    "prompt",
    "review_guidance",
    "things_to_look_for",
}

REQUIRED_FIELDS = (
    "id",
    "source_findings",
    "weakness_shape",
    "enumerator",
    "judge_question",
    "expected_fp_sources",
)

PURPOSE = (
    "TRIAGE INPUT MATERIAL — semantic precedent-card sweep: confirmed "
    "findings generalized into machine-executable enumeration recipes "
    "(deep-fn-technique-plan Phase D / D6 semantic tier). Every entry is "
    "a CANDIDATE, not a finding: the compiler never files findings and "
    "never routes externally — feed this file to /triage for "
    "adjudication. Each candidate carries the card's judge_question: the "
    "one question the verifier answers for that row."
)


# ---------------------------------------------------------------------------
# card validation — the REJECT gate
# ---------------------------------------------------------------------------


def _field_set_for(card: dict) -> tuple[dict | None, list[str]]:
    """Resolve the enumerator field schema this card's predicate is
    checked against. Returns (fields|None, errors)."""
    name = card.get("enumerator")
    spec = ENUMERATORS.get(name)
    if spec is None:
        return None, [
            f"unknown_enumerator: {name!r} is not a shipped "
            f"deterministic enumerator "
            f"({', '.join(sorted(ENUMERATORS))})"
        ]
    opts = card.get("enumerator_options") or {}
    if name == "sanitizer-probes":
        fields = dict(SANITIZER_DISCOVERY_FIELDS)
        if opts.get("run") is True:
            fields.update(SANITIZER_RUN_FIELDS)
        return fields, []
    if name == "symbol-index":
        query = opts.get("query") or {}
        mode = query.get("mode")
        if mode not in SYMBOL_INDEX_FIELDS or not query.get("name"):
            return None, [
                "symbol_index_query_missing: symbol-index cards must "
                "declare enumerator_options.query = {mode: defs|refs, "
                "name: <symbol>}"
            ]
        return SYMBOL_INDEX_FIELDS[mode], []
    return spec["fields"], []


def _validate_predicate(node, fields: dict, path: str = "predicate") -> list[str]:
    """Recursive predicate-AST validation against a field schema."""
    errors: list[str] = []
    if not isinstance(node, dict) or not node:
        return [f"{path}: predicate node must be a non-empty mapping"]
    combos = [k for k in ("all", "any", "not") if k in node]
    if combos:
        if len(node) != 1:
            return [f"{path}: combinator node must contain exactly one of all/any/not"]
        key = combos[0]
        if key == "not":
            return _validate_predicate(node["not"], fields, f"{path}.not")
        kids = node[key]
        if not isinstance(kids, list) or not kids:
            return [f"{path}.{key}: must be a non-empty list"]
        for i, kid in enumerate(kids):
            errors += _validate_predicate(kid, fields, f"{path}.{key}[{i}]")
        return errors
    # leaf
    field = node.get("field")
    op = node.get("op")
    if not isinstance(field, str) or not field:
        errors.append(f"{path}: leaf needs a `field`")
    elif field not in fields:
        errors.append(
            f"{path}: field {field!r} is not in the enumerator's output "
            f"schema — a predicate over fields the enumerator never "
            f"emits is prose, not a recipe (known fields: "
            f"{', '.join(sorted(fields))})"
        )
    if op not in ALL_OPS:
        errors.append(f"{path}: unknown op {op!r} (ops: {', '.join(sorted(ALL_OPS))})")
    elif op in VALUE_OPS and "value" not in node:
        errors.append(f"{path}: op {op!r} requires a `value`")
    elif op in VALUE_FREE_OPS and "value" in node:
        errors.append(f"{path}: op {op!r} takes no `value`")
    if op == "matches" and "value" in node:
        try:
            re.compile(str(node["value"]))
        except re.error as e:
            errors.append(f"{path}: bad regex for `matches`: {e}")
    extra = set(node) - {"field", "op", "value"}
    if extra:
        errors.append(f"{path}: unknown leaf keys {sorted(extra)}")
    return errors


def validate_card(card: dict) -> list[str]:
    """Full card validation. Empty list = VALID; otherwise the reasons
    the card is REJECTED (all recorded, never just the first)."""
    errors: list[str] = []
    if not isinstance(card, dict):
        return ["card must be a mapping"]
    for f in REQUIRED_FIELDS:
        if not card.get(f):
            errors.append(f"missing_required: `{f}`")
    prose = PROSE_FIELDS & set(card)
    if prose:
        errors.append(
            f"prose_checklist_fields: {sorted(prose)} — cards compile to "
            "worklist generators, never to review prose (plan Phase D: "
            "zero cards shipped as prose checklists)"
        )
    sf = card.get("source_findings")
    if sf is not None and (
        not isinstance(sf, list)
        or not all(isinstance(s, dict) and (s.get("finding_id") or s.get("id")) for s in sf)
    ):
        errors.append(
            "source_findings: must be a list of mappings each "
            "carrying a finding_id/id (provenance is part of "
            "the recipe)"
        )
    sev = card.get("severity_hint")
    if sev is not None and sev not in SEVERITY_ENUM:
        errors.append(f"severity_hint: {sev!r} not in {sorted(SEVERITY_ENUM)}")

    fields, ferrs = _field_set_for(card)
    errors += ferrs
    pred = card.get("predicate")
    if not pred:
        errors.append(
            "no_predicate: card has no filter predicate over an "
            "enumerator's output — that is a prose checklist, REJECTED "
            "(the D6 'compiles to worklists or is rejected' rule)"
        )
    elif fields is not None:
        errors += _validate_predicate(pred, fields)
    return errors


# ---------------------------------------------------------------------------
# predicate application
# ---------------------------------------------------------------------------


def _get(row: dict, dotted: str):
    cur = row
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _leaf(node: dict, row: dict) -> bool:
    val = _get(row, node["field"])
    op = node["op"]
    want = node.get("value")
    if op == "eq":
        return val == want
    if op == "ne":
        return val != want
    if op == "in":
        return val in (want or [])
    if op == "not_in":
        return val not in (want or [])
    if op == "contains":
        if isinstance(val, (list, tuple, set)):
            return want in val
        return str(want) in str(val or "")
    if op == "not_contains":
        if isinstance(val, (list, tuple, set)):
            return want not in val
        return str(want) not in str(val or "")
    if op == "matches":
        return bool(re.search(str(want), str(val or ""), re.IGNORECASE))
    if op == "gte":
        try:
            return val is not None and float(val) >= float(want)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return val is not None and float(val) <= float(want)
        except (TypeError, ValueError):
            return False
    if op == "empty":
        return val is None or val == "" or val == [] or val == {}
    if op == "not_empty":
        return not (val is None or val == "" or val == [] or val == {})
    if op == "truthy":
        return bool(val)
    if op == "falsy":
        return not bool(val)
    raise ValueError(f"unknown op {op!r}")  # pragma: no cover - gated


def apply_predicate(node: dict, row: dict) -> bool:
    if "all" in node:
        return all(apply_predicate(k, row) for k in node["all"])
    if "any" in node:
        return any(apply_predicate(k, row) for k in node["any"])
    if "not" in node:
        return not apply_predicate(node["not"], row)
    return _leaf(node, row)


# ---------------------------------------------------------------------------
# enumerator execution + row extraction
# ---------------------------------------------------------------------------


def run_enumerator(name: str, options: dict, repo: Path, work: Path) -> dict:
    """Run one enumerator on a checkout, return its parsed artifact.
    All enumerators are the shipped deterministic scripts; nothing here
    interprets code."""
    spec = ENUMERATORS[name]
    if name == "symbol-index":
        q = options["query"]
        flag = "--defs" if q["mode"] == "defs" else "--refs"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                spec["module"],
                "--repo",
                str(repo),
                flag,
                str(q["name"]),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{name}: {proc.stderr[-400:]}")
        return json.loads(proc.stdout)
    script = SCRIPTS / spec["script"]
    out = work / f"{name}-{abs(hash(json.dumps(options, sort_keys=True)))}.json"
    cmd = [sys.executable, str(script), str(repo), "--out", str(out)]
    if name == "sanitizer-probes":
        cmd.append("--run" if options.get("run") is True else "--list")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    if proc.returncode != 0 or not out.is_file():
        raise RuntimeError(f"{name}: {proc.stderr[-400:]}")
    return json.loads(out.read_text(encoding="utf-8"))


def rows_of(name: str, options: dict, artifact: dict) -> list[dict]:
    if name == "sanitizer-probes":
        key = "probes" if options.get("run") is True else "candidates"
        return artifact.get(key) or []
    if name == "symbol-index":
        mode = (options.get("query") or {}).get("mode")
        return artifact.get(mode) or []
    return artifact.get(ENUMERATORS[name]["rows_key"]) or []


# ---------------------------------------------------------------------------
# candidate emission — the sweep-candidates generic shape
# ---------------------------------------------------------------------------

TEST_PATH_RX = re.compile(r"(^|/)(tests?|testdata|fixtures?|mocks?|examples?)(/|$)|_test\.")


def _loc_excerpt(name: str, options: dict, row: dict) -> tuple[str | None, int | None, str]:
    if name == "config-matrix":
        src = row.get("source") or {}
        sink = row.get("sink") or {}
        return (
            src.get("path"),
            src.get("line"),
            (
                f"{row.get('key')}={row.get('effective_default')} "
                f"[system={src.get('system')} class={row.get('class')} "
                f"sink={sink.get('status', 'unresolved')}]"
            ),
        )
    if name == "route-guards":
        reg = row.get("registration") or {}
        h = row.get("handler") or {}
        return (
            reg.get("path"),
            reg.get("line"),
            (
                f"{row.get('method')} {row.get('pattern')} -> "
                f"{h.get('expr')} [guards={row.get('guards')} "
                f"scope_guards={row.get('scope_guards')} "
                f"unguards={row.get('unguard_markers', [])}"
                f"{' ASYMMETRY' if row.get('asymmetry') else ''}]"
            ),
        )
    if name == "sanitizer-probes":
        return (
            row.get("path"),
            row.get("line"),
            (
                f"{row.get('function')}({row.get('arg')}) "
                f"outcome={row.get('outcome', 'discovered')} "
                f"survived={row.get('survived', 'n/a')}"
            ),
        )
    # symbol-index
    mode = (options.get("query") or {}).get("mode")
    if mode == "defs":
        return (
            row.get("path"),
            row.get("line"),
            (f"{row.get('kind')} {row.get('name')} ({row.get('language')})"),
        )
    return row.get("path"), row.get("line"), str(row.get("text", ""))


def candidate_of(card: dict, row: dict, repo_slug: str, repo_url: str | None) -> dict:
    name = card["enumerator"]
    options = card.get("enumerator_options") or {}
    file, line, excerpt = _loc_excerpt(name, options, row)
    prov = [str(s.get("finding_id") or s.get("id")) for s in card.get("source_findings", [])]
    return {
        # --- sweep_engine.py emit generic-candidate fields (unchanged
        # keys so /triage ingests this file like any sweep batch) ---
        "repo": repo_slug,
        "url": repo_url,
        "file": file,
        "line": line,
        "end_line": line,
        "location": f"{file}:{line}" if line else str(file),
        "excerpt": excerpt[:400],
        "rule_id": card["id"],
        "severity_hint": card.get("severity_hint", "medium"),
        "test_path": bool(file and TEST_PATH_RX.search(str(file))),
        "source_finding_provenance": prov,
        # --- semantic-tier extras (ride into the verifier prompt) ---
        "origin": "semantic-sweep",
        "card_id": card["id"],
        "enumerator": name,
        "judge_question": card["judge_question"],
        "expected_fp_sources": card.get("expected_fp_sources", []),
    }


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------


def harness_version() -> str:
    try:
        return (HARNESS_ROOT / "VERSION").read_text().strip()
    except OSError:
        return "unknown"


def load_cards(path: Path) -> list[dict]:
    if yaml is None:
        sys.exit("compile_precedent_cards: PyYAML required to load cards")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cards = doc.get("cards")
    if not isinstance(cards, list):
        sys.exit(f"{path}: expected a top-level `cards:` list")
    return cards


def partition_cards(cards: list[dict]) -> tuple[list, list]:
    """(valid, rejected) — rejected entries carry all reasons."""
    valid, rejected = [], []
    for card in cards:
        errors = validate_card(card)
        if errors:
            rejected.append(
                {
                    "id": (card.get("id") if isinstance(card, dict) else None) or "(unnamed)",
                    "expect_reject": bool(isinstance(card, dict) and card.get("expect_reject")),
                    "reasons": errors,
                }
            )
        else:
            valid.append(card)
    return valid, rejected


def compile_from_artifacts(
    cards: list[dict],
    artifacts: dict,
    repo_slug: str,
    repo_url: str | None,
    cards_file: str = "(inline)",
) -> dict:
    """Apply already-validated cards to pre-generated enumerator
    artifacts. `artifacts` maps enumerator name (or, for symbol-index,
    'symbol-index:<card id>') -> parsed artifact dict."""
    candidates, card_stats = [], []
    for card in cards:
        name = card["enumerator"]
        options = card.get("enumerator_options") or {}
        art = artifacts.get(f"{name}:{card['id']}") or artifacts.get(name)
        if art is None:
            card_stats.append(
                {
                    "id": card["id"],
                    "enumerator": name,
                    "status": "no_artifact",
                    "rows_enumerated": 0,
                    "matched": 0,
                }
            )
            continue
        rows = rows_of(name, options, art)
        matched = [r for r in rows if apply_predicate(card["predicate"], r)]
        for row in matched:
            candidates.append(candidate_of(card, row, repo_slug, repo_url))
        card_stats.append(
            {
                "id": card["id"],
                "enumerator": name,
                "status": "compiled",
                "rows_enumerated": len(rows),
                "matched": len(matched),
            }
        )
    return {
        "artifact": "sweep-candidates",
        "tier": "semantic",
        "purpose": PURPOSE,
        "generated": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": harness_version(),
        "rule_id": "precedent-cards-semantic",
        "cards_file": cards_file,
        "repo": repo_slug,
        "repo_url": repo_url,
        "cards": card_stats,
        "rejected_cards": [],
        "repos_swept": 1,
        "repos_with_hits": 1 if candidates else 0,
        "repo_errors": 0,
        "candidates": candidates,
    }


def compile_repo(cards: list[dict], repo: Path, cards_file: str) -> dict:
    """Run each valid card's enumerator on the checkout (cached per
    (enumerator, options)) and apply predicates."""
    artifacts: dict = {}
    cache: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="precedent-cards-") as tmp:
        work = Path(tmp)
        for card in cards:
            name = card["enumerator"]
            options = card.get("enumerator_options") or {}
            key = f"{name}|{json.dumps(options, sort_keys=True)}"
            if key not in cache:
                cache[key] = run_enumerator(name, options, repo, work)
            artifacts[f"{name}:{card['id']}"] = cache[key]
    return compile_from_artifacts(cards, artifacts, repo.name, f"dir:{repo}", cards_file)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--cards", type=Path, required=True, help="YAML file with a top-level cards: list"
    )
    ap.add_argument(
        "--validate-only",
        action="store_true",
        help="validate every card against the enumerator schemas; run nothing",
    )
    ap.add_argument(
        "--repo", type=Path, default=None, help="local checkout to compile the cards against"
    )
    ap.add_argument("--card", default=None, help="compile only this card id")
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output file (default sweep-candidates-semantic.json)",
    )
    ap.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="reuse a pre-generated enumerator artifact instead of running the enumerator",
    )
    args = ap.parse_args(argv)

    if not args.cards.is_file():
        print(f"cards file not found: {args.cards}", file=sys.stderr)
        return 1
    cards = load_cards(args.cards)
    if args.card:
        cards = [c for c in cards if isinstance(c, dict) and c.get("id") == args.card]
        if not cards:
            print(f"no card with id {args.card}", file=sys.stderr)
            return 1
    valid, rejected = partition_cards(cards)

    unexpected = [r for r in rejected if not r["expect_reject"]]
    for r in rejected:
        tag = "REJECTED (expected — pinned reject example)" if r["expect_reject"] else "REJECTED"
        print(f"{r['id']}: {tag}")
        for reason in r["reasons"]:
            print(f"  - {reason}")
    for c in valid:
        print(f"{c['id']}: VALID (enumerator={c['enumerator']})")

    if args.validate_only:
        print(
            f"\nvalidate: {len(valid)} valid, {len(rejected)} rejected "
            f"({len(unexpected)} unexpected)"
        )
        return 1 if unexpected else 0

    if args.repo is None and not args.artifact:
        print("compile: need --repo (or --artifact NAME=PATH, or --validate-only)", file=sys.stderr)
        return 1

    if args.artifact:
        artifacts = {}
        for spec in args.artifact:
            name, _, path = spec.partition("=")
            artifacts[name] = json.loads(Path(path).read_text(encoding="utf-8"))
        slug = args.repo.name if args.repo else "artifact-input"
        report = compile_from_artifacts(
            valid,
            artifacts,
            slug,
            f"dir:{args.repo.resolve()}" if args.repo else None,
            str(args.cards),
        )
    else:
        repo = args.repo.resolve()
        if not repo.is_dir():
            print(f"not a directory: {repo}", file=sys.stderr)
            return 1
        report = compile_repo(valid, repo, str(args.cards))

    report["rejected_cards"] = rejected
    out = args.out or Path("sweep-candidates-semantic.json")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"\ncompile: {len(report['candidates'])} candidate(s) from "
        f"{len(valid)} card(s) ({len(rejected)} rejected) -> {out} "
        "(sweep-candidates shape — /triage ingests it unchanged)"
    )
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
