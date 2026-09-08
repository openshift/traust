#!/usr/bin/env python3
# Migration utility archived 2026-08-11
"""Backfill explicit ref provenance into legacy audit reports.

(branch-awareness Phase 0): new reports declare the checked-out
ref in `metadata.ref` + `metadata.ref_kind`; the ~18k pre-0.122.0 reports
carry the ref only implicitly, in the report/directory slug
(`__release-X.Y` / `__openshift-X.Y`). This tool makes that implicit ref
explicit, deriving it from the SAME identity rules corpus.py applies
(split_ref over the report base, then over the repo directory name) so
the declared value can never disagree with what the resolver already
computes today. Reports whose slug carries no ref (HEAD audits) are left
untouched — the default-branch NAME is not recorded anywhere locally and
guessing one would fabricate provenance.

Safety properties:

- DRY-RUN BY DEFAULT. Nothing is written without --apply.
- Idempotent: a report that already declares `metadata.ref` or
  `metadata.ref_kind` is never modified; a second --apply run is a no-op.
- Symlinked reports (dedup aliases) are never touched — only the
  canonical file is rewritten, exactly once.
- Every touched report is re-validated against its schema
  (report.schema.json / cloud-config-audit.schema.json) BEFORE the file
  is replaced; a validation failure skips the write and is reported.

This tool ships dormant: running --apply against the committed
analysis-results corpus is a separate, explicitly-batched decision
(thousands of artifact edits; per-product staging, never `git add -A`).

CLI:
    python3 -m traust.cli.backfill_report_refs --results-root PATH [--apply]
    (repeat --results-root for multiple trees, e.g. findings/ and
    oss-findings/)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
from referencing import Registry, Resource
from traust_contracts.paths import schema_dir
from traust_engine.corpus import resolver as corpus

SCHEMA_DIR = schema_dir()

# (json suffix, schema file) — the same report kinds corpus.py discovers.
REPORT_SCHEMAS = (
    (corpus.AUDIT_JSON_SUFFIX, "report.schema.json"),
    (corpus.CLOUD_JSON_SUFFIX, "cloud-config-audit.schema.json"),
)


def _build_registry() -> Registry:
    reg = Registry()
    for sf in SCHEMA_DIR.glob("*.schema.json"):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        reg = reg.with_resource(uri=doc.get("$id", sf.name), resource=Resource.from_contents(doc))
    return reg


def _validators() -> dict[str, jsonschema.protocols.Validator]:
    reg = _build_registry()
    out = {}
    for suffix, schema_file in REPORT_SCHEMAS:
        schema = json.loads((SCHEMA_DIR / schema_file).read_text(encoding="utf-8"))
        cls = jsonschema.validators.validator_for(schema)
        out[suffix] = cls(schema, registry=reg, format_checker=jsonschema.FormatChecker())
    return out


@dataclass
class Stats:
    scanned: int = 0
    already_declared: int = 0
    no_slug_ref: int = 0  # HEAD reports — nothing to declare
    would_stamp: int = 0
    stamped: int = 0
    skipped_invalid: list[str] = field(default_factory=list)
    unparseable: list[str] = field(default_factory=list)
    per_product: dict[str, int] = field(default_factory=dict)


def derive_slug_ref(path: Path) -> str | None:
    """The ref corpus.py's legacy fallback computes for this report:
    split_ref over the report base, then over its directory name."""
    base = None
    for suffix, _ in REPORT_SCHEMAS:
        if path.name.endswith(suffix):
            base = path.name[: -len(suffix)]
            break
    if base is None:
        return None
    _, ref = corpus.split_ref(base)
    if ref is None:
        _, ref = corpus.split_ref(path.parent.name)
    return ref


def iter_reports(root: Path):
    """Walk one results root with corpus.py's skip rules; canonical
    (non-symlink) JSON reports only."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not corpus._skip_dir(d) and not (dp / d).is_symlink()]
        for fn in sorted(filenames):
            if not fn.endswith(tuple(s for s, _ in REPORT_SCHEMAS)):
                continue
            p = dp / fn
            if not p.is_symlink():
                yield p


def backfill_root(root: Path, apply: bool, validators: dict, stats: Stats) -> None:
    for path in iter_reports(root):
        stats.scanned += 1
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            md = report.get("metadata")
            if not isinstance(md, dict):
                raise ValueError("metadata is not an object")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            stats.unparseable.append(f"{path}: {exc}")
            continue

        if "ref" in md or "ref_kind" in md:
            stats.already_declared += 1
            continue

        ref = derive_slug_ref(path)
        if ref is None:
            stats.no_slug_ref += 1
            continue

        # slug refs are release/openshift branches by construction
        md["ref"] = ref
        md["ref_kind"] = "branch"

        suffix = next(s for s, _ in REPORT_SCHEMAS if path.name.endswith(s))
        errors = [e.message for e in validators[suffix].iter_errors(report)]
        if errors:
            stats.skipped_invalid.append(f"{path}: {errors[0]}")
            continue

        # product = path between the tree root and the repo dir, matching
        # corpus.py's ReportRecord.product ("." -> shallow, no product)
        product = str(path.parent.relative_to(root).parent)
        if product == ".":
            product = "(shallow)"
        stats.per_product[product] = stats.per_product.get(product, 0) + 1

        if apply:
            path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            stats.stamped += 1
        else:
            stats.would_stamp += 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--results-root",
        action="append",
        required=True,
        type=Path,
        dest="results_roots",
        metavar="PATH",
        help="a findings-style tree to walk (repeatable), e.g. analysis-results/findings",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="write the derived ref/ref_kind (default: dry-run, report only)",
    )
    args = ap.parse_args(argv)

    validators = _validators()
    stats = Stats()
    for root in args.results_roots:
        if not root.is_dir():
            sys.exit(f"results root not found: {root}")
        backfill_root(root.resolve(), args.apply, validators, stats)

    mode = "APPLY" if args.apply else "DRY-RUN (pass --apply to write)"
    print(f"backfill_report_refs — {mode}")
    print(f"  reports scanned:          {stats.scanned}")
    print(f"  already declare ref:      {stats.already_declared}")
    print(f"  HEAD (no slug ref):       {stats.no_slug_ref}")
    if args.apply:
        print(f"  stamped:                  {stats.stamped}")
    else:
        print(f"  would stamp:              {stats.would_stamp}")
    if stats.per_product:
        print("  per-product batch summary:")
        for product, n in sorted(stats.per_product.items()):
            print(f"    {product}: {n}")
    for label, items in (
        ("unparseable", stats.unparseable),
        ("validation-skipped", stats.skipped_invalid),
    ):
        for line in items:
            print(f"  WARNING [{label}] {line}", file=sys.stderr)
    return 1 if stats.unparseable or stats.skipped_invalid else 0


if __name__ == "__main__":
    raise SystemExit(main())
