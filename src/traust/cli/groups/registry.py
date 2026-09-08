"""``traust registry …`` — model registry and product catalog."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from traust_contracts import DeploymentConfigMissing
from traust_engine.registry import products as pd

from traust.cli.groups._registry import OpSpec


def add_models_args(ap) -> None:
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    p = sub.add_parser("resolve")
    p.add_argument("role")
    p.add_argument("--tier", default=None)
    p = sub.add_parser("stamp")
    p.add_argument("role")
    p.add_argument("model")
    p = sub.add_parser("spend")
    p.add_argument("--skill", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--tokens-in", type=int, default=0, help="best-effort; omit when unknown")
    p.add_argument("--tokens-out", type=int, default=0, help="best-effort; omit when unknown")
    p.add_argument("--cache-read", type=int, default=0)
    p.add_argument("--cache-creation", type=int, default=0)
    p.add_argument("--batch", default=None)
    p.add_argument("--repo", default=None, help="repo slug this spend audited (calibration tuple)")
    p.add_argument("--loc", type=int, default=None, help="target size in LoC/bytes at audit time")
    p.add_argument("--note", default=None)


def call_models(engine, args) -> int:
    reg = engine.models.registry()
    if args.cmd == "validate":
        errors = engine.models.validate()
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(f"model registry: {'OK' if not errors else f'{len(errors)} error(s)'}")
        return 1 if errors else 0
    if args.cmd == "list":
        for role, r in sorted(reg.roles.items()):
            print(f"{role:22s} floor={r.floor:13s} approved={','.join(r.approved)}")
        return 0
    if args.cmd == "resolve":
        try:
            print(engine.models.resolve(args.role, args.tier))
            return 0
        except (KeyError, ValueError) as e:
            print(str(e), file=sys.stderr)
            return 1
    if args.cmd == "stamp":
        print(json.dumps(engine.models.stamp(args.role, args.model)))
        return 0
    if args.cmd == "spend":
        try:
            engine.metrics._progress_tracker()
        except DeploymentConfigMissing:
            msg = (
                "spend: progress-tracker not configured — declaration skipped; "
                "the embedding platform records usage itself"
            )
            if os.environ.get("HARNESS_REQUIRE_SPEND_LEDGER") == "1":
                print(msg + " (HARNESS_REQUIRE_SPEND_LEDGER=1: failing)", file=sys.stderr)
                return 1
            print(msg, file=sys.stderr)
            return 0
        row = engine.models.spend_row(
            args.model,
            args.tokens_in,
            args.tokens_out,
            args.cache_read,
            args.cache_creation,
            repo=args.repo,
            loc=args.loc,
        )
        if args.batch:
            row["batch"] = args.batch
        engine.metrics.append(f"model-spend:{args.skill}", row, note=args.note or "")
        return 0
    return 2


MODELS = OpSpec(
    add_args=add_models_args,
    call=call_models,
    help="Model registry validate, list, resolve, stamp, spend",
)


def add_products_args(ap) -> None:
    ap.add_argument(
        "--package",
        action="append",
        default=[],
        help="findings package name (-findings suffix optional)",
    )
    ap.add_argument("--repo-url", action="append", default=[])
    ap.add_argument("--product", action="append", default=[], help="ps_product id")
    ap.add_argument(
        "--all",
        action="store_true",
        help="propose a match for every package under processed-results/",
    )
    ap.add_argument("--map", type=Path, default=pd._cli_default_map_path())
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--json", action="store_true", help="JSON only, no human-readable summary")


def call_products(engine, args) -> int:
    cache_dir = args.cache_dir
    if cache_dir is None:
        try:
            cache_dir = engine.models.feeds_cache()
        except DeploymentConfigMissing:
            cache_dir = None

    source_status, source, doc = pd._source_block(cache_dir)
    warnings: list[str] = []
    out = {"source_status": source_status, "source": source, "results": []}

    if doc is None:
        out["warnings"] = [
            "product-definitions cache unavailable — this source is "
            "optional; continue with the other ownership sources when "
            "the feed cache is unreachable."
        ]
        print(json.dumps(out, indent=2))
        return 0

    idx = pd.build_indexes(doc)
    mappings, map_warnings = pd.load_mappings(args.map)
    warnings.extend(map_warnings)

    packages = list(args.package)
    if args.all:
        packages_dir = pd._default_packages_dir()
        if packages_dir and packages_dir.is_dir():
            packages += sorted(
                p.name for p in packages_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
            )
        else:
            warnings.append(f"{packages_dir} not found — --all resolved no packages")

    for name in packages:
        res = pd.resolve_package(idx, name, mappings)
        res["query"] = {"kind": "package", "value": name}
        out["results"].append(res)
    for url in args.repo_url:
        mapped = (mappings.get("repos") or {}).get(url) or (mappings.get("repos") or {}).get(
            pd.norm_repo_url(url)
        )
        res = (
            (pd.resolve_product(idx, mapped, "mapped") if mapped else None)
            or pd.resolve_repo_url(idx, url)
            or {
                "match_tier": "none",
                "ps_products": [],
                "ps_modules": [],
                "lifecycle": pd.lifecycle_of(idx["modules"], []),
                "contacts": [],
                "embargo_cc": "absent",
                "dropped_contacts": [],
                "evidence": {"repo_url": url},
            }
        )
        res["query"] = {"kind": "repo-url", "value": url}
        out["results"].append(res)
    for pid in args.product:
        res = pd.resolve_product(idx, pid, "mapped") or {
            "match_tier": "none",
            "ps_products": [],
            "ps_modules": [],
            "lifecycle": pd.lifecycle_of(idx["modules"], []),
            "contacts": [],
            "embargo_cc": "absent",
            "dropped_contacts": [],
            "evidence": {"error": f"{pid!r} not in registry"},
        }
        res["query"] = {"kind": "product", "value": pid}
        out["results"].append(res)

    kept = sum(len(r["contacts"]) for r in out["results"])
    lost = sum(len(r["dropped_contacts"]) for r in out["results"])
    if lost and kept + lost and lost / (kept + lost) > pd.DROP_RATE_WARN:
        warnings.append(
            f"{lost} of {kept + lost} contact values failed the kerberos-id "
            f"shape gate. Upstream publishes with --expand-aliases, so a "
            f"high rate suggests that regressed — check the compile before "
            f"trusting an empty contact list."
        )
    if source_status == "stale":
        warnings.append(
            f"cache is {source.get('age_hours')}h old (threshold "
            f"{source.get('max_age_hours')}h) — refresh with "
            f"traust feeds fetch --feed product-definitions"
        )
    if warnings:
        out["warnings"] = warnings

    print(json.dumps(out, indent=2))
    if not args.json:
        pd._summarise(out)
    return 0


PRODUCTS = OpSpec(
    add_args=add_products_args,
    call=call_products,
    help="Resolve ownership context from the product registry",
)
