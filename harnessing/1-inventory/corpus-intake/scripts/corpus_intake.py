#!/usr/bin/env python3
"""Corpus intake — the maintained front door for corpus-config.yaml.

$TRAUST_CONFIG_HOME/corpus-config.yaml is the single source of truth for which trees
under analysis-results/ belong to the report corpus and who owns them.
Hand-editing it invites exactly the drift the corpus resolver exists to
kill (a tree on disk nobody registered, an ownership tag nobody vetted),
so every change goes through this tool: it validates before it writes,
rejects overlapping or duplicate registrations, and re-renders the file
from a canonical template so the layout and documentation comments never
rot.

The /corpus-intake skill drives this interactively (interview mode);
scripted callers pass the same fields as flags.

CLI:
    python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py list \\
        [--config PATH] [--analysis-results PATH]
    python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py add-tree NAME \\
        --label L --ownership owned|upstream|external-bu|harness-qa \\
        --business-unit BU [--notes TEXT]
    python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py add-engagement NAME \\
        --label L --ownership external-bu --business-unit BU \\
        --tree TREE [--inventory PATH] [--notes TEXT]
    python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py update \\
        (tree|engagement) NAME [--label ...] [--ownership ...] \\
        [--business-unit ...] [--tree ...] [--inventory ...] [--notes ...]

All mutating commands support --dry-run (print the resulting file, write
nothing) and exit non-zero without touching the file when validation
fails. After a successful write the caller should re-run /census so the
corpus manifest reflects the new registration immediately.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml
from traust_contracts import (
    CorpusConfig,
    optional_config_path,
)
from traust_engine._util.script_loader import load_script

from traust.context import add_config_home_arg, resolve_results_root

# Harness root: the directory holding VERSION, walked rather than counted.
# This was `Path(__file__).resolve().parents[2]`, which resolved to `harnessing/` and so pointed one
# level too shallow — the C8 script-placement migration moved this file
# into scripts/ and the count was never updated.
HARNESS = next(p for p in Path(__file__).resolve().parents if (p / "VERSION").is_file())

# The operational corpus registry ($TRAUST_CONFIG_HOME);
# the harness repo ships only config/corpus-config.example.yaml.
DEFAULT_CONFIG = optional_config_path("corpus-config.yaml")

corpus = load_script("corpus", HARNESS)

NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

HEADER = """\
# Corpus ownership configuration — the single source of truth for which
# trees under analysis-results/ belong to the report corpus, who owns them,
# and how their numbers roll up.
#
# Consumed by traust.cli.groups.corpus, which every dashboard builder uses for
# file discovery, deduplication, and ownership tagging. Update this file
# through the /corpus-intake skill (interactive registration), not by hand.
#
# Ownership tags:
#   owned       — Hybrid Platforms BU backlog; appears in every cut and in
#                 the canonical Lens 2 (distinct exposure) headline.
#   upstream    — upstream community code HP relies on and contributes to;
#                 shown as an adjacent supply-chain line beneath the owned
#                 headline and in portfolio cuts, never folded into owned.
#   external-bu — scan engagements performed for other business units;
#                 Lens 1 (work performed) only, excluded from HP executive
#                 risk numbers.
#   harness-qa  — harness self-measurement artifacts (probes, benchmarks,
#                 side-by-side runs, e.g. scan-testing/); registered so
#                 drift-watch knows the tree is vetted, but EXCLUDED from
#                 every metrics lens — corpus.resolve() never walks it.
"""

ENGAGEMENTS_COMMENT = """\
# Registered engagements whose trees do not exist yet. The resolver treats
# a registered tree exactly like a configured tree the moment it appears on
# disk; until then the label is reserved and reported as "registered, no
# output". Tree-per-engagement is the convention for new external-BU work.
"""

OVERRIDES_COMMENT = """\
# Per-product or per-repo ownership overrides within a tree, for cases where
# a BU boundary cuts through a tree. Keys are <tree>/<product> or
# <tree>/<product>/<repo-slug>; values override label/ownership/business_unit.
"""

ENTRY_FIELDS = ("label", "ownership", "business_unit", "tree", "status", "inventory", "notes")


# ---------------------------------------------------------------------------
# render — the script owns the file layout, so comments never rot
# ---------------------------------------------------------------------------


def _dump_entry(name: str, entry: dict, indent: int = 2) -> str:
    pad = " " * indent
    lines = [f"{pad}{name}:"]
    for key in ENTRY_FIELDS:
        if key not in entry or entry[key] in (None, ""):
            continue
        # yaml.safe_dump handles quoting/folding; re-indent its output
        # (key at column 0, continuations at 2) under our entry.
        dumped = yaml.safe_dump({key: entry[key]}, width=72, default_flow_style=False).rstrip("\n")
        lines.extend(f"{pad}  {ln}" for ln in dumped.split("\n"))
    return "\n".join(lines)


def render_config(cfg: dict) -> str:
    parts = [HEADER, f"version: {cfg.get('version', 1)}", "", "trees:"]
    for name, entry in cfg.get("trees", {}).items():
        parts.append(_dump_entry(name, entry))
    parts += ["", ENGAGEMENTS_COMMENT.rstrip("\n"), "engagements:"]
    engagements = cfg.get("engagements") or {}
    if not engagements:
        parts[-1] = "engagements: {}"
    for name, entry in engagements.items():
        parts.append(_dump_entry(name, entry))
    parts += ["", OVERRIDES_COMMENT.rstrip("\n")]
    overrides = cfg.get("overrides") or {}
    if overrides:
        parts.append(
            yaml.safe_dump({"overrides": overrides}, default_flow_style=False).rstrip("\n")
        )
    else:
        parts.append("overrides: {}")
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def validate_new(cfg: dict, kind: str, name: str, entry: dict, updating: bool = False) -> list[str]:
    errors = []
    trees = cfg.get("trees") or {}
    engagements = cfg.get("engagements") or {}

    if not NAME_RX.match(name):
        errors.append(f"invalid name {name!r} (letters, digits, . _ - only; no path separators)")
    if entry.get("ownership") not in corpus.OWNERSHIP_TAGS:
        errors.append(f"ownership must be one of {corpus.OWNERSHIP_TAGS}")
    for key in ("label", "business_unit"):
        if not entry.get(key):
            errors.append(f"missing --{key.replace('_', '-')}")

    if not updating:
        if name in trees or name in engagements:
            errors.append(f"{name!r} is already registered")
        labels = {e.get("label") for e in list(trees.values()) + list(engagements.values())}
        if entry.get("label") in labels:
            errors.append(f"label {entry.get('label')!r} is already in use")

    if kind == "engagement":
        tree = entry.get("tree")
        if not tree:
            errors.append(
                "engagements require --tree (the directory the engagement's output will land in)"
            )
        elif not NAME_RX.match(tree):
            errors.append(f"invalid tree name {tree!r}")
        else:
            taken = set(trees) | {e.get("tree") for n, e in engagements.items() if n != name}
            if tree in taken:
                errors.append(f"tree {tree!r} is already mapped")
    return errors


def drift(cfg: dict, analysis_results: Path) -> list[str]:
    """Unregistered trees on disk that hold audit reports."""
    if not analysis_results.is_dir():
        return []
    res = corpus.Resolution(analysis_results=str(analysis_results))
    corpus._flag_unregistered_trees(
        analysis_results,
        corpus.active_trees(CorpusConfig.model_validate(cfg), analysis_results),
        res,
    )
    return res.warnings


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _write(cfg: dict, path: Path, dry_run: bool) -> None:
    text = render_config(cfg)
    # round-trip guard: the rendered file must load back identically
    reparsed = yaml.safe_load(text)
    for section in ("trees", "engagements", "overrides"):
        if (reparsed.get(section) or {}) != (cfg.get(section) or {}):
            sys.exit(f"internal error: render round-trip mismatch in {section} — nothing written")
    if dry_run:
        print(text, end="")
        return
    # validate through the resolver BEFORE the real file changes, then
    # rename into place — a failed gate can never corrupt the config
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        corpus.load_config(tmp)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(path)
    print(f"wrote {path}")


def cmd_list(cfg: dict, analysis_results: Path) -> int:
    print(f"{'name':<24} {'kind':<11} {'ownership':<12} {'label':<18} business unit")
    print("-" * 88)
    for name, e in (cfg.get("trees") or {}).items():
        print(f"{name:<24} {'tree':<11} {e['ownership']:<12} {e['label']:<18} {e['business_unit']}")
    for name, e in (cfg.get("engagements") or {}).items():
        on_disk = (analysis_results / e["tree"]).is_dir() if analysis_results.is_dir() else False
        kind = "engagement" + ("*" if on_disk else "")
        print(
            f"{name:<24} {kind:<11} {e['ownership']:<12} "
            f"{e['label']:<18} {e['business_unit']} "
            f"(tree: {e['tree']}{', ACTIVE on disk' if on_disk else ''})"
        )
    warnings = drift(cfg, analysis_results)
    for w in warnings:
        print(f"\nDRIFT: {w}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument(
        "--results-root",
        "--analysis-results",
        type=Path,
        default=None,
        dest="results_root",
        help="analysis-results root (default: $TRAUST_CONFIG_HOME)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="registered entries + drift warnings")

    def add_common(p, engagement: bool):
        p.add_argument("name")
        p.add_argument("--label", required=True)
        p.add_argument("--ownership", required=True, choices=corpus.OWNERSHIP_TAGS)
        p.add_argument("--business-unit", required=True)
        if engagement:
            p.add_argument("--tree", required=True)
            p.add_argument("--inventory", default=None)
        p.add_argument("--notes", default=None)
        p.add_argument("--dry-run", action="store_true")

    add_common(
        sub.add_parser(
            "add-tree",
            help="register a tree that exists (or will exist) directly under analysis-results/",
        ),
        False,
    )
    add_common(
        sub.add_parser(
            "add-engagement",
            help="reserve a label + tree for an engagement that has not produced output yet",
        ),
        True,
    )

    pu = sub.add_parser("update", help="modify fields of an existing entry")
    pu.add_argument("kind", choices=("tree", "engagement"))
    pu.add_argument("name")
    for flag in (
        "--label",
        "--ownership",
        "--business-unit",
        "--tree",
        "--inventory",
        "--notes",
        "--status",
    ):
        pu.add_argument(flag, default=None)
    pu.add_argument("--dry-run", action="store_true")

    args = ap.parse_args(argv)
    analysis_results = resolve_results_root(args)
    # This is the config EDITOR, so it works on the raw dict form (merging,
    # rendering YAML); the typed model is only used for validation on write.
    cfg = corpus.load_config(args.config).model_dump(exclude_none=True)

    if args.cmd == "list":
        return cmd_list(cfg, analysis_results)

    if args.cmd in ("add-tree", "add-engagement"):
        kind = "tree" if args.cmd == "add-tree" else "engagement"
        entry = {
            "label": args.label,
            "ownership": args.ownership,
            "business_unit": args.business_unit,
        }
        if args.notes:
            entry["notes"] = args.notes
        if kind == "engagement":
            entry["tree"] = args.tree
            entry["status"] = "registered"
            if args.inventory:
                entry["inventory"] = args.inventory
        errors = validate_new(cfg, kind, args.name, entry)
        if errors:
            for e in errors:
                print(f"error: {e}", file=sys.stderr)
            return 2
        section = "trees" if kind == "tree" else "engagements"
        cfg.setdefault(section, {})[args.name] = entry
        _write(cfg, args.config, args.dry_run)
        for w in drift(cfg, analysis_results):
            print(f"DRIFT: {w}", file=sys.stderr)
        return 0

    if args.cmd == "update":
        section = "trees" if args.kind == "tree" else "engagements"
        entries = cfg.get(section) or {}
        if args.name not in entries:
            print(f"error: no {args.kind} named {args.name!r}", file=sys.stderr)
            return 2
        entry = dict(entries[args.name])
        for field in ENTRY_FIELDS:
            val = getattr(args, field.replace("-", "_"), None)
            if val is not None:
                entry[field] = val
        errors = validate_new(cfg, args.kind, args.name, entry, updating=True)
        if errors:
            for e in errors:
                print(f"error: {e}", file=sys.stderr)
            return 2
        entries[args.name] = entry
        _write(cfg, args.config, args.dry_run)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
