#!/usr/bin/env python3
"""Layer-2 re-score router for the governance-model migration (v0.131.1+).

Deterministic pre-pass over refreshed facts: decides which repos actually
need an agent re-score under the crypto-governance model, and how much of
one — so the Layer-2 fleet re-scores the affected population instead of
blindly re-visiting every scored repo. Routes only; never authors a
verdict (deterministic-tooling contract).

Tiers (worst first):
  full   — the governance model can change scores/buckets here: new
           HP_GOV_PLATFORM_* / HP_DB_* facts fired, fips_mode was
           annotated, or the repo is high-stakes under the new decision
           tree (2030-clock items, hndl_priority, not-ready /
           blocked-external bucket — blast-radius + ceiling candidates).
  light  — scored repos with first-party crypto facts but none of the
           above: needs per-check crypto_governance labels and a PQCA-3
           ceiling check, but score movement is unlikely. Pack more per
           agent.
  skip   — verified zero-hit not-applicable repos (re-templated during
           the refresh) and repos whose facts are entirely
           vendor/test_docs (score-excluded by calibration): re-derive
           the bucket from the decision tree, no agent needed.

Repos whose facts are not yet stamped by the current adapter+rules are
listed `unrefreshed` (re-run after the Layer-1 refresh advances);
repos with no readiness report are `unscored` (normal Phase-1 backlog,
not migration work).

Usage:
  python3 l2_prepass.py [--results-root DIR] [--config-home PATH] [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
sys.path.insert(0, str(HERE))
from pqc_facts import ADAPTER_VERSION, rules_pack_sha  # noqa: E402

GOV_PREFIXES = ("HP_GOV_", "HP_DB_")


def route_repo(facts: dict, readiness: dict | None) -> tuple[str, dict]:
    """Return (tier, hints) for one refreshed repo."""
    fl = facts.get("facts") or []
    # first-party only: vendored governance hits (pre-1.4.0 facts) are
    # API type definitions, not consumption evidence
    gov = sorted(
        {
            f["rule_id"]
            for f in fl
            if str(f.get("rule_id", "")).startswith(GOV_PREFIXES)
            and f.get("path_class") == "first_party"
        }
    )
    fips = sum(1 for f in fl if f.get("fips_mode"))
    fp = [f for f in fl if f.get("path_class") == "first_party"]
    hints = {
        "gov_rules": gov,
        "fips_mode_facts": fips,
        "facts": len(fl),
        "first_party_facts": len(fp),
    }
    if readiness is None:
        return "unscored", hints
    bucket = readiness.get("readiness_bucket")
    flags = readiness.get("flags") or {}
    hints["old_bucket"] = bucket
    if bucket == "not-applicable" and not fl:
        return "skip", hints
    if not fp:
        hints["note"] = "all facts vendor/test_docs (score-excluded); re-derive bucket only"
        return "skip", hints
    if (
        gov
        or fips
        or flags.get("has_2030_clock_items")
        or flags.get("hndl_priority")
        or bucket in ("not-ready", "blocked-external")
    ):
        return "full", hints
    return "light", hints


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    results = resolve_results_root(args)
    pqc = results / "pqc"
    out = args.out or (pqc / "_manifest" / f"l2-worklist-adapter-{ADAPTER_VERSION}.json")
    want = {"adapter_version": ADAPTER_VERSION, "rules_sha256": rules_pack_sha(HERE / "rules")}

    tiers: dict[str, list] = {
        "full": [],
        "light": [],
        "skip": [],
        "unscored": [],
        "unrefreshed": [],
    }
    for d in sorted(p for p in pqc.iterdir() if p.is_dir() and not p.name.startswith("_")):
        slug = d.name
        fp = d / f"{slug}-pqc-facts.json"
        if not fp.is_file():
            continue
        try:
            facts = json.loads(fp.read_text())
        except (OSError, json.JSONDecodeError):
            tiers["unrefreshed"].append({"slug": slug, "note": "unreadable facts"})
            continue
        stamps = facts.get("stamps") or {}
        if any(stamps.get(k) != v for k, v in want.items()):
            tiers["unrefreshed"].append({"slug": slug})
            continue
        rp = d / f"{slug}-pqc-readiness.json"
        readiness = None
        if rp.is_file():
            try:
                readiness = json.loads(rp.read_text())
            except (OSError, json.JSONDecodeError):
                readiness = None
        tier, hints = route_repo(facts, readiness)
        tiers[tier].append({"slug": slug, **hints})

    doc = {
        "artifact": "pqc-l2-rescore-worklist",
        "role": (
            "deterministic router for the governance-model Layer-2 "
            "re-score — routes only, never authors a verdict"
        ),
        "stamps": want,
        "summary": {k: len(v) for k, v in tiers.items()},
        "tiers": tiers,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(
        f"[l2-prepass] wrote {out}: " + ", ".join(f"{k}={len(v)}" for k, v in tiers.items()),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
