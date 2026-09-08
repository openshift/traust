#!/usr/bin/env python3
"""Bootstrap recall-benchmark candidates from the disposition ledger.

The campaign has already manufactured ground truth without noticing: every
finding the ledger records as RESOLVED at a named fix commit means the fix
commit's parent provably contains that bug at a known location/CWE. This
script walks every *-findings-current.json + *-findings-layer.json pair,
extracts (finding, fix commit) pairs, and emits candidate entries conforming
to contracts/schemas/benchmark-target.schema.json with admitted=false — admission is a
human review (countersign-style: the evidence excerpt must support "bug
provably present at fix_commit^"), never automatic.

Fix-commit extraction, in precedence order:
  1. resolved event source.type == "commit" -> source.ref
  2. first `[Cc]ommit <sha>` reference in the resolved event's rationale

pre_fix_sha is left null here; the admission step (or the benchmark runner)
resolves fix_commit^ against the live repo — network access is deliberately
not required to bootstrap.

Exclusions: findings whose current validity is false_positive or hardening,
findings with no location paths (fingerprint would collapse), non-GitHub/
GitLab URLs (unclonable in the benchmark runner).

CLI:
    python3 scripts/bootstrap_benchmark_targets.py \
        --results-root PATH \
        --out candidates.yaml [--limit N] [--held-out-frac 0.2] [--seed 7]

The held-out flag is assigned here (deterministic hash of target id, not
random state) so the split is stable across re-bootstraps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml
from traust_engine.ledger import canon_repo, fingerprint

from traust.context import (
    add_config_home_arg,
    resolve_results_root,
)

COMMIT_IN_TEXT_RX = re.compile(r"\b[Cc]ommit\s+([0-9a-f]{7,40})\b")
CLONABLE_RX = re.compile(r"^https://(github\.com|gitlab\.[a-z.]+)/")


def fix_commit_of(events: list[dict]) -> tuple[str | None, dict | None]:
    """(fix_commit, evidencing_event) from a finding's resolved events."""
    for e in events:
        if (e.get("disposition") or {}).get("resolution") != "resolved":
            continue
        src = e.get("source") or {}
        if src.get("type") == "commit" and src.get("ref"):
            m = re.search(r"[0-9a-f]{7,40}", src["ref"])
            if m:
                return m.group(0), e
        m = COMMIT_IN_TEXT_RX.search(e.get("rationale") or "")
        if m:
            return m.group(1), e
    return None, None


def collect_candidates(results_root: Path) -> list[dict]:
    out: list[dict] = []
    seen_fp: set[str] = set()
    for cur in sorted(results_root.glob("findings/**/*-findings-current.json")):
        if cur.is_symlink() or "_manifest" in cur.parts:
            continue
        layer = Path(str(cur).replace("-findings-current.json", "-findings-layer.json"))
        if not layer.is_file():
            continue
        try:
            rep = json.loads(cur.read_text(encoding="utf-8"))
            lay = json.loads(layer.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        repo_url = canon_repo((rep.get("metadata") or {}).get("repository"))
        if not repo_url or not CLONABLE_RX.match(repo_url):
            continue
        events_by_ref: dict[str, list] = {}
        for e in lay.get("events") or []:
            events_by_ref.setdefault(e.get("finding_ref"), []).append(e)

        slug = cur.name[: -len("-findings-current.json")]
        n_in_repo = 0
        for f in rep.get("findings") or []:
            disp = f.get("disposition") or {}
            if disp.get("resolution") != "resolved":
                continue
            if (disp.get("validity") or f.get("validation_status")) in (
                "false_positive",
                "hardening",
            ):
                continue
            paths = sorted(
                {
                    (loc.get("path") or "").strip()
                    for loc in (f.get("locations") or [])
                    if loc.get("path")
                }
            )
            if not paths or not f.get("cwes"):
                continue
            fix, ev = fix_commit_of(events_by_ref.get(f.get("id")) or [])
            if not fix:
                continue
            fp = f.get("fingerprint") or fingerprint(f, repo_url)
            if fp in seen_fp:
                continue
            seen_fp.add(fp)
            n_in_repo += 1
            tid = f"bt-{slug.lower()}-{n_in_repo:03d}"
            out.append(
                {
                    "id": tid,
                    "repo_url": repo_url,
                    "fix_commit": fix,
                    "pre_fix_sha": None,
                    "provenance": "self_replay",
                    "evidence": {
                        "kind": (
                            "verification_report"
                            if (ev.get("source") or {}).get("type") == "verification_report"
                            else "ledger_event"
                        ),
                        "ref": (ev.get("source") or {}).get("ref")
                        or str(layer.relative_to(results_root)),
                        "excerpt": (ev.get("rationale") or "")[:600],
                    },
                    "embargo": "internal",
                    # deterministic split — stable across re-bootstraps
                    "held_out": int(hashlib.sha256(tid.encode()).hexdigest(), 16) % 100 < 20,
                    "admitted": False,
                    "admitted_by": None,
                    "admitted_at": None,
                    "expected": [
                        {
                            "source_finding": f.get("id") or "",
                            "fingerprint": fp,
                            "cwes": [str(c).upper() for c in f["cwes"]],
                            "paths": paths,
                            "severity": (f.get("severity") or "informational").lower(),
                            "title": (f.get("title") or "")[:200],
                        }
                    ],
                }
            )
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)

    results_root = resolve_results_root(args)

    cands = collect_candidates(results_root)
    if args.limit:
        cands = cands[: args.limit]
    doc = {
        "version": 1,
        "updated": "1970-01-01",  # stamped by the caller on write-out
        "targets": cands,
    }
    args.out.write_text(yaml.safe_dump(doc, sort_keys=False, width=100), encoding="utf-8")
    held = sum(1 for c in cands if c["held_out"])
    print(
        f"wrote {args.out}: {len(cands)} candidates "
        f"({held} held-out) — all admitted=false pending review"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
