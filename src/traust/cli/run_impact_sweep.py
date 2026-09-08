#!/usr/bin/env python3
"""Execute a fleet-OSV worklist — the missing consumer of the argv arrays
`fleet_sweep.py` has always emitted but nothing ever ran.

WHY THIS EXISTS (measured 2026-08-11, harness v0.261.0). fleet_sweep.py
builds `impact_argv` per advisory and writes them into
`fleet-osv-worklist-*.json` with the note "run them with subprocess(list)
or safe_exec". No caller did. Consequence: of 29 impact artifacts in the
entire campaign, 28 were Go and 1 was npm — 219 of 220 pypi+npm
advisories had never been analyzed, and Maven (which HAS a Joern
reachability tier) had never been analyzed at all. The gap was never a
missing capability; it was a missing loop.

SYMBOL INJECTION. Each advisory is first passed through
`resolve_advisory_symbols.py`; every resolved symbol is appended as
`--symbols`. This is the difference between a tier that can reach
`affected` and one that ceilings at `likely_affected` forever —
/impact-analysis promotes only on a `kind: "symbol"` Joern hit, which
exists only when `--symbols` is supplied, and OSV publishes per-symbol
data for Go alone. Resolution is cached per advisory under
`--symbol-cache` so a re-run costs nothing and so the symbol set is
auditable separately from the sweep.

Resolution failures are NOT sweep failures: an advisory with no resolvable
symbol still runs, just without the symbol tier — exactly the pre-existing
behaviour. Empty symbols mean UNRESOLVED, never "no vulnerable symbol".

SAFETY. argv arrays are executed with subprocess(list) — never joined into
a shell string (fleet_sweep H1). Only the advisory's own emitted argv is
run, with `--out` optionally redirected by `--out-dir` so a measurement
run cannot clobber the baseline artifacts it is being compared against.
A sustained error streak aborts the run (GitHub secondary-ban guard, the
same posture as the other fleet sweeps: jobs<=4, resume from disk).

Usage:
    python3 -m traust.cli.run_impact_sweep WORKLIST.json \
        [--ecosystem maven,npm,pypi] [--advisory ID ...] \
        [--out-dir DIR] [--symbol-cache DIR] [--no-symbols] \
        [--limit N] [--timeout 1800] [--log FILE] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    resolve_results_root,
    workspace_dir,
)

RESOLVER = [
    sys.executable,
    "-m",
    "traust.cli.resolve_advisory_symbols",
]
ERROR_STREAK_ABORT = 6


def resolve_symbols(
    advisory: str, ecosystem: str, module: str, cache_dir: Path, timeout: int = 180
) -> tuple[list[str], str]:
    """(symbols, status) for an advisory, cached on disk."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    art = cache_dir / f"{advisory}.json"
    if not art.is_file():
        try:
            subprocess.run(
                [
                    *RESOLVER,
                    advisory,
                    "--ecosystem",
                    ecosystem,
                    "--module",
                    module,
                    "--out",
                    str(art),
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as e:
            return [], f"resolver error: {type(e).__name__}"
    if not art.is_file():
        return [], "resolver produced no artifact"
    try:
        doc = json.loads(art.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], "resolver artifact unreadable"
    return ([s["symbol"] for s in (doc.get("symbols") or [])], doc.get("status", "unknown"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("worklist", type=Path)
    ap.add_argument("--ecosystem", default="", help="comma-separated filter (default: all)")
    ap.add_argument(
        "--advisory", action="append", default=[], help="run only these advisory ids (repeatable)"
    )
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results checkout (default: configured analysis-results)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="redirect each --out here (keeps baseline "
        "artifacts intact for before/after comparison)",
    )
    ap.add_argument(
        "--symbol-cache",
        type=Path,
        default=None,
        help="per-advisory symbol resolution cache (default: <results-root>/impact/_symbols)",
    )
    ap.add_argument(
        "--no-symbols", action="store_true", help="baseline mode — do not inject --symbols"
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--log", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    workspace = workspace_dir(engine).resolve()
    results_root = resolve_results_root(args)
    symbol_cache = args.symbol_cache or results_root / "impact" / "_symbols"

    doc = json.loads(args.worklist.read_text(encoding="utf-8"))
    rows = doc.get("worklist") or doc.get("advisories") or []
    ecos = [e for e in args.ecosystem.split(",") if e]

    work = []
    for r in rows:
        if ecos and r.get("ecosystem") not in ecos:
            continue
        if args.advisory and r.get("id") not in args.advisory and r.get("osv") not in args.advisory:
            continue
        for c in r.get("commands") or []:
            work.append((r, c))
    work.sort(key=lambda rc: (rc[0].get("ecosystem") or "", rc[0].get("in_range_repos") or 0))
    if args.limit:
        work = work[: args.limit]

    log_fh = args.log.open("a") if args.log else None

    def emit(obj):
        line = json.dumps(obj)
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()
        else:
            print(line, flush=True)

    emit(
        {
            "event": "start",
            "commands": len(work),
            "symbols": not args.no_symbols,
            "out_dir": str(args.out_dir) if args.out_dir else None,
        }
    )

    streak = 0
    for i, (r, c) in enumerate(work, 1):
        adv = r.get("id") or r.get("osv")
        cmd = list(c["impact_argv"])
        cmd[0] = sys.executable
        out = None
        for j, a in enumerate(cmd):
            if a == "--out":
                out = Path(cmd[j + 1])
                if args.out_dir:
                    out = args.out_dir / Path(cmd[j + 1]).name
                    cmd[j + 1] = str(out)
                break
        if out and not out.is_absolute():
            out = workspace / out

        syms, sym_status = [], "skipped"
        if not args.no_symbols:
            syms, sym_status = resolve_symbols(
                adv, r.get("ecosystem", ""), c.get("module", ""), symbol_cache
            )
            for s in syms:
                cmd += ["--symbols", s]

        if out and out.exists():
            emit({"event": "skip", "i": i, "adv": adv, "reason": "exists"})
            continue
        if args.dry_run:
            emit(
                {
                    "event": "dry-run",
                    "i": i,
                    "adv": adv,
                    "symbols": len(syms),
                    "symbol_status": sym_status,
                }
            )
            continue

        t0 = time.time()
        try:
            p = subprocess.run(
                cmd,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=args.timeout,
                stdin=subprocess.DEVNULL,
            )
            ok, err = p.returncode == 0, (p.stderr or p.stdout)[-300:]
        except subprocess.TimeoutExpired:
            ok, err = False, f"timeout after {args.timeout}s"

        rec = {
            "event": "run",
            "i": i,
            "n": len(work),
            "adv": adv,
            "eco": r.get("ecosystem"),
            "module": c.get("module"),
            "ok": ok,
            "secs": round(time.time() - t0, 1),
            "symbols": len(syms),
            "symbol_status": sym_status,
        }
        if ok and out and out.exists():
            try:
                d = json.loads(out.read_text(encoding="utf-8"))
                rec["summary"] = d.get("summary")
                jr = {}
                for rp in d.get("repos", []):
                    k = (rp.get("evidence") or {}).get("joern_reachability")
                    if k:
                        jr[k.split(":")[0]] = jr.get(k.split(":")[0], 0) + 1
                if jr:
                    rec["joern"] = jr
            except (OSError, json.JSONDecodeError):
                pass
            streak = 0
        else:
            rec["error"] = err
            streak += 1
        emit(rec)
        if streak >= ERROR_STREAK_ABORT:
            emit({"event": "abort", "reason": f"{streak} consecutive failures"})
            return 1

    emit({"event": "done"})
    if log_fh:
        log_fh.close()
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["impact", "sweep", *sys.argv[1:]]))
