#!/usr/bin/env python3
# Migration utility written 2026-09-02
"""Re-stamp the finding fingerprints the v2 -> v3 recipe change moved.

Ledger plan item A4. `ALGO_VERSION` v3 (traust-ledger 0.19.0) selects the **lowest CWE
by number** instead of the first one listed, so identity no longer depends on the
order of a model-authored list.

Scope, measured against the installed recipe rather than assumed:

- **15,730 findings move**, across **6,352 baseline reports**. Note this is larger
  than the plan's long-standing figure of 11,085: that count came from `min(cwes)`
  read *lexicographically*, where `CWE-1104` precedes `CWE-937`. Numeric was chosen
  deliberately (Michele, 2026-09-02), and it moves more.
- **18,425 event stamps move**, across **4,457 layers**.

**This is why v3 is a heavier migration than v2 was.** The v1->v2 pass touched no
event at all — zero events carried a stamp then — so no Merkle root moved and nothing
was re-signed. Here 18,425 stamps change, every one of them inside an event, and
under `leaf_format 2` the leaf binds full event content. So every touched layer
re-roots and must be re-signed, and this migration cannot run without a signing key.

**Overwriting an event stamp is deliberate, and is the exception to the rule.**
`attach_identity` never overwrites — "identity is a historical observation". That
rule protects a stamp recorded under the recipe of its day. It does not apply here:
the whole point is to move stamps from one recipe version to the next, and each
rewritten stamp has its `fingerprint_algo` set to v3 so the record stays honest about
which recipe produced it.

**On A15.** This writes baselines, and that gate reserves baseline writes for the
three audit skills. It is not the violation A15 exists to stop: no finding is added,
removed, or re-scoped, and no claim field changes — `CLAIM_FIELDS` is (id, title,
severity, cwes, locations, description, remediation) and `fingerprint` is not among
them, so `claim_hashes` and the baseline tamper-guard are untouched. Precedent: the
v2 pass and the P0.4 correction of 606 forged stamps.

Safety properties, inherited from the v2 migration and extended:

- **DRY-RUN BY DEFAULT.** Nothing is written without `--apply`.
- **Idempotent.** A value already at v3 is skipped; a second `--apply` is a no-op.
- **Refuses on drift.** If a stored fingerprint is neither the recomputed v2 nor the
  recomputed v3 value, the finding is reported and skipped, never overwritten — a
  third value means something else edited the report and this tool is not the
  adjudicator.
- **Recomputes, never trusts a worklist.** Both sides are computed from the finding
  as it stands at run time.
- **Restore on failure**, and a signature that arrives valid must leave valid. The
  2026-08-31 incident wrote 112 layers re-rooted and unsigned while reporting
  success; the guards that caught it are reproduced here.

    python3 -m traust.migrations.restamp_fingerprints_v3 <results-root> \\
        [--apply] [--pubkey PATH] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from traust_engine.ledger import (
    ALGO_VERSION,
    LedgerError,
    fingerprint,
    verify_merkle_integrity,
    verify_merkle_signature,
)

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
LAYER_SUFFIX = "-findings-layer.json"


def _v2_primary_cwe(finding: dict) -> str:
    """What v2 would have hashed: the FIRST listed CWE, uppercased and trimmed."""
    cwes = [c for c in (finding.get("cwes") or []) if str(c).strip()]
    if not cwes:
        return "CWE-0"
    return str(cwes[0]).strip().upper() or "CWE-0"


def _v2_fingerprint(finding: dict, repo_url: str | None) -> str:
    """Recompute the v2 value by feeding v3 a single-CWE finding.

    Cheaper and less brittle than re-implementing the recipe: v2 and v3 differ only
    in which CWE is selected, so hashing a copy whose `cwes` is exactly v2's choice
    reproduces the v2 digest exactly.
    """
    return fingerprint({**finding, "cwes": [_v2_primary_cwe(finding)]}, repo_url)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(ap)
    ap.add_argument("results_root", type=Path, nargs="?", default=None)
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    ap.add_argument(
        "--pubkey",
        type=Path,
        default=None,
        help="verify each fresh signature before keeping the write",
    )
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    results_root = (args.results_root or analysis_results_dir(engine)).resolve()

    if ALGO_VERSION != "v3":
        print(
            f"ERROR: installed recipe is {ALGO_VERSION}, expected v3 — roll the "
            f"traust-ledger pin first",
            file=sys.stderr,
        )
        return 2

    tally: Counter[str] = Counter()
    problems: list[str] = []
    started = time.monotonic()

    layers = sorted(results_root.rglob(f"*{LAYER_SUFFIX}"))
    for layer_path in layers:
        if args.limit and tally["layers written"] >= args.limit:
            break
        rel = layer_path.relative_to(results_root)
        if STATE_DIRS.intersection(rel.parts):
            continue
        try:
            layer = json.loads(layer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable layer"] += 1
            continue
        meta = layer.get("metadata") or {}
        repo = meta.get("repository")
        report_path = layer_path.parent / Path(str(meta.get("audit_report") or "")).name
        if not report_path.is_file():
            tally["no baseline report"] += 1
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            tally["unreadable report"] += 1
            continue

        # ── the finding side ────────────────────────────────────────────────
        moved: dict[str, str] = {}
        report_dirty = False
        for f in report.get("findings") or []:
            stored = f.get("fingerprint")
            if not stored:
                continue
            v3 = fingerprint(f, repo)
            if stored == v3:
                tally["finding already v3"] += 1
                continue
            if stored != _v2_fingerprint(f, repo):
                tally["finding stamp is neither v2 nor v3 — SKIPPED"] += 1
                problems.append(f"{report_path.name}: {f.get('id')}: unrecognised stamp")
                continue
            f["fingerprint"] = v3
            f["fingerprint_algo"] = "v3"
            moved[stored] = v3
            report_dirty = True
            tally["findings re-stamped"] += 1

        # ── the event side ──────────────────────────────────────────────────
        layer_dirty = False
        for e in layer.get("events") or []:
            fp = e.get("fingerprint")
            if fp and fp in moved:
                e["fingerprint"] = moved[fp]
                e["fingerprint_algo"] = "v3"
                layer_dirty = True
                tally["event stamps re-stamped"] += 1

        if not report_dirty and not layer_dirty:
            continue
        tally["reports touched"] += 1 if report_dirty else 0
        if not args.apply:
            tally["layers to re-sign"] += 1 if layer_dirty else 0
            continue

        # ── write, with the 2026-08-31 guards ───────────────────────────────
        orig_report = report_path.read_bytes()
        orig_layer = layer_path.read_bytes()
        try:
            prior_sig = (json.loads(orig_layer).get("metadata") or {}).get("merkle_root_signature")
        except json.JSONDecodeError:
            prior_sig = None

        def _restore(
            reason: str,
            detail: str,
            _rp=report_path,
            _lp=layer_path,
            _ro=orig_report,
            _lo=orig_layer,
        ) -> None:
            _rp.write_bytes(_ro)
            _lp.write_bytes(_lo)
            tally[reason] += 1
            problems.append(f"{_lp.name}: {detail}")

        if report_dirty:
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if not layer_dirty:
            tally["reports written (no layer change)"] += 1
            continue

        svc = engine.ledger.service(data_dir=layer_path.parent)
        svc.store_layer(layer_path, layer)
        try:
            svc.sign(layer_path)
        except LedgerError as exc:
            _restore("sign failed — NOT written", str(exc))
            continue

        fresh = svc.read_layer_file(layer_path)
        fresh_sig = (fresh.get("metadata") or {}).get("merkle_root_signature")
        if prior_sig and not fresh_sig:
            _restore("signature LOST — NOT written", "arrived signed, unsigned after sign()")
            continue
        if prior_sig and fresh_sig == prior_sig:
            _restore(
                "signature STALE — NOT written",
                "event content changed but the signature is byte-identical",
            )
            continue
        if [x for x in verify_merkle_integrity(fresh) if x.severity.name == "ERROR"]:
            _restore("merkle ERROR — NOT written", "root does not recompute")
            continue
        if args.pubkey and [
            x
            for x in verify_merkle_signature(fresh, str(args.pubkey))
            if x.severity.name == "ERROR"
        ]:
            _restore("fresh signature failed to verify — NOT written", "bad signature")
            continue
        tally["layers written"] += 1
        if tally["layers written"] % 250 == 0:
            rate = tally["layers written"] / max(time.monotonic() - started, 1e-9)
            print(f"  … {tally['layers written']} layers ({rate:.1f}/s)", flush=True)

    print(
        f"{'APPLY' if args.apply else 'DRY RUN'} · {len(layers):,} layer files · "
        f"{time.monotonic() - started:.0f}s"
    )
    for k, v in tally.most_common():
        print(f"  {k:46} {v:,}")
    for p in problems[:10]:
        print(f"    ! {p}")
    if not args.apply:
        print("\n(dry run — re-run with --apply to write)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
