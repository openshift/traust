"""Verify every report against the digest its layer signed.

The acceptance gate on a report migration (ledger plan §4.4.0 step 3, executed by the
SCI platform team). Each layer carries `metadata.audit_report_sha256`, and since
signature format 3 that digest is INSIDE the signed payload — so a report can be
proven to be the exact bytes the ledger annotated, without trusting whoever moved it.
A copy that truncates, corrupts or substitutes a file is detectable here.

Reports are fetched through `corpus.report_store`, so the same command verifies a
local checkout today and a bucket after the move: that is what step 2b bought.

    python3 -m traust.cli.verify_report_digests
    python3 -m traust.cli.verify_report_digests --json

Exit 1 on any mismatch or unreadable report. Missing digests are reported but do not
fail: a layer written before the field existed is not evidence of tampering.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_engine.corpus import report_store

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)


def _layer_meta(store: report_store.ReportStore, ref: str) -> dict | None:
    try:
        doc = store.get_json(ref)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return doc.get("metadata") or {} if isinstance(doc, dict) else None


def verify(results_root: Path, engine) -> dict:
    store = report_store.ReportStore(report_store.LocalBackend(results_root))
    res = report_store.load_resolution(results_root, engine.corpus.config())

    counts = {
        "layers": 0,
        "verified": 0,
        "mismatch": 0,
        "no_digest": 0,
        "unreadable_layer": 0,
        "unreadable_report": 0,
    }
    problems: list[dict] = []

    for rec in res.records:
        if not rec.findings_layer:
            continue
        counts["layers"] += 1
        layer_ref = report_store.to_ref(rec.findings_layer, results_root)
        meta = _layer_meta(store, layer_ref)
        if meta is None:
            counts["unreadable_layer"] += 1
            problems.append({"layer": layer_ref, "problem": "layer unreadable"})
            continue

        recorded = meta.get("audit_report_sha256")
        if not recorded:
            counts["no_digest"] += 1
            problems.append(
                {
                    "layer": layer_ref,
                    "problem": "no audit_report_sha256",
                    "audit_report": meta.get("audit_report"),
                }
            )
            continue

        # The ref the ledger records wins once it exists; until then the report sits
        # beside the layer under the name the layer states.
        ref = meta.get("audit_report_ref")
        if not ref:
            name = meta.get("audit_report")
            if not name:
                counts["unreadable_report"] += 1
                problems.append({"layer": layer_ref, "problem": "no audit_report name"})
                continue
            ref = str(Path(layer_ref).parent / Path(name).name)

        try:
            data = store.get(ref)
        except (OSError, ValueError):
            counts["unreadable_report"] += 1
            problems.append({"layer": layer_ref, "problem": "report unreadable", "ref": ref})
            continue

        import hashlib

        actual = hashlib.sha256(data).hexdigest()
        if actual == recorded:
            counts["verified"] += 1
        else:
            counts["mismatch"] += 1
            problems.append(
                {
                    "layer": layer_ref,
                    "problem": "digest mismatch",
                    "ref": ref,
                    "recorded": recorded,
                    "actual": actual,
                }
            )

    return {"counts": counts, "problems": problems}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--limit-problems",
        type=int,
        default=20,
        help="cap the problems printed in text mode (JSON is never capped)",
    )
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    root = (args.results_root or analysis_results_dir(engine)).resolve()
    out = verify(root, engine)
    c = out["counts"]

    if args.json:
        print(json.dumps(out, indent=1))
    else:
        print(f"layers with a ledger: {c['layers']:,}")
        print(f"  verified against the signed digest : {c['verified']:,}")
        print(f"  MISMATCH                           : {c['mismatch']:,}")
        print(f"  report unreadable                  : {c['unreadable_report']:,}")
        print(f"  layer unreadable                   : {c['unreadable_layer']:,}")
        print(f"  no digest recorded (not a failure) : {c['no_digest']:,}")
        shown = [p for p in out["problems"] if p["problem"] != "no audit_report_sha256"]
        for p in shown[: args.limit_problems]:
            print(f"    {p['problem']}: {p['layer']}")
        if len(shown) > args.limit_problems:
            print(
                f"    … {len(shown) - args.limit_problems} more "
                f"(use --json for the full list — this cap is display only)"
            )

    return 1 if (c["mismatch"] or c["unreadable_report"] or c["unreadable_layer"]) else 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "report-digests", *sys.argv[1:]]))
