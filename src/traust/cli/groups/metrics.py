"""``traust metrics …`` — metrics journal, spend, SLA."""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from traust_engine.metrics import collect_spend as css

from traust.cli.groups._registry import OpSpec


def add_history_args(ap) -> None:
    ap.add_argument("cmd", choices=["append", "latest", "verify", "render-exec"])
    ap.add_argument("--source", help="Dashboard slug (append/latest)")
    ap.add_argument("--metrics-json", help="Path to a JSON object of metrics, or '-' for stdin")
    ap.add_argument("--note", default="")


def call_history(engine, args) -> int:
    metrics = engine.metrics
    if args.cmd == "verify":
        ok, issues = metrics.verify()
        for i in issues:
            print(f"✗ {i}")
        print("✓ chain verified" if ok else f"✗ {len(issues)} issue(s)")
        return 0 if ok else 1

    if args.cmd == "latest":
        if not args.source:
            print("error: --source required", file=sys.stderr)
            return 2
        row = metrics.previous(args.source)
        print(json.dumps(row, indent=2) if row else "null")
        return 0

    if args.cmd == "append":
        if not args.source or not args.metrics_json:
            print("error: --source and --metrics-json required", file=sys.stderr)
            return 2
        raw = (
            sys.stdin.read()
            if args.metrics_json == "-"
            else Path(args.metrics_json).read_text(encoding="utf-8")
        )
        row = metrics.append(args.source, json.loads(raw), note=args.note)
        print(f"appended {row['source']} @ {row['snapshot_at']} (row_sha {row['row_sha'][:12]}…)")
        return 0

    if args.cmd == "render-exec":
        mdp, htmlp = metrics.render()
        print(f"wrote {mdp}\nwrote {htmlp}")
        return 0
    return 2


HISTORY = OpSpec(
    add_args=add_history_args,
    call=call_history,
    help="Append-only metrics history ledger (append, latest, verify, render-exec)",
)


def add_spend_args(ap) -> None:
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument(
        "--budget",
        type=Path,
        default=None,
        help="budget-policy.yaml carrying monthly_budget",
    )


def call_spend(engine, args) -> int:
    out = engine.metrics.build_spend_dashboard(
        out_dir=args.out_dir,
        budget_path=args.budget,
        budget_section=engine.ctx.budget_policy,
    )
    print(f"wrote {out}")
    return 0


SPEND = OpSpec(
    add_args=add_spend_args,
    call=call_spend,
    help="Rebuild the model-spend dashboard from ledger rows",
)


def add_collect_spend_args(ap) -> None:
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: today for live view)")
    ap.add_argument(
        "--append",
        action="store_true",
        help="record completed days into the metrics ledger (idempotent)",
    )


def call_collect_spend(engine, args) -> int:
    metrics = engine.metrics
    ws = args.workspace or metrics.workspace()
    dirs = metrics.session_project_dirs(ws)
    if not dirs:
        print(
            f"no Claude Code project transcripts under {css.PROJECTS} for {ws}",
            file=sys.stderr,
        )
        return 1

    today = datetime.date.today().isoformat()

    if args.append:
        appended = metrics.append_session_spend(dirs)
        print(f"appended {appended} day×model session-spend row(s)")
        return 0

    day = args.date or today
    agg = metrics.collect_session_spend(dirs, day)
    rows = agg.get(day, {})
    print(
        f"session spend — {day} ({'live' if day == today else 'final'}) "
        f"across {len(dirs)} project dir(s)"
    )
    if not rows:
        print("  no usage recorded")
        return 0
    for model, a in sorted(rows.items()):
        r = css._row(model, a)
        print(
            f"  {model}: out={r['tokens_out']:,} in={r['tokens_in']:,} "
            f"cache_read={r['cache_read']:,} cache_new={r['cache_creation']:,} "
            f"({r['messages']} msgs, {r['sessions']} sessions)"
        )
    return 0


COLLECT_SPEND = OpSpec(
    add_args=add_collect_spend_args,
    call=call_collect_spend,
    help="Collect session spend from Claude Code transcripts",
)


def add_attribute_spend_args(ap) -> None:
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--date", default=None, help="one day, YYYY-MM-DD")
    ap.add_argument("--month", default=None, help="one month, YYYY-MM")
    ap.add_argument(
        "--reconcile",
        action="store_true",
        help="prove the split is lossless vs collect_session_spend.py and exit non-zero if not",
    )
    ap.add_argument(
        "--append",
        action="store_true",
        help="record completed days into the metrics ledger under spend-attribution:<skill>",
    )
    ap.add_argument("--json", action="store_true")


def call_attribute_spend(engine, args) -> int:
    from traust_engine.metrics import attribute_spend as attr

    metrics = engine.metrics
    ws = args.workspace or metrics.workspace()
    dirs = css.workspace_slugs(ws)
    if not dirs:
        print(f"no session transcripts under {css.PROJECTS} for {ws}", file=sys.stderr)
        return 3

    month = args.month
    if not month and not args.date:
        month = datetime.date.today().strftime("%Y-%m")

    if args.reconcile:
        res = metrics.attribute_reconcile(dirs, args.date, month)
        print(
            json.dumps(res, indent=1)
            if args.json
            else "\n".join(
                [
                    "reconciliation vs collect_session_spend.py:",
                    f"  attributed output tokens: {attr._fmt(res['attributed']['output_tokens'])}",
                    f"  baseline   output tokens: {attr._fmt(res['baseline']['output_tokens'])}",
                    f"  lossless: {res['lossless']}",
                ]
                + (
                    []
                    if res["lossless"]
                    else [f"  MISMATCH {k}: {v:+d}" for k, v in res["deltas"].items() if v]
                )
            )
        )
        return 0 if res["lossless"] else 1

    if args.append:
        n = metrics.append_attribution_rows(metrics.collect_attributed(dirs))
        print(f"appended {n} date×skill×model attribution row(s)")
        return 0

    agg = metrics.collect_attributed(dirs, args.date, month)
    if args.json:
        out = {
            d: {
                s: {
                    m: {k: v for k, v in a.items() if k != "sessions"}
                    | {"sessions": len(a["sessions"])}
                    for m, a in models.items()
                }
                for s, models in skills.items()
            }
            for d, skills in agg.items()
        }
        print(json.dumps(out, indent=1, sort_keys=True))
        return 0
    print("\n".join(metrics.render_attribution(agg, args.date or month or "all")))
    return 0


ATTRIBUTE_SPEND = OpSpec(
    add_args=add_attribute_spend_args,
    call=call_attribute_spend,
    help="Attribute session spend to harness lanes from transcripts",
)


def add_sla_args(ap) -> None:
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="SLA policy YAML (data, schema-validated). Default: the shipped SLA policy.",
    )
    ap.add_argument(
        "--profile", default=None, help="profile name (default: the policy's default profile)"
    )
    ap.add_argument("--as-of", default=None)
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="default: <metrics-root>/metrics/dashboards/sla",
    )
    ap.add_argument(
        "--pd-cache-dir",
        type=Path,
        default=None,
        help="product-definitions feed cache dir (optional source)",
    )


def call_sla(engine, args) -> int:
    import datetime as dt

    metrics = engine.metrics
    db = args.db or metrics.findings_db()
    if not db.is_file():
        print(
            f"ERROR: {db} not found — build it first: traust corpus findings-db",
            file=sys.stderr,
        )
        return 1
    as_of = dt.date.fromisoformat(args.as_of) if args.as_of else None
    view, out_dir = metrics.build_sla_view(
        db_path=db,
        policy_path=args.policy,
        profile=args.profile,
        as_of=as_of,
        out_dir=args.out_dir,
        pd_cache_dir=args.pd_cache_dir,
    )
    s = view["summary"]
    profile_name = view["metadata"]["profile"]
    print(f"wrote {out_dir}/sla-view.{{json,md}} (profile {profile_name})")
    print(
        f"  open in-SLA {s['open_in_sla']:,} | overdue "
        f"{s['open_overdue']:,} | no-SLA {s['open_no_sla']:,} | "
        f"unclocked {s['unclocked']:,} | resolved compliance "
        f"{s['resolved_sla_compliance_pct']}%"
    )
    return 0


SLA = OpSpec(
    add_args=add_sla_args,
    call=call_sla,
    help="Owner-response SLA views over the findings projection",
)
