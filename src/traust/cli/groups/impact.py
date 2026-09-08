"""``traust impact …`` — CVE impact analysis and sweep tooling."""

from __future__ import annotations

from traust.cli.groups._registry import OpSpec, passthrough_op


def add_analyze_args(ap) -> None:
    ap.add_argument(
        "cve",
        help="Advisory id — CVE-/GHSA-/MAL-/PYSEC-/GO-/RUSTSEC-/OSV- "
        "(e.g. CVE-2026-33186, GHSA-abcd-efgh-ijkl)",
    )
    ap.add_argument("--module", required=True, help="Affected module path")
    ap.add_argument(
        "--ecosystem",
        default="go",
        choices=[
            "go",
            "npm",
            "pypi",
            "maven",
            "cargo",
            "ruby",
            "nuget",
            "actions",
            "docker",
            "helm",
        ],
        help="Package ecosystem of --module (default: go).",
    )
    ap.add_argument("--vulnerable-range", default="", help="Version constraint (e.g. '< v1.64.1')")
    ap.add_argument("--fixed-version", default=None, help="First safe version")
    ap.add_argument("--symbols", default="", help="Comma-separated vulnerable symbols")
    ap.add_argument("--packages", default="", help="Comma-separated vulnerable packages")
    ap.add_argument(
        "--feature-desc",
        default=None,
        help="Human-readable feature description for the CVE",
    )
    ap.add_argument("--db", default=None, help="Portfolio graph DB path")
    ap.add_argument(
        "--out",
        default=None,
        help="Output path (default: <cve>-impact-analysis.json)",
    )
    ap.add_argument("--jobs", type=int, default=4, help="Parallel clone+analyze workers")
    ap.add_argument(
        "--skip-scan",
        action="store_true",
        help="Graph queries only — skip cloning and scanning",
    )


def call_analyze(engine, args) -> int:
    return engine.impact.analyze(
        cve=args.cve,
        module=args.module,
        ecosystem=args.ecosystem,
        vulnerable_range=args.vulnerable_range,
        fixed_version=args.fixed_version,
        symbols=args.symbols,
        packages=args.packages,
        feature_desc=args.feature_desc,
        out=args.out,
        jobs=args.jobs,
        skip_scan=args.skip_scan,
        db=args.db,
    )


ANALYZE = OpSpec(
    add_args=add_analyze_args,
    call=call_analyze,
    help="CVE impact analysis across the portfolio graph",
)

_PASSTHROUGH: tuple[tuple[str, str, str], ...] = (
    (
        "sweep",
        "run_impact_sweep",
        "Execute a fleet-OSV worklist — the missing consumer of the advisory-symbol index.",
    ),
    (
        "calibrate-rule-pack",
        "calibrate_rule_pack",
        "Calibrate an external opengrep rule pack against campaign ground truth.",
    ),
    (
        "resolve-advisory-symbols",
        "resolve_advisory_symbols",
        "Resolve an advisory's VULNERABLE SYMBOLS from its fix commit(s).",
    ),
    (
        "cluster-state-diff",
        "cluster_state_diff",
        "Cluster state diffing — validation-improvement-plan P5, sweep lane.",
    ),
)

IMPACT_OPS: dict[str, object] = {
    name: passthrough_op(module, help) for name, module, help in _PASSTHROUGH
}
