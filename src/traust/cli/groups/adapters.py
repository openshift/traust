"""``traust adapters …`` — scanner adapter CLIs (opengrep, govulncheck)."""

from __future__ import annotations

import datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path

from traust_engine.adapters.govulncheck import (
    REACH_ORDER,
    _run_govulncheck,
    harness_version,
    repo_head,
)
from traust_engine.adapters.opengrep import _execute_opengrep_scan, resolve_rule_pack_dir

from traust.cli.groups._registry import OpSpec


def add_opengrep_args(ap) -> None:
    ap.add_argument("target", help="Checkout directory to scan.")
    ap.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Rules source (path | git URL[@SHA] | p/<pack>). Repeatable.",
    )
    ap.add_argument("--out", help="Output file (default: <target-basename>-opengrep.json).")
    ap.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Overall scan timeout in seconds (default 900).",
    )
    ap.add_argument(
        "--rule-allow",
        default=None,
        help="Restrict emitted findings to these bare rule ids (comma list or @file).",
    )
    ap.add_argument(
        "--rule-pack",
        type=Path,
        default=None,
        help="Default traust rule pack (default: locations.opengrep_rules, bundled)",
    )
    ap.add_argument("--opengrep", default="opengrep", help="opengrep binary (default: from PATH).")


def call_opengrep(engine, args) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    if not shutil.which(args.opengrep):
        print(
            f"opengrep not found on PATH ({args.opengrep}) — install from "
            "https://github.com/opengrep/opengrep/releases",
            file=sys.stderr,
        )
        return 1

    try:
        rule_pack = resolve_rule_pack_dir(args.rule_pack, engine.ctx.locations)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    allowlist = engine.adapters.allowlist_for_opengrep()
    try:
        report = _execute_opengrep_scan(
            target,
            args.rules,
            timeout=args.timeout,
            opengrep_bin=args.opengrep,
            rule_pack=rule_pack,
            rule_allow=args.rule_allow,
            allowlist=allowlist,
            loc=engine.ctx.locations,
        )
    except subprocess.TimeoutExpired:
        print(f"opengrep timed out after {args.timeout}s", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("opengrep produced no JSON", file=sys.stderr)
        return 1

    facts = report["facts"]
    errors = report["errors"]
    out = Path(args.out) if args.out else Path(f"{target.name}-opengrep.json")
    out.write_text(json.dumps(report, indent=2))
    by_sev: dict[str, int] = {}
    for f in facts:
        by_sev[f["severity_hint"]] = by_sev.get(f["severity_hint"], 0) + 1
    print(
        f"run_opengrep: {len(facts)} fact(s) {by_sev or ''} across "
        f"{report['stats']['files_scanned']} file(s); "
        f"{len(errors)} engine error(s), "
        f"{report['stats']['skipped_rules']} skipped rule(s)"
    )
    print(f"  rules: {', '.join(r['source'] for r in report['rules'])}")
    print(f"  report: {out}")
    return 0


OPENGREP = OpSpec(
    add_args=add_opengrep_args,
    call=call_opengrep,
    help="Opengrep pre-scan: normalized semantic-pattern facts",
)


def add_govulncheck_args(ap) -> None:
    ap.add_argument(
        "--repo",
        required=True,
        type=Path,
        help="target repo clone at the pinned audit SHA (read-only)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output JSON (default: ./<repo-basename>-govulncheck.json)",
    )
    ap.add_argument(
        "--timeout", type=int, default=900, help="scan timeout in seconds (default 900)"
    )
    ap.add_argument(
        "--govulncheck", default="govulncheck", help="govulncheck binary (default: from PATH)"
    )


def call_govulncheck(engine, args) -> int:
    repo = args.repo.resolve()
    if not (repo / "go.mod").exists() and not list(repo.glob("*/go.mod")):
        print(
            f"ERROR: no go.mod under {repo} — govulncheck stage only applies to Go modules",
            file=sys.stderr,
        )
        return 1

    out = args.out or Path.cwd() / f"{repo.name}-govulncheck.json"
    profile_map = engine.adapters.safe_exec_profile_map()
    cmd = [args.govulncheck, "-json", "./..."]
    try:
        rc, _out, err, tool, candidates = _run_govulncheck(
            repo,
            args.timeout,
            args.govulncheck,
            profile_map=profile_map,
        )
    except FileNotFoundError:
        print(
            f"ERROR: {args.govulncheck} not found — go install "
            "golang.org/x/vuln/cmd/govulncheck@latest",
            file=sys.stderr,
        )
        return 1
    except subprocess.TimeoutExpired:
        print(f"ERROR: govulncheck exceeded {args.timeout}s", file=sys.stderr)
        return 1
    if not tool:
        print(
            f"ERROR: govulncheck produced no scan output (exit {rc}):\n{err.strip()[:2000]}",
            file=sys.stderr,
        )
        return 1

    summary = {lvl: 0 for lvl in REACH_ORDER}
    for c in candidates:
        summary[c["reachability"]] += 1

    doc = {
        "metadata": {
            "artifact": "govulncheck-reachability-candidates",
            "role": (
                "candidate generator — context for audit/triage agents; "
                "never a finding or verdict of record. 'not_observed' is "
                "not 'unreachable'."
            ),
            "harness_version": harness_version(),
            "tool": tool,
            "repository": str(repo),
            "commit": repo_head(repo),
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "invocation": " ".join(cmd),
        },
        "summary": {"osv_total": len(candidates), **summary},
        "candidates": candidates,
    }
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {out}")
    print(
        f"  {len(candidates)} advisories: "
        f"{summary['symbol_reachable']} symbol-reachable, "
        f"{summary['package_imported_not_observed']} imported-not-observed, "
        f"{summary['module_required_not_observed']} module-only"
    )
    return 0


GOVULNCHECK = OpSpec(
    add_args=add_govulncheck_args,
    call=call_govulncheck,
    help="Govulncheck reachability pre-scan for Go modules",
)


# ---------------------------------------------------------------------------
# checkov (K8s hardening / scan_k8s_hardening)
# ---------------------------------------------------------------------------


def add_checkov_args(ap) -> None:
    ap.add_argument("target", help="Checkout directory to scan.")
    ap.add_argument("-o", "--out", help="Output JSON (default: <basename>-k8s-hardening.json).")
    ap.add_argument(
        "--summary",
        action="store_true",
        help="Print per-check counts instead of writing JSON",
    )


def call_checkov(_engine, args) -> int:
    from traust_engine.adapters.checkov import Scanner

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    scanner = Scanner(target)
    scanner.run()
    report = scanner.report()
    if args.summary:
        print(f"scan_k8s_hardening: {len(report['results'])} fact(s)")
        for check, count in report.get("summary", {}).items():
            print(f"  {check}: {count}")
        return 0
    out = Path(args.out) if args.out else Path(f"{target.name}-k8s-hardening.json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"checkov: {len(report['results'])} fact(s) → {out}")
    return 0


CHECKOV = OpSpec(
    add_args=add_checkov_args,
    call=call_checkov,
    help="Kubernetes hardening pre-scan (KHS-* facts)",
)


# ---------------------------------------------------------------------------
# gitleaks
# ---------------------------------------------------------------------------


def add_gitleaks_args(ap) -> None:
    ap.add_argument("--repo", required=True, type=Path, help="Target clone")
    ap.add_argument("--out", type=Path, help="Output JSON (default: <repo>-gitleaks.json)")
    ap.add_argument(
        "--mode",
        choices=("dir", "history"),
        default="dir",
        help="dir = working tree; history = full git history",
    )
    ap.add_argument("--config", type=Path, help="gitleaks TOML (default: from context)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--gitleaks", default="gitleaks", help="gitleaks binary")


def call_gitleaks(engine, args) -> int:
    from traust_engine.adapters import gitleaks as gl

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    config = gl.resolve_gitleaks_config(args.config, engine.ctx.locations)
    try:
        raw = gl._run_gitleaks(repo, args.mode, config, args.timeout, args.gitleaks)
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    candidates = gl.parse_report(raw, repo, args.mode)
    doc = {
        "metadata": {
            "artifact": "gitleaks-secret-candidates",
            "mode": args.mode,
            "repository": str(repo),
            "head": gl.repo_head(repo),
            "gitleaks_version": gl.tool_version(args.gitleaks),
        },
        "candidates": candidates,
    }
    out = args.out or Path.cwd() / f"{repo.name}-gitleaks.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"gitleaks: {len(candidates)} candidate(s) → {out}")
    return 0


GITLEAKS = OpSpec(
    add_args=add_gitleaks_args,
    call=call_gitleaks,
    help="Gitleaks secret pre-scan candidate generator",
)


# ---------------------------------------------------------------------------
# osv-scanner
# ---------------------------------------------------------------------------


def add_osv_args(ap) -> None:
    ap.add_argument("--repo", required=True, type=Path, help="Target clone")
    ap.add_argument("--out", type=Path, help="Output JSON (default: <repo>-osv-scanner.json)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--osv-scanner", default="osv-scanner", help="osv-scanner binary")
    ap.add_argument(
        "--no-freeze",
        action="store_true",
        help="Allow osv-scanner to refresh its local DB during the scan",
    )


def call_osv(_engine, args) -> int:
    from traust_engine.adapters import osv as osv_mod

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    try:
        proc, invocation = osv_mod.run_scanner(
            args.osv_scanner,
            repo,
            args.timeout,
            freeze=not args.no_freeze,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if not proc.stdout.strip().startswith("{"):
        print(
            f"ERROR: osv-scanner produced no JSON (exit {proc.returncode}):\n"
            f"{(proc.stderr or proc.stdout).strip()[:2000]}",
            file=sys.stderr,
        )
        return 1
    scan_doc = json.loads(proc.stdout)
    candidates = osv_mod.parse_output(scan_doc, repo)
    tool_ver = (
        (scan_doc.get("experimental_config") or {}).get("version")
        or osv_mod._tool_version(args.osv_scanner)
        or ""
    )
    doc = {
        "metadata": {
            "artifact": "osv-scanner-dependency-candidates",
            "repository": str(repo),
            "tool": args.osv_scanner,
            "tool_version": tool_ver,
            "invocation": invocation,
        },
        "candidates": candidates,
    }
    out = args.out or Path.cwd() / f"{repo.name}-osv-scanner.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"osv: {len(candidates)} candidate(s) → {out}")
    return 0


OSV = OpSpec(
    add_args=add_osv_args,
    call=call_osv,
    help="OSV-scanner multi-ecosystem dependency-CVE candidates",
)


# ---------------------------------------------------------------------------
# yara
# ---------------------------------------------------------------------------


def add_yara_args(ap) -> None:
    ap.add_argument("target", help="Directory tree to scan (e.g. rootfs)")
    ap.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Rules source (path | git URL@SHA). Repeatable; default pack if omitted.",
    )
    ap.add_argument("--out", type=Path, help="Output JSON (default: <basename>-yara.json)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--yara", default="yara", help="yara binary")
    ap.add_argument("--max-file-mb", type=int, default=64)


def call_yara(_engine, args) -> int:
    from traust_engine.adapters import yara as yara_mod

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    try:
        report = yara_mod._execute_yara_scan(
            target,
            args.rules,
            timeout=args.timeout,
            yara_bin=args.yara,
            max_file_mb=args.max_file_mb,
        )
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    out = args.out or Path.cwd() / f"{target.name}-yara.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"yara: {len(report.get('facts', []))} fact(s) → {out}")
    return 0


YARA = OpSpec(
    add_args=add_yara_args,
    call=call_yara,
    help="YARA known-malware-family signature pre-scan",
)


# ---------------------------------------------------------------------------
# joern reachability
# ---------------------------------------------------------------------------


def add_joern_args(ap) -> None:
    ap.add_argument("--repo", required=True, type=Path, help="Repository root")
    ap.add_argument("--out", required=True, type=Path, help="Output JSON artifact")
    ap.add_argument("--language", choices=("java", "c"), default="java")
    ap.add_argument(
        "--symbols",
        nargs="*",
        default=[],
        help="Vulnerable symbols (Java class#method or C function names)",
    )
    ap.add_argument(
        "--packages",
        default="",
        help="Comma-separated package prefixes to match",
    )
    ap.add_argument("--module", default="", help="Maven module id for package derivation")
    ap.add_argument("--timeout", type=int, default=1200)
    ap.add_argument("--max-sites", type=int, default=200)


def call_joern(_engine, args) -> int:
    from traust_engine.adapters import joern as joern_mod

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    doc = joern_mod._run_joern_scan(
        repo,
        symbols=list(args.symbols) or None,
        timeout=args.timeout,
        max_sites=args.max_sites,
        language=args.language,
        packages=args.packages,
        module=args.module,
    )
    joern_mod.emit(args.out, doc)
    return 0


JOERN = OpSpec(
    add_args=add_joern_args,
    call=call_joern,
    help="Joern call-site reachability facts (Java/C)",
)


# ---------------------------------------------------------------------------
# crypto-probe
# ---------------------------------------------------------------------------


def add_crypto_probe_args(ap) -> None:
    ap.add_argument("--repo-dir", required=True, type=Path, help="Repository root")
    ap.add_argument("-o", "--out", type=Path, help="Write JSON facts (default: stdout)")
    ap.add_argument("--json", action="store_true", help="Emit JSON (default when -o omitted)")


def call_crypto_probe(_engine, args) -> int:
    from dataclasses import asdict

    from traust_engine.adapters import crypto_probe as cp

    repo = args.repo_dir.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    facts = [asdict(f) for f in cp.probe_repo(repo)]
    payload = json.dumps(facts, indent=2) + "\n"
    if args.out:
        args.out.write_text(payload, encoding="utf-8")
        print(f"crypto-probe: {len(facts)} fact(s) → {args.out}")
    else:
        print(payload, end="")
    return 0


CRYPTO_PROBE = OpSpec(
    add_args=add_crypto_probe_args,
    call=call_crypto_probe,
    help="Source-level crypto provider census (CRYPTO_* facts)",
)


# ---------------------------------------------------------------------------
# crypto-audit (source | image | cluster)
# ---------------------------------------------------------------------------


def add_crypto_audit_args(ap) -> None:
    sub = ap.add_subparsers(dest="crypto_audit_cmd", required=True)

    src = sub.add_parser("source", help="Source-level repo crypto census")
    src.add_argument("path", type=Path, help="Repository root directory")
    src.add_argument("--from-sbom", type=Path, default=None, help="Optional CycloneDX SBOM")
    _add_crypto_audit_common(src)

    img = sub.add_parser("image", help="Container image structural data extraction")
    img.add_argument("image", help="Container image reference")
    img.add_argument(
        "--runtime",
        choices=["podman", "docker"],
        default="",
        help="Container runtime (auto-detected if omitted)",
    )
    img.add_argument("--platform", default="", help="Platform override (e.g. linux/arm64)")
    img.add_argument("--no-pull", action="store_true", help="Skip image pull")
    _add_crypto_audit_common(img)

    cl = sub.add_parser("cluster", help="Runtime cluster data collection via oc")
    cl.add_argument("--context", required=True, help="Kubeconfig context name")
    cl.add_argument(
        "--namespaces",
        nargs="+",
        required=True,
        help="Namespaces to probe",
    )
    cl.add_argument(
        "--targets",
        required=True,
        type=Path,
        help="Mode-1 rules-of-engagement targets.yaml for scope gating",
    )
    cl.add_argument(
        "--discover",
        action="store_true",
        help="Enumerate services in namespaces and probe each for TLS",
    )
    cl.add_argument(
        "--groups",
        default="",
        help="TLS groups to offer (e.g. X25519MLKEM768:X25519)",
    )
    _add_crypto_audit_common(cl)


def _add_crypto_audit_common(ap) -> None:
    ap.add_argument("--component", default="", help="Component name for governance chain keying")
    ap.add_argument("--output", "-o", default="", help="Write JSON to file (default: stdout)")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress on stderr")


def call_crypto_audit(_engine, args) -> int:
    from traust_engine.adapters import crypto_audit as ca

    out = Path(args.output) if args.output else None
    if args.crypto_audit_cmd == "source":
        return ca.audit_source(
            args.path,
            from_sbom=args.from_sbom,
            component=args.component,
            output=out,
            quiet=args.quiet,
        )
    if args.crypto_audit_cmd == "image":
        return ca.audit_image(
            args.image,
            runtime=args.runtime,
            platform=args.platform,
            no_pull=args.no_pull,
            component=args.component,
            output=out,
            quiet=args.quiet,
        )
    return ca.audit_cluster(
        args.context,
        args.namespaces,
        targets=args.targets,
        discover=args.discover,
        groups=args.groups,
        component=args.component,
        output=out,
        quiet=args.quiet,
    )


CRYPTO_AUDIT = OpSpec(
    add_args=add_crypto_audit_args,
    call=call_crypto_audit,
    help="Crypto data collector (source | image | cluster)",
)
