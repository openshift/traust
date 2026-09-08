#!/usr/bin/env python3
"""Normalize external scanner output into the triage findings container.

The /triage skill's generic ingestion rules (SKILL.md Phase 1a) handle
flat JSON shapes; this script deterministically normalizes the three
formats those rules cannot trivially parse (SARIF plan P1,;
progress-tracker/plans/sarif-integration-plan.md):

1. SARIF 2.x — from ANY producer: CodeQL, Semgrep, Snyk, Trivy, Bandit,
   Coverity 2023+, and the harness's own deterministic tools when run
   standalone with SARIF output (opengrep `--sarif`, gitleaks
   `-f sarif`, osv-scanner `--format sarif`, checkov `-o sarif`,
   grype `-o sarif`, govulncheck `-format sarif`).
2. Dependabot alerts JSON — the GitHub REST export
   (`/repos/{o}/{r}/dependabot/alerts`), an array of alert objects.
3. govulncheck native `-json` stream — concatenated JSON records
   (config/osv/finding), the same shape `traust adapters govulncheck`
   consumes.

Output is `{"metadata": …, "findings": […]}` with triage's canonical
field names (file, line, category, severity, title, description,
recommendation, cwes, orig_id) — the container Phase 1a already
recognizes. Everything here is a machine-static CLAIM under the
track-findings trust policy: normalization never sets a verdict, and
triage's adversarial N-vote applies to every finding regardless of the
producing tool's asserted level.

Stdlib only; no subprocess, no network. Usage:

    python3 harnessing/4-triage/triage/scripts/normalize_input.py <input> [<input> ...]
    python3 harnessing/4-triage/triage/scripts/normalize_input.py alerts.json -o out.json
    python3 harnessing/4-triage/triage/scripts/normalize_input.py scan.sarif --include-suppressed
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# SARIF level / security-severity -> harness severity
# (inverse of `traust reporting sarif`; sarif-integration-plan.md table)
_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "informational",
    "none": "informational",
}
_CWE_RX = re.compile(r"cwe[-/](\d+)", re.IGNORECASE)


def _sec_sev_to_severity(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def _cwes(*tag_lists) -> list[str]:
    out: list[str] = []
    for tags in tag_lists:
        for tag in tags or []:
            m = _CWE_RX.search(str(tag))
            if m and f"CWE-{m.group(1)}" not in out:
                out.append(f"CWE-{m.group(1)}")
    return out


# ---------------------------------------------------------------------------
# arm 1: SARIF 2.x
# ---------------------------------------------------------------------------


def is_sarif(doc) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("runs"), list)
        and str(doc.get("version", "")).startswith("2.")
    )


def _sarif_rule(run: dict, result: dict) -> dict:
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = driver.get("rules") or []
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    rid = result.get("ruleId")
    for pool in [rules] + [
        (e.get("rules") or []) for e in (run.get("tool") or {}).get("extensions") or []
    ]:
        for r in pool:
            if r.get("id") == rid:
                return r
    return {}


def _sarif_location(result: dict) -> tuple[str | None, int | None]:
    for loc in result.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        uri = (phys.get("artifactLocation") or {}).get("uri")
        if uri:
            line = (phys.get("region") or {}).get("startLine")
            return uri, line
        for logical in loc.get("logicalLocations") or []:
            name = logical.get("fullyQualifiedName") or logical.get("name")
            if name:
                return name, None
    return None, None


def normalize_sarif(doc: dict, include_suppressed: bool) -> dict:
    findings, tools, suppressed = [], [], 0
    for run in doc.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name") or "unknown-sarif-producer"
        tools.append(
            {"name": tool_name, "version": driver.get("version") or driver.get("semanticVersion")}
        )
        for result in run.get("results") or []:
            if result.get("suppressions") and not include_suppressed:
                suppressed += 1
                continue
            rule = _sarif_rule(run, result)
            rule_props = rule.get("properties") or {}
            res_props = result.get("properties") or {}
            sec_sev = res_props.get("security-severity") or rule_props.get("security-severity")
            if sec_sev is not None:
                try:
                    severity = _sec_sev_to_severity(float(sec_sev))
                except (TypeError, ValueError):
                    severity = None
            else:
                severity = None
            if severity is None:
                # SARIF spec default level is "warning"
                severity = _LEVEL_TO_SEVERITY.get(result.get("level", "warning"), "medium")

            file, line = _sarif_location(result)
            title = (
                (rule.get("shortDescription") or {}).get("text")
                or result.get("ruleId")
                or "(untitled)"
            )
            description = (result.get("message") or {}).get("text") or ""
            full = (rule.get("fullDescription") or {}).get("text")
            if full and full not in description:
                description = f"{description}\n\n{full}".strip()

            finding = {
                "source_tool": tool_name,
                "source_format": "sarif",
                "orig_id": result.get("guid")
                or (result.get("partialFingerprints") or {}).get("harnessFindingId/v1"),
                "category": result.get("ruleId"),
                "severity": severity,
                "title": title,
                "description": description,
                "file": file,
                "line": line,
                "cwes": _cwes(rule_props.get("tags"), res_props.get("tags")),
                "recommendation": (rule.get("help") or {}).get("text"),
                "sarif_fingerprints": result.get("partialFingerprints") or None,
            }
            precision = rule_props.get("precision")
            if precision:  # CodeQL convention
                finding["scanner_confidence"] = {
                    "very-high": 0.95,
                    "high": 0.85,
                    "medium": 0.6,
                    "low": 0.4,
                }.get(precision)
            findings.append({k: v for k, v in finding.items() if v not in (None, [], {})})
    return {"tools": tools, "findings": findings, "suppressed_skipped": suppressed}


# ---------------------------------------------------------------------------
# arm 2: Dependabot alerts (GitHub REST export)
# ---------------------------------------------------------------------------


def is_dependabot(doc) -> bool:
    return (
        isinstance(doc, list)
        and bool(doc)
        and all(isinstance(a, dict) and "security_advisory" in a for a in doc)
    )


def normalize_dependabot(alerts: list) -> dict:
    findings = []
    for alert in alerts:
        adv = alert.get("security_advisory") or {}
        vuln = alert.get("security_vulnerability") or {}
        dep = alert.get("dependency") or {}
        pkg = dep.get("package") or {}
        ids = [adv.get("ghsa_id"), adv.get("cve_id")]
        fixed = (vuln.get("first_patched_version") or {}).get("identifier")
        finding = {
            "source_tool": "dependabot",
            "source_format": "dependabot-alerts",
            "orig_id": adv.get("ghsa_id") or f"dependabot-{alert.get('number')}",
            "category": "supply-chain",
            "severity": (vuln.get("severity") or adv.get("severity") or "").lower() or None,
            "title": adv.get("summary") or f"Vulnerable dependency {pkg.get('name')}",
            "description": "\n".join(
                filter(
                    None,
                    [
                        adv.get("description"),
                        f"Package: {pkg.get('ecosystem')}/{pkg.get('name')} "
                        f"({vuln.get('vulnerable_version_range', 'range unknown')})",
                        f"Identifiers: {', '.join(i for i in ids if i)}" if any(ids) else None,
                        f"Alert state: {alert.get('state')}" if alert.get("state") else None,
                    ],
                )
            ),
            "file": dep.get("manifest_path"),
            "cwes": [c.get("cwe_id") for c in adv.get("cwes") or [] if c.get("cwe_id")],
            "recommendation": f"Upgrade to {fixed} or later." if fixed else None,
        }
        findings.append({k: v for k, v in finding.items() if v not in (None, [], {})})
    return {"tools": [{"name": "dependabot"}], "findings": findings, "suppressed_skipped": 0}


# ---------------------------------------------------------------------------
# arm 3: govulncheck native -json stream (concatenated JSON records)
# ---------------------------------------------------------------------------


def iter_json_stream(text: str):
    decoder = json.JSONDecoder()
    pos, n = 0, len(text)
    while pos < n:
        while pos < n and text[pos] in " \t\r\n":
            pos += 1
        if pos >= n:
            break
        try:
            obj, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        yield obj


def looks_like_govulncheck_stream(text: str) -> bool:
    records = []
    for i, rec in enumerate(iter_json_stream(text)):
        records.append(rec)
        if i >= 4:
            break
    return bool(records) and all(
        isinstance(r, dict) and any(k in r for k in ("config", "progress", "osv", "finding"))
        for r in records
    )


def normalize_govulncheck(text: str) -> dict:
    tool = {"name": "govulncheck"}
    osv_meta: dict[str, dict] = {}
    by_osv: dict[str, dict] = {}
    for rec in iter_json_stream(text):
        if not isinstance(rec, dict):
            continue
        if "config" in rec:
            cfg = rec["config"]
            tool = {
                "name": cfg.get("scanner_name", "govulncheck"),
                "version": cfg.get("scanner_version"),
                "db": cfg.get("db"),
            }
        elif "osv" in rec:
            osv = rec["osv"]
            osv_meta[osv.get("id", "")] = osv
        elif "finding" in rec:
            f = rec["finding"]
            osv_id = f.get("osv")
            if not osv_id:
                continue
            trace = f.get("trace") or []
            frame = trace[0] if trace else {}
            entry = by_osv.setdefault(
                osv_id,
                {
                    "frame": frame,
                    "fixed": f.get("fixed_version"),
                    "symbol_reachable": False,
                    "modules": set(),
                },
            )
            # a trace ending in a function = called-symbol evidence —
            # the strongest reachability govulncheck reports
            if frame.get("function"):
                entry["symbol_reachable"] = True
                entry["frame"] = frame
            if frame.get("module"):
                entry["modules"].add(f"{frame['module']}@{frame.get('version', '?')}")

    findings = []
    for osv_id, entry in by_osv.items():
        osv = osv_meta.get(osv_id, {})
        aliases = [a for a in osv.get("aliases") or [] if a]
        frame = entry["frame"]
        pos = frame.get("position") or {}
        reach = "symbol_reachable" if entry["symbol_reachable"] else "module_present"
        finding = {
            "source_tool": "govulncheck",
            "source_format": "govulncheck-json",
            "orig_id": osv_id,
            "category": "supply-chain",
            "title": f"{osv_id}: {osv.get('summary') or 'vulnerable Go dependency'}",
            "description": "\n".join(
                filter(
                    None,
                    [
                        (osv.get("details") or "")[:800] or None,
                        f"Aliases: {', '.join(aliases)}" if aliases else None,
                        f"Modules: {', '.join(sorted(entry['modules']))}"
                        if entry["modules"]
                        else None,
                        f"Reachability: {reach} (govulncheck call-graph evidence; "
                        f"symbol_reachable means a vulnerable symbol is on a "
                        f"called path)",
                    ],
                )
            ),
            "file": pos.get("filename"),
            "line": pos.get("line"),
            "reachability": reach,
            "recommendation": f"Upgrade to {entry['fixed']} or later." if entry["fixed"] else None,
        }
        findings.append({k: v for k, v in finding.items() if v not in (None, [], {})})
    return {"tools": [tool], "findings": findings, "suppressed_skipped": 0}


# ---------------------------------------------------------------------------


def normalize_path(path: Path, include_suppressed: bool) -> dict | None:
    text = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if doc is not None and is_sarif(doc):
        return normalize_sarif(doc, include_suppressed)
    if doc is not None and is_dependabot(doc):
        return normalize_dependabot(doc)
    if doc is None and looks_like_govulncheck_stream(text):
        return normalize_govulncheck(text)
    # single-record streams parse as plain JSON too
    if (
        doc is not None
        and isinstance(doc, dict)
        and any(k in doc for k in ("config", "osv", "finding"))
    ):
        return normalize_govulncheck(text)
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="SARIF file(s), Dependabot alerts JSON, or govulncheck -json stream",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        help="output path (single input only; default: <input stem>-normalized-findings.json)",
    )
    parser.add_argument(
        "--include-suppressed",
        action="store_true",
        help="keep SARIF results that carry suppressions (default: skip and count them)",
    )
    args = parser.parse_args(argv)

    if args.out and len(args.inputs) > 1:
        print("ERROR: -o/--out requires exactly one input", file=sys.stderr)
        return 2

    rc = 0
    for path in args.inputs:
        try:
            normalized = normalize_path(path, args.include_suppressed)
        except OSError as e:
            print(f"ERROR: cannot read {path}: {e}", file=sys.stderr)
            rc = 1
            continue
        if normalized is None:
            print(
                f"ERROR: {path}: not a recognized format (SARIF 2.x, "
                "Dependabot alerts, or govulncheck -json stream) — "
                "triage's generic Phase 1a rules may still apply",
                file=sys.stderr,
            )
            rc = 1
            continue
        out_doc = {
            "metadata": {
                "source": str(path),
                "normalizer": "harnessing/4-triage/triage/scripts/normalize_input.py",
                "tools": normalized["tools"],
                "suppressed_skipped": normalized["suppressed_skipped"],
                "trust_note": "machine-static claims under the "
                "track-findings trust policy; every finding "
                "still gets triage's adversarial N-vote",
            },
            "findings": normalized["findings"],
        }
        stem = path.name[: -len(path.suffix)] if path.suffix else path.name
        out = args.out or path.with_name(f"{stem}-normalized-findings.json")
        out.write_text(json.dumps(out_doc, indent=2) + "\n", encoding="utf-8")
        n = len(normalized["findings"])
        skipped = normalized["suppressed_skipped"]
        note = f", {skipped} suppressed skipped" if skipped else ""
        print(f"wrote {out} ({n} finding{'s' if n != 1 else ''}{note})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
