#!/usr/bin/env python3
"""Deterministic fix-propagation check for cross-repo remediations.

When a finding's fix lands in a DIFFERENT repository (upstream library,
vendored dependency, base image), the finding is not resolved until the
ORIGINAL repo consumes the fixed version. This script answers that one
question deterministically: given the original repo's checkout and the
fixed module@version, is the fix consumed?

Checks, in evidence order:
  1. Go: go.mod require lines + vendor/modules.txt pins
  2. Manifest ecosystems: lockfile pins via the run_impact_analysis
     extractors (requirements/Pipfile.lock/poetry.lock, Cargo.lock,
     package-lock.json/yarn.lock, pom.xml/gradle)
  3. Optional: shipped-image SBOMs (--sbom-glob) for what is delivered

Output (JSON to stdout, and --out if given):
  {"propagation": "consumed" | "pending" | "module_absent",
   "checked": [ {source, version, in_range_of_fix} ... ]}

'module_absent' is NOT automatically 'consumed': removal usually fixes,
but the verifier judges (the dependency may have been vendored under a
different name). Never auto-resolve from this script's output alone.

Usage:
  check_fix_propagation.py --repo-dir /tmp/repo \
      --module golang.org/x/net --fixed-version v0.17.0 \
      [--sbom-glob 'analysis-results/graph/sboms/*.cdx.json'] [--out f.json]

Exit 0 = ran (any propagation state); 2 = usage error.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

from traust_engine.impact.analyzer import (
    JavaAnalyzer,
    JavaScriptAnalyzer,
    PythonAnalyzer,
    RustAnalyzer,
    parse_semver,
)

_GOMOD_REQ_RX = re.compile(r"^\s*(?:require\s+)?([\w./-]+)\s+(v[\w.+-]+)", re.M)
_VENDOR_RX = re.compile(r"^# ([\w./-]+) (v[\w.+-]+)", re.M)


def _consumed(version: str, fixed: str) -> bool | None:
    ver, fix = parse_semver(version), parse_semver(fixed)
    if ver is None or fix is None:
        return None
    return ver >= fix


def check_go(repo: Path, module: str, fixed: str) -> list[dict]:
    out = []
    for rel, rx in (("go.mod", _GOMOD_REQ_RX), ("vendor/modules.txt", _VENDOR_RX)):
        f = repo / rel
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in rx.finditer(text):
            if m.group(1) == module:
                ver = m.group(2)
                out.append({"source": rel, "version": ver, "consumed": _consumed(ver, fixed)})
    return out


_MANIFEST_ANALYZERS = (
    (PythonAnalyzer(), ("requirements*.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml")),
    (RustAnalyzer(), ("Cargo.lock",)),
    (JavaScriptAnalyzer(), ("package-lock.json", "yarn.lock", "package.json")),
    (JavaAnalyzer(), ("pom.xml", "build.gradle", "build.gradle.kts")),
)


def check_manifests(repo: Path, module: str, fixed: str) -> list[dict]:
    out = []
    names = {module.lower(), module.rpartition(":")[2].lower(), module.rpartition("/")[2].lower()}
    for analyzer, globs in _MANIFEST_ANALYZERS:
        for g in globs:
            for mf in sorted(repo.rglob(g)):
                if any(p in ("vendor", "node_modules", ".git") for p in mf.parts):
                    continue
                try:
                    text = mf.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for name, ver in analyzer.extract_pins(mf.name, text).items():
                    if name.lower() in names:
                        out.append(
                            {
                                "source": str(mf.relative_to(repo)),
                                "version": ver,
                                "consumed": _consumed(ver, fixed),
                            }
                        )
    return out


def check_sboms(sbom_glob: str, module: str, fixed: str) -> list[dict]:
    out = []
    module_l = module.lower()
    for f in sorted(glob.glob(sbom_glob)):  # noqa: PTH207
        try:
            sbom = json.loads(Path(f).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for comp in sbom.get("components") or []:
            name = (comp.get("name") or "").lower()
            purl = (comp.get("purl") or "").lower()
            if module_l == name or module_l in purl:
                ver = comp.get("version") or ""
                out.append(
                    {
                        "source": f"sbom:{Path(f).name}",
                        "version": ver,
                        "consumed": _consumed(ver, fixed),
                    }
                )
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--repo-dir", required=True, help="Checkout of the ORIGINAL (consuming) repository"
    )
    ap.add_argument("--module", required=True)
    ap.add_argument("--fixed-version", required=True)
    ap.add_argument(
        "--sbom-glob", default=None, help="Optional glob of CycloneDX SBOMs of shipped images"
    )
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    repo = Path(args.repo_dir)
    if not repo.is_dir():
        print(f"repo-dir not found: {repo}", file=sys.stderr)
        return 2

    checked = check_go(repo, args.module, args.fixed_version)
    checked += check_manifests(repo, args.module, args.fixed_version)
    if args.sbom_glob:
        checked += check_sboms(args.sbom_glob, args.module, args.fixed_version)

    if not checked:
        propagation = "module_absent"
    elif all(c["consumed"] for c in checked if c["consumed"] is not None) and any(
        c["consumed"] for c in checked
    ):
        propagation = "consumed"
    else:
        propagation = "pending"

    result = {
        "module": args.module,
        "fixed_version": args.fixed_version,
        "propagation": propagation,
        "checked": checked,
    }
    text = json.dumps(result, indent=1)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["check", "fix-propagation", *sys.argv[1:]]))
