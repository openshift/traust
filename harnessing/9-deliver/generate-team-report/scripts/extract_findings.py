#!/usr/bin/env python3
"""Extract CVSS-scored findings from security audit Markdown reports.

Usage:
    python3 extract_findings.py <dir1> [<dir2> ...] [--product-map 'dir1=Name1,dir2=Name2']

Scans each directory recursively for *-security-audit.md files, parses CVSS
lines, and emits a JSON summary to stdout.

Component dirs holding several audit files (main + release-branch re-audits)
resolve deterministically: the slug matching the dir name wins, then any
non-'__' slug. Branch-variant components (name contains '__') are excluded
from all counts and listed under "branch_variants" instead.

Output schema:
{
  "unique_components": int,          # branch variants excluded
  "branch_variants": [str],          # '__'-named re-audit dirs, not counted
  "totals": {"c": int, "h": int, "m": int, "l": int, "i": int, "total": int},
  "products": {"Name": {"c":..., "h":..., "m":..., "l":..., "i":..., "comps": int}},
  "critical": [{"score": float, "comp": str, "prod": str, "find_id": str, "title": str}],
  "high":     [same shape],
  "all":      [same shape, all severities]
}
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dirs", nargs="+", help="Directories to scan")
    p.add_argument(
        "--product-map",
        default="",
        help="Comma-separated dir=ProductName pairs, e.g. 'rhacm=RHACM,mce=MCE'",
    )
    return p.parse_args()


def build_product_map(raw: str, dirs: list[str]) -> dict[str, str]:
    mapping = {}
    if raw:
        for pair in raw.split(","):
            k, v = pair.strip().split("=", 1)
            mapping[k.strip()] = v.strip()
    for d in dirs:
        base = Path(d.rstrip("/")).name
        if base not in mapping:
            mapping[base] = base
    return mapping


def extract(dirs: list[str], prod_map: dict[str, str]):
    components: dict[tuple[str, str], dict] = {}
    for d in dirs:
        if not Path(d).is_dir():
            print(f"WARNING: {d} is not a directory, skipping", file=sys.stderr)
            continue
        base = Path(d.rstrip("/")).name
        prod = prod_map.get(base, base)
        for root, _subdirs, files in os.walk(d):
            audits = sorted(f for f in files if f.endswith("-security-audit.md"))
            if not audits:
                continue
            comp = Path(root).name

            # A dir can hold the main audit plus release-branch re-audits of the
            # same code (slug contains '__', e.g. foo__release-5.1-security-audit.md).
            # Prefer the audit whose slug matches the dir name, then any
            # non-branch-variant slug; never pick by filesystem walk order.
            def slug_of(f):
                return f[: -len("-security-audit.md")]

            preferred = (
                [f for f in audits if slug_of(f) == comp]
                or [f for f in audits if "__" not in slug_of(f)]
                or audits
            )
            fp = Path(root) / preferred[0]
            key = (prod, comp)
            if key not in components:
                components[key] = {
                    "product": prod,
                    "dir": base,
                    "file": fp,
                    "comp": comp,
                    # branch-variant *dirs* (console__release-2.14/…) are re-audits
                    # of one component; callers should exclude them from totals.
                    "branch_variant": "__" in comp,
                }

    all_findings = []
    product_counts: dict[str, dict] = {}

    branch_variants = sorted(i["comp"] for i in components.values() if i["branch_variant"])

    for _key, info in sorted(components.items()):
        if info["branch_variant"]:
            continue  # re-audit of the same code on a release branch — coverage, not new findings
        comp = info["comp"]
        prod = info["product"]
        fp = info["file"]
        with Path.open(fp) as fh:
            content = fh.read()

        if prod not in product_counts:
            product_counts[prod] = {"c": 0, "h": 0, "m": 0, "l": 0, "i": 0, "comps": 0}
        product_counts[prod]["comps"] += 1

        for line in content.split("\n"):
            if "CVSS" not in line:
                continue
            cleaned = re.sub(r"v3\.\d+", "vXX", line)
            scores = [
                float(s)
                for s in re.findall(r"(?<![/v])(\d+\.\d+)", cleaned)
                if 1.0 <= float(s) <= 10.0
            ]
            if not scores:
                continue
            score = max(scores)

            sev_match = re.search(
                r"\b(Critical|High|Medium|Low|Informational)\b", line, re.IGNORECASE
            )
            if sev_match:
                sev = sev_match.group(1).capitalize()
            else:
                if score >= 9.0:
                    sev = "Critical"
                elif score >= 7.0:
                    sev = "High"
                elif score >= 4.0:
                    sev = "Medium"
                elif score >= 0.1:
                    sev = "Low"
                else:
                    sev = "Informational"

            pos = content.find(line)
            preceding = content[:pos]
            find_match = list(
                re.finditer(
                    r"###\s+(FIND-\d+|FND-\d+|KC-\d+|OCM-\d+)\s*[—-]\s*(.*?)$",
                    preceding,
                    re.MULTILINE,
                )
            )
            find_id = find_match[-1].group(1) if find_match else "?"
            title = find_match[-1].group(2).strip()[:150] if find_match else "?"

            entry = {
                "score": score,
                "sev": sev,
                "comp": comp,
                "prod": prod,
                "find_id": find_id,
                "title": title,
            }
            all_findings.append(entry)

            s = sev.lower()[0]
            product_counts[prod][s] += 1

    tc = sum(v["c"] for v in product_counts.values())
    th = sum(v["h"] for v in product_counts.values())
    tm = sum(v["m"] for v in product_counts.values())
    tl = sum(v["l"] for v in product_counts.values())
    ti = sum(v["i"] for v in product_counts.values())

    return {
        "unique_components": len(components) - len(branch_variants),
        "branch_variants": branch_variants,
        "totals": {"c": tc, "h": th, "m": tm, "l": tl, "i": ti, "total": tc + th + tm + tl + ti},
        "products": product_counts,
        "critical": sorted(
            [f for f in all_findings if f["sev"] == "Critical"], key=lambda x: -x["score"]
        ),
        "high": sorted([f for f in all_findings if f["sev"] == "High"], key=lambda x: -x["score"]),
        "all": all_findings,
    }


def main():
    args = parse_args()
    prod_map = build_product_map(args.product_map, args.dirs)
    data = extract(args.dirs, prod_map)
    json.dump(data, sys.stdout, indent=2)
    print()  # trailing newline


if __name__ == "__main__":
    main()
