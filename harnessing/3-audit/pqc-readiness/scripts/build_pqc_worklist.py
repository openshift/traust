#!/usr/bin/env python3
"""Build the PQC sweep worklist: one entry per UNIQUE repository URL.

Sources:
  * every canonical *security-audit.json under analysis-results/findings/
    (repository URLs normalized via corpus.normalize_repo_url)
  * the PQC unreachable-triage manifest (recovered URLs join scope; residual
    entries are emitted with route=sbom-only / access-request)

Priority ordering (plan Section 7): crypto chokepoints first (PKI/CA, auth
stacks, signing/release infra), then repos whose audits carry crypto-class
CWE findings (ground-truth in-scope), then the long tail.

Writes findings/_manifest/pqc-worklist.{json,md}.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from traust_engine.corpus.resolver import normalize_repo_url

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)

CRYPTO_CWES = {
    "CWE-256",
    "CWE-259",
    "CWE-261",
    "CWE-295",
    "CWE-296",
    "CWE-297",
    "CWE-310",
    "CWE-311",
    "CWE-312",
    "CWE-319",
    "CWE-321",
    "CWE-322",
    "CWE-323",
    "CWE-324",
    "CWE-325",
    "CWE-326",
    "CWE-327",
    "CWE-328",
    "CWE-329",
    "CWE-330",
    "CWE-331",
    "CWE-335",
    "CWE-338",
    "CWE-347",
    "CWE-522",
    "CWE-540",
    "CWE-547",
    "CWE-757",
    "CWE-798",
    "CWE-916",
    "CWE-1240",
}
CHOKEPOINT_RX = re.compile(
    r"(oauth-proxy|kube-rbac-proxy|keycloak|authorino|cert-manager|"
    r"service-ca|cluster-ingress|certman|ingress-operator|router|haproxy|"
    r"sigstore|cosign|chains|recert|openssl|crypto|vault|pki|ca-operator|"
    r"sso|dex|oauth)",
    re.I,
)


def crypto_cwe_hit(report: dict) -> bool:
    for f in report.get("findings", []):
        for c in f.get("cwes") or []:
            cid = c if isinstance(c, str) else (c.get("id") or "")
            if str(cid).upper().split(":")[0].strip() in CRYPTO_CWES:
                return True
    return False


def main():
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--analysis-results", type=Path, default=None)
    args = ap.parse_args()

    engine = load_engine(args.config_home)
    ar = args.analysis_results.resolve() if args.analysis_results else analysis_results_dir(engine)
    findings = ar / "findings"
    if not findings.is_dir():
        raise SystemExit(f"findings/ not found under {ar}")

    repos: dict[str, dict] = {}
    seen_real = set()
    for aj in sorted(findings.rglob("*security-audit.json")):
        if aj.is_symlink() or "_manifest" in aj.parts:
            continue
        real = aj.resolve()
        if real in seen_real:
            continue
        seen_real.add(real)
        base = aj.name.removesuffix("-security-audit.json")
        if "__" in base:
            continue
        try:
            rep = json.loads(aj.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        url = normalize_repo_url((rep.get("metadata") or {}).get("repository"))
        if not url:
            continue
        e = repos.setdefault(
            url,
            {
                "repository": url,
                "filings": [],
                "crypto_cwe_ground_truth": False,
                "chokepoint": bool(CHOKEPOINT_RX.search(url)),
            },
        )
        e["filings"].append(str(aj.parent.relative_to(ar)))
        if not e["crypto_cwe_ground_truth"] and crypto_cwe_hit(rep):
            e["crypto_cwe_ground_truth"] = True

    triage_p = findings / "_manifest" / "pqc-unreachable-triage.json"
    residual = []
    if triage_p.exists():
        triage = json.loads(triage_p.read_text())
        for t in triage.get("entries", []):
            cls = t.get("class", "")
            if cls in ("recovered_by_normalization", "recovered_via_graph"):
                continue  # normalized URLs already resolve via audits
            residual.append(
                {
                    "repository": t.get("normalized") or t.get("repository"),
                    "class": cls,
                    "filing_count": t.get("filing_count", 0),
                    "route": ("access-request" if cls == "access_denied" else "sbom-only"),
                }
            )

    def tier(e):
        if e["chokepoint"]:
            return 0
        if e["crypto_cwe_ground_truth"]:
            return 1
        return 2

    worklist = sorted(repos.values(), key=lambda e: (tier(e), -len(e["filings"]), e["repository"]))
    for e in worklist:
        e["priority_tier"] = (
            "chokepoint"
            if e["chokepoint"]
            else "crypto-cwe"
            if e["crypto_cwe_ground_truth"]
            else "tail"
        )

    doc = {
        "artifact": "pqc-worklist",
        "generated_from": str(ar),
        "summary": {
            "unique_repos": len(worklist),
            "chokepoint": sum(1 for e in worklist if e["priority_tier"] == "chokepoint"),
            "crypto_cwe": sum(1 for e in worklist if e["priority_tier"] == "crypto-cwe"),
            "tail": sum(1 for e in worklist if e["priority_tier"] == "tail"),
            "residual_unreachable": len(residual),
        },
        "worklist": worklist,
        "residual": residual,
    }
    out = findings / "_manifest" / "pqc-worklist.json"
    out.write_text(json.dumps(doc, indent=1))
    md = [
        "# PQC sweep worklist",
        "",
        f"- Unique repos: **{doc['summary']['unique_repos']}** "
        f"(chokepoint {doc['summary']['chokepoint']} / crypto-cwe "
        f"{doc['summary']['crypto_cwe']} / tail {doc['summary']['tail']})",
        f"- Residual unreachable routed sbom-only/access-request: {len(residual)}",
    ]
    (findings / "_manifest" / "pqc-worklist.md").write_text("\n".join(md) + "\n")
    print(f"[+] wrote {out}")
    print(f"[+] {json.dumps(doc['summary'])}")


if __name__ == "__main__":
    main()
