#!/usr/bin/env python3
"""Operator privilege profile — static least-privilege inventory (tiers 1-2).

Tier 1: parse every manifest/CSV in an operator repo and persist what the
operator ASKS FOR: SCC requests (RBAC `use` on securitycontextconstraints
+ shipped SCC objects), per-container securityContext, namespaces/install
modes, and the COMPLETE RBAC rule enumeration (not just over-grants).

Tier 2: diff the shipped RBAC against the code's declared requirements
(`+kubebuilder:rbac:` markers) — shipped-but-not-declared rules are the
least-privilege surplus candidates.

Runtime truth (which SCC is actually applied) is tier 3:
capture_runtime_privileges.py, executed separately against a live cluster.

Usage:
  build_priv_profile.py --repo <checkout> --name <repo-name> --out-dir <dir>
  build_priv_profile.py --repo-url <url> [--ref <ref>] --name <n> --out-dir <dir>
  build_priv_profile.py --rollup <profiles-glob> --rollup-out <dir>
"""

from __future__ import annotations

import argparse
import glob as globmod
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml required (run under the harness venv)", file=sys.stderr)
    raise

SKIP_DIRS = {"vendor", "node_modules", ".git", "third_party", "testdata"}
EXAMPLE_DIRS = {
    "test",
    "tests",
    "e2e",
    "examples",
    "example",
    "samples",
    "sample",
    "docs",
    "doc",
    "demo",
    "hack",
    "dev",
}


def _is_example(rel: Path) -> bool:
    return bool(EXAMPLE_DIRS.intersection(part.lower() for part in rel.parts[:-1]))


WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
SC_FIELDS = (
    "privileged",
    "allowPrivilegeEscalation",
    "runAsNonRoot",
    "runAsUser",
    "readOnlyRootFilesystem",
    "seccompProfile",
    "capabilities",
)
KB_RBAC_RX = re.compile(r"^\s*//\s*\+kubebuilder:rbac:(.+)$", re.M)


def _iter_docs(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in (".yaml", ".yml", ".json"):
            continue
        if SKIP_DIRS.intersection(p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "{{" in text[:2000] and p.suffix != ".json":
            continue  # helm/go templates: unparseable, counted by caller
        try:
            docs = [json.loads(text)] if p.suffix == ".json" else list(yaml.safe_load_all(text))
        except Exception:
            continue
        for d in docs:
            if isinstance(d, dict) and d.get("kind"):
                yield p.relative_to(root), d


def _sc(sc: dict | None) -> dict:
    sc = sc or {}
    out = {k: sc[k] for k in SC_FIELDS if k in sc}
    return out


def _workload(rel, spec_outer, kind, name):
    pod = (spec_outer.get("template") or {}).get("spec") or {}
    return {
        "kind": kind,
        "name": name,
        "manifest": str(rel),
        "serviceAccountName": pod.get("serviceAccountName") or pod.get("serviceAccount"),
        "hostNetwork": bool(pod.get("hostNetwork")),
        "hostPID": bool(pod.get("hostPID")),
        "hostIPC": bool(pod.get("hostIPC")),
        "hostPath_volumes": sum(1 for v in pod.get("volumes") or [] if "hostPath" in v),
        "pod_securityContext": _sc(pod.get("securityContext")),
        "containers": [
            {
                "name": c.get("name"),
                "image": c.get("image"),
                "securityContext": _sc(c.get("securityContext")),
            }
            for c in (pod.get("containers") or []) + (pod.get("initContainers") or [])
        ],
    }


def _strlist(v, default=None):
    """Real-world manifests put nested lists and nulls where the RBAC
    schema says list-of-string; flatten to strings so set/join ops hold."""
    out = []
    for x in v if isinstance(v, list) else [] if v is None else [v]:
        if isinstance(x, list):
            out.extend(str(y) for y in x if y is not None)
        elif x is not None:
            out.append(str(x))
    return out or (default or [])


def _rules(rules, scope, source):
    out = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        out.append(
            {
                "scope": scope,
                "source": source,
                "apiGroups": _strlist(r.get("apiGroups"), [""]),
                "resources": _strlist(r.get("resources")),
                "verbs": _strlist(r.get("verbs")),
                "resourceNames": _strlist(r.get("resourceNames")),
            }
        )
    return out


def _rule_flags(rules):
    f = {
        "wildcard_verbs": [],
        "wildcard_resources": [],
        "secrets_access": [],
        "rbac_write": [],
        "escalate_bind_impersonate": [],
        "pods_exec": [],
        "scc_use": [],
        "nodes_access": [],
    }
    for r in rules:
        key = ":".join(
            [r["scope"], ",".join(r["apiGroups"]), ",".join(r["resources"]), ",".join(r["verbs"])]
        )
        if "*" in r["verbs"]:
            f["wildcard_verbs"].append(key)
        if "*" in r["resources"]:
            f["wildcard_resources"].append(key)
        if "secrets" in r["resources"]:
            f["secrets_access"].append(key)
        if {"roles", "clusterroles", "rolebindings", "clusterrolebindings"} & set(
            r["resources"]
        ) and {"create", "update", "patch", "*"} & set(r["verbs"]):
            f["rbac_write"].append(key)
        if {"escalate", "bind", "impersonate"} & set(r["verbs"]):
            f["escalate_bind_impersonate"].append(key)
        if "pods/exec" in r["resources"]:
            f["pods_exec"].append(key)
        if "securitycontextconstraints" in r["resources"] and {"use", "*"} & set(r["verbs"]):
            f["scc_use"].append({"sccs": r["resourceNames"] or ["<any>"], "rule": key})
        if {"nodes", "nodes/proxy"} & set(r["resources"]):
            f["nodes_access"].append(key)
    return f


def _kb_markers(root: Path):
    """Parse +kubebuilder:rbac markers into rule dicts."""
    rules = []
    for p in root.rglob("*.go"):
        if SKIP_DIRS.intersection(p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in KB_RBAC_RX.finditer(text):
            fields = {}
            for part in m.group(1).split(","):
                k, _, v = part.partition("=")
                fields.setdefault(k.strip(), []).extend(
                    x.strip() for x in v.split(";") if x.strip()
                )
            if "verbs" in fields:
                rules.append(
                    {
                        "apiGroups": fields.get("groups") or [""],
                        "resources": fields.get("resources") or [],
                        "verbs": fields.get("verbs") or [],
                        "file": str(p.relative_to(root)),
                    }
                )
    return rules


def _norm_pairs(rules):
    """Expand rules to (group, resource, verb) triples for set comparison."""
    triples = set()
    for r in rules:
        for g in r.get("apiGroups") or [""]:
            for res in r.get("resources") or []:
                for v in r.get("verbs") or []:
                    triples.add((g or "", res, v))
    return triples


def _covered(triple, declared):
    """True if a shipped (g,res,verb) triple is covered by declared triples
    (with * wildcards on either side)."""
    g, res, v = triple
    for dg, dres, dv in declared:
        if (dg in ("*", g)) and (dres in ("*", res)) and (dv in ("*", v)):
            return True
    return False


def profile_repo(root: Path, name: str) -> dict:
    workloads, rbac, sccs_shipped, namespaces, install_modes = [], [], [], set(), {}
    operatorgroups = []
    example_workloads = example_rules = 0
    for rel, d in _iter_docs(root):
        kind = d.get("kind")
        if not isinstance(kind, str):
            continue  # non-k8s YAML (kind absent or not a scalar)
        if _is_example(rel):
            if kind in WORKLOAD_KINDS or kind == "ClusterServiceVersion":
                example_workloads += 1
            elif kind in ("Role", "ClusterRole"):
                example_rules += len(d.get("rules") or [])
            continue  # example/test/docs manifests: excluded from the profile
        meta = d.get("metadata") or {}
        if kind in WORKLOAD_KINDS:
            workloads.append(_workload(rel, d.get("spec") or {}, kind, meta.get("name")))
            if meta.get("namespace"):
                namespaces.add(meta["namespace"])
        elif kind == "ClusterServiceVersion":
            spec = d.get("spec") or {}
            for im in spec.get("installModes") or []:
                install_modes[im.get("type")] = bool(im.get("supported"))
            inst = ((spec.get("install") or {}).get("spec")) or {}
            for dep in inst.get("deployments") or []:
                workloads.append(
                    _workload(rel, dep.get("spec") or {}, "CSV-Deployment", dep.get("name"))
                )
            for perm in inst.get("permissions") or []:
                rbac += _rules(
                    perm.get("rules"),
                    "namespace",
                    f"{rel} CSV permissions ({perm.get('serviceAccountName')})",
                )
            for perm in inst.get("clusterPermissions") or []:
                rbac += _rules(
                    perm.get("rules"),
                    "cluster",
                    f"{rel} CSV clusterPermissions ({perm.get('serviceAccountName')})",
                )
        elif kind == "ClusterRole":
            rbac += _rules(d.get("rules"), "cluster", str(rel))
        elif kind == "Role":
            rbac += _rules(d.get("rules"), "namespace", str(rel))
        elif kind == "SecurityContextConstraints":
            sccs_shipped.append(
                {
                    "name": meta.get("name"),
                    "manifest": str(rel),
                    "allowPrivilegedContainer": d.get("allowPrivilegedContainer"),
                    "allowHostNetwork": d.get("allowHostNetwork"),
                    "runAsUser": (d.get("runAsUser") or {}).get("type"),
                }
            )
        elif kind == "Namespace":
            namespaces.add(meta.get("name"))
        elif kind == "OperatorGroup":
            operatorgroups.append(
                {
                    "manifest": str(rel),
                    "targetNamespaces": (d.get("spec") or {}).get("targetNamespaces"),
                }
            )

    flags = _rule_flags(rbac)
    scc_requests = flags.pop("scc_use")

    # tier 2: kubebuilder markers vs shipped rules
    markers = _kb_markers(root)
    tier2 = {"kubebuilder_markers": len(markers)}
    if markers:
        declared = _norm_pairs(markers)
        shipped = _norm_pairs(rbac)
        surplus = sorted(t for t in shipped if not _covered(t, declared))
        deficit = sorted(t for t in declared if not _covered(t, shipped))
        tier2.update(
            {
                "shipped_not_declared": [list(t) for t in surplus[:200]],
                "shipped_not_declared_count": len(surplus),
                "declared_not_shipped_count": len(deficit),
                "note": (
                    "shipped_not_declared = RBAC granted in manifests/CSV with no "
                    "+kubebuilder:rbac marker backing it — the least-privilege "
                    "surplus candidates; verify against non-kubebuilder call sites "
                    "before filing."
                ),
            }
        )
    else:
        tier2["note"] = (
            "no +kubebuilder:rbac markers — required-vs-granted diff "
            "not derivable statically for this repo; runtime capture "
            "(tier 3) is the path to a needs baseline"
        )

    priv_workloads = [
        w
        for w in workloads
        if any(
            (
                c["securityContext"].get("privileged")
                or c["securityContext"].get("allowPrivilegeEscalation") is True
            )
            for c in w["containers"]
        )
        or w["hostNetwork"]
        or w["hostPID"]
        or w["hostIPC"]
        or w["hostPath_volumes"]
    ]
    return {
        "repo": name,
        "tier": "static (1-2); runtime SCC assignment requires tier-3 capture",
        "workloads": workloads,
        "rbac_rules": rbac,
        "rbac_flags": {k: v for k, v in flags.items() if v},
        "scc_requests": scc_requests,
        "sccs_shipped": sccs_shipped,
        "namespaces": sorted(n for n in namespaces if n),
        "install_modes": install_modes,
        "operatorgroups": operatorgroups,
        "tier2_required_vs_granted": tier2,
        "example_or_test_manifests_excluded": {
            "workload_like": example_workloads,
            "rbac_rules": example_rules,
        },
        "summary": {
            "workloads": len(workloads),
            "privileged_or_host_workloads": len(priv_workloads),
            "rbac_rules": len(rbac),
            "distinct_rule_triples": len(_norm_pairs(rbac)),
            "distinct_cluster_triples": len(
                _norm_pairs([r for r in rbac if r["scope"] == "cluster"])
            ),
            "cluster_scoped_rules": sum(1 for r in rbac if r["scope"] == "cluster"),
            "scc_requests": [s for req in scc_requests for s in req["sccs"]],
            "wildcard_rules": len(flags.get("wildcard_verbs", []))
            + len(flags.get("wildcard_resources", [])),
            "no_scc_request_recorded": not scc_requests,
        },
    }


def render_md(p: dict) -> str:
    s = p["summary"]
    L = [
        f"# Privilege Profile — {p['repo']}",
        "",
        "_Static inventory (tiers 1–2): what the operator **asks for**. The SCC it "
        "actually **runs with** is cluster-assigned — see tier-3 runtime capture. "
        "Absent an explicit SCC request, OpenShift assigns `restricted-v2` by default._",
        "",
        f"- Workloads: {s['workloads']} ({s['privileged_or_host_workloads']} privileged/host-touching)",
        f"- RBAC rules: {s['rbac_rules']} ({s['cluster_scoped_rules']} cluster-scoped; "
        f"{s['wildcard_rules']} wildcard)",
        f"- SCC requests: {', '.join(s['scc_requests']) if s['scc_requests'] else 'none recorded (default restricted-v2 expected)'}",
        f"- Namespaces: {', '.join(p['namespaces']) or '—'}",
        f"- Install modes: {', '.join(k for k, v in p['install_modes'].items() if v) or '—'}",
        "",
    ]
    if p["workloads"]:
        L += [
            "## Workloads & security contexts",
            "",
            "| Workload | SA | host* | Containers: securityContext |",
            "|---|---|---|---|",
        ]
        for w in p["workloads"]:
            host = "/".join(k for k in ("hostNetwork", "hostPID", "hostIPC") if w[k]) or (
                "hostPath" if w["hostPath_volumes"] else "—"
            )
            cs = "; ".join(
                f"{c['name']}: {json.dumps(c['securityContext']) if c['securityContext'] else '∅'}"
                for c in w["containers"]
            )[:220]
            L.append(
                f"| {w['kind']}/{w['name']} | {w['serviceAccountName'] or '—'} | {host} | {cs} |"
            )
        L.append("")
    if p["rbac_flags"]:
        L += ["## RBAC risk flags", ""]
        for k, v in p["rbac_flags"].items():
            L.append(
                f"- **{k}** ({len(v)}): "
                + "; ".join(f"`{x}`" for x in v[:4])
                + (" …" if len(v) > 4 else "")
            )
        L.append("")
    t2 = p["tier2_required_vs_granted"]
    L += ["## Required vs granted (tier 2)", ""]
    if t2.get("shipped_not_declared_count") is not None:
        L.append(
            f"- kubebuilder markers: {t2['kubebuilder_markers']} · "
            f"**surplus (shipped, not declared): {t2['shipped_not_declared_count']}** · "
            f"deficit: {t2['declared_not_shipped_count']}"
        )
        for t in t2.get("shipped_not_declared", [])[:12]:
            L.append(f"  - `{t[0] or 'core'} / {t[1]} / {t[2]}`")
        if t2["shipped_not_declared_count"] > 12:
            L.append(f"  - _…and {t2['shipped_not_declared_count'] - 12} more (see JSON)._")
    L.append(f"- {t2['note']}")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo"), ap.add_argument("--repo-url"), ap.add_argument("--ref")
    ap.add_argument("--name"), ap.add_argument("--out-dir")
    ap.add_argument("--rollup", help="glob of *-priv-profile.json to aggregate")
    ap.add_argument("--rollup-out")
    args = ap.parse_args()

    if args.rollup:
        profs = [json.loads(Path(f).read_text()) for f in sorted(globmod.glob(args.rollup))]  # noqa: PTH207
        out = Path(args.rollup_out or ".")
        out.mkdir(parents=True, exist_ok=True)
        rows = []
        for p in profs:
            s = p["summary"]
            t2 = p["tier2_required_vs_granted"]
            # securityContext posture: privileged/host counts + runAsNonRoot coverage
            n_cont = n_nonroot = n_priv = 0
            for w in p.get("workloads", []):
                pod_nr = (w.get("pod_securityContext") or {}).get("runAsNonRoot")
                for c in w.get("containers", []):
                    n_cont += 1
                    sc = c.get("securityContext") or {}
                    if sc.get("privileged"):
                        n_priv += 1
                    if sc.get("runAsNonRoot") or (sc.get("runAsNonRoot") is None and pod_nr):
                        n_nonroot += 1
            flags = p.get("rbac_flags") or {}
            rows.append(
                {
                    "repo": p["repo"],
                    **s,
                    "containers": n_cont,
                    "privileged_containers": n_priv,
                    "runasnonroot_containers": n_nonroot,
                    "namespaces": p.get("namespaces") or [],
                    "install_modes": [k for k, v in (p.get("install_modes") or {}).items() if v],
                    "rbac_risk_flags": {k: len(v) for k, v in flags.items()},
                    "surplus": t2.get("shipped_not_declared_count"),
                    "markers": t2.get("kubebuilder_markers", 0),
                }
            )
        rows.sort(
            key=lambda r: (
                -(r["surplus"] or 0),
                -r["wildcard_rules"],
                -r["privileged_or_host_workloads"],
            )
        )

        def _scc_cell(r):
            reqs = sorted(set(r["scc_requests"]))
            return ", ".join(reqs) if reqs else "(none — restricted-v2 default)"

        def _sc_cell(r):
            bits = []
            if r["privileged_containers"]:
                bits.append(f"{r['privileged_containers']} privileged")
            if r["privileged_or_host_workloads"]:
                bits.append(f"{r['privileged_or_host_workloads']} host-touching wl")
            bits.append(f"runAsNonRoot {r['runasnonroot_containers']}/{r['containers']}")
            return ", ".join(bits)

        def _rbac_cell(r):
            fl = r["rbac_risk_flags"]
            parts = [
                f"{r.get('distinct_cluster_triples', r['cluster_scoped_rules'])} cluster / "
                f"{r.get('distinct_rule_triples', r['rbac_rules'])} total grants"
            ]
            risk = ", ".join(f"{k}×{v}" for k, v in sorted(fl.items(), key=lambda kv: -kv[1])[:3])
            if risk:
                parts.append(risk)
            if r["surplus"]:
                parts.append(f"surplus {r['surplus']}")
            return "; ".join(parts)

        L = [
            "# Operator Least-Privilege Rollup (static, tiers 1–2)",
            "",
            "_One row per operator, one column per assessment question. **SCC column is "
            "what the operator REQUESTS** (RBAC `use` on securitycontextconstraints); the "
            "SCC it actually RUNS WITH is cluster-assigned — tier-3 runtime capture. "
            "Ranked by RBAC surplus, then wildcards, then privileged workloads. Surplus "
            "n/a = no kubebuilder markers (needs baseline not statically derivable)._",
            "",
            "| Repo | SCCs requested | Security context | Namespaces / install modes | Required roles (RBAC) |",
            "|---|---|---|---|---|",
        ]
        for r in rows:
            ns = ", ".join(r["namespaces"][:3]) + ("…" if len(r["namespaces"]) > 3 else "")
            im = ", ".join(r["install_modes"])
            nscell = " · ".join(x for x in (ns, im) if x) or "—"
            L.append(
                f"| {r['repo']} | {_scc_cell(r)} | {_sc_cell(r)} | {nscell} | {_rbac_cell(r)} |"
            )
        (out / "priv-profile-rollup.md").write_text("\n".join(L) + "\n")
        (out / "priv-profile-rollup.json").write_text(json.dumps(rows, indent=1) + "\n")

        import csv

        with (out / "priv-profile-rollup.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(
                [
                    "repo",
                    "sccs_requested",
                    "privileged_containers",
                    "host_touching_workloads",
                    "runasnonroot_containers",
                    "containers_total",
                    "namespaces",
                    "install_modes",
                    "cluster_grants",
                    "total_grants",
                    "wildcard_rules",
                    "rbac_risk_flags",
                    "tier2_surplus",
                    "kubebuilder_markers",
                ]
            )
            for r in rows:
                w.writerow(
                    [
                        r["repo"],
                        ";".join(sorted(set(r["scc_requests"]))),
                        r["privileged_containers"],
                        r["privileged_or_host_workloads"],
                        r["runasnonroot_containers"],
                        r["containers"],
                        ";".join(r["namespaces"]),
                        ";".join(r["install_modes"]),
                        r.get("distinct_cluster_triples", r["cluster_scoped_rules"]),
                        r.get("distinct_rule_triples", r["rbac_rules"]),
                        r["wildcard_rules"],
                        ";".join(f"{k}={v}" for k, v in sorted(r["rbac_risk_flags"].items())),
                        r["surplus"] if r["surplus"] is not None else "n/a",
                        r["markers"],
                    ]
                )

        # compact self-contained HTML dashboard
        n = len(rows)
        n_scc = sum(1 for r in rows if r["scc_requests"])
        n_priv = sum(
            1 for r in rows if r["privileged_containers"] or r["privileged_or_host_workloads"]
        )
        n_surplus = sum(1 for r in rows if r["surplus"])
        from html import escape

        top = "".join(
            f"<tr><td>{escape(r['repo'])}</td><td>{escape(_scc_cell(r))}</td>"
            f"<td>{escape(_sc_cell(r))}</td>"
            f"<td>{escape(', '.join(r['namespaces'][:2]) or '—')}</td>"
            f"<td>{escape(_rbac_cell(r))}</td></tr>"
            for r in rows[:60]
        )
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Operator Least-Privilege Dashboard</title><style>
body{{font-family:-apple-system,'Red Hat Text',sans-serif;background:#f5f5f5;color:#151515;margin:24px}}
.card{{background:#fff;border-radius:6px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.08)}}
h1{{font-size:20px}}h2{{font-size:14px;color:#6a6e73;text-transform:uppercase}}
table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{padding:4px 8px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}}
.kpi{{display:inline-block;margin-right:32px}}.kpi b{{font-size:34px}}.kpi span{{color:#6a6e73;font-size:12px;display:block}}
.banner{{background:#151515;color:#fff;padding:6px 12px;font-size:12px;border-radius:4px;margin-bottom:16px}}
.note{{font-size:12px;color:#6a6e73}}</style></head><body>
<div class="banner">RED HAT INTERNAL — EMBARGOED</div>
<h1>Operator Least-Privilege Dashboard <span class="note">· static tiers 1–2 · SCC column = REQUESTED (assigned SCC needs tier-3 runtime capture)</span></h1>
<div class="card"><span class="kpi"><b>{n}</b><span>operators profiled</span></span>
<span class="kpi"><b>{n_scc}</b><span>request explicit SCCs</span></span>
<span class="kpi"><b>{n - n_scc}</b><span>restricted-v2 default expected</span></span>
<span class="kpi"><b style="color:#ec7a08">{n_priv}</b><span>privileged / host-touching</span></span>
<span class="kpi"><b style="color:#cc0000">{n_surplus}</b><span>with RBAC surplus (tier-2)</span></span></div>
<div class="card"><h2>Assessment (top 60 by surplus / wildcards / privilege — full set in priv-profile-rollup.json)</h2>
<table><thead><tr><th>Operator</th><th>SCCs requested</th><th>Security context</th><th>Namespaces</th><th>Required roles (RBAC)</th></tr></thead>
<tbody>{top}</tbody></table></div>
<div class="card note">Per-operator detail: analysis-results/findings/&lt;product&gt;/&lt;repo&gt;/&lt;repo&gt;-priv-profile.md · Semantics: no SCC request ⇒ OpenShift assigns restricted-v2 by default · surplus = shipped RBAC with no +kubebuilder:rbac marker backing (verify non-kubebuilder call sites before filing) · generated by operator-priv-profile.</div>
</body></html>"""
        (out / "priv-profile-dashboard.html").write_text(html)
        print(
            f"rollup: {len(rows)} profiles -> {out}/priv-profile-rollup.{{md,json}} + priv-profile-dashboard.html"
        )
        return 0

    if not args.name or not args.out_dir:
        ap.error("--name and --out-dir required for profiling")
    if args.repo_url:
        # operator-supplied today, but gate anyway (plan P0.1 sweep):
        # https-only transport, no option injection via url/ref
        if not re.match(r"^https://[^\s'\"]+$", args.repo_url):
            ap.error("--repo-url must be an https:// URL")
        if args.ref and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", args.ref):
            ap.error("--ref contains unsafe characters")
        tmp = tempfile.mkdtemp(prefix=f"privprofile-{args.name}-")
        cmd = ["git", "clone", "-q", "--depth", "1"]
        if args.ref:
            cmd += ["--branch", args.ref]
        subprocess.run(
            [*cmd, "--", args.repo_url, tmp],
            check=True,
            timeout=600,
            env={**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"},
        )
        root = Path(tmp)
    else:
        root = Path(args.repo)
    prof = profile_repo(root, args.name)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.name}-priv-profile.json").write_text(json.dumps(prof, indent=1) + "\n")
    (out / f"{args.name}-priv-profile.md").write_text(render_md(prof))
    s = prof["summary"]
    print(
        f"{args.name}: {s['workloads']} workloads, {s['rbac_rules']} rules "
        f"({s['cluster_scoped_rules']} cluster), scc={s['scc_requests'] or 'default'}, "
        f"surplus={prof['tier2_required_vs_granted'].get('shipped_not_declared_count', 'n/a')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
