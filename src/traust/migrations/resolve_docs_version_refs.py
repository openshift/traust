#!/usr/bin/env python3
# Migration utility archived 2026-08-11
"""Doc-version → repository-ref resolver (doc-variance lane, part 2).

Answers the join the variance register's code_evidence.ref field needs:
given a docs.redhat.com product slug and a documentation version, which
repo@ref pairs does that version's documentation describe? Three modes,
declared per product in <inputs>/adhoc/
docs-product-map.yaml (version_to_refs):

  graph-release  the repo-graph's ships_ref edges carry release labels
                 (OCP: docs 4.19 -> release "4.19" -> ~161 repo@branch
                 pairs, exactly the audited release-branch window)
  ref-pattern    branch-name convention (ACM: docs 2.17 ->
                 release-2.17 refs present in the graph's ref layer)
  head           rolling documentation (OCM 1-latest, ROSA latest) —
                 claims verify against HEAD

Deterministic, read-only, fail-loud: an unmapped product, a version
with no matching refs under its declared mode, or a map row still
confirmed:false is reported loudly (unconfirmed rows RESOLVE but the
output carries confirmed:false — consumers label accordingly, same
discipline as scope-registry drafts).

Usage:
    python3 resolve_docs_version_refs.py --product <slug> --version <v>
        [--map <yaml>] [--graph <json>] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    inputs_dir,
    load_engine,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def _ref_target(node_id: str):
    """ref:github.com/org/name@branch -> (org/name, branch)."""
    if not node_id.startswith("ref:") or "@" not in node_id:
        return None
    body = node_id[len("ref:") :]
    url, _, branch = body.rpartition("@")
    parts = url.split("/")
    return ("/".join(parts[-2:]), branch) if len(parts) >= 2 else None


def resolve(map_doc: dict, graph: dict, product: str, version: str) -> dict:
    entry = (map_doc.get("products") or {}).get(product)
    if entry is None:
        known = ", ".join(sorted(map_doc.get("products") or {}))
        raise SystemExit(f"product {product!r} not in the docs map (declared: {known})")
    rule = entry.get("version_to_refs")
    if not rule:
        raise SystemExit(f"{product}: no version_to_refs rule declared")
    if version not in (entry.get("versions") or []):
        raise SystemExit(
            f"{product}: version {version!r} not in the "
            f"enumerated set {entry.get('versions')} — "
            f"re-enumerate the map before resolving"
        )
    mode = rule["mode"]
    pairs = []
    if mode == "graph-release":
        want = rule["release"].replace("{version}", version)
        for e in graph.get("edges") or []:
            if e.get("rel") == "ships_ref" and e.get("release") == want:
                t = _ref_target(str(e.get("to") or ""))
                if t:
                    pairs.append(t)
    elif mode == "ref-pattern":
        want = rule["pattern"].replace("{version}", version)
        for e in graph.get("edges") or []:
            rel = e.get("rel")
            if rel in ("ships_ref", "has_ref"):
                t = _ref_target(str(e.get("to") or ""))
                if t and t[1] == want:
                    pairs.append(t)
            elif rel == "has-findings":
                # branch re-audits appear as findings slugs with the
                # __<branch> suffix (branch-awareness convention);
                # the from-node is the repo
                to = str(e.get("to") or "")
                frm = str(e.get("from") or "")
                if to.endswith(f"__{want}") and frm.startswith("repo:"):
                    parts = frm[len("repo:") :].split("/")
                    pairs.append(("/".join(parts[-2:]), want))
    elif mode == "head":
        for pid in entry.get("graph_products") or []:
            for e in graph.get("edges") or []:
                if e.get("rel") == "ships" and e.get("from") == pid:
                    to = str(e.get("to") or "")
                    if to.startswith("repo:"):
                        parts = to[len("repo:") :].split("/")
                        pairs.append(("/".join(parts[-2:]), "HEAD"))
    else:
        raise SystemExit(f"unknown version_to_refs mode {mode!r}")
    pairs = sorted(set(pairs))
    if not pairs:
        raise SystemExit(
            f"{product}@{version}: mode {mode} resolved "
            f"ZERO repo@ref pairs — stale map or graph; "
            f"refusing an empty answer"
        )
    return {
        "product": product,
        "version": version,
        "mode": mode,
        "confirmed": bool(entry.get("confirmed")),
        "repo_refs": [{"repo": r, "ref": b} for r, b in pairs],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--product", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--map", type=Path, default=None)
    ap.add_argument("--graph", type=Path, default=None)
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)

    engine = load_engine(args.config_home)
    map_path = args.map or (inputs_dir(engine) / "adhoc" / "docs-product-map.yaml")
    graph_path = args.graph or (analysis_results_dir(engine) / "graph" / "repo-graph.json")
    if yaml is None:
        sys.exit("PyYAML required")
    map_doc = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    res = resolve(map_doc, graph, args.product, args.version)
    if args.as_json:
        print(json.dumps(res, indent=2))
    else:
        tag = "" if res["confirmed"] else " [map row UNCONFIRMED]"
        print(
            f"{res['product']}@{res['version']} ({res['mode']})"
            f"{tag}: {len(res['repo_refs'])} repo@ref pairs"
        )
        for rr in res["repo_refs"][:10]:
            print(f"  {rr['repo']} @ {rr['ref']}")
        if len(res["repo_refs"]) > 10:
            print(f"  ... +{len(res['repo_refs']) - 10} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
