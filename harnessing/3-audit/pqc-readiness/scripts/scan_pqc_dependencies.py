#!/usr/bin/env python3
"""scan_pqc_dependencies.py — portfolio-graph crypto backfeed.

Populates the portfolio graph (analysis-results/graph/portfolio-graph.db)
from the PQC sweep's already-emitted facts — no re-scanning. Two layers,
per the Phase 2b design in plan v1.3:

  L1  crypto-dep nodes      one node per crypto library x version, from
                            DEP_* / HP_FW_* dependency facts
                              node  kind=crypto-dep  id=crypto-dep:<name>@<ver>
                              edge  repo -[uses_crypto_dep]-> crypto-dep
  L3  algorithm-usage edges one node per (ir8547 usage x qclass) cell —
                            fully deterministic, no free-authored taxonomy
                              node  kind=crypto-usage id=crypto-usage:<usage>:<qclass>
                              edge  repo -[uses_crypto]-> crypto-usage
                            edge attrs carry fact counts, per-rule counts,
                            first-party counts and 2030-clock counts, so
                            finer queries (e.g. "RSA key exchange") are a
                            json_extract over rule_ids.

Repo nodes additionally get a `pqc` attrs block (overall / bucket /
hndl_priority / has_2030_clock_items / assessed_at) from the readiness
report when one exists, which is the data source the exec views
expect.

The run is a deterministic full rebuild: all `uses_crypto*` edges and all
`crypto-dep`/`crypto-usage` nodes are dropped and re-derived from the
facts corpus, so per-batch re-runs are idempotent and never accumulate
stale rows. Repos missing from the graph (e.g. private-forge repos the graph
build never saw) are added as plain repo nodes.

Queries this enables (examples):
  -- all repos with quantum-vulnerable key establishment
  SELECT DISTINCT src FROM edges WHERE rel='uses_crypto'
    AND dst LIKE 'crypto-usage:ke:shor%';
  -- all repos depending on go-jose (any version)
  SELECT src, dst FROM edges WHERE rel='uses_crypto_dep'
    AND dst LIKE 'crypto-dep:go-jose@%';

Usage: scan_pqc_dependencies.py [--results-root PATH] [--config-home PATH]
                                [--graph-db <path>] [--summary <path>]
"""

import argparse
import collections
import json
import re
import sqlite3
import sys
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root

# rel names owned by this backfeed — dropped and rebuilt every run
OWNED_RELS = ("uses_crypto", "uses_crypto_dep")
OWNED_KINDS = ("crypto-dep", "crypto-usage")

# canonical library name per dependency rule, used when the fact match is
# masked (e.g. "github.c***v4.1.4") or carries no explicit name
RULE_LIB = {
    "DEP_GO_JOSE": "go-jose",
    "DEP_PYCA_CRYPTOGRAPHY": "pyca-cryptography",
    "DEP_PYCRYPTODOME": "pycryptodome",
    "DEP_PARAMIKO": "paramiko",
    "DEP_OPENSSL": "openssl",
    "DEP_RUST_OPENSSL": "rust-openssl",
    "DEP_RUST_RSA_CRATE": "rust-rsa",
    "DEP_BORINGSSL": "boringssl",
    "DEP_BOUNCYCASTLE": "bouncycastle",
    "DEP_JAVA_BOUNCYCASTLE": "bouncycastle",
    "HP_FW_DJANGO": "django",
    "HP_FW_RAILS": "rails",
    "HP_FW_SPRING": "spring",
}

VERSION_RX = re.compile(r"v?\d+(?:\.\d+)+(?:[-.\w]*)$")


def dep_identity(rule_id: str, match: str) -> tuple[str, str]:
    """(library, version) for a dependency fact, tolerant of masking."""
    match = (match or "").strip()
    name, ver = "", "unknown"
    if "@" in match:
        raw_name, raw_ver = match.rsplit("@", 1)
        if "*" not in raw_name and raw_name:
            name = raw_name.lower()
        if raw_ver and "*" not in raw_ver:
            ver = raw_ver
    else:
        m = VERSION_RX.search(match)
        if m and "*" not in m.group(0):
            ver = m.group(0)
    if not name:
        name = RULE_LIB.get(rule_id, rule_id.lower().replace("dep_", "").replace("hp_fw_", ""))
    if ver != "unknown" and not VERSION_RX.match(ver):
        ver = "unknown"
    return name, ver


def repo_node_id(url: str) -> tuple[str, str]:
    """(node_id, label) matching build_portfolio_graph.py conventions."""
    u = (url or "").strip().rstrip("/")
    u = re.sub(r"^[a-z+]+://", "", u)
    u = re.sub(r"^git@([^:]+):", r"\1/", u)
    if u.endswith(".git"):
        u = u[:-4]
    label = "/".join(u.split("/")[1:]) or u
    return f"repo:{u}", label


def is_dep_fact(fact: dict) -> bool:
    r = fact.get("rule_id", "")
    usage = (fact.get("ir8547") or {}).get("usage")
    return r.startswith("DEP_") or r.startswith("HP_FW_") or usage == "dep"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--graph-db", default=None)
    ap.add_argument("--summary", default=None)
    args = ap.parse_args()
    results = resolve_results_root(args)
    pqc = results / "pqc"
    db_path = (
        Path(args.graph_db).resolve() if args.graph_db else results / "graph" / "portfolio-graph.db"
    )
    if not db_path.exists():
        print(f"error: graph db not found: {db_path}", file=sys.stderr)
        return 1

    facts_files = sorted(pqc.glob("*/*-pqc-facts.json"))
    if not facts_files:
        print(f"error: no facts under {pqc}", file=sys.stderr)
        return 1

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    # deterministic rebuild of everything this backfeed owns
    cur.execute(f"DELETE FROM edges WHERE rel IN ({','.join('?' * len(OWNED_RELS))})", OWNED_RELS)
    cur.execute(
        f"DELETE FROM nodes WHERE kind IN ({','.join('?' * len(OWNED_KINDS))})", OWNED_KINDS
    )

    dep_nodes: dict[str, dict] = {}
    usage_nodes: dict[str, dict] = {}
    dep_edges: dict[tuple, dict] = {}
    usage_edges: dict[tuple, dict] = {}
    repos_seen, repos_added, repos_stamped = 0, 0, 0
    skipped = []

    for ff in facts_files:
        try:
            doc = json.loads(ff.read_text())
        except (json.JSONDecodeError, OSError) as e:
            skipped.append(f"{ff.name}: {e}")
            continue
        url = doc.get("repository")
        if not url:
            skipped.append(f"{ff.name}: no repository field")
            continue
        rid, label = repo_node_id(url)
        repos_seen += 1

        cur.execute("SELECT attrs FROM nodes WHERE id=?", (rid,))
        row = cur.fetchone()
        attrs = json.loads(row[0]) if row and row[0] else {}
        if row is None:
            repos_added += 1

        # stamp repo attrs with the readiness verdict when one exists
        slug_dir = ff.parent
        readiness = slug_dir / ff.name.replace("-pqc-facts.json", "-pqc-readiness.json")
        if readiness.exists():
            try:
                rd = json.loads(readiness.read_text())
                flags = rd.get("flags") or {}
                attrs["pqc"] = {
                    "overall": (rd.get("scores") or {}).get("overall"),
                    "readiness_bucket": rd.get("readiness_bucket"),
                    "hndl_priority": flags.get("hndl_priority"),
                    "has_2030_clock_items": flags.get("has_2030_clock_items"),
                    "assessed_at": (rd.get("metadata") or {}).get("assessed_at"),
                    "slug": slug_dir.name,
                }
                repos_stamped += 1
            except (json.JSONDecodeError, OSError):
                pass
        cur.execute(
            "INSERT INTO nodes (id, kind, label, attrs) VALUES (?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET attrs=excluded.attrs",
            (rid, "repo", label, json.dumps(attrs, sort_keys=True)),
        )

        for fact in doc.get("facts", []):
            ir = fact.get("ir8547") or {}
            first_party = fact.get("path_class") == "first_party"
            if is_dep_fact(fact):
                name, ver = dep_identity(fact.get("rule_id", ""), fact.get("match", ""))
                nid = f"crypto-dep:{name}@{ver}"
                dep_nodes.setdefault(nid, {"library": name, "version": ver})
                e = dep_edges.setdefault(
                    (rid, nid),
                    {
                        "facts": 0,
                        "first_party": 0,
                        "files": set(),
                        "rule_ids": collections.Counter(),
                    },
                )
                e["facts"] += 1
                e["first_party"] += int(first_party)
                if len(e["files"]) < 12:
                    e["files"].add(fact.get("file", ""))
                e["rule_ids"][fact.get("rule_id", "?")] += 1
            usage = ir.get("usage") or "unclassified"
            qclass = ir.get("qclass") or "unclassified"
            nid = f"crypto-usage:{usage}:{qclass}"
            usage_nodes.setdefault(nid, {"usage": usage, "qclass": qclass})
            e = usage_edges.setdefault(
                (rid, nid),
                {"facts": 0, "first_party": 0, "clock_2030": 0, "rule_ids": collections.Counter()},
            )
            e["facts"] += 1
            e["first_party"] += int(first_party)
            clock = ir.get("clock") or {}
            if (
                clock.get("deprecated_after") == 2030
                or str(clock.get("deprecated_after")) == "2030"
            ):
                e["clock_2030"] += 1
            e["rule_ids"][fact.get("rule_id", "?")] += 1

    for nid, a in dep_nodes.items():
        cur.execute(
            "INSERT OR REPLACE INTO nodes (id, kind, label, attrs) VALUES (?,?,?,?)",
            (nid, "crypto-dep", f"{a['library']}@{a['version']}", json.dumps(a, sort_keys=True)),
        )
    for nid, a in usage_nodes.items():
        cur.execute(
            "INSERT OR REPLACE INTO nodes (id, kind, label, attrs) VALUES (?,?,?,?)",
            (nid, "crypto-usage", f"{a['usage']} / {a['qclass']}", json.dumps(a, sort_keys=True)),
        )
    for (src, dst), e in dep_edges.items():
        cur.execute(
            "INSERT OR REPLACE INTO edges (src, dst, rel, attrs) VALUES (?,?,?,?)",
            (
                src,
                dst,
                "uses_crypto_dep",
                json.dumps(
                    {
                        "facts": e["facts"],
                        "first_party": e["first_party"],
                        "files": sorted(e["files"]),
                        "rule_ids": dict(e["rule_ids"]),
                    },
                    sort_keys=True,
                ),
            ),
        )
    for (src, dst), e in usage_edges.items():
        cur.execute(
            "INSERT OR REPLACE INTO edges (src, dst, rel, attrs) VALUES (?,?,?,?)",
            (
                src,
                dst,
                "uses_crypto",
                json.dumps(
                    {
                        "facts": e["facts"],
                        "first_party": e["first_party"],
                        "clock_2030": e["clock_2030"],
                        "rule_ids": dict(e["rule_ids"]),
                    },
                    sort_keys=True,
                ),
            ),
        )
    con.commit()

    summary = {
        "facts_files": len(facts_files),
        "repos_seen": repos_seen,
        "repos_added_to_graph": repos_added,
        "repos_with_pqc_attrs": repos_stamped,
        "crypto_dep_nodes": len(dep_nodes),
        "crypto_usage_nodes": len(usage_nodes),
        "uses_crypto_dep_edges": len(dep_edges),
        "uses_crypto_edges": len(usage_edges),
        "skipped": skipped[:20],
    }
    out = (
        Path(args.summary).resolve()
        if args.summary
        else results / "graph" / "pqc-backfeed-summary.json"
    )
    out.write_text(json.dumps(summary, indent=1) + "\n")
    print(
        f"[+] backfeed complete: {repos_seen} repos "
        f"({repos_stamped} stamped with readiness attrs, "
        f"{repos_added} new repo nodes) · "
        f"{len(dep_nodes)} crypto-dep nodes / {len(dep_edges)} edges · "
        f"{len(usage_nodes)} crypto-usage nodes / {len(usage_edges)} edges"
    )
    if skipped:
        print(f"[!] skipped {len(skipped)} facts files (see summary)")
    print(f"[+] wrote {out}")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
