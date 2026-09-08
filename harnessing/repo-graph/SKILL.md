---
name: repo-graph
description: Build or refresh the portfolio repository graph. Reads every segment of the inputs inventory (`locations.inputs`) by the kind declared in `<inputs>/inventory.yaml` (groups / release-payload / catalog / services; ansible/ excluded by default), cross-references every repo against analysis-results/findings/ coverage (audit/triage/threat-model + severity), and emits repo-graph.{json,dot,gexf,html} + repo-graph-stats.md into analysis-results/graph/. Use when asked to "build the repo graph", "update the portfolio graph", "map repos to findings", "which repos have no coverage", or "what ships kube-rbac-proxy".
argument-hint: "[--inputs DIR] [--findings DIR] [--out DIR] [--exclude SEGMENT]... [--date YYYY-MM-DD]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust/harnessing/repo-graph/scripts/build_repo_graph.py:*)
  - Bash(ls:*)
  - Bash(jq:*)
  - Bash(open *.html:*)
  - Read
  - Write
  # scoped 2026-07-31 (P1-W4): A11 grandfather retired —
  # per-script anchored grants replace Bash(python3:*)
---

# repo-graph

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Build a directed graph of the entire Hybrid Platforms source-code portfolio
and overlay security-findings coverage on it. One command, five artefacts.

## What it produces

Written to `--out` (default `../analysis-results/graph/`):

| File | Purpose |
|---|---|
| `repo-graph.json` | Full-fidelity `{nodes,edges,stats}`. Canonical machine-readable output. |
| `repo-graph.dot` | GraphViz source. Render with `dot -Tsvg -Ksfdp` (large — expect minutes). |
| `repo-graph.gexf` | Gephi import for interactive layout / community detection. |
| `repo-graph.html` | Self-contained vis-network page: pan/zoom, text filter, segment-focus dropdown, double-click-to-open. Product-version and category nodes are collapsed into tooltips so the ~10k-node graph stays interactive. |
| `repo-graph-stats.md` | Node/edge counts, coverage %, top-20 hub repos by degree. |

`repo-graph-stats.md` and `repo-graph.html` embed the standard population block (python3 -m traust.cli corpus) for cross-dashboard reconciliation.

## Node types

`segment` → `release` / `product` → `product-version` → `category` → `repo` → `findings`
plus `owner-team` → `repo` (dashed) and `repo` → `repo-ref` (ref layer, below).

Repo nodes are coloured by max triaged severity across all linked findings
dirs (`CRITICAL` red · `HIGH` orange · `MEDIUM` yellow · `LOW` green · none
grey) and carry `attrs.tp_total`, `attrs.findings_dirs`,
`attrs.findings ∈ {audit,triage,tm,none,…}`.

## Edge relations

| rel | meaning |
|---|---|
| `contains` | hierarchy: segment→release/product, product→version, release/version→category |
| `ships` | inventory row: this release/version/category/product ships this repo |
| `owned-by` | owners.csv: this Owner Team owns this repo |
| `has-findings` | this repo has a findings directory under `analysis-results/findings/` (any depth — `<product>/<slug>/` or shallow `<slug>/`) |
| `has_ref` | ref layer: repo → its `repo-ref` node |
| `ships_ref` | ref layer: the same shipper as the branch-carrying `ships` edge, targeted at the `repo-ref` node |

## Ref layer (branch-awareness Phase 2)

Where an inventory CSV row declares a Source Branch, the builder ALSO emits
an optional first-class ref node — id `ref:<host>/<org>/<name>@<branch>`,
kind `repo-ref`, label `<org>/<name>@<branch>`, `attrs.branch` — deduplicated
to one node per unique (repo, branch) regardless of how many rows mention it.
Refs exist only where inventories declare branches (release-payload and
catalog segments carry `Source Branch`; groups/services rows normally do not). The layer is
strictly additive: repo-node identity, all pre-existing edges/attrs, hub
degrees in stats.md, and the HTML view are unchanged — which is why the
parallel edge uses the distinct rel `ships_ref` instead of reusing `ships`
(every existing `ships` consumer stays byte-identical and can never
double-count a branch-carrying row).

Queries this unlocks:

    # repos shipping release-4.19 from a (non-default) inventory branch
    jq -r '.nodes[]|select(.type=="repo-ref" and .attrs.branch=="release-4.19")
           |.label' repo-graph.json

    # every branch an inventory declares for one repo
    jq -r --arg r github.com/openshift/api \
      '.edges[]|select(.rel=="has_ref" and .from=="repo:"+$r)|.to' repo-graph.json

    # which release/version/category ships a specific repo@branch
    jq -r '.edges[]|select(.rel=="ships_ref" and
           .to=="ref:github.com/openshift/api@release-4.19")|.from' repo-graph.json

Per-ref enrichment (dependencies, PQC posture at the ref) is Phase 3 —
`repo-ref` nodes pass through portfolio-graph spine ingest as inert
`kind='repo-ref'` rows; every existing enrichment stage filters
`kind='repo'` and ignores them.

## Procedure

`$ARGUMENTS` are passed straight through to `build_repo_graph.py`. From the
`traust/` checkout:

1. Resolve paths. If the user supplied `--inputs` / `--findings` / `--out`,
   honour them; otherwise use defaults relative to the harness checkout
   (the inputs inventory, `../analysis-results/findings`,
   `../analysis-results/graph`).

2. Run the builder:

       python3 harnessing/repo-graph/scripts/build_repo_graph.py $ARGUMENTS

   The script discovers audit reports through the corpus resolver
   (python3 -m traust.cli corpus, the single definition of report discovery):
   a depth-tolerant walk of the findings tree that includes shallow
   `findings/<repo>/` dirs and excludes symlink aliases. It hard-fails if
   the resolver cannot load. Each report's JSON is indexed for
   `metadata.repository` (preferring the sibling `*-findings-current.json`
   cumulative report from the `track-findings` skill when present — findings
   nodes then carry `dispositions`, `resolved_findings`, `open_findings`,
   and `false_positives` attributes, and stats.md reports ledger coverage),
   ingests all inventory CSVs from the non-excluded segments, links repos
   to findings (exact URL match, then a guarded name-only fallback that
   refuses dirs whose recorded URL points at a different repo), and writes
   all five outputs.

3. Report the summary. Read `repo-graph-stats.md` back to the user and call
   out:
   - node/edge totals and coverage %
   - the top-3 hub repos
   - `repos_without_findings` count — these are gap targets for
     `secure-code-audit`.

4. If the user asked to "open" or "view" the graph, run
   `open <out>/repo-graph.html`.

## Answering questions from the graph

Once `repo-graph.json` exists, common queries:

    # repos with no findings coverage
    jq -r '.nodes[]|select(.type=="repo" and .attrs.findings=="none")|.label' repo-graph.json

    # every product/release that ships a given repo
    jq -r --arg r github.com/openshift/kube-rbac-proxy \
      '.edges[]|select(.rel=="ships" and .to=="repo:"+$r)|.from' repo-graph.json

    # repos owned by a team, sorted by TP
    jq -r --arg t "OpenShift Storage" \
      '[.edges[]|select(.rel=="owned-by" and .from=="owner-team:"+$t)|.to] as $r
       | .nodes[]|select(.id as $i|$r|index($i))
       | "\(.attrs.tp_total // 0)\t\(.label)"' repo-graph.json | sort -rn

## Excluding segments

`--exclude` is repeatable; default is `ansible`. To also drop a catalog
segment named `operators`: `--exclude ansible --exclude operators`.

## Segment kinds

Which layout a segment uses is declared in `<inputs>/inventory.yaml`
(`traust.inventory`), never inferred from the directory name. An undeclared
segment is `groups` — the layout `/add-inputs` writes. `release-payload`
segments become `release` nodes, `catalog` segments `product` →
`product-version` nodes, `groups`/`services` segments `product` nodes per
group directory.

## Integrations

`repo-graph.json` is the spine `/portfolio-graph` builds on (L0), and
the graph's `ships` edges drive per-product reporting in the PQC and
findings dashboards. `/drift-watch` flags the graph stale when
`the inputs inventory` HEAD moves. The DOT/GEXF/HTML renders are
human-terminal.
