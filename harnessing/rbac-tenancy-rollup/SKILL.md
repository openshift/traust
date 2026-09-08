---
name: rbac-tenancy-rollup
description: Use when the user asks for a portfolio view of RBAC or multi-tenancy findings — "what are our RBAC issues", "top RBAC misconfigurations", "multi-tenancy findings rollup", "which repos have over-permissive RBAC", "tenant-isolation findings summary", "ATT&CK view of our RBAC findings" — or asks to (re)build the RBAC/tenancy dashboard. Deterministically aggregates authorization and tenant-isolation findings from the corpus-resolved report population (disposition-aware, FP-excluded, branch re-audits excluded) into an executive rollup with MITRE ATT&CK candidate-technique heat, a detailed top-misconfigurations report, and a self-contained HTML dashboard under progress-tracker/metrics/dashboards/rbac-tenancy/.
metadata:
  harness.tier: "secondary"
---

# RBAC & Multi-Tenancy Rollup

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Aggregates the campaign's RBAC (authorization) and multi-tenancy
(tenant-isolation) findings into leadership-facing rollups. All analysis
is script-side and deterministic; the model's job is to run the builder,
sanity-check the outputs, and narrate.

## Input

`$ARGUMENTS` may be empty (default: the owned `findings` tree) or name
corpus trees (`--trees findings cloud-config`), an alternate
analysis-results path, or an alternate output directory.

## Procedure

### Step 1 — run the deterministic builder

```bash
python harnessing/rbac-tenancy-rollup/scripts/build_rbac_tenancy_rollup.py \
    [--trees findings ...] [--analysis-results <path>] [--out <dir>]
```

The builder resolves the population via python3 -m traust.cli corpus (never a
hand-rolled walker), embeds the standard population block, and writes to
`progress-tracker/metrics/dashboards/rbac-tenancy/`:

| Artifact | Audience |
|---|---|
| `rbac-tenancy-rollup.md` | executive one-pager: headline counts, top patterns, top repos |
| `rbac-tenancy-detailed.md` | per-pattern finding tables (top misconfigurations with ids/locations) |
| `rbac-tenancy.html` | self-contained dashboard |
| `rbac-tenancy.json` | machine-readable rollup (full selected-finding list) |

### Step 2 — interpret honestly

- **Counting semantics** (mirror the census taxonomy): disposition-aware
  where a `findings-current.json` ledger view exists (false positives
  excluded, `resolved` counted separately, `hardening` bucketed as
  posture debt, `confirmed` badged); raw-audit severity otherwise.
  Branch re-audits and md-only reports are excluded from counts.
- **Selection tiers are confidence labels, not equals**: T1 = structured
  fields (`category` ∈ {authorization, tenant-isolation},
  `peach_references`, `isolation_dimensions`/`isolation_boundary`);
  T2 = framework signals (authz CWE set 862/863/269/284/266/250/648/283/639/668,
  OWASP-K8s K02/K08 or `KHS-R*` citations); T3 = lexical keyword matches
  (heuristic). Never quote an individual T3 row to leadership without
  opening the underlying finding; T3 aggregates are directional only.
- **Pattern buckets** are first-match regex clusters (confused-deputy via
  controller SA, cross-tenant access, cluster-admin bindings, wildcard
  verbs/resources, cluster-wide secrets read, escalate/bind/impersonate,
  RBAC self-escalation, cross-namespace / AllNamespaces, missing tenant
  scoping, SA-token automount, missing network segmentation,
  webhook/aggregated-API exposure, GitHub-Actions workflow privilege,
  unauthenticated endpoints, app-level role over-grants,
  injection-to-privilege, untrusted build/auto-merge input, TLS
  verification gaps, client-supplied identity trust, hardcoded/leaked
  credentials, privileged workload config, cloud IAM overbreadth, shared
  identities). A finding lands in exactly one bucket; `other` collects
  the remainder — if `other` dominates, the buckets need extending (file
  it, don't hand-wave).
- **ATT&CK semantics**: the technique heat table lists **weakness-derived
  CANDIDATE techniques** (what an adversary would use to exploit that
  weakness class), inferred from three sources in confidence order —
  `cited` (finding text names the technique), `pattern` (bucket-derived
  map), `category` (attack-coverage's shared `category_map`). All IDs are
  validated against the pinned vendored ATT&CK table
  (`harnessing/attack-coverage/tables/`); deprecated/revoked/unknown IDs
  are dropped and reported. NEVER present candidates as observed
  adversary behavior — for validated chains use `/attack-coverage`, which
  joins live-validation evidence. Keep the MITRE attribution line in any
  derived artifact.

### Step 3 — placement discipline

Outputs are dashboards/rollups → they belong in
`progress-tracker/metrics/dashboards/` and ONLY there. Never copy the
underlying findings reports into progress-tracker; the rollups reference
`analysis-results` paths (owner directive, 2026-07-21).

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `configured tree missing on disk` warning | tree name typo or unregistered tree | check `$TRAUST_CONFIG_HOME/corpus-config.yaml` / run `/census` |
| `other` pattern bucket dominates | bucket regexes lag new finding phrasing | extend `PATTERNS` in the builder (order matters; first match wins) |
| Counts disagree with census headline | census counts ALL findings; this rollup selects RBAC/tenancy classes only and applies the same disposition rules | expected — cite the population block |
| Zero tenancy findings on a multi-tenant tree | reports predate PEACH tagging | note the coverage gap; re-audit or isolation-review refreshes tags |
