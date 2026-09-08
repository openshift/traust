---
name: findings-trends
description: Use when the user asks whether portfolio security findings are trending up or down, wants a burndown, remediation velocity, MTTR, risk-index, or accepted-risk trend, or asks to (re)build the findings-trends dashboard — e.g. "are we getting better", "findings over time", "how fast are we remediating", "what risk have we accepted". Replays every repo's track-findings disposition ledger against time buckets and emits findings-trends.{json,md,html} with direction arrows per metric.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# Findings Trends

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Track whether the portfolio is getting better or worse. Because the
`track-findings` disposition layers are append-only ledgers of timestamped
events, the portfolio's state at **any past date** can be reconstructed by
replaying only the events dated before it — no snapshots, no stored trend
state, fully deterministic. This skill runs that replay at monthly (or
weekly) boundaries and reports the direction of every metric.

## When to Use

- "Are findings trending up or down?" / "are we getting better?"
- "Show me the burndown" / "remediation velocity" / "MTTR"
- "How much risk have we accepted?" / "what's on the accepted-risk register?"
- "Rebuild the trends dashboard"

## Invocation

```
python3 harnessing/findings-trends/scripts/build_trends.py $ARGUMENTS
    [--results-root DIR]        # default ../analysis-results
    [--granularity month|week]  # default month
    [--since YYYY-MM]
    [--product <name>]          # one product directory slice
    [--as-of YYYY-MM-DD]        # pin the series end (reproducible runs)
    [--out-dir DIR]             # default <results-root>/trends
```

Outputs `findings-trends.{json,md,html}` into `progress-tracker/metrics/dashboards/trends/`. The md/html outputs embed the standard population block (roots, unit, filters, denominator) for cross-dashboard reconciliation, plus an "Ownership cuts (latest bucket)" section splitting open findings, open C/H, and risk index between owned (`findings/`, Hybrid Platforms) and upstream (`oss-findings/`) — upstream is never folded into the owned headline.

## Semantics (fixed by design decisions, 2026-07-10)

- **Option A open counting.** Every finding from every audited repo counts
  as *open* until a ledger event closes it. Repos without ledgers therefore
  contribute permanent open exposure — that is the point: total exposure is
  what leadership needs, and the ledger-coverage figure is printed next to
  every headline so partial coverage can't masquerade as a trend.
- **Accepted risk is not remediation.** `risk_accepted` findings leave
  "open" but land on a standing **Accepted Risk Register** — unfixed and
  unmitigated, reported with severity, CVSS, who accepted, when, and the
  recorded rationale. The register never decays; it shrinks only through
  remediation or re-triage. The accepted-risk CVSS sum is its own trend
  series, distinct from the open risk index.
- **Risk index = CVSS sum.** Sum of `cvss.score` over open findings;
  findings without CVSS use their severity band midpoint (critical 9.5,
  high 8.0, medium 5.5, low 2.0, informational 0). Custom weighting is
  a deliberate non-goal for now.
- **Buckets use `occurred_at`.** Events bucket by their source timestamp
  (commit date, Jira transition, MR comment date) when the adapters
  recorded one, falling back to `recorded_at` — late ingestion does not
  distort the series.
- **Countersign rule honoured.** State replay reuses the track-findings
  merge engine (`derive_disposition`), so a machine-refuted finding stays
  open until an LDAP-verified human countersigns the false positive.

## Metrics and polarity

| Metric | Good direction |
|---|---|
| Open findings, risk index, new findings, MTTR, FP rate, regressions, accepted risk index | ↓ |
| Remediation velocity, ledger coverage | ↑ |

Direction = last bucket vs the mean of up to three prior buckets, with a
±10% dead band rendered as → flat. Worsening metrics carry a ⚠ flag.

## Procedure

1. **Refresh the exploitation feeds** (pull-through cache; no scheduler
   needed — skip silently offline, the builder falls back to the stale
   copy or to CVSS-only likelihood):

   ```bash
   python3 -m traust.cli feeds fetch   # EPSS + CISA KEV, 24h freshness
   ```

2. Resolve arguments; run the builder (above). It walks
   `findings/**/*-security-audit.json` (plus `oss-findings/`), pairs each
   audit with its sibling `*-findings-layer.json`, and replays. When the
   feeds cache is present, CVE-bearing findings gain an
   **exploitation-evidence likelihood factor** (KEV membership / EPSS
   band — `threat_intel_factor` in `risk-rating-methodology.json`); the
   dashboard's methodology note records feed versions and staleness.
3. Read `findings-trends.md` back to the user. Lead with the direction
   table, then call out:
   - any **worsening ⚠** metric, with the driving repos where identifiable
   - the **Accepted Risk Register** headcount and its highest-CVSS entries
   - the **ledger coverage** figure and its trend — if coverage is low,
     say explicitly that the open count is dominated by untracked repos
4. Offer the HTML dashboard path for sharing.

## Gotchas

- **The final bucket is usually partial.** A mid-month run undercounts the
  current month; the classifier still uses it. For board-ready numbers run
  with `--as-of` set to the last day of the previous month.
- **Trends only move when ledgers move.** If nothing was ingested since
  the last run, the series is identical — flat is the correct answer, not
  a bug. Coverage ↑ is the first trend to chase on a new portfolio.
- **Don't hand-compute the numbers.** All aggregation lives in
  `build_trends.py`; the skill presents, it never re-derives.
- **A shrinking open count with shrinking coverage is a red flag** — check
  whether repos were removed from the findings tree rather than remediated.
