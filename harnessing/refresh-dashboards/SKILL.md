---
name: refresh-dashboards
description: >-
  Use when the user asks to refresh, rebuild, or update all the dashboards — "refresh the dashboards", "rebuild every dashboard", "update the derived views", "run the weekly dashboards job" — or on the weekly orchestration cadence. Runs python3 -m traust.cli dashboard refresh, the packaged "Dashboards rebuild" job from docs/continuous-operations.md: projections first (findings.db, census), then the per-dashboard builders (executive summary, trends, insecure-patterns, validation-fuzz, RBAC/tenancy rollup, SLA view, compliance, ATT&CK coverage, LoC cache-only, dependency-exposure, spend), then the leadership scoreboard last because it harvests the others. Deterministic, ~$0, no agents.
argument-hint: "[--only <stage...>] [--skip <stage>] [--spend-actuals] [--note <text>]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust* -m traust.cli.refresh_dashboards:*)
  - Read
---

# Refresh Dashboards — the one-command derived-views rebuild

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Every dashboard is a rebuildable projection of the disposition ledger and
the findings corpus. This skill rebuilds all of them in dependency order
as **one sequential deterministic job** — the same chain
`docs/continuous-operations.md` schedules weekly ("Dashboards rebuild"),
packaged so an operator, cron leg, or orchestrator fragment can fire it
as a single command.

Ordering is the whole point:

1. **Projections** — python3 -m traust.cli corpus findings-db, then
   `harnessing/census/scripts/build_census.py`. Everything downstream reads
   these; a failure here **aborts the run** (consumers would silently
   read stale data).
2. **Consumers** — executive summary, findings-trends,
   insecure-patterns, validation-fuzz dashboard, RBAC/tenancy rollup,
   SLA view, compliance dashboard, ATT&CK coverage rollup,
   LoC dashboard (cache-only), dependency-exposure, spend dashboard.
   Each continues on error; failures are collected.
3. **Scoreboard last** — `collect_harness_metrics.py` harvests headline
   numbers *from* the dashboards above, so it runs after all of them
   and appends its usual immutable row to `metrics-history.jsonl`.

## Procedure

1. Run the chain (deterministic; from the harness root):

   ```bash
   python3 -m traust.cli dashboard refresh \
       [--workspace-root <path>] [--results-root <path>] \
       [--only <stage...>] [--skip <stage>] \
       [--spend-actuals] [--note "<snapshot note>"] \
       [--list] [--dry-run]
   ```

   `--list` prints the stage names; `--only`/`--skip` select stages
   (canonical order is always preserved); `--note` is forwarded to the
   scoreboard's metrics-history snapshot row.

2. **Read the summary table back.** Report which stages ran, which
   failed, and the elapsed time. A projection failure means the run
   aborted — say what did not run and fix the projection before
   retrying. Consumer failures don't block the others; report each
   failed stage with its builder so the user can rerun it alone
   (`--only <stage>`).

3. **Commit the rebuilt artifacts** in `analysis-results/` and
   `progress-tracker/` per the workspace convention (dashboards are
   projections — regenerating them is always safe; history lives in
   `metrics-history.jsonl`, which only appends).

## What it does NOT cover

- **Spend actuals** (python3 -m traust.cli metrics collect-spend --append) reads
  Claude Code session transcripts on the operator's workstation, so the
  default job skips it to stay orchestrator-portable. Pass
  `--spend-actuals` when running on a workstation that has transcripts;
  the `dashboards:spend-actuals` drift row guards this leg either way.
- **LoC language-cache refresh** — the `loc` stage rebuilds the
  dashboard from the committed `gh-languages-cache.jsonl` only
  (`--no-fetch`); refreshing the cache sweeps the GitHub API and stays
  with `/loc-dashboard` under the gh-api fleet-sweep constraints.
- **Agent-built views** — the threat register (`/threat-register`)
  involves judgment, not just aggregation, and is rebuilt by its owning
  skill on its own cadence. The scoreboard reads whatever its latest
  artifact says.
- **Campaign-lane artifacts** that live in the same dashboards folder —
  pqc views, operator-least-priv, rbac-openshift-platform, fuzz,
  benchmark — are outputs of their campaign runs (`/pqc-readiness`,
  `/operator-priv-profile`, `/create-fuzzing`, `/recall-benchmark`),
  not aggregation dashboards; they update when those lanes run.
- **Deciding when to rebuild** — that's `/drift-watch`; its
  `dashboards:*` rows remain the dead-timer backstop (scoreboard >7d,
  spend >4d).

## Stages

| Stage | Tier | Builder |
|---|---|---|
| `findings-db` | projection | python3 -m traust.cli corpus findings-db |
| `census` | projection | `harnessing/census/scripts/build_census.py` |
| `exec-summary` | consumer | `harnessing/executive-summary-findings/scripts/build_executive_summary.py` |
| `trends` | consumer | `harnessing/findings-trends/scripts/build_trends.py` |
| `insecure-patterns` | consumer | `harnessing/insecure-patterns/scripts/build_insecure_patterns.py` |
| `validation-fuzz` | consumer | `harnessing/validation-fuzz-dashboard/scripts/build_validation_fuzz_dashboard.py` |
| `rbac-tenancy` | consumer | `harnessing/rbac-tenancy-rollup/scripts/build_rbac_tenancy_rollup.py` |
| `sla` | consumer | python3 -m traust.cli metrics sla |
| `compliance` | consumer | python3 -m traust.cli compliance dashboard |
| `attack-coverage` | consumer | `harnessing/attack-coverage/scripts/build_attack_coverage.py` |
| `loc` | consumer | `harnessing/loc-dashboard/scripts/build_loc_dashboard.py --no-fetch` (committed gh-languages cache only) |
| `dependency-exposure` | consumer | `harnessing/refresh-dashboards/scripts/build_dependency_exposure.py` (portfolio-graph dependency layer + impact/fleet-OSV artifacts; degrades gracefully when absent) |
| `spend-actuals` | consumer, opt-in | python3 -m traust.cli metrics collect-spend --append |
| `spend` | consumer | python3 -m traust.cli metrics spend |
| `scoreboard` | consumer | `harnessing/traust-metrics/scripts/collect_harness_metrics.py` |

## Integrations

- **Emits no artifact of its own** — every output is owned by the
  builder that writes it (census.{json,md,html}, the dashboard files
  under `progress-tracker/metrics/dashboards/`, findings.db, the
  scoreboard + metrics-history). Consumers are documented in each
  owning skill.
- **docs/continuous-operations.md** names this script as the "Dashboards
  rebuild" scheduled job (orchestrator target: weekly; spend ≤4d).
- **/drift-watch** routes attention here: when `dashboards:*` rows go
  stale, the refresh command is this script.
- **/traust-metrics `--refresh-sources`** remains the
  scoreboard-scoped partial refresh (a skill-level token interpreted by
  the agent — the collector script itself has no such argparse flag);
  this skill is the full chain.
