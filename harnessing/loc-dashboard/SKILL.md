---
name: loc-dashboard
description: Use when the user asks how many lines of code have been scanned/audited, wants a LoC breakdown by language or repo across the security-audit campaign, or asks to (re)build the LoC dashboard. Produces gh-languages-cache.jsonl and a self-contained loc-dashboard.html from the campaign manifests.
metadata:
  harness.tier: "tertiary"
allowed-tools:
  - Read
  - Write
  - Bash(python3 *traust/harnessing/loc-dashboard/scripts/build_loc_dashboard.py:*)
  - Bash(open *loc-dashboard.html:*)
  # Confinement added 2026-07-31 (P1 gate rework — the
  # widened S1 privilege tokens made this skill's missing
  # allowlist visible; assessment root-cause 3). Never
  # widen to a bare interpreter — scope scripts individually.
---

# LoC Dashboard

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Estimate and visualise the lines-of-code coverage of the security-audit campaign by querying the GitHub Languages API for every repository that already has a completed audit report, then rendering an interactive single-file HTML dashboard.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Incremental run — fetch only repos missing from the cache, rebuild dashboard. |
| `refresh` | Ignore the cache; refetch every repo from the GitHub API. |
| `no-fetch` | Skip the API entirely; rebuild the dashboard from the existing cache. |
| `open` | Open the resulting dashboard in the default browser when done. |
| `summary` | After building, print a plain-text summary table to the conversation. |
| `<path>` | Override the analysis-results root (directory containing `findings/` and `oss-findings/`). |

---

## Procedure

### Step 1 — Locate the analysis-results root

The harness needs the directory that contains `findings/_manifest/*.csv` and `oss-findings/`.

Resolution order:

1. A path passed in `$ARGUMENTS`.
2. `$AUDIT_RESULTS_ROOT` environment variable.
3. `../analysis-results` relative to the `traust` checkout (the normal sibling layout).
4. Walk upward from `$PWD` looking for a directory that contains `findings/_manifest/audit-manifest.csv`.

If none resolve, ask the user for the path.

### Step 2 — Run the harness script

The skill ships `build_loc_dashboard.py` alongside this file. Invoke it with Bash:

```bash
python3 "$SKILL_DIR/scripts/build_loc_dashboard.py" \
    --results-root <resolved-root> \
    [--refresh | --no-fetch] [--open] [--workers 20]
```

What the script does:

1. Reads the four manifest CSVs in `findings/_manifest/`:
   `audit-manifest.csv`, `services-manifest.csv`, `gap-manifest.csv`, `oss-manifest.csv`.
2. Filters to rows whose `canonical_path` report (`.json` or `.md`) **already exists on disk** — so the dashboard reflects *completed* audits and grows as the campaign progresses.
3. Deduplicates by GitHub URL. Counts internal-GitLab repos separately (they are reported as "not estimated").
4. For each unique GitHub repo not already in `gh-languages-cache.jsonl`, calls
   `gh api repos/{owner}/{repo}/languages` (parallel, default 20 workers).
   Linguist already excludes `vendor/`, `node_modules/`, generated code, and binary blobs.
5. Converts per-language byte counts → estimated LoC using the `BPL` table in the script.
6. Writes:
   - `findings/_manifest/gh-languages-cache.jsonl` — one JSON object per repo (sorted, diffable).
   - `progress-tracker/metrics/dashboards/loc-dashboard.html` — self-contained dashboard (no CDN deps).

### Step 3 — Report back

Always tell the user:

- The output paths (relative to the results root).
- Headline numbers: code-LoC, total-LoC, calibrated first-party LoC (÷ `FIRST_PARTY_DIVISOR`), repo counts, GitLab-excluded count.
- How many repos were freshly fetched vs cache-hit.

If `summary` was requested, also print the per-bucket and top-10-language tables to the conversation.

### Step 4 — Interpretation note (include once per session)

> The GitHub Languages API counts **all non-vendored source** including tests, fixtures, and tooling. Audit reports that hand-state LoC typically cite *first-party non-test* code only. Spot-checking against reports that record both gives a median ratio of ~`FIRST_PARTY_DIVISOR`× — the dashboard surfaces both figures.

---

## Outputs

| File | Purpose |
|---|---|
| `findings/_manifest/gh-languages-cache.jsonl` | Raw per-repo Linguist byte counts. Incremental cache; commit it so re-runs only fetch new repos. |
| `progress-tracker/metrics/dashboards/loc-dashboard.html` | Interactive dashboard: summary cards, bucket bars, language breakdown, sortable/filterable repo table with language-mix strips. |

The dashboard embeds the standard population block (python3 -m traust.cli corpus) as a final panel for cross-dashboard reconciliation.

---

## Operational notes

- **Auth:** uses the `gh` CLI; the user must be `gh auth login`-ed. No tokens are read or written by the skill.
- **Rate limit:** a full `--refresh` of ~2 k repos consumes ~2 k of the 5 k/hr core limit. Incremental runs cost only `<new repos>` calls.
- **Idempotent:** safe to wire into `finalize_batch.sh` or a `/loop` — incremental mode is the default.
- **Tuning:** edit the constants at the top of `build_loc_dashboard.py`:
  - `BPL` — bytes-per-line ratios per language
  - `DOC_LANGS` — languages excluded from the "code-only" total
  - `FIRST_PARTY_DIVISOR` — calibration factor for the first-party headline
- **GitLab repos** (any GitLab host in the inventory) are counted but not sized — the GitHub API can't reach them. If a GitLab MCP/token is available the script can be extended to call `GET /projects/:id/languages`.

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `gh: command not found` | GitHub CLI not installed | `brew install gh` / `dnf install gh` |
| Many `error: HTTP 404` rows | Repo renamed/deleted/private | Expected; they appear in the dashboard with status `err` and contribute 0 LoC. |
| `rate limit exceeded` | >5 k fetches in an hour | Re-run later; cache means only the failed tail re-fetches. |
| Dashboard shows 0 repos | Wrong `--results-root` | Pass the directory that contains `findings/_manifest/`. |

## Trends

Each run appends `total_loc` / `repos_with_loc` / `languages` (source
`loc-dashboard`) to the central metrics ledger (python3 -m traust.cli metrics history,
no-op when unchanged) and injects a trend-vs-previous banner into the
dashboard HTML.
