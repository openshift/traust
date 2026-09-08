---
name: validation-fuzz-dashboard
description: Use when the user asks for a live-validation dashboard, fuzzing-results dashboard, validation coverage roll-up, or "how many findings were confirmed exploitable / refuted" — e.g. "build the validation dashboard", "combine validation and fuzz results", "what did live validation confirm", "validation false-positive rate". Aggregates every validations/*/*validation*.json report plus FUZZ-CAMPAIGN-SUMMARY.md into one self-contained HTML dashboard.
metadata:
  harness.tier: "secondary"
---

# Live Validation & Fuzzing — Portfolio Dashboard

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Roll up every live-validation report (verdicts rendered against static-audit
findings in real environments) and the offline fuzz campaign into a single
self-contained HTML dashboard: confirmed-exploitable hero number, verdict share
by claimed severity, validation coverage, top targets by confirmed findings,
attack chains with a confirmed step, fuzz pattern hit-rates, and the confirmed
fuzz-bug table.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Standard run — scan `<results-root>/validations/` + `FUZZ-CAMPAIGN-SUMMARY.md`, write the dashboard. |
| `open` | Open the resulting HTML in the default browser when done. |
| `summary` | After building, print verdict totals and top-5 targets to the conversation. |
| `<path>` | Override the analysis-results root (directory containing `validations/`). |

---

## Procedure

### Step 1 — Locate the analysis-results root

Resolution order (same as `/executive-summary-findings`):

1. A path passed in `$ARGUMENTS`.
2. `$AUDIT_RESULTS_ROOT` environment variable.
3. `../analysis-results` relative to the `traust` checkout.
4. Walk upward from `$PWD` looking for a directory containing `validations/`.

If none resolve, ask the user for the path.

### Step 2 — Run the harness script

The skill ships `build_validation_fuzz_dashboard.py` alongside this file:

```bash
python3 "$SKILL_DIR/scripts/build_validation_fuzz_dashboard.py" \
    --results-root <resolved-root>
```

What the script does:

1. Walks `<results-root>/validations/*/`, loading every `*validation*.json`
   (the live-validation report schema: `validated_findings[]` with
   `verdict` ∈ CONFIRMED / REFUTED / INCONCLUSIVE / BLOCKED_BY_SCOPE /
   NOT_ATTEMPTED and `claimed_severity`, plus `attack_chains[]` and
   `needs_credential[]`).
2. Reads `<results-root>/FUZZ-CAMPAIGN-SUMMARY.json` (machine-readable
   sidecar from `build_fuzz_rollup.py`) — totals, batches, confirmed bugs
   (repo / bug / CVSS / CWE / advisory), and pattern hit-rates; falls back
   to parsing the `.md` pipe tables on pre-sidecar trees.
3. Aggregates: verdict × claimed-severity matrix, per-target confirmed counts,
   confirmed-Critical finding list, attack chains with ≥ 1 confirmed step
   (never the raw mapped-chain count — most steps are `not_attempted` and the
   raw number misleads), validation coverage (attempted / total checks).
4. Writes:
   - `progress-tracker/metrics/dashboards/Live-validation-fuzz-dashboard.html` — single file,
     inline SVG (no CDN), light/dark via `prefers-color-scheme`, hover tooltips
     plus `<details>` table views so no value is color- or hover-gated.
   - `progress-tracker/metrics/dashboards/Live-validation-fuzz-dashboard.md` — Markdown one-pager
     (same numbers: headline, verdict×severity table, top targets, fuzz
     hit-rates and bugs, confirmed-Critical list). Suitable for pasting into
     a doc or Slack. Override with `--out-md`.

Design notes (dataviz conventions baked into the script — keep them if editing):
verdict segments use the fixed status palette (confirmed=critical red,
inconclusive=warning, blocked=serious, refuted=good) with 2px surface gaps,
legend, and in-segment % labels only where they fit; magnitude bars are
single-hue (categorical slot 1); NOT_ATTEMPTED is excluded from the stacked
bars and shown as a coverage meter instead, so validated and unvalidated
populations are never conflated.

### Step 3 — Report back

Always tell the user:

- The two output paths (HTML + Markdown).
- Headline numbers: reports scanned, confirmed / refuted / inconclusive /
  blocked totals, confirmed-Critical count, coverage %, fuzz bugs confirmed.
- The top 3 targets by confirmed findings.

If `summary` was requested, also print the verdict-by-severity table.

---

## Outputs

| File | Purpose |
|---|---|
| `Live-validation-fuzz-dashboard.html` | Self-contained dashboard: hero (confirmed-exploitable), KPI tiles, verdict-by-severity stacked bars, coverage meter, top-targets bars, fuzz pattern hit-rates, confirmed fuzz-bug and confirmed-Critical tables. |
| `Live-validation-fuzz-dashboard.md` | Markdown one-pager with the same numbers — headline, verdict×severity table, top targets, fuzz hit-rates/bugs, confirmed-Critical list. Paste-ready for docs or Slack. |

Both outputs embed the standard population block (python3 -m traust.cli corpus) for
cross-dashboard reconciliation.

The script is idempotent and read-only over its inputs — re-run it whenever new
validation reports land or the fuzz summary changes.

## Trends

Each run appends `confirmed_exploitable` / `refuted` / `checks_attempted` /
`chains_confirmed` / `fuzz_bugs` (source `validation-fuzz`) to the central
metrics ledger (python3 -m traust.cli metrics history, no-op when unchanged) and injects
a trend-vs-previous banner into both outputs.
