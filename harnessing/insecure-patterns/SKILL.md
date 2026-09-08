---
name: insecure-patterns
description: Use when the user asks which insecure coding patterns recur across the portfolio, wants findings grouped/ranked by CWE or OWASP ASVS category, asks "what are our top vulnerabilities by pattern", "which repos share CWE-X", or asks to (re)build the insecure-patterns dashboard. Walks every *-security-audit.json under analysis-results/findings/ (owned) and analysis-results/oss-findings/ (upstream, reported as a separate tagged cut), keeps only source-code findings (drops YAML/Dockerfile/Helm config gaps), buckets by primary CWE mapped to ASVS 5.0, and writes insecure-patterns/{top25.md, detailed.md, dashboard.html, .json}.
argument-hint: "[summary] [open] [<results-root-path>]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust/harnessing/insecure-patterns/scripts/build_insecure_patterns.py:*)
  - Bash(ls:*)
  - Bash(open *.html:*)
  - Read
  # scoped 2026-07-31 (P1-W4): A11 grandfather retired —
  # per-script anchored grants replace Bash(python3:*)
---

# Insecure Coding Patterns — ASVS 5.0 roll-up

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Aggregate every source-code security finding across the campaign into a ranked
table of recurring insecure coding patterns, categorised against the OWASP
ASVS 5.0 taxonomy, with example `repo · file · function` tuples and a
one/two-line root-cause fix per pattern.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Default run — scan `findings/` (owned) + `oss-findings/` (upstream), write all four outputs. |
| `summary` | Also print the top-25 table to the conversation. |
| `open` | Open the resulting dashboard in the default browser when done. |
| `<path>` | Override the analysis-results root (directory containing `findings/`; `oss-findings/` is optional — the upstream cut is skipped when absent). |

---

## Procedure

### Step 1 — Locate the analysis-results root

Resolution order:

1. A path passed in `$ARGUMENTS`.
2. `$AUDIT_RESULTS_ROOT` environment variable.
3. `../analysis-results` relative to the `traust` checkout (the normal sibling layout).

If none resolve, ask the user for the path.

### Step 2 — Run the harness script

```bash
python3 harnessing/insecure-patterns/scripts/build_insecure_patterns.py \
    --results-root <resolved-root> \
    [--summary]
```

What the script does:

1. Globs `findings/**/*-security-audit.json` (owned tree; recursive; ~5 k+
   reports) **and** `oss-findings/**/*-security-audit.json` (upstream tree),
   tagging every report with its tree. The two trees are aggregated
   separately — the owned tree drives all ranked tables; the upstream tree
   feeds only the tagged **Upstream cut** section and is never folded into
   the owned ranking, repo counts, or examples. When a sibling
   `*-findings-current.json` (cumulative report from the
   `track-findings` skill) exists, it is parsed **instead of** the audit by
   default, so the false-positive drop honours human triage and machine
   validation dispositions. The stats table reports how many reports carried
   dispositions, split owned vs upstream.
2. For each finding, decides **code vs config**: kept iff ≥1 `location.path`
   has a source-code extension (`.go`/`.py`/`.ts`/`.js`/`.java`/`.c`/`.rs`/…)
   *or* ≥1 `evidence.language` is a source-code language. Findings whose only
   artefacts are YAML/JSON/Dockerfile/Helm/TOML/Makefile are dropped as
   config/manifest gaps.
3. Drops findings with `validation_status: false_positive`.
4. **Pattern key = primary CWE** (`cwes[0]`, required by the report schema).
5. De-duplicates occurrences by `(repo, cwe, path)` — applied within each
   tree independently — so per-branch report copies count once. Repo is
   `metadata.repository` normalised to `owner/repo`.
6. Maps each CWE → OWASP ASVS 5.0 chapter/section via the curated
   `CWE_META` table in the script (ASVS 5.0 dropped its own CWE column, so
   this mapping is maintained in-harness). Unmapped tail CWEs land in
   `V15.3 Defensive Coding`.
7. Extracts a best-effort function/method name per occurrence from evidence
   code (`func`/`def`/`function`/`fn` regexes) → location description →
   `filename:lines` fallback.
8. Ranks patterns by **distinct repository count**, then occurrence count
   (owned tree only). The upstream tree gets its own top-10 ranking by the
   same key, rendered as the compact **Upstream cut (oss-findings/)**
   section in `insecure-patterns-top25.md` and a panel in the dashboard
   HTML, plus an additive `upstream` object in `insecure-patterns.json`.
9. Writes four artefacts under `progress-tracker/metrics/dashboards/insecure-patterns/`.

### Step 3 — Report back

Always tell the user:

- The four output paths (relative to the results root).
- Corpus stats: reports scanned (owned vs upstream), total findings, code
  findings kept, config/manifest dropped, distinct patterns.
- The top-25 table (CWE · pattern · ASVS § · repos · occurrences) — owned
  tree only; mention the upstream cut headline (reports + top pattern) when
  `oss-findings/` was scanned.

If `open` was requested, open the dashboard:
`open progress-tracker/metrics/dashboards/insecure-patterns/insecure-patterns-dashboard.html`

---

## Outputs

| File | Purpose |
|---|---|
| `insecure-patterns/insecure-patterns-top25.md` | Ranked top-25 table (owned) + ASVS-chapter distribution + **Upstream cut (oss-findings/)** top-10 section + method note. |
| `insecure-patterns/insecure-patterns-detailed.md` | Top-50 (owned): per-pattern ASVS ref, repo count, 6 example `repo · file:lines · function` tuples, co-tagged CWEs, and a 1-2 line root-cause fix. |
| `insecure-patterns/insecure-patterns-dashboard.html` | Self-contained interactive dashboard: summary cards, ASVS-chapter bars, filterable top-50 table (owned) with expandable examples + inline fixes, plus the tagged upstream-cut panel. |
| `insecure-patterns/insecure-patterns.json` | Machine-readable roll-up: full ranked pattern list (owned) with all repos, examples, severity mix; additive `upstream` object (`stats` + `patterns` for `oss-findings/`). |

The Markdown outputs and the dashboard HTML embed the standard population block (roots, unit, filters, denominator — from python3 -m traust.cli corpus) as a final section/panel for cross-dashboard reconciliation. Roots list both trees with their ownership tags (`findings/` owned, `oss-findings/` upstream) and every count is split owned vs upstream.

---

## Tuning

Edit constants at the top of `build_insecure_patterns.py`:

- `CODE_EXT` / `CODE_LANGS` — what counts as source code
- `CONFIG_EXT` — what marks a finding as config-only
- `CWE_META` — CWE → (name, ASVS section, section name, root-cause fix). Add
  entries here when a new CWE enters the top-50.
- `FUNC_PATTERNS` — regexes that pull function names out of evidence blocks

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: <root>/findings/ not found` | Wrong `--results-root` | Pass the directory that contains `findings/`. |
| Top-N pattern shows a finding-title instead of a CWE name | CWE not in `CWE_META` | Add a curated entry (name + ASVS section + fix). |
| Function column mostly `file:lines` | Evidence blocks don't include the definition line | Expected — the fallback is intentional. |
| A config-only finding leaked through | It also touched a `.sh`/`.go` helper | Tighten `CODE_EXT` or add the path to `CONFIG_EXT`. |

## Trends

Each run appends `code_findings` / `distinct_cwes` (source
`insecure-patterns`) to the central metrics ledger (python3 -m traust.cli metrics history,
no-op when unchanged) and injects a trend-vs-previous banner into
`insecure-patterns-top25.md` and the dashboard HTML.
