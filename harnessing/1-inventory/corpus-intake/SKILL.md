---
name: corpus-intake
description: Use when the user wants to register, update, or review a corpus tree or scan engagement — "add a new BU engagement", "register this tree", "onboard <name> scanning work", "why is this tree unregistered", "update the ownership of X" — or when any census/dashboard run reports an unregistered-tree drift warning. Interactively interviews for the registration fields (or takes them as arguments), validates and updates $TRAUST_CONFIG_HOME/corpus-config.yaml through corpus_intake.py (never hand-edited), then re-runs /census so the corpus manifest reflects the change immediately.
argument-hint: "[add|update|list] [<name>] [field=value ...]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 *traust/harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py:*)
  - Bash(python3 *traust/harnessing/census/scripts/build_census.py:*)
  - Bash(ls:*)
  - Read
  # scoped 2026-07-31 (P1-W4): A11 grandfather retired —
  # per-script anchored grants replace Bash(python3:*)
---

# Corpus Intake — register trees and engagements

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


`$TRAUST_CONFIG_HOME/corpus-config.yaml` is the single source of truth for which trees
under `analysis-results/` are in the report corpus and who owns them.
This skill is its only supported write path: interview → validate →
atomic write → census refresh. Never edit the file by hand.

## Input

`$ARGUMENTS` may be empty (full interview), `list`, or a partial
registration (`add contoso tree=contoso-findings ...`) whose missing
fields the interview fills in.

---

## Procedure

### Step 1 — Show current state

```bash
python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py list
```

Present the registered trees/engagements and any DRIFT warnings. If the
user only asked to review ("list", "what's registered"), stop here.

### Step 2 — Interview for the registration fields

Collect, one question at a time, anything not already provided:

1. **Kind** — does the output tree already exist (or is it about to)
   under `analysis-results/` (→ tree), or is this reserving a label for
   an engagement that has not produced output yet (→ engagement)?
2. **Name** — the config key (engagement codename or tree directory
   name). Letters/digits/`._-` only.
3. **Tree** (engagements only) — the directory the output will land in.
   Convention: `<name>-findings/`, one tree per engagement.
4. **Ownership tag** — exactly one of:
   - `owned` — Hybrid Platforms BU backlog (Lens 2 headline);
   - `upstream` — community code HP relies on; adjacent line, never
     folded into the owned headline;
   - `external-bu` — scan work for another BU; Lens 1 (work performed)
     only, excluded from HP executive risk numbers.
   - `harness-qa` — harness self-measurement artifacts (probes,
     benchmarks, side-by-side sweeps); registered so drift-watch knows
     the tree is vetted, but excluded from EVERY metrics lens —
     `corpus.resolve()` never walks it.
   Probe the semantics, not just the label: "Does Hybrid Platforms own
   the remediation backlog for this code?" (owned) / "Do we ship or
   depend on it?" (upstream) / "Are we only performing the scanning
   work?" (external-bu) / "Is this the harness measuring itself, where
   counting the findings would double-count or distort?" (harness-qa).
5. **Business unit** — the human-readable BU/initiative name shown on
   dashboards.
6. **Inventory** (optional) — path to the input inventory CSV in
   the inputs inventory (`locations.inputs`) if one exists.
7. **Notes** (optional) — anything non-obvious, especially product-vs-BU
   dualities (see the `ansible` entry: catalog operators inside
   `findings/` stay owned while the BU engagement is external).

If the answers reveal a BU boundary cutting through an existing tree
(some products owned, some not), do NOT force a tree-level tag — flag it
to the user and record the exception in `notes`; per-product `overrides`
support lands with a later phase.

### Step 3 — Apply

```bash
python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py add-tree <name> \
    --label <label> --ownership <tag> --business-unit "<BU>" \
    [--notes "..."]
# or
python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py add-engagement <name> \
    --label <label> --ownership <tag> --business-unit "<BU>" \
    --tree <tree> [--inventory <path>] [--notes "..."]
# or targeted field changes
python3 harnessing/1-inventory/corpus-intake/scripts/corpus_intake.py update \
    (tree|engagement) <name> [--ownership ...] [--business-unit ...] ...
```

The tool validates before writing (duplicate names/labels, overlapping
tree mappings, ownership enum, name syntax), renders the file from its
canonical template (documentation comments never rot), and writes
atomically — a failed gate cannot corrupt the config. Exit 2 = validation
error: relay the message, fix the field, retry.

### Step 4 — Refresh the census

```bash
python3 harnessing/census/scripts/build_census.py
```

Confirm the new entry appears (engagements show "registered, no output"
until their tree exists) and that no unexpected DRIFT warnings remain.

### Step 5 — Remind about inventory

If the engagement has repos to scan and no inventory registered, remind
the user to run `/add-inputs` to add them to the inputs inventory
(and record the path here via `update ... --inventory`).

---

## Outputs

- Updated `$TRAUST_CONFIG_HOME/corpus-config.yaml` (atomic, validated, canonical
  layout).
- Refreshed `census.{json,md,html}` under
  `progress-tracker/metrics/dashboards/census/`. (`corpus-manifest.json` was
  retired 2026-08-20; the resolved record list lives in findings.db `repos`.)

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `label 'x' is already in use` | Another tree/engagement claimed it | Pick a distinct label or update the existing entry instead. |
| `tree 'x' is already mapped` | Tree collision with an existing entry | One tree per engagement — pick a new directory name. |
| DRIFT warning persists after add | Tree on disk differs from the registered name | Register the exact directory name shown in the warning. |
| Render round-trip mismatch | Bug — file untouched by design | Report it; nothing was written. |
