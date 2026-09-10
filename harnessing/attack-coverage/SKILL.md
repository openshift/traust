---
name: attack-coverage
description: Use when the user asks for MITRE ATT&CK coverage of the portfolio — "which ATT&CK techniques/tactics do our threats or validated chains cover", "build the ATT&CK Navigator layer", "ATT&CK heat map", or after updating threat models/validations to refresh the coverage roll-up. Deterministically joins validated attack chains, threat-model attack_refs, and finding-category-derived candidates against the pinned vendored ATT&CK table and emits a Navigator layer JSON plus a tactic/technique coverage one-pager.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# ATT&CK Coverage Roll-up

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Fleet-wide MITRE ATT&CK coverage from artifacts the pipeline already
produces. **Fully deterministic** — every number is a table lookup or a
count; no agent authors, adds, or reinterprets a technique reference.

## The three evidence classes (never blended)

| Class | Source | Meaning |
|---|---|---|
| **observed** (score 3) | `validations/**/*validation*.json` → `attack_chains[].mitre_attack_refs` on confirmed chains | adversary behavior demonstrated against a live target |
| **modeled** (score 2) | threat models' optional `attack_refs` column (section 4) | behavior an owner/bootstrap pass named as a threat |
| **derived** (score 1) | audit finding categories → [`tables/attack-mapping.json`](tables/attack-mapping.json) `category_map` | candidate techniques implied by a weakness class — potential, not behavior |

## Shared assets (used by other skills)

- [`tables/attack-techniques.json`](tables/attack-techniques.json) — distilled technique/mitigation table
  from ONE sha256-pinned ATT&CK release (`build_attack_table.py`; pin in
  [`tables/attack-bundle.sha256`](tables/attack-bundle.sha256)). The single source every harness
  component validates technique IDs against.
- [`tables/attack-mapping.json`](tables/attack-mapping.json) — harness vocabulary → candidate technique
  IDs (`capability_map` feeds `validate-findings/chain.py`; `category_map`
  feeds this roll-up). Schema: `contracts/schemas/attack-mapping.schema.json`.
- `attack_refs.py` — loader + validator. CLI:
  `--validate <ids…>` (used by threat-model authors) and
  `--validate-tables` (referential integrity, also enforced in tests).

## Run

```bash
python3 harnessing/attack-coverage/scripts/build_attack_coverage.py \
    --results-root ../analysis-results
```

Outputs to `progress-tracker/metrics/dashboards/attack-coverage/`:

| File | Contents |
|---|---|
| `attack-navigator-layer.json` | ATT&CK Navigator layer (format 4.5) — load at <https://mitre-attack.github.io/attack-navigator/>; score 1/2/3 = derived/modeled/observed |
| `attack-coverage.md` | per-tactic and per-technique coverage tables, population block, dropped-reference report |

Also appends `attack-coverage` metrics to the shared hash-chained ledger
(best-effort, `append_if_changed`).

## Hard rules

- Technique IDs are **selected, never authored**: anything not present and
  live in the pinned table is dropped *and listed* in the "Dropped
  references" section — no silent loss.
- `derived` counts never masquerade as observed behavior; the three
  classes stay separate in every output.
- Upgrading the ATT&CK release is a deliberate act: bump `ATTACK_VERSION`
  in `build_attack_table.py`, run with `--refresh-pin`, review the diff
  (revocations!), fix any mapping fallout flagged by
  `attack_refs.py --validate-tables`, commit.
- ATT&CK® is © The MITRE Corporation, used with attribution under the
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/);
  the attribution statement travels in the vendored table and every
  emitted layer.
