---
name: sla-view
description: >-
  Use when the user asks about SLA compliance, overdue findings, response/remediation deadlines, breach counts, or escalation lists — e.g. "what's past SLA", "criticals overdue", "are we meeting the 30-day clock", "SLA view for FedRAMP", "who's most overdue". Replays disposition-ledger clocks against a schema-validated SLA policy (default: Red Hat PSIRT VMWM) and emits sla-view.{json,md} with per-team overdue tables and a human-gated escalation digest.
metadata:
  harness.tier: "secondary"
---

# SLA View — Owner-Response Clocks

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Per-severity resolve clocks over every clocked finding, scored against a
policy file. This is the adoption metric that replaced the retired
"team packages delivered" count: it measures whether owners respond,
not whether we shipped them lists.

## The one rule that matters

**SLAs are policy data, never code.** The shipped default is the Red Hat
PSIRT Vulnerability Management Workflow Manual policy
(`progress-tracker/configs/sla-policy.yaml`, gated by
`contracts/schemas/sla-policy.schema.json`, provenance + retrieval date inside).
Different SLAs — customer contracts, per-BU policies — are a different
file passed with `--policy`, never an edit to the script. The
severity mapping (PSIRT Important→high, Moderate→medium, Low→low) is
part of that data, because external severity vocabularies and the
harness enum are different languages and the join must stay auditable.

## Procedure

1. **Freshness first** — the view reads the C9 findings DB; rebuild it
   if the ledgers moved since its `built_at`:

   ```bash
   python3 -m traust.cli corpus findings-db
   ```

2. **Build the view** (repeat per profile when asked for a compliance
   cut):

   ```bash
   python3 -m traust.cli metrics sla \
       [--profile internal-cve|fedramp-rosa-gc|fedramp-aro] \
       [--policy <other-policy.yaml>] [--as-of YYYY-MM-DD] \
       [--pd-cache-dir <feeds-dir>]
   ```

   Output: `progress-tracker/metrics/dashboards/sla/sla-view.{json,md}`.

3. **Report back**: overdue count (lead with criticals), resolved-SLA
   compliance %, the per-team overdue table, and the unclocked /
   out-of-scope counts (transparency rows — findings the profile does
   not clock are counted, never silently dropped). Label the profile on
   every number: internal-cve and fedramp-rosa-gc figures are different
   clocks over the same findings, not different findings. When a digest
   row carries an `accountable_contact` (Product Security registry),
   report it with the caveat that an accountable contact is an
   escalation path, **not** an owner — anyone acting on one checks the
   contact against the deployment's employee directory first (the
   ledger's `LEDGER_DIRECTORY_COMMAND`, where one is configured).

## Clock semantics (deterministic, stated in the artifact)

- Clock start ladder (`clock_start: first_routed_or_filed`): routing/
  filing ledger event → earliest ledger event → report audit date. No
  ladder rung ⇒ `unclocked`, counted and shown, never guessed. (No
  filing events exist in today's corpus; that rung activates when
  Jira-filing events reach the ledger.)
- `resolve_days: null` = tracked, never overdue (PSIRT Low).
- `cvss_floor_days` (FedRAMP ARO): CVSS ≥ threshold overrides the
  severity clock.
- Resolved findings score compliance against their due date; median
  days-to-resolve is reported per severity.

## Constraints

- **The escalation digest is generated, never auto-sent.** Routing it
  to individuals or channels requires human review of the list first.
- **The registry join is optional and corroborating.** Accountable
  contacts come from python3 -m traust.cli registry products at trustworthy
  match tiers only (`mapped`/`repo-url` — a slug guess never lands in an
  unattended artifact). An absent or off-VPN cache reads as
  `source_status: unavailable` in the metadata with null contacts —
  never a failed run. Escalation contacts confer no disposition
  authority, and only tier 1 is embargo-cleared (see
  `assign-findings-owners` Step 6 for the rules — not restated here).
- Branch re-audits are excluded (HEAD findings carry the clock);
  hardening/FP/refuted classes are excluded like every dashboard.
- The census remains the denominator authority; when an SLA headline
  will be quoted upward, state the profile, the policy retrieval date,
  and the DB build time (all embedded in the artifact metadata).
- When touching the shipped policy file, re-verify the values at the
  source URL and update `source.retrieved`.

## Integrations

**Consumes:** the C9 findings DB (producer:
python3 -m traust.cli corpus findings-db); `progress-tracker/configs/sla-policy.yaml`
(human-curated policy data); `analysis-results/feeds/product_definitions.json`
(producer: python3 -m traust.cli feeds fetch --feed product-definitions, read via
python3 -m traust.cli registry products) plus `$TRAUST_CONFIG_HOME/product-definitions-map.yaml`
for the accountable-contact join.

**Emits:** `progress-tracker/metrics/dashboards/sla/sla-view.{json,md}` —
read by humans and quoted by the executive dashboards; the escalation
digest inside it is generated, never auto-sent.
