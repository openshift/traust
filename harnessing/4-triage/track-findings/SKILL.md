---
name: track-findings
description: Use when the user wants to record human triage feedback or machine validation results against the findings of a *-security-audit, *-cloud-config-audit, or *-container-audit report and produce a cumulative status report — ingesting merge-request comments, commits, Jira tickets, interactive human triage, live-validation reports, and remediation-verification reports into an append-only disposition layer, then generating a schema-conformant *-findings-current.{json,md} showing the current validity and resolution of every finding.
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - AskUserQuestion
  # forge/Jira text this skill parses is attacker-postable; the ledger
  # writers are the only mutation path (audit D6, plan P2.14). Never
  # widen to a bare interpreter or grant raw egress.
  - Bash(git show:*)
  - Bash(git log:*)
  - Bash(git rev-parse:*)
  - Bash(jq:*)
  - Bash(ls:*)
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(head:*)
  - Bash(python3 -m traust.cli build cumulative:*)
  - Bash(python3 *harnessing/4-triage/track-findings/scripts/baseline_claims.py:*)
  - Bash(python3 *-m traust.cli.countersign:*)
  - Bash(python3 *-m traust.cli corpus finding-identity:*)
  - Bash(python3 *-m traust.cli reporting validate:*)
  - Bash(python3 *-m traust.cli.emit_triage_ledger_events:*)
  - Bash(python3 *-m traust.cli.emit_validation_ledger_events:*)
  - Bash(python3 *-m traust.cli.emit_verification_ledger_events:*)
  - Bash(python3 *-m traust.cli.route_regressions:*)
---

# Track Findings

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


An audit report is a snapshot; the truth about its findings keeps evolving
afterward. This skill maintains a **disposition layer** — an append-only
ledger of who or what said what about each finding since the audit — and
regenerates a **cumulative report** showing every finding's current state.

Two artifacts, per audited repo, living next to the original audit report
(e.g. `analysis-results/findings/<product>/<repo>/`):

| Artifact | Schema | Nature |
|---|---|---|
| `<repo>-findings-layer.json` | `contracts/schemas/layer.schema.json` | Append-only ledger. Events are never edited or deleted; corrections are new events. |
| `<repo>-findings-current.{json,md}` | `contracts/schemas/report.schema.json` (with `disposition` blocks) | Derived. Regenerated from scratch every run by `build_cumulative.py`. |

The original `*-security-audit.json` is **never modified** — and since
harness 0.39.0 that is machine-enforced: `harnessing/4-triage/track-findings/scripts/baseline_claims.py`
records a sha256 of every finding's claim fields into
`metadata.claim_hashes`, `validate_report.py` verifies them on every layer
validation, and `build_cumulative.py` refuses to rebuild from a baseline
whose claims drifted. Sanctioned appends (follow-up findings) are pinned on
the next run; in-place revision requires `validation_status: corrected`
plus an explicit `--rebaseline`.

> Naming matters: the cumulative file is deliberately named
> `-findings-current`, NOT `-security-audit-*`, so the portfolio roll-ups
> (`executive-summary-findings`, `insecure-patterns`) that glob
> `*security-audit.{json,md}` never double-count it.

## When to Use

- User has triage feedback on findings from an MR/PR discussion, a commit,
  or a Jira ticket and wants it recorded
- User wants to run an interactive triage session over a report's findings
- User wants machine results (`*-validation.json` from validate-findings,
  `*-remediation-verification.json` from verify-remediation) folded into
  a single current-status view
- User asks "what's the current state of the findings for <repo>?",
  "mark finding X false positive", "ingest the MR feedback", or
  "build the cumulative report"

## Inputs

`$ARGUMENTS` contains the audit report reference followed by zero or more
disposition sources:

1. **The audit report** — same resolution as `verify-remediation`:
   - Path to a `*-security-audit.json`
   - Path to a `*-cloud-config-audit.json` (declared-layer IaC audit from
     `/cloud-config-audit`; resolves under
     `analysis-results/cloud-config/<target>/`). Its findings enter the
     ledger like any baseline. Note: audit-time `status: suppressed` /
     `needs_review` on those findings is the *auditor's* claim, not a
     disposition — to make it ledger-truth, record it as an event
     (machine static, normal trust policy). Most cloud-config findings
     are hardening-class; expect `hardening` validity events rather
     than `confirmed`.
   - Path to a `*-container-audit.json` (container-image audit from
     `/secure-container-audit`; lives beside the source repo's code
     audit under `analysis-results/findings/<product>/<image>/`). Its
     findings enter the ledger like any baseline, with one naming rule:
     because the report **shares a directory with the code audit**, its
     ledger artifacts keep the full report stem —
     `<image>-container-audit-findings-layer.json` and
     `<image>-container-audit-findings-current.{json,md}` — never the
     short `<image>-findings-*` names, which belong to the code audit.
     (`build_cumulative.py` and the ledger emitters derive exactly this
     naming by default.) Cloud-config baselines are the inverse
     (P0-4 emitter fix, 2026-07-31): they normally live alone in the
     `analysis-results/cloud-config/<repo>/` tree, so their ledger
     artifacts use the **short** `<repo>-findings-*` names — matching
     every production cloud-config ledger — and keep the full
     `<repo>-cloud-config-audit-findings-*` stem only when a code
     audit shares the directory (companion IaC baseline under
     `findings/`). Expect mostly `dependency_audit`-promoted CVE
     findings; a fixed image rebuild is a **new digest and a new
     baseline** — dispositions carry forward via the
     `finding_identity.py` fingerprint match, not by editing the old
     report (see the secure-container-audit skill's disposition-flow
     section).
   - `<product>/<repo>` →
     `analysis-results/findings/<product>/<repo>/<repo>-security-audit.json`
   - `<slug>-findings/<repo>` →
     `progress-tracker/processed-results/<slug>-findings/<repo>/...`

2. **Sources** (each classified by shape):
   - **MR/PR URL** (`/-/merge_requests/N` or `/pull/N`) — ingest discussion
     comments
   - **Commit** (7–40 hex chars, or a commit URL, or `--commit <sha>`) —
     ingest the commit message
   - **Jira key** (`[A-Z][A-Z0-9]+-\d+`) — ingest ticket status + comments
   - **Report path** (`*.json`) — a validation or remediation-verification
     report
   - **`--interactive`** — run a triage session with the human
   - **No sources at all** — auto-discover: machine reports in the audit
     report's directory and `analysis-results/validations/*/`, plus any
     Jira keys recorded by the `file-security-defect` skill

Examples:
```
/track-findings openstack-operator/sg-core https://gitlab.example.com/g/sg-core/-/merge_requests/17
/track-findings openstack-operator/sg-core OSPRH-1234 OSPRH-1235
/track-findings openstack-operator/sg-core --commit feedface12
/track-findings openstack-operator/sg-core path/to/sg-core-remediation-verification.json
/track-findings openstack-operator/sg-core --interactive
/track-findings openstack-operator/sg-core
```

`--auto` skips interactive confirmations; only tier-1 events are recorded
and everything else queues (see the trust policy below).

---

## The Two-Axis Disposition Model

Every event answers one or both of two independent questions:

| Axis | Question | Values |
|---|---|---|
| **validity** | Is the finding real? | `confirmed`, `false_positive`, `corrected`, `hardening` (`not_verified` is the default, never set by an event) |
| **resolution** | Is it dealt with? | `open`, `fix_in_progress`, `resolved`, `partially_resolved`, `risk_accepted`, `regression_introduced` |

`hardening` (harness ≥ 0.27.0) = accurately-described defense-in-depth or
benchmark gap with no concrete exploit path (triage exclusion rule 13) —
real, risk-bearing at a category-aware λ weight in `findings-trends`,
never a false positive, and never counted as a confirmed vulnerability.

The cumulative report keeps `validation_status` equal to the validity
axis, so all existing consumers keep working; the resolution axis lives
in the new per-finding `disposition` block.

### Source vocabulary mapping

| Source | Feeds | Mapping |
|---|---|---|
| `*-validation.json` verdicts (via python3 -m traust.cli ledger emit-validation) | validity | `confirmed` → confirmed (class-1 execution-verified — outranks every static determination); `refuted` → machine false_positive event (see countersign rule) + `*-refuted-register.json` merge-append; `inconclusive`/`blocked_by_scope`/`not_attempted` → no event. One validation report fans out across every repo ledger its `source_reports` cover; baselines resolve by direct path, content sha256, or claim-hash match (claim-identical alias trees all receive the event), and a direct-path baseline whose sha changed since validation queues a `stale_baseline` review item. `--manifest` batch mode replays a whole validation campaign idempotently. |
| `*-triage.json` verdicts (via python3 -m traust.cli ledger emit-triage) | validity | `true_positive` → confirmed (skipped when needs_manual_test); `hardening` → hardening with category-aware λ recorded at emission; `false_positive` → machine FP event — auto-accept tier (`auto_accept_tier: true`: unanimous + lint-clean + confidence ≥ 8 + low/informational-claimed) sets validity directly with a 10% audit-valve sample queued, everything else countersign-gated; `undetermined` → needs_review item (`undetermined_finding`); `duplicate` → nothing. Every FP also lands in `*-refuted-register.json` (fuzzing/live-validation targeting input). Auto-discover `*-triage.json` next to the audit report. |
| validation runs' `target-attestation.json` (P2) | both | read by the ledger emitter beside each validation report: `attested: false` (or a missing artifact on post-0.176.0 reports) voids every verdict in that run — all findings route to needs_review as `environment_invalid`/`attestation_missing`, never to FP/confirmed events; countersign cards render the attestation status |
| `*-remediation-verification.json` verdicts (via python3 -m traust.cli ledger emit-verification) | both | `resolved` → resolved; `partially_resolved` → partially_resolved (override: `fix_in_progress` when `cross_repo.propagation == pending`); `unresolved` → open; `new_approach` → resolved; `regression` → regression_introduced; `false_positive` → machine false_positive (countersign-gated); `risk_accepted` → risk_accepted. Class-1 evidence, tier-0 resolution authority. |
| `*-remediation-verification.json` `regressions[]` (via python3 -m traust.cli route regressions) | new findings | Phase-5 regressions become **first-class ledger findings directly — no `/triage` precondition** (user directive 2026-07-27; parity with the scanning skills). The router carries each regression on its ledger event (never the baseline — gate A15) audit as a campaign-ID finding (`{REPO_SLUG}-{PATCHED_SHA7}-{NNN}`, numbering continuing at the patched sha), `validation_status: not_verified`, `origin: verify-remediation`, script-computed fingerprint, REG id + report path in `source_findings` (and `routed_id` back on the regression entry); pins the claim hash (add-only) and appends a machine birth event (`resolution: open`, verification report as `evidence_ref` — validity is never set at birth). Idempotent; triage/validation adjudicate downstream like any claimed finding. |
| `*-remediation-verification.json` `cross_repo` blocks | resolution | overrides the verdict row above when present: `partially_resolved` + `propagation: pending` → **fix_in_progress** (the upstream fix exists but the original repo has not consumed it — `evidence_refs` must carry the fix repo commit and the verification report; re-ingest after the next propagation check and promote to resolved on `consumed`); `resolved` + `consumed` → resolved; `propagation: not_applicable` → follow the verdict row (fix legitimately lives in the other repo); `module_absent` → follow the verdict, citing the verifier's removal judgment |
| Jira | both | Done/Fixed → resolved; Won't Do with risk language → risk_accepted; Not a Bug → false_positive (attributed to the **resolving user** from the ticket changelog, never the bare status); In Progress → fix_in_progress. Ambiguous resolutions are queued, never guessed. |
| MR/PR comment | either | Tier policy below |
| Commit message | resolution | Finding ID + fix trailer → `fix_in_progress` (never `resolved` — that claim belongs to verify-remediation, which actually checks the code) |
| Interactive | either | Human states it directly |

### The human-countersign rule (hard requirement)

**`validation_status: false_positive` requires an identity-verified human
determination** (the ledger identity token, stamped by the SDK) — with one carve-out. A machine `refuted` verdict enters
the ledger as evidence but the cumulative report shows the finding as
*"refuted — awaiting human sign-off"*
(`disposition.refuted_awaiting_signoff: true`) until a human countersigns
via any tier-1 source or an interactive session. The carve-out
(harness ≥ 0.27.0): auto-accept-tier triage FPs (`auto_accept_tier: true`
— unanimous, verdict-citation-lint clean, mean confidence ≥ 8, claimed
severity low/informational) set validity directly, with a deterministic
10% sample queued for human audit (`fp_audit_valve`). Both the layer
validator and `build_cumulative.py` enforce this.

### Evidence-class precedence and the falsifiability of FPs (harness ≥ 0.27.0)

Validity conflicts resolve by **evidence strength, not actor identity**:
1 execution-verified (`validation_report`, `verification_report` —
reproducing exploits/crashes) > 2 human static determinations > 3 machine
static (`triage_report` and other machine events). Recency breaks ties
only *within* a class. Consequences, all enforced by
`build_cumulative.py`:

- A class-1 `confirmed` **overrides a human false-positive assertion** —
  validity flips to confirmed and `disposition.fp_overridden: true`
  surfaces loudly with the original countersigner attributed. A human FP
  is a falsifiable claim, never a shield against assessment.
- **Two-person rule:** after execution-verified confirmation, re-asserting
  false positive requires TWO distinct identity-verified humans post-dating
  the proof; a single attempt sets `disposition.fp_reassertion_blocked`.
- Every FP (auto-accepted or countersigned) stays in the **refuted
  register**, feeding fuzz-harness target selection and live-validation
  scoping — nothing leaves verification scope because someone said
  "false positive".
- Each disposition carries `assurance`
  (`claimed | machine_verified | human_reviewed | execution_proven`) —
  the highest evidence class that has spoken; `findings-trends` reports
  the claimed/verified/proven views, the triage-compression and
  validation-gap deltas, and per-identity FP-override rates.

---

## The Three-Tier Trust Policy for Human Statements

MR comments (and free-text Jira comments) are conversation, not workflow
state. The skill only auto-records what needs zero interpretation.

**Tier 1 — auto-record** (all three required):
1. **Explicit grammar**: the statement names a canonical finding ID and
   makes a declarative disposition — either the structured convention
   `/traust <disposition> <FINDING-ID> <rationale>`
   (dispositions: `false-positive`, `confirmed`, `risk-accepted`,
   `fix-in-progress`, `resolved`) or an unambiguous declarative sentence
   ("SG_CORE-abcdef0-001 is a false positive: the value is validated in
   the CRD webhook before this path").
2. **Verified identity**: the author's forge username maps to an employee
   via `python python3 -m traust.cli admin validate-employee`.
3. **Authority**: the author is one of the findings package's assigned
   owners (owners.csv / assign-findings-owners output) or a project
   Maintainer+ (forge members API). An **escalation contact**
   (owners-mapping.md `Escalation` column / Product Security registry
   contact) is **not** an owner and confers no disposition authority —
   escalation contacts hold Drive commenter access (2026-07-30 decision)
   and will appear as commenters, but their statements queue as tier-2
   `insufficient_authority`.

**Tier 2 — needs-review queue**: anything else that mentions a finding ID
or reads disposition-like. Recorded in the layer's `needs_review[]` with
verbatim quote, permalink, author, `queue_reason`
(`ambiguous_statement` / `unverified_identity` / `insufficient_authority`
/ `no_finding_id`), and the skill's *suggested* interpretation — but **no
state change**. Pending items surface at the top of the cumulative
Markdown and get resolved in the next `--interactive` session: on
confirmation, a real event is appended attributed to the **confirming
human**, with the original commenter preserved in `source.reported_by`.

**Never**: model-inferred intent from vague text silently changing state.
`--auto` does not lower the bar — it only skips confirmation for tier-1
events, which need none.

---

## Procedure

### Phase 1 — Resolve and load

1. Resolve the audit report; load findings and `metadata.commit`.
2. Load `<repo>-findings-layer.json` if present; otherwise initialize it:
   ```json
   {"metadata": {"audit_report": "<relative path>", "audit_commit": "...",
     "repository": "...", "created": "<now>", "harness_version": "<VERSION>-<sha>"},
    "events": [], "needs_review": []}
   ```
3. Build the set of valid finding IDs. Every event must reference one.
4. **Baseline the claims** (tamper-evidence for the audit report):
   ```
   python3 <harness>/harnessing/4-triage/track-findings/scripts/baseline_claims.py record <audit.json> <layer.json>
   ```
   This pins each finding's canonical claim fields into
   `metadata.claim_hashes` — new findings (sanctioned appends from
   `/create-fuzzing`, `/vuln-scan`, `/validate-findings` novel findings,
   or `/verify-remediation` regression routing) get added; already-baselined hashes
   are never overwritten. **If `record` refuses** (hash mismatch), the
   audit report was edited in place: stop and surface it to the user —
   either the report must be restored from git, or, for a finding
   legitimately revised under `validation_status: corrected`, re-run with
   `--rebaseline <id>`. Do not proceed to ingestion over a tampered
   baseline; `build_cumulative.py` would refuse anyway.

### Phase 2 — Ingest each source

Classify each argument and run the matching adapter. For every candidate
event, compute the idempotency key **before** appending:

```
event_id = sha256("<source.ref>|<finding_ref>|<validity or ''>|<resolution or ''>")
```

If an event with that `event_id` already exists, skip it silently —
re-running the skill on the same MR/ticket/report is a no-op.

Set **`occurred_at`** on every event to the source's own timestamp —
commit author date, Jira transition date, MR comment creation date,
machine report `metadata.date` — so the `findings-trends` skill buckets
the event into the period it actually happened, not the period it was
ingested. `recorded_at` stays the append time (it must remain
chronological across the ledger). If no source timestamp is available,
omit `occurred_at` and tooling falls back to `recorded_at`.

**MR/PR comments** — GitLab: `mr_discussions` / `list_merge_request_notes`
(MCP); GitHub: PR review comments. For each comment: scan for finding IDs
and disposition statements; apply the tier policy; for tier-1, resolve the
author (username → the deployment's employee directory, if one is
configured — `LEDGER_DIRECTORY_COMMAND`; authority via
owners.csv and the members API — escalation contacts are excluded:
commenter access does not imply authority); event `source.ref` is the
comment permalink; `rationale` is the verbatim quote.

**Commit** — `git show -s --format='%H%n%an <%ae>%n%aI%n%B' <sha>` (or the
forge commit API). Look for finding IDs in the message/trailers. Map to
`fix_in_progress`. The commit author is the actor (check the email against
the deployment's employee directory when one is configured).

**Jira** — `jira_get_issue` with changelog + comments. Match the finding:
tickets filed by `file-security-defect` carry the finding ID in the
description; otherwise match by summary and confirm interactively. Map
status/resolution per the table; attribute to the user who made the
transition (from the changelog). Ambiguous → queue.

**Machine reports** — validate them first
(`validate_report.py --schema validation.schema.json` /
`verification.schema.json`); refuse unvalidated input. One event per
finding verdict, `actor.kind: machine`,
`actor.identity: "<skill-name>"`, `source.ref` = report path,
`rationale` = the report's explanation for that finding.

For a **remediation-verification report**, use the dedicated emitter
and (separately) the regression router:

```bash
python3 -m traust.cli ledger emit-verification \
    <path>/<repo>-remediation-verification.json \
    --results-root analysis-results --build-cumulative

python3 -m traust.cli route regressions \
    <path>/<repo>-remediation-verification.json
```

The emitter maps each `verified_findings[]` verdict to a resolution (or
validity for `false_positive`) event per the mapping table above,
including the `cross_repo.propagation` override. It skips `regressions[]`
— those go through `route_regressions` (idempotent, order-independent).
`route_regressions` carries each regression on its ledger event (never
the baseline — gate A15). `build_cumulative` unions event-carried
findings back at replay.
Mechanics: [docs/findings-routing.md](../../../docs/findings-routing.md).

**Interactive** — use the countersign workbench
(python3 -m traust.cli admin countersign); never hand-assemble interactive events.

1. **Build the inbox:**
   `python3 -m traust.cli admin countersign queue --root <findings-tree>`
   (or `--repo-dir <one repo>`). This derives every
   `refuted_awaiting_signoff` finding and pending `needs_review` item and
   renders one self-contained DECISION CARD each — the audit claim, the
   machine refutation with lint-verified evidence, and what signing
   records — so the reviewer never needs the original report open.
2. **Present ONE card per question.** Show the card as the question's
   preview; options: *Confirm false positive* / *Keep open (reject the
   refutation)* / *Defer*. A blank rationale on false_positive adopts
   the machine rationale, explicitly framed as the signer's adopted
   determination; `keep_open` REQUIRES the human's own rationale —
   "false positive" (or its rejection) without a why is not recordable.
3. **Record through the tool:**
   `countersign.py record --layer <ledger> --finding <ref> --decision
   ... [--rationale ...]` — the signer is the ledger identity token
   holder (`ledger auth login` / `ledger auth local`; recording is
   REFUSED without a verifiable token); the events go through the ledger
   SDK, which stamps the token-verified actor on each
   (`source.ref = interactive:<ISO date>:<signer>`, `identity_verified:
   true`), then it rebuilds the cumulative pair and prints a receipt.
4. **Asynchronous alternative:** hand the reviewer the annotatable
   `countersign-queue.md`; they mark `[x]` decisions and rationales in an
   editor, then `countersign.py apply countersign-queue.md` ingests the
   whole batch under the reviewer's own ledger token.
5. Pending `needs_review` items appear at the end of the queue file —
   confirm/reject each interactively (rejections get a
   `resolution_note`).

Append events in `recorded_at` order (the layer must stay chronological);
update `metadata.updated`.

### Phase 3 — Merge deterministically

Never hand-compute the cumulative state. Run the merge engine (from the
workspace root):

```bash
python traust/traust.cli.build_cumulative \
  <audit.json> <layer.json>
```

It applies the precedence rules (human > machine on validity;
verification_report > jira > other on resolution; latest within a tier),
the countersign gate, and conflict detection
(`confirmed` + `false_positive` both present → `conflict: true`,
surfaced in a "needs re-review" section, never silently resolved), and
writes `<repo>-findings-current.{json,md}`.

### Phase 4 — Validate and deliver

```bash
python python3 -m traust.cli reporting validate --schema layer.schema.json <repo>-findings-layer.json
python python3 -m traust.cli reporting validate <repo>-findings-current.json
```

Both must pass (the default schema validates the cumulative report's
disposition blocks and summary counts).

When the owning team consumes findings through GitHub Code Scanning (or
any SARIF-speaking tool), the cumulative report is the artifact to hand
over — it is disposition-aware, so false positives arrive as SARIF
suppressions rather than re-alerts:

```bash
python python3 -m traust.cli reporting sarif <repo>-findings-current.json
```

(One-way projection; the report + ledger stay authoritative — see
`docs/artifacts.md`.) Then present the delta:

```markdown
## Findings Status Updated: <repo>

**This run:** 3 events appended, 2 statements queued for review, 1 duplicate skipped.

| Finding | Was | Now | Via |
|---|---|---|---|
| SG_CORE-abcdef0-001 | not_verified / open | not_verified / resolved | verify-remediation report |
| SG_CORE-abcdef0-002 | not_verified / open | false_positive / open | MR !17 comment (jdoe, identity-verified) |

**Awaiting human sign-off:** SG_CORE-abcdef0-003 (refuted by live validation)
**Needs review:** 2 pending — resolve with `/track-findings <report> --interactive`
```

---

## Integrations

Consumed artifacts (producer named per artifact):

- Baseline reports — `*-security-audit.json` (`/secure-code-audit`),
  `*-cloud-config-audit.json` (`/cloud-config-audit`),
  `*-container-audit.json` (`/secure-container-audit`).
- `*-triage.json` — produced by `/triage`; verdicts enter via
  python3 -m traust.cli ledger emit-triage.
- `*-validation.json` (+ `target-attestation.json`) — produced by
  `/validate-findings` / `/validate-operator-live` /
  `/validate-browser-finding`; verdicts enter via
  python3 -m traust.cli ledger emit-validation.
- `*-remediation-verification.json` — produced by `/verify-remediation`;
  verdicts emitted via python3 -m traust.cli ledger emit-verification
  as resolution events (class-1 evidence, tier-0 resolution authority), and its
  `regressions[]` are routed into the **ledger** by
  python3 -m traust.cli route regressions as findings-carrying
  events — never into the baseline (gate A15; see the mapping table).
- Forge/Jira sources (MR comments, commits, tickets) — tier-policed
  human statements.

Emitted artifacts:

- `*-findings-layer.json` — the append-only authority; consumed by
  `build_cumulative.py`, `/findings-trends`, `/countersign`,
  `/mine-ledger`, `/sla-view`, `/verify-remediation` sweep tiering, and
  python3 -m traust.cli corpus findings-db.
- `*-findings-current.{json,md}` — derived cumulative view; consumed by
  `/findings-trends`, `/generate-team-report`, `/sla-view`,
  python3 -m traust.cli reporting sarif handovers, and the census/dashboard layer.
- `*-refuted-register.json` — FP register feeding `/create-fuzzing`
  target selection and `/validate-findings` scoping.

## Options

| Variable | Default | Effect |
|----------|---------|--------|
| `HARNESS_SIGNING_REQUIRED` | `0` | When `1`, `validate_report.py` warns if a layer's merkle root is unsigned. When `0` (default), unsigned layers pass silently — signing is opt-in. |
| `HARNESS_SIGNING_VERIFY_PUBKEY` | — | Public key path for keypair signature verification during layer sweeps. |
| `HARNESS_SIGNING_METHOD` | `keypair` | `keypair` or `identity` — which signing backend to use. |

## Gotchas

- **The layer is the authority; the cumulative report is a cache.** Never
  edit `*-findings-current.json` directly, and never edit or delete a
  ledger event — append a correcting event instead. The validator hard-errors
  on non-chronological or hash-mismatched events.

- **Idempotency lives in the event_id.** If you change how a source maps to
  a disposition, the same comment produces a *different* event_id and would
  double-record. Skip ingestion-time remapping of already-ingested sources;
  append a correction event instead.

- **A machine can confirm, only a human can refute permanently.** Execution
  evidence proving exploitability sets validity=confirmed on its own.
  Execution evidence *failing* to exploit sets refuted_awaiting_signoff —
  absence of proof isn't proof of absence, so a named human owns every
  false_positive call.

- **Jira statuses lie about who decided.** Always attribute to the user in
  the changelog transition, not the assignee or reporter. If the changelog
  is inaccessible, queue instead of recording.

- **Don't let the cumulative filename drift.** Anything matching
  `*security-audit.{json,md}` gets swept into the portfolio dashboards and
  double-counts the repo.

- **Bot comments never tier-1.** CI bots and integration accounts are
  machine identities by design; their statements queue at most.

- **Conflicts are a feature.** When a human and the machine disagree, the
  report is supposed to look unresolved — that's the signal for
  re-validation or a triage conversation, not something to normalize away.

- **This skill dispositions findings; it doesn't verify fixes.** "The MR
  fixing this merged" is `fix_in_progress` until `/verify-remediation`
  says `resolved`. Point users there for code-level verification.
