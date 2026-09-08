---
name: countersign
description: Review and sign off pending human decisions in the findings
  disposition ledger — machine-refuted false positives awaiting an
  identity-verified countersignature, and queued needs-review items — and
  record human overrides on any finding, including severity
  upgrades/downgrades and validity flips in both directions (false
  positive to true positive via reopen, true positive to false positive
  via override). Renders each pending decision as a self-contained card
  (claim + refutation + evidence) so nothing needs to be remembered from
  the original reports, records decisions through the countersign
  workbench, and rebuilds the cumulative reports. Use when asked to
  "countersign findings", "sign off false positives", "review pending
  refutations", "what's waiting for my signature", "clear the disposition
  queue", "downgrade/upgrade this finding's severity", "reclassify this
  finding", or "this finding is actually a false positive / actually
  real".
argument-hint: "[<findings-root>|<product>/<repo>] [--identity <token-holder>]"
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Write
  - Glob
  - Grep
  - AskUserQuestion
  - Bash(python3 *-m traust.cli.countersign:*)
  - Bash(python3 *-m traust.cli reporting validate:*)
  # (Bash(git:*) dropped 2026-07-31 P1-W4: no git invocation in this skill's flow)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(jq:*)
---

# countersign

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


The human inbox for the disposition ledger. Machine false-positive
evidence pends (`refuted_awaiting_signoff`) until an identity-verified human
decides; undetermined findings and audit-valve samples queue in
`needs_review`. Both are derived state — this skill materializes them as
decision cards and records the human's determinations through
python3 -m traust.cli admin countersign, never by hand-assembling ledger events.

**Paths:** `<skill-base>` is this skill's base directory; `<harness>` =
`<skill-base>/../..`. The default findings root is the
`analysis-results/findings` sibling of the harness checkout; a
`<product>/<repo>` argument narrows to one repo directory.

**What signing means (state it to the user up front, once):** a
countersign records `validity: false_positive` attributed to them as the
ledger identity token proves them. The finding stays in the refuted register — fuzzing or
live validation can still override the signature with a reproducing
exploit (`fp_overridden`). Rejecting a refutation (`keep_open`) records a
human `confirmed` and requires their own rationale. Deferring records
nothing.

## Procedure

### 1. Build the inbox

```
python3 -m traust.cli admin countersign queue \
    --root <findings-root> --out ./countersign-queue.md \
    --json-out ./countersign-queue.json --base <findings-root>/..
```

(Use `--repo-dir` for a single-repo argument.) Read the JSON summary. If
nothing is pending, tell the user the inbox is empty — name the last
rebuild time of the newest cumulative report so "empty" is credible —
and stop.

### 2. Identify the signer

No identity prompt: the signer is whoever holds the ledger identity token
(`ledger auth status` shows it). `--identity` is optional and only a sanity
check — it must name the token holder. Verification happens once, at
recording time, inside the SDK. Tell the user recording will be refused
without a verifiable token (`ledger auth login` for an OIDC provider,
`ledger auth local --identity <you>` for a local identity).

### 3. Present ONE card per question

For each awaiting-signoff card, one AskUserQuestion call with ONE
question. Attach the card's full text as the `preview` of every option so
the evidence is on screen at decision time.

Cards for **machine refutations from live validation** carry a
**RAW PROBE OUTPUT** section — the probe's `observed` text rendered
verbatim from the validation report (or its evidence artifacts). Judge
the refutation on that raw output, not the squashed rationale: a
transcript reading `Forbidden: User "<validator>" cannot …`,
`command not found`, or an empty `vf-rbac-tried:` list means the probe
never tested the claim — choose keep_open or defer, don't sign. When the
raw output is unavailable the card says so explicitly; treat those
refutations with the same suspicion. (New runs gate such verdicts at the
source — `harnessing/5-validate/validate-findings/soundness.py` makes them
`inconclusive` + `soundness_flag` and routes them to `needs_review`,
queue reason `unsound_refutation` — so signable refutation cards should
carry a real probe transcript.)

- **Confirm false positive** — "adopts the verifiers' rationale as your
  determination unless you dictate your own (use Other to dictate)"
- **Keep open — reject the refutation** — "records a human `confirmed`;
  you MUST provide your own rationale (use Other to state it, or answer
  and provide it at the follow-up)"
- **Defer** — "leave pending; it stays in the inbox"

Batch at most 4 findings per AskUserQuestion call (one question each)
when the queue is long; never merge multiple findings into one question —
that recreates the wall-of-text failure this skill exists to fix. A
`keep_open` answer without a rationale gets exactly one follow-up
question; if still none, treat as defer and say so.

Then walk pending `needs_review` items the same way (confirm → the
suggested disposition becomes a recorded event via the queue-file flow;
reject → record a `resolution_note`). This includes
`needs_manual_test` items — unconfident triage confirmations awaiting a
human PoC or live validation.

**Attention cards** (the queue's middle section) are derived states that
need eyes, not always signatures: `fp_overridden` (an execution proof
overturned a human FP — informational, acknowledge and move on),
`fp_reassertion_blocked` (a SECOND independent signer must concur to
re-assert FP against a PoC — their own rationale mandatory), and
`conflict` (both confirmed and false_positive in the ledger — adjudicate
with your own rationale either way). Present these after the signoff
cards, same one-card-per-question pattern.

### 4. Record through the workbench

Annotate the generated `countersign-queue.md` with the collected
decisions (Write: mark `[x]` and fill `RATIONALE:` lines — leave adopted
rationales blank so the tool applies the canonical adopted-determination
framing), then ONE call:

```
python3 -m traust.cli admin countersign apply ./countersign-queue.md
```

The workbench resolves the signer from the ledger token once and submits
the canonical events through the ledger SDK, which verifies the token,
stamps that identity on every event (nothing the CLI asserts about the
signer reaches the layer), dedups per signer-day, finalizes and signs;
then it rebuilds the cumulative report pair per touched repo and prints a
receipt. If verification fails, report it verbatim and stop — NEVER work
around it, never write a layer file directly, never set
`identity_verified` by hand.

### 5. Receipt and follow-through

Show the receipt (decisions recorded, events, new validity summary per
repo). Validate each touched cumulative report
(`validate_report.py <repo>-findings-current.json`). Remind the user the
ledger artifacts are committable (`*-findings-layer.json`,
`*-findings-current.{json,md}`) and offer to commit/push. Clean up
`./countersign-queue.{md,json}` unless the user wants to keep the
annotated copy.

## Human overrides — severity and validity (harness >= 0.128.0)

At any point in the session the user may request a change on a finding
that is NOT in the derived queue: a severity upgrade/downgrade, flipping
a countersigned false positive back to a true positive, or flipping a
confirmed/open finding to a false positive. These are first-class
workbench decisions, never hand-edited ledger events:

| Request | Decision | Records |
|---|---|---|
| "this is actually a true positive" (FP → TP) | `reopen` | human `confirmed`, attributed to the token holder |
| "this is actually a false positive" (TP → FP) | `override_false_positive` | human `false_positive`; **evidence-class precedence still applies** — over an execution proof the two-person rule holds validity at confirmed until a second independent signer concurs (`fp_reassertion_blocked`) |
| "this should be high, not medium" (up **or** down) | `severity=<level>` | human severity event; the audit's original severity is never rewritten — the cumulative report carries `effective_severity` per finding plus a `severity_overrides` table, so dashboard counts on original severity stay stable |

Flow: locate the finding's layer (`<repo>-findings-layer.json` beside its
audit report), present ONE confirmation card via AskUserQuestion showing
the claim, its current validity/severity/assurance from the cumulative
report, and exactly what recording does (including the second-signer
guard when the finding is execution-proven). A rationale **in the user's
own words is mandatory for all three** — there is no machine rationale to
adopt; a missing rationale gets exactly one follow-up, then the request
is dropped and said so. Record via:

```
python3 -m traust.cli admin countersign record \
    --layer <repo>-findings-layer.json --finding <FIND-ID> \
    --decision reopen|override_false_positive --rationale "..."
python3 -m traust.cli admin countersign record \
    --layer ... --finding ... --decision severity --severity high \
    --rationale "..."
```

(Override cards can also be appended to the annotated queue file using
the same `<!-- countersign finding=… layer=… -->` marker with
`DECISION: [x] severity=high` / `reopen` / `override_false_positive` —
`apply` handles them in the same pass.) Severity overrides are
idempotent per signer-day-and-level; changing your mind the same day to
a different level records normally. Machine actors can never carry a
severity — the layer validator rejects it.

## Gotchas

- The queue file's cards carry `<!-- countersign finding=… layer=… -->`
  markers the `apply` parser depends on — do not reformat them.
- Decisions are per-finding, never bulk: "countersign everything" from
  the user still means presenting each card (they can answer fast; the
  evidence must still have been in front of them).
- This skill records validity determinations and severity overrides.
  Resolution changes (resolved/risk-accepted) still belong to
  `/track-findings` ingestion from Jira/MRs/verification reports.
- Design rationale: `docs/disposition-ledger.md` §6/§6a.

## Rebaseline mapping proposals (harness >= 0.53.0)

`queue` also surfaces every unconfirmed `metadata.finding_aliases` entry
(written by python3 -m traust.cli corpus finding-identity rebaseline — the cross-scan
correlation of a superseded report's findings to the current baseline).
Each card shows the proposed old→new mapping, its match tier and scores,
and both findings side by side. Decisions:

- **confirm_mapping** — the two are the same vulnerability; the alias is
  marked confirmed with your token-verified attribution and the old
  finding's ledger history transfers to the new id at the next
  `build_cumulative` merge.
- **reject_mapping** — not the same vulnerability; recorded with
  attribution and the mapping is never re-proposed.
- **defer** — leave pending.

Rationales are optional for both (recorded verbatim as the alias `note`
when given). Fingerprint-tier mappings never appear here — they
auto-confirm at rebaseline time.

## Identity verification — the ledger token is the signer

Distinct from signing, and worth separating because they were conflated: the
**signing key** proves the LEDGER's integrity, while **identity verification**
proves who a human signer is.

Identity comes from the ledger SDK, never from this skill. `countersign
apply` / `record` resolve the current ledger identity token
(`traust_ledger.cli.identity.actor.require_verified_actor`: `LAAS_TOKEN`,
`LEDGER_TOKEN_PATH`, `LEDGER_TOKEN`, the credential stored by `ledger auth
login`, or a local token when `LEDGER_LOCAL_IDENTITY` is set), verify it
cryptographically, and hand the events to `submit_events`. The SDK's submit
handler re-derives the actor from the same token and **overwrites**
`source.actor` on every event, so the layer records the token holder and
nothing else. Machine identities cannot countersign.

| How the signer authenticates | Command | Recorded as |
|---|---|---|
| OIDC provider (device-code flow) | `ledger auth login` | `identity_provider: oidc`, issuer + subject from the token |
| Local identity (no IdP; solo or offline adopter) | `ledger auth local --identity <you>` | `identity_provider: local`, self-asserted — **refused by countersign unless the deployment sets `HARNESS_COUNTERSIGN_ALLOW_LOCAL=1`**; say so in any report that cites it |

A local token verifies against a key in the signer's own config directory,
so anyone with a shell can mint one for any name. That is acceptable for
machine events and for an adopter with no identity provider; it is not
acceptable as the human sign-off the two-person rule counts. Deployments
with an OIDC provider leave `HARNESS_COUNTERSIGN_ALLOW_LOCAL` unset.

An **employee-directory cross-check** ("is this identity a current active
employee") is a deployment concern, not an identity proof. A deployment
supplies it as a command: `LEDGER_DIRECTORY_COMMAND="<cmd>"` is run as
`<cmd> <identity>` and must print `RESULT uid=<identity> status=<…>`; only
`active` passes and is stamped as `employee_status`; anything else, or a
command that cannot answer, refuses. The SDK applies it on every write path;
this workbench applies it once more up front so a refusal happens before the
queue is parsed. The harness ships no directory implementation. Until
2026-09-08 this skill ran its own LDAP check and wrote the layer file
directly, bypassing the SDK — that path is gone.

**A verifier that cannot answer is not an answer.** A missing, expired or
unverifiable token is refused outright; recording never proceeds on an
unverified actor and never falls back to a name typed on the command line.

## Integrations

**Consumes:** pending machine refutations and needs_review items from
`*-findings-layer.json` ledgers (queue built across the findings
roots); the audit baseline beside each layer (all three naming
conventions — see `baseline_for`); raw probe output from validation
results directories for decision cards.

**Emits:** human decision events appended to `*-findings-layer.json`
and deterministically rebuilt `*-findings-current.{json,md}` cumulative
reports — consumed by `/track-findings`, `/findings-trends`,
`/sla-view`, and every ledger-reading dashboard. The annotatable
countersign-queue files (`tracking/countersign-queue.{md,json}`) are
its own worklist, re-consumed by `apply`.
