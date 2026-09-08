# Validation Process — how live validation reaches a trustworthy verdict

The reference for the validate* lanes (`/validate-findings`,
`/validate-browser-finding`): what a verdict must survive before it
enters the disposition ledger. The doctrine behind the gates is
[error-model.md](error-model.md) (machines confirm, humans dismiss); the
lane procedure is the
[validate-findings skill](../harnessing/5-validate/validate-findings/SKILL.md);
how the resulting events are weighed and countersigned is
[disposition-ledger.md](disposition-ledger.md) §5–§6.

## Mission — three purposes

1. **Validity** — prove or refute that a finding is an accurate,
   exploitable security issue against an authorized live target.
2. **Severity** — validate the assigned severity: a live run turns CVSS
   vector components from estimates into observations.
3. **Chaining** — identify further issues by combining findings into
   demonstrated attack chains; chain membership is severity evidence
   for its constituents.

## The gate stack (every verdict passes all of these)

Layered fail-closed controls, in execution order. Each gate quarantines
to `needs_review` — never silently drops, never emits a false-positive
ledger event. This table is the single list of gates; other documents
link here rather than restating it.

| # | Gate | Question it answers | Quarantine flags |
|---|---|---|---|
| 0 | **Target attestation** (python3 -m traust.cli admin attest-target → `target-attestation.json`) | *Is the environment even testable?* Cluster reachable, operator installed, pods Ready, version inside the affected range, endpoint answering. `attested: false` voids **every** verdict in the run, confirmed and refuted alike. | `environment_invalid`; `attestation_missing` when the artifact is absent |
| 0b | **Positive controls** (`step_result.controls[]`) | *Did the assay work?* Every refutation-capable probe pairs a same-session action that must succeed (known-allowed RBAC action, planted canary secret, owned page) or must be denied. | `failed-positive-control` at any age; `missing-positive-control` when no control passed |
| 0c | **Differential probing** (`step_result.differential`) | *Can the oracle discriminate?* Authz refutations probe the claimed action AND a neighbour with a known-different expected outcome. | `non-discriminating-oracle` when outcomes are identical, at any age; `missing-differential-probe` for an authz refutation without a pair |
| 0d | **Evidence grades** (`validated_finding.evidence_grade`) | *How strong is a confirmation?* E0 observed effect · E1 authenticated success on the exploit action · E2 strong inference · E3 error-message inference. Only E0/E1 are execution-class evidence with override power over human FP signatures; E2 records as machine-static with a grade annotation; E3 never auto-confirms. | `weak_confirmation` (E3, any age); `ungraded_confirmation` |
| 1 | **Soundness signatures** (`soundness.py`) | *Does the transcript actually test the claim?* Error-signature transcripts, zero-subject RBAC enumerations, template placeholders, install-failure runs. | `unsound_refutation` |
| 1b | **Conflict routing** (`derive_disposition`) | *Do the lanes agree?* Confirmed and false_positive both in evidence (fuzz confirms, live refutes) adjudicates as a CONFLICT card carrying both transcripts and DECISION markers — never as an unopposed FP countersign. | — (card type, not a quarantine) |
| 2 | **Ledger discipline** (`emit_validation_ledger_events.py`) | Machine `refuted` → countersign queue (humans dismiss); machine `confirmed` → class-1 evidence (machines confirm); quarantined items → `needs_review` with the flag and transcript on the countersign card. | — |

**Grandfathering.** Gates that require *new* artifacts apply only to
reports at or after the harness version that introduced the artifact
(the `*_SINCE` constants in the emitter: attestation 0.176.0, controls
0.177.0, differential 0.178.0, grades 0.179.0); older reports pass those
gates ungated. Gates that detect *broken* evidence (failed control,
non-discriminating oracle, error signatures) apply at any age.
Pre-grade confirmations keep their historical class-1 weight.

## Artifact flow

```
scope (targets.yaml, fail-closed)
  └─ target-attestation.json          gate 0 — testability proof
  └─ attack-plan.yaml                 replay + chained + novel probes
  └─ execution: each step records
        controls[]                    gate 0b — assay proof
        differential                  gate 0c — oracle discrimination
        replay                        script + inputs + attestation fingerprint
        evidence artifacts            transcripts, artifacts/, rollback
  └─ <slug>-validation.{json,md}      schemas/v1/validation.schema.json
  └─ validation-audit.jsonl           append-only action trail
        │
        ▼
emit_validation_ledger_events.py      gates 0/0b/0c/0d/1 re-checked at
        │                             ingest; quarantines → needs_review
        ▼
disposition ledger (per-finding)      confirmed = class-1 execution
        │                             evidence; refuted = pending human
        ▼                             countersign — never auto-FP
countersign cards                     attestation status, transcripts,
                                      control results on every card
```

Discovery candidates found while validating (cluster-state diffing,
python3 -m traust.cli impact cluster-state-diff) carry
`origin: validation-discovery` and route to `/triage` as new findings,
not as verdicts.

## Severity validation

Every confirmation records the CVSS v3.1 components the exploit
**demonstrated** — vector used, privileges actually held, interaction,
scope crossing, impact axes evidenced — plus the signed delta against
the claimed score. Material deltas (|delta| ≥ 1.0) from E0/E1/E2
evidence become machine severity **proposals** in the countersign queue
(`severity_proposal`); E3 never proposes. Machines never write
`disposition.severity` — the layer validator rejects a machine actor
carrying one — so severity stays human-decided. Chain membership
(`chain_context`) is severity evidence for constituents and is cited in
the proposal rationale. Downgrades are as valuable as upgrades.

## Where the rest is defined

- **Evidence classes and grades → ledger weight**, the override rule and
  the two-person rule: [disposition-ledger.md](disposition-ledger.md) §5
  and §6. The validation-lane emitter has no auto-accept path; that tier
  exists only in the triage lane.
- **Fuzzing as the offline execution-evidence lane** (a reproducing
  crash is E0 by construction; the refuted register feeds target
  selection; build plus deterministic reproduction is its environment
  gate): the [create-fuzzing skill](../harnessing/6-fuzz/create-fuzzing/SKILL.md).
- **Credential-liveness probing** (one read-only introspection call,
  scope-gated to a `credential_probes.classes` entry and the single verb
  `introspect`): the validate-findings skill, section
  "Credential-liveness verification".
- **The benchmark** (vulnerable/safe-twin fixture pairs under
  `harnessing/5-validate/validate-findings/benchmark/`; confirm-recall
  and refute-precision floors; severity within ±1.0 of the planted
  vector): the validate-findings skill, section "Benchmark mode", run by
  python3 -m traust.cli sweep benchmark. Its `check-trigger`
  subcommand exits non-zero when validation-lane paths changed since the
  last benchmarked tag, and `/drift-watch` flags a stale scorecard.

## Hard rules

- The scope guard is absolute: out-of-scope steps are refused and
  logged, never silently skipped.
- No auto-FP from machine evidence: refutations queue for
  identity-verified countersign; execution evidence overrides FP
  signatures loudly (`fp_overridden`), and re-asserting FP after an
  executed proof takes two independent humans.
- Probe transcripts are evidence, not verdicts — the verdict is what
  survives the gate stack.
