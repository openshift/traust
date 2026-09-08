# /threat-model pr

> **Re-read note:** If you need this file mid-session and the Read tool
> reports "file unchanged", the prior result was evicted from context; reload
> with `cat <skill-base>/pr.md` via Bash.

Threat-model a **change**, not a system. Scope: the diff plus its immediate
neighbors. Output: a lightweight **PR Threat Assessment** ending in a review
verdict — never a threat model, and never overwriting one. This is
the cheap onramp for teams that will never sit through a full modeling
session, and the insertion point for security review on merge requests.

The Step-0 safety preamble applies: static analysis only, no execution, no
network calls against the target. Diffs come from local git only.

---

## Inputs

- `<target-dir>` (required): local checkout, on the branch to assess.
- `--base <ref>` (optional, default: the repo's default branch —
  `git -C <target-dir> symbolic-ref refs/remotes/origin/HEAD` or `main`):
  the merge base to diff against.
- `--patch <file>` (optional): assess a patch file instead of the branch
  diff.

---

## P1. Get the diff

`git -C <target-dir> diff <base>...HEAD` (three-dot: changes on this branch
only). If empty, say so and stop. If a patch file was given, Read it
instead.

## P2. Classify the changes (deterministic-ish gate before judgment)

Bucket every changed file; skip buckets with no security relevance
(formatting, comments, test fixtures, docs-only) and **say what you
skipped**:

- new/modified endpoints or routes → new attack surface
- auth/authz logic → bypass or weakening risk
- new data stores, schema changes → new data at risk
- new dependencies or integrations → new trust relationships
- IaC / Dockerfile / k8s manifests / CI → trust-boundary changes
- secret or credential handling → exposure risk
- removed checks, validations, or limits → regression risk

## P3. Build the scoped context

For each security-relevant change, read the changed hunks **and** their
immediate neighbors (callers/callees one hop out — the diff shows the
change, not its blast radius). Identify which trust boundaries the change
touches and what data flows through it. Do not re-analyze the rest of the
system.

## P4. Cross-reference the existing threat model

Resolve the target's model per SKILL.md's model-file resolution rule
(either naming convention). If one exists:

- Which section 4 threats does this change touch? Risk up, down, or
  resolved?
- Does it break or weaken a section 8 mitigation?
- Does it open surface not in section 3 (a candidate for a later
  `review` pass)?

If none exists, note that and proceed — the assessment stands alone.

## P5. Emit the assessment

Print to the conversation (write `<target-dir>/PR_THREAT_ASSESSMENT.md`
only if the user asks). Use schema vocabulary — `actor`, `impact`,
`likelihood` from `schema.md` enums — so the assessment reads consistently
with the full model:

```markdown
## PR Threat Assessment: <branch or title>

### Change summary
<2-3 sentences: what changed, why it matters for security.>

### New threats introduced
One bullet per threat: sentence (litmus-test level), actor, impact ×
likelihood, and the diff hunks involved (file:line citations ARE
appropriate here — this artifact is scoped to a diff and dies with the MR).

### Existing threats affected
| threat id | effect | why |
(risk_increased / risk_decreased / resolved / mitigation_weakened)

### Recommendation
**approve** | **approve_with_conditions** | **request_changes**
- conditions or required changes, one per line
```

Verdict bar: `request_changes` only for concrete, reachable issues the
diff introduces; `approve_with_conditions` for real-but-bounded concerns;
`approve` otherwise. Never manufacture a finding to justify the mode's
existence — "no security-relevant changes" is a valid assessment.

## P6. Hand back

Recommendation first, then the assessment, then: if new surface was found
and a threat model exists, suggest `/threat-model review <target-dir>`
after merge; if confirmed-vulnerability-shaped issues surfaced, point at
`/secure-code-audit` + `/triage` rather than concluding severity here — a
PR assessment is advisory and feeds no ledger events.
