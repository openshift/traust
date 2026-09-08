# triage

A Claude Code skill that triages a batch of raw security-scanner findings:
verifies each is real, collapses duplicates, re-ranks by derived
exploitability, and tags each survivor with a component owner. Turns a raw
dump into a short, ranked, owned list.

## Status

Ingests secure-code-audit reports, `*-vuln-findings.json` (legacy
`VULN-FINDINGS.json`), vuln-pipeline
`results/` directories, and loosely-structured JSON or markdown from other
scanners.

## Requirements

- Claude Code (or Crush) installed and authenticated
- A read-only checkout of the target codebase (verification reads source;
  it does not build or run anything)
- A file or directory of findings to triage

## Installation

Ships with this repo like every other skill: `harnessing/4-triage/triage/` is the
source of truth, discovered via the `.claude/skills/triage` and
`.crush/skills/triage` symlinks (see AGENTS.md "Adding a new skill"). For
use outside this repo's workspace, symlink it user-scoped:

```bash
ln -s /path/to/traust/harnessing/4-triage/triage ~/.claude/skills/triage
```

## Deterministic accelerators

The skill uses two harness scripts (see
`docs/deterministic-inferential-mix.md`): python3 -m traust.cli check citations
gates each finding's cited file/line/anchor before verifier votes are
spent, and python3 -m traust.cli admin query-index gives verifiers one-lookup
definition/reference queries over a per-run symbol index keyed by
`(repo, sha)`. Both degrade gracefully — on any error the skill falls back
to full votes and plain Grep. Neither ever authors a verdict.

## Usage

From a Claude Code session in the target repo:

```
/triage path/to/findings.json
```

Interactive mode (the default) opens with a short interview about your
environment, threat model, and preferred scoring standard — these shape how
reachability is judged and how severity is labeled. To skip the interview
and use defaults:

```
/triage path/to/findings.json --auto
```

Common invocations:

```
/triage <repo>-vuln-findings.json                   # vuln-scan output, repo = cwd
/triage results/mytarget/2026-04-14/ --repo .       # vuln-pipeline output
/triage scanner_export/ --votes 5 --repo ~/src/app  # high-stakes batch, 5-vote verify
/triage backlog.md --auto --votes 1                 # quick first pass on a markdown report
```

## Output

- `./<repo>-triage.json` — every input finding, annotated with `verdict`,
  `verify_verdict`, recomputed `severity`, `severity_alignment` vs. the
  scanner's claim, `preconditions`, `vote_breakdown`, `rationale` citing
  file:line evidence, `owner_hint`, and `duplicate_of` where applicable.
  Sorted by what to act on first.
- `./<repo>-triage.md` — reviewer-facing report: an "Act on these" section with
  one entry per confirmed finding, a "Hardening backlog" section, an
  "Undetermined" section, then a "Dropped" table explaining every
  rejection.

**Verdict taxonomy.** `true_positive` (reachable, exploitable) |
`hardening` (accurately-described defense-in-depth or benchmark gap —
CIS/STIG/Scorecard/SLSA-style — with no concrete exploit path; routed to
an owner as backlog, never recorded as a false positive) | `undetermined`
(cited material missing/unreadable, or verification could not decide;
never recorded as a false positive) | `false_positive` (the finding is
wrong: unreachable, mitigated, or misread) | `duplicate`.

A `needs_manual_test` verify-verdict means static reasoning hit its limit
on that finding — treat it as a recommendation for a human to build a
controlled proof-of-concept, not as a failure.

## Checkpointing and resume

Per-phase state is written to `./.triage-state/`. If a run is interrupted
(rate limit, context exhaustion, Ctrl-C), re-invoking `/triage` with the same
arguments resumes from the last completed phase — the interview is not
re-asked and verifiers already tallied are not re-spawned. Pass `--fresh` to
start over. `./.triage-state/` is scratch; add it to `.gitignore`.

## What it does and doesn't do

- **Does:** read source, grep for callers, reason about reachability and
  protections, vote, rank, and route.
- **Does not:** build, run, or test the target; install dependencies;
  reach the network; write proof-of-concept exploits. All conclusions are
  static. This is deliberate — the skill is meant to run in a review box
  alongside a read-only checkout.

## Provenance

Derivative work of the `triage` skill in
**defending-code-reference-harness** (Copyright 2026 Anthropic PBC, Apache
License 2.0 — see the harness root `NOTICE` and `LICENSES/Apache-2.0.txt`),
ported into this harness at v0.22.0 and modified per `CHANGELOG.md` —
notably the citation gate, symbol index, verdict taxonomy, and
`contracts/schemas/triage.schema.json` machine gate, which are harness additions.
