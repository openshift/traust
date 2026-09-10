---
description: "Deduplicate findings, verify their evidence, rank confirmed risks, and route them to owners."
---

Triage the security findings at $ARGUMENTS using the triage skill. Load the skill at .claude/skills/triage/SKILL.md and follow its full six-phase procedure — interview (or `--auto` defaults), ingest/normalize, deduplicate, run the deterministic citation gate (python3 -m traust.cli tools check-citations) to route vote spend, spawn N independent adversarial verifiers per surviving finding (using python3 -m traust.cli tools query-index for one-lookup reachability), rank confirmed findings by precondition-derived severity, route to owners, and write `./TRIAGE.json` + `./TRIAGE.md`. `$ARGUMENTS` is a findings JSON file or directory plus optional flags: `--auto`, `--votes N`, `--repo PATH` (target clone, read-only), `--fp-rules FILE`, `--fresh`. State checkpoints to `./.triage-state/` and resumes automatically on re-invocation.
