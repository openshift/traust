---
description: "Validate security findings against authorized live targets with scope enforcement and execution audit logs."
---

Validate security findings for $ARGUMENTS against a live authorized target using the validate-findings skill. Load the skill at .claude/skills/validate-findings/SKILL.md and follow its full procedure — Phase 1 (ingest), Phase 2 (attack planning: replay + chain + novel), Phase 3 (review gate), Phase 4 (execute via target adapters with audit logging), Phase 5 (emit *-validation.{json,md}). Enforce scope binding via targets.yaml / inline flags / inferred metadata; never act outside the declared boundary.
