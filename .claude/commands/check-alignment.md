---
description: "Check skill contracts, artifact wiring, and cross-skill conventions for alignment."
---

Run the cross-skill alignment guard using the check-alignment skill. Load the skill at .claude/skills/check-alignment/SKILL.md and follow it: run python3 -m traust.cli tools check-skill-alignment and, on failure, fix the skill (adopt the missing convention, create the missing wiring, repoint the dead reference) rather than the checker; add a reasoned EXEMPTIONS entry only for genuinely inapplicable triggers. Required before committing any new or edited skill; the pre-commit hook enforces the same script.
