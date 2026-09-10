---
description: "Check bundled content licensing or review the license of a proposed external dependency."
---

Run the harness licensing gate using the check-licensing skill. Load the skill at .claude/skills/check-licensing/SKILL.md and follow it: run python3 -m traust.cli tools check-content-licenses (restrictive content-license markers, PEACH-adaptation fingerprints, CIS recommendation-text signatures) and report violations with the fix being removal of the flagged text, never guard edits. If `$ARGUMENTS` names a new external tool/framework/data feed/rule pack, run the license-intake checklist instead: verify the upstream license with evidence, classify the usage model, and add the row to docs/external-dependencies.md.
