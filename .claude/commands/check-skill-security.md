---
description: "Check skills and scripts for unsafe execution, credential handling, and scope controls."
---

Run the skill security-posture gate using the check-skill-security skill. Load the skill at .claude/skills/check-skill-security/SKILL.md and follow it: run python3 -m traust.cli tools check-skill-security from the harness root, report each violation with its rule id, file, and the audit finding class it guards, and walk the user through the prescribed fix pattern for every rule that fired (never by adding an exemption for new code). $ARGUMENTS may name a specific skill directory to focus the explanation on.
