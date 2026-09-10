---
description: "Rebuild deterministic dashboards in dependency order and report failed stages with rerun commands."
---

Rebuild every deterministic dashboard using the refresh-dashboards skill. Load the skill at .claude/skills/refresh-dashboards/SKILL.md and follow its procedure — run python3 -m traust.cli tools refresh-dashboards (projections first: findings.db then census; consumers next; scoreboard last), read the summary table back reporting any failed stage with its rerun command (`--only <stage>`), and commit the rebuilt artifacts. Pass through any stage-selection arguments the user gave ($ARGUMENTS). The spend-actuals leg is opt-in via --spend-actuals (operator workstations only); agent-built views (threat register, attack coverage) are rebuilt by their owning skills, not this one.
