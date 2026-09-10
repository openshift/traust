---
description: "Summarize fleet MITRE ATT&CK coverage by observed, modeled, and derived evidence."
---

Build the fleet MITRE ATT&CK coverage roll-up using the attack-coverage skill. Load the skill at .claude/skills/attack-coverage/SKILL.md and follow its procedure — running .claude/skills/attack-coverage/build_attack_coverage.py against the analysis-results root implied by $ARGUMENTS (default ../analysis-results), then reporting the technique counts per evidence class (observed / modeled / derived), tactics covered, any dropped references, and the paths to attack-navigator-layer.json and attack-coverage.md back to the user.
