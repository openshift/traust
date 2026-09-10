---
description: "Mine confirmed findings for detection gaps, candidate rules, and precision calibration."
---

Mine the disposition ledger for confirmed true positives using the mine-ledger skill. Load the skill at .claude/skills/mine-ledger/SKILL.md and follow its full procedure — run python3 -m traust.cli sweep mine over the findings tree, interpret the uncovered-cluster backlog (detectability verdict + rule candidates per cluster), review per-rule precision from audits' judge decisions, and hand back the calibration picture. `$ARGUMENTS` may override the findings tree, --pack, or --out (default: progress-tracker/metrics/rule-mining/).
