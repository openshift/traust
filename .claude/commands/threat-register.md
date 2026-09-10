---
description: "Build the fleet threat register and highlight top open threats and remediation opportunities."
---

Build the fleet-wide threat register using the threat-register skill. Load the skill at .claude/skills/threat-register/SKILL.md and follow it: run `python3 <skill-dir>/build_threat_register.py --root <analysis-results>` (pass $ARGUMENTS through as flags), then report the model/threat counts, the open-threat totals by impact, the top 5 open threats by rank score, and the top 5 quick wins. If `models_skipped_nonconforming` is nonzero, run python3 -m traust.cli reporting lint to locate the nonconforming models and report them. The register is a deterministic projection — never edit a threat model to change what it reports.
