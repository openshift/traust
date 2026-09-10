---
description: "Query portfolio findings with labeled population metrics or rebuild the ledger-derived database."
---

Query or rebuild the findings database using the findings-db skill. Load the skill at .claude/skills/findings-db/SKILL.md and follow its procedure — check `meta.built_at` staleness first (rebuild with python3 -m traust.cli corpus findings-db when the ledgers are newer), translate the question in $ARGUMENTS into SQL over the documented schema (repos / findings / events / validations / graph_edges and the v_open, v_hardening, v_distinct_owned views), and present results with the lens labeled (occurrences vs distinct fingerprints). The DB is a projection: headline numbers reconcile to /census, and the disposition ledger remains the only write path.
