---
description: "Build a portfolio repository graph from inventory data and cross-reference assessment coverage."
---

Build or refresh the portfolio repository graph using the repo-graph skill. Load the skill at .claude/skills/repo-graph/SKILL.md and follow it: read the inputs-inventory CSV files, cross-reference findings coverage, and emit repo-graph.{json,dot,gexf,html} + repo-graph-stats.md into analysis-results/graph/. `$ARGUMENTS` may override inventory or output paths. Note: /portfolio-graph consumes this output as its spine and gate-checks its freshness.
