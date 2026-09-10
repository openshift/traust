---
description: "Determine which portfolio repositories are affected by a CVE using dependency and reachability evidence."
---

Determine per-repo CVE affectedness across the portfolio using the impact-analysis skill. Load the skill at .claude/skills/impact-analysis/SKILL.md and follow it: python3 -m traust.cli impact analyze queries portfolio-graph.db for blast radius, refines by L4 package imports, deep-scans with language-specific analyzers (Go: govulncheck symbol reachability + ELF; Python/Rust/JS/Java: lockfile + source-import manifest tier; C/C++: header grep + DT_NEEDED binary scan), and emits a schema-validated `<cve>-impact-analysis.json` consumed by /triage Phase 2f, /verify-remediation --impact-filter, /fleet-fix worklists, and /file-security-defect citations. `$ARGUMENTS` is the CVE ID plus `--module <mod>` and optional range/package/feature flags.
