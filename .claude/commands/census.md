---
description: "Reconcile corpus populations, distinct vulnerabilities, and duplication across findings trees."
---

Build the corpus census using the census skill. Load the skill at .claude/skills/census/SKILL.md and follow its full procedure — resolving the workspace root, running harnessing/census/scripts/build_census.py with the flags implied by $ARGUMENTS (summary / open / explicit workspace-root path), and reporting the executive view (distinct owned vulnerabilities + upstream adjacent line + external-BU work), the five duplication vectors, drift warnings, and output file paths back to the user.
