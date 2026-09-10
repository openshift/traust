---
description: "Audit RPM source packages, packaging practices, and supply-chain controls for security weaknesses."
---

Perform a comprehensive security audit on $ARGUMENTS using the secure-rpm-audit skill. Load the skill at .claude/skills/secure-rpm-audit/SKILL.md and follow its full procedure — covering OWASP ASVS, SEI CERT C/C++, Fedora Packaging Guidelines (RPM01-RPM10), SLSA, and OpenSSF Scorecard — including the Source Preparation step (fetch lookaside sources, verify SHA512, apply patches). `$ARGUMENTS` may be a single GitLab dist-git URL, `<component> <stream>` shorthand, or a CSV batch file. Place reports in findings/<stream>/<component>/.
