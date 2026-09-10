---
description: "Audit container images for vulnerabilities, configuration risks, provenance, and source drift."
---

Perform a container image security audit on $ARGUMENTS using the secure-container-audit skill. Load the skill at .claude/skills/secure-container-audit/SKILL.md and follow its full procedure — skopeo image-config/signature/tag-hygiene inspection, syft SBOM generation, grype CVE scan of the SBOM, cross-reference against the source repo's code-profile audit, and source-drift comparison. `$ARGUMENTS` may be a single image reference (tag or digest), a payload analysis CSV (Payload Image Key(s) column), or a text file of image references. Place reports in findings/<product>/<image-name>/<image-name>-container-audit.json with metadata.audit_profile "container".
