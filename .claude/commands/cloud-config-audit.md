Run the cloud config audit skill for the IaC checkout given in $ARGUMENTS.

Follow harnessing/3-audit/cloud-config-audit/SKILL.md exactly: Layer-1 deterministic facts via the pinned Checkov engine fully offline (run_checkov.py — no cloud API calls, no platform key, secrets framework skipped), then bounded Layer-2 disposition (dedupe, cited suppressions, rubric-based severity, CWE + control_refs mapping), schema-validated to 0 errors via run_checkov.py --validate-report. Declared configuration only — the report never claims observation.
