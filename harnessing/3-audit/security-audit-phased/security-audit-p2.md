Perform Phase 2 (Prior Vulnerability Pattern Analysis) of the security code audit in progress.

Read `$AUDIT_DIR_NAME/phase1-recon.json` from the current working directory — that is your Phase 1 input. The source code and prior vulnerability reports are in this conversation.

If no prior vulnerability reports are present in this conversation (i.e. Phase 1 was run without a prior vulnerability argument — confirmed by Phase 1's output stating "No prior vulnerability reports were supplied"), skip all analysis. Write the following stub to `$AUDIT_DIR_NAME/phase2-prior-vulns.json` and stop — do not produce any analysis JSON block or human-readable note:

```json
{
  "pattern_analyses": [],
  "systemic_issues": [],
  "no_prior_vulns": true,
  "summary": "Phase 2 skipped — no prior vulnerability reports provided.",
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  }
}
```

For each prior vulnerability report:

- Identify the **root cause pattern** — the class of mistake, not just the specific instance
- Determine whether the **same pattern recurs** elsewhere — developers who make a mistake once often make it systematically
- Check whether prior **fixes are complete** (look for CWE-1055: Incomplete Fix) — narrow fix addressing only the reported instance, or comprehensive fix addressing the root cause?
- Search for **variant vulnerabilities** in adjacent functions, sibling modules, or copy-pasted code

The output must conform to this structure:

```json
{
  "pattern_analyses": [
    {
      "prior_finding_reference": "title or ID of the prior vulnerability",
      "root_cause_pattern": "the class of mistake",
      "recurrences": [
        {
          "location": "file:function:line",
          "description": "how this instance exhibits the same root cause"
        }
      ],
      "fix_completeness": "complete|partial|incomplete",
      "fix_notes": "what the fix addressed and what it may have missed",
      "variants_found": [
        {
          "location": "file:function:line",
          "description": "how this variant differs from the original",
          "cwe": "CWE-ID",
          "severity_estimate": "Critical|High|Medium|Low|Informational",
          "severity_emoji": "🔴|🟠|🟡|🔵|🟢 (emoji matching severity_estimate — 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · 🟢 Informational)"
        }
      ]
    }
  ],
  "systemic_issues": [
    {
      "pattern": "recurring weakness pattern",
      "instances": ["file:function:line"],
      "cwe": "CWE-ID",
      "notes": "why this is systemic and what a comprehensive fix requires"
    }
  ],
  "no_prior_vulns": false,
  "summary": "prose summary of what the prior vulnerability history reveals",
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  }
}
```

**Cost reporting**: Before writing the JSON file, populate the `cost` field from your API usage metadata for this phase: set `input_tokens` and `output_tokens` from the usage data, set `total_tokens` to their sum, and set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.

Write the JSON object to `$AUDIT_DIR_NAME/phase2-prior-vulns.json`.

After writing the file, output a brief human-readable note highlighting the most significant pattern findings and any questions for the reviewer before proceeding to Phase 3.
