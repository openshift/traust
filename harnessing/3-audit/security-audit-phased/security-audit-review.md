Review a security audit final report.

Your role is a senior security engineer challenging the auditor's work — not re-auditing the code, but assessing whether the findings are real, correctly calibrated, and complete enough to act on.

Start by reading these things from disk:
1. `$AUDIT_DIR_NAME/phase4-final.json` — the audit report to review
2. The source code: $ARGUMENTS (if a path was provided) or infer from the current working directory
3. `$AUDIT_DIR_NAME/phase1-recon.json`, `$AUDIT_DIR_NAME/phase2-prior-vulns.json`, and `$AUDIT_DIR_NAME/phase3-hunt.json` — read these solely to extract their `cost` blocks for aggregation into `total_cost`. Do not use any other data from these files to alter your review logic.

Do not rely on any prior conversation context. Treat this as a fresh, independent review.

For each finding, determine:

- **Is the trigger scenario realistic?** Can an attacker actually reach this code with the described input given the architecture and trust model? Findings behind adequate controls, in dead code, or requiring unreachable preconditions are not exploitable.
- **Is the required access level realistic for the threat model?** Check the finding's `minimum_access_required` and `trust_boundary_crossing` fields against the Phase 1 `privilege_contexts` map. A real vulnerability lets a lower-trust context compromise a higher-trust context. Reject findings where exploitation requires the attacker to already have root, kernel access, write access to privileged filesystem paths, or a prior undemonstrated compromise of another component. An attacker who already has root has simpler, more direct paths to damage. A finding only reachable post-compromise is noise, not signal, unless the threat model explicitly includes insider attackers or privilege escalation within a hardened environment.
- **Does a real trust boundary crossing exist?** Verify that untrusted or lower-privilege input actually flows into a higher-privilege execution path. If the attacker and the vulnerable code operate at the same trust level, the finding has no escalation value and should be downgraded or rejected.
- **Is the severity calibrated correctly?** Overstatement wastes remediation resources. Understatement lets real bugs slip through.
- **Is the evidence sufficient?** Does the quoted code actually contain the weakness, or is this superficial pattern-matching?
- **Is the recommended fix specific and correct?**

Also check for:
- **False positives** — findings that are not real vulnerabilities and why. Common causes include: attacker-controlled data cannot reach the sink; a validation or bound check was missed; the finding is in test or dead code; the "vulnerable" pattern is an unexploitable code smell; the trigger scenario implicitly assumes the attacker already has local, root, or admin access that is not part of the defined threat model (pre-compromise access assumption); there is no trust boundary crossing — the attacker and the vulnerable code operate at the same privilege level, so exploitation provides no escalation; or the finding reports a **delegated-control non-boundary** — a security control performed by a component that already has equal or greater capabilities than bypassing the control would grant (e.g., "component A verifies component B using A's own code" is not a trust boundary violation when A already controls B's entire lifecycle and has code execution at the same privilege level; the real boundary is whoever verified A)
- **Coverage gaps** — obvious omissions given the code and the auditor's own gaps section
- **Systemic pattern accuracy** — are the identified patterns real and is the codebase-wide fix recommendation appropriate?

Disposition options for each finding: `accepted` | `severity_adjusted` | `needs_more_investigation` | `rejected`

Generate a `summary_table` field as the first field in the JSON output following the **Summary Table Generation** rules below.

### Summary Table Generation

The `summary_table` field must be the first field in the JSON output.
Generate it as follows:

**Columns** (in this exact order):
| Review Severity | ID | Name | CWE Chain | Requires Root | Requires Local Access | False Positive |

**Sort order**: By reviewed severity descending (Critical > High > Medium > Low > Informational). When findings share the same reviewed severity, sub-sort by finding ID ascending (e.g., P2-001 before P3-002).

**Review Severity column**: Use `reviewed_severity` from the disposition for each finding.

**CWE Chain column**: Extract `cwe_chain` from Phase 4 input (`final_report.all_findings`). Join CWE IDs with ` > ` separator. If a finding has only a single CWE and no chain, display the single CWE ID.

**Access columns** — derive from `minimum_access_required` in Phase 4 input:
- `local_root`             → Requires Root: yes, Requires Local Access: yes
- `local_unprivileged`     → Requires Root: no,  Requires Local Access: yes
- `authenticated_remote`   → Requires Root: no,  Requires Local Access: no
- `unauthenticated_remote` → Requires Root: no,  Requires Local Access: no

**False Positive column**: Display ✓ (U+2713) if the finding's `finding_id` appears in the `false_positives` array. Otherwise leave the cell blank. Rejected findings not in `false_positives` also leave this cell blank.

**Edge cases**:
- Zero findings: render the header row with no data rows
- Single CWE (no chain): display the CWE ID alone in the CWE Chain column

Respond with a JSON object using this structure:

```json
{
  "summary_table": "| Review Severity | ID | Name | CWE Chain | Requires Root | Requires Local Access | False Positive |\n|---|---|---|---|---|---|---|\n| Critical | P3-001 | Buffer overflow in parse_input | CWE-120 > CWE-787 | no | no | |\n| Low | P4-001 | Race condition in cleanup | CWE-362 | no | no | ✓ |\n...",
  "finding_dispositions": [
    {
      "finding_id": "P3-001",
      "disposition": "accepted|severity_adjusted|needs_more_investigation|rejected",
      "original_severity": "High",
      "reviewed_severity": "High",
      "confidence_in_disposition": "High|Medium|Low",
      "rationale": "specific evidence-based reasoning",
      "reviewer_notes": "caveats or conditions affecting exploitability"
    }
  ],
  "false_positives": [
    {
      "finding_id": "P3-004",
      "rationale": "specific reason this is not exploitable"
    }
  ],
  "severity_adjustments": [
    {
      "finding_id": "P3-007",
      "original_severity": "Critical",
      "adjusted_severity": "High",
      "rationale": "reason for adjustment"
    }
  ],
  "needs_more_investigation": [
    {
      "finding_id": "P4-002",
      "questions": ["specific question that must be answered to confirm or reject this finding"],
      "suggested_approach": "how a human reviewer or dynamic testing could resolve the uncertainty"
    }
  ],
  "coverage_gaps": [
    {
      "area": "description of underanalyzed area",
      "location": "file:function:line or component",
      "suggested_cwe": "CWE-ID",
      "basis": "why you believe this area may contain missed findings"
    }
  ],
  "remediation_priorities": [
    {
      "rank": 1,
      "finding_ids": ["P3-001", "P4-002"],
      "rationale": "severity, exploitability, breadth, systemic nature"
    }
  ],
  "systemic_pattern_assessment": "prose: are the auditor's systemic patterns accurate and are the codebase-wide fixes appropriate?",
  "prior_findings_status_assessment": "prose: are the conclusions about previously reported vulnerabilities accurate?",
  "audit_quality": {
    "overall": "High|Medium|Low",
    "false_positive_rate_estimate": "Low (<10%) | Medium (10-30%) | High (>30%)",
    "coverage_estimate": "Thorough | Adequate | Superficial",
    "notes": "observations about methodology, blind spots, or strengths"
  },
  "reviewer_summary": "3-5 paragraph prose: findings accepted vs. rejected, most significant real risks, what needs further investigation, recommended remediation roadmap",
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  },
  "total_cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null,
    "phases_included": [],
    "phases_missing_cost": []
  }
}
```

Output only valid JSON. Then write the JSON object to `$AUDIT_DIR_NAME/review.json`. After the JSON block, add a brief plain-text summary of your top 3 concerns for the team to address immediately.

**Cost reporting**: Before writing the JSON file, populate the cost fields as follows:

- `cost`: Populate from your API usage metadata for the review phase itself — set `input_tokens` and `output_tokens` from the usage data, set `total_tokens` to their sum, and set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.

- `total_cost`: Aggregate the `cost` blocks from all five phase files:
  1. Collect the `cost` object from each of: `phase1-recon.json`, `phase2-prior-vulns.json`, `phase3-hunt.json`, `phase4-final.json`, and the review's own `cost` block computed above.
  2. For each phase: if the file was missing, or the `cost` key was absent, add that phase key (`"phase1"`, `"phase2"`, `"phase3"`, `"phase4"`, or `"review"`) to `phases_missing_cost` and exclude it from numeric sums.
  3. Sum `input_tokens`, `output_tokens`, and `total_tokens` across all phases with valid `cost` blocks. For `cost_usd`, sum only the non-null values; if all are null, set `total_cost.cost_usd` to `null`.
  4. Set `phases_included` to the list of phase keys that contributed valid `cost` data.
