---
description: "Analyze cross-cutting risks and vulnerability chains, then consolidate the phased audit report."
---

Perform Phase 4 (Cross-Cutting Analysis and Final Report) of the security code audit in progress.

Read the following files from the current working directory before starting:
- `$AUDIT_DIR_NAME/phase1-recon.json` — Phase 1 reconnaissance
- `$AUDIT_DIR_NAME/phase2-prior-vulns.json` — Phase 2 pattern analysis
- `$AUDIT_DIR_NAME/phase3-hunt.json` — Phase 3 systematic findings

The source code and prior vulnerability reports are in this conversation.

### Step 1: Cross-Cutting Analysis

Look for issues that span the categories already investigated:

**Error handling paths** — trace every error/exception path and verify:
- Resources are freed, locks released, handles closed on all paths
- Partial state is not left exploitable after a failure
- Error responses do not leak sensitive information

**Concurrency** — if the code is multi-threaded or async, examine every piece of shared mutable state for races. Focus on: lock ordering violations, missing locks, lock-free code with incorrect atomicity assumptions.

**Vulnerability chains** — look for sequences of individually minor weaknesses that together form an exploitable path (e.g., integer truncation → size miscalculation → buffer overflow). Report a chain as a single finding with a `cwe_chain` field.

**Tenant-isolation chains (PEACH)** — if `phase1-recon.json → tenant_isolation.applicable` is `true`, look for the cross-tenant escape pattern: *interface bug in a high-complexity shared interface* → *escape of a low-strength boundary (containerization or data segmentation)* → *unmet P.E.A.C.H. parameter enabling lateral reach to other tenants or the control plane*. This is the ChaosDB / ExtraReplica pattern; report it as a single chained finding with `peach_references` set to every parameter the chain exploits, and rate it `high` or `critical` (blast radius = all co-hosted tenants). Methodology: the PEACH framework by Wiz, Inc.; this description is original text.

### Step 2: Final Report

Consolidate all findings from all phases into a complete report. Reference finding IDs rather than re-describing findings. Identify systemic patterns. Be honest about coverage gaps.

### Summary Table Generation

The `summary_table` field in `final_report` must contain a pre-rendered markdown table summarizing all findings for quick triage. Generate it as follows:

**Columns** (in this exact order):
| ID | Name | CWE Chain | Requires Root | Requires Local Access |

**Sort order**: By severity descending (Critical > High > Medium > Low > Informational). When findings share the same severity, sub-sort by finding ID ascending.

**CWE Chain column**: Join CWE IDs from the `cwe_chain` array with ` > ` separator. If a finding has only a single CWE and no chain, display the single CWE ID.

**Access columns** — derive from `minimum_access_required`:
- `local_root` → Requires Root: yes, Requires Local Access: yes
- `local_unprivileged` → Requires Root: no, Requires Local Access: yes
- `authenticated_remote` → Requires Root: no, Requires Local Access: no
- `unauthenticated_remote` → Requires Root: no, Requires Local Access: no

**Edge cases**:
- Zero findings: render the header row with no data rows
- Single CWE (no chain): display the CWE ID alone in the CWE Chain column

The output must conform to this structure:

Use the following ID format for each finding: `{DIRECTORY}-{YYYYMMDD}-{RUNTOKEN}-{NNN}`, where `DIRECTORY` is the uppercase name of the source directory being audited (e.g. `PODMAN`), `YYYYMMDD` is today's audit date, `RUNTOKEN` is the unique token for this audit run, and `NNN` is a 3-digit sequence starting at `001` and incrementing per finding. The run token for this audit is `$RUN_TOKEN`. If this placeholder was not substituted (i.e. it appears literally as `$RUN_TOKEN`), generate a random 4-character uppercase hex string (e.g. `B2D9`) and use it consistently for all findings in this session. Example: `PODMAN-20260406-$RUN_TOKEN-001`.

```json
{
  "cross_cutting_findings": [
    {
      "id": "PODMAN-20260406-$RUN_TOKEN-001",
      "title": "short descriptive title",
      "severity": "Critical|High|Medium|Low|Informational",
      "severity_emoji": "🔴|🟠|🟡|🔵|🟢 (emoji matching severity — 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · 🟢 Informational)",
      "cwe": "CWE-ID",
      "cwe_name": "full CWE name",
      "cwe_chain": ["CWE-ID", "CWE-ID"],
      "location": "file:function:line",
      "description": "what is wrong and why",
      "trigger_scenario": "concrete step-by-step attacker scenario",
      "impact": "worst realistic exploitable impact",
      "evidence": "quoted source code",
      "relationship_to_prior": "Novel finding. | Recurrence of [prior]. | Variant of [prior].",
      "recommended_fix": "specific actionable remediation",
      "peach_references": ["PEACH-P|PEACH-E|PEACH-A|PEACH-C|PEACH-H (omit for non-tenant-isolation findings)"],
      "confidence": "High|Medium|Low"
    }
  ],
  "final_report": {
    "summary_table": "| ID | Name | CWE Chain | Requires Root | Requires Local Access |\n|---|---|---|---|---|\n| PODMAN-20260406-$RUN_TOKEN-001 | Buffer overflow in parse_input | CWE-120 > CWE-787 | no | no |\n...",
    "all_findings": [
      {
        "id": "PODMAN-20260406-$RUN_TOKEN-001",
        "phase": "P3",
        "title": "short descriptive title",
        "severity": "Critical|High|Medium|Low|Informational",
        "severity_emoji": "🔴|🟠|🟡|🔵|🟢 (emoji matching severity — 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · 🟢 Informational)",
        "cwe": "CWE-ID",
        "cwe_chain": ["CWE-ID", "CWE-ID"],
        "location": "file:function:line",
        "minimum_access_required": "unauthenticated_remote|authenticated_remote|local_unprivileged|local_root",
        "confidence": "High|Medium|Low"
      }
    ],
    "severity_counts": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "informational": 0
    },
    "systemic_patterns": [
      {
        "pattern": "recurring weakness class",
        "finding_ids": ["PODMAN-20260406-$RUN_TOKEN-001", "PODMAN-20260406-$RUN_TOKEN-005"],
        "recommendation": "codebase-wide remediation approach"
      }
    ],
    "coverage_gaps": [
      "area that could not be fully analyzed and why"
    ],
    "prior_findings_status": {
      "fully_resolved": [],
      "partially_fixed": [],
      "still_present": []
    },
    "executive_summary": "3-5 paragraph prose summary: what was audited, what was found, the most significant risks, and remediation priorities"
  },
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  }
}
```

**Cost reporting**: Before writing the JSON file, populate the `cost` field from your API usage metadata for this phase: set `input_tokens` and `output_tokens` from the usage data, set `total_tokens` to their sum, and set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.

Write the JSON object to `$AUDIT_DIR_NAME/phase4-final.json`.
