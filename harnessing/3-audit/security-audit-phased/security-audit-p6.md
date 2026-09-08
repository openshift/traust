Perform Phase 6 (Reproducer Generation) of the security code audit in progress.

Read the following files from the current working directory before starting (in this order):
1. `$AUDIT_DIR_NAME/review.json` — finding dispositions (accepted / severity_adjusted / rejected)
2. `$AUDIT_DIR_NAME/phase4-final.json` — finding ID index and P4 cross-cutting finding details
3. `$AUDIT_DIR_NAME/phase3-hunt.json` — P3 finding full details (trigger scenarios, evidence)
4. `$AUDIT_DIR_NAME/phase2-prior-vulns.json` — P2 variant finding details (may be empty)

Do not rely on any prior conversation context. Treat this as a fresh, independent assessment.

### Scope

Generate a reproducer for every finding whose `disposition` in `review.json` is `accepted` or `severity_adjusted`. Skip findings with disposition `rejected` or `needs_more_investigation` (document them in `skipped_findings`).

### Finding Lookup Logic

`review.json` `finding_dispositions[]` lists which findings to include and their dispositions. `phase4-final.json` `final_report.all_findings[]` is a **summary index only** — used to determine originating phase, NOT for full finding details. Full details come from the originating phase file.

| Finding phase | Where to look |
|---|---|
| P4 (cross-cutting) | `phase4-final.json` → `cross_cutting_findings[]` (match by `id`) |
| P3 | `phase3-hunt.json` → `category_results[].findings[]` (match by `id`) |
| P2 (variant) | `phase2-prior-vulns.json` → `pattern_analyses[].variants_found[]` (match by location+description) |

If a finding cannot be resolved in any phase file, set `reproducer_type: "not_reproducible"` and document which files were searched in `caveats`.

### What Makes a Good Reproducer

A reproducer has one job: make the bug observable to a security engineer who has access to the source code and a build environment. For each finding:

1. **Use the trigger scenario as your blueprint.** The `trigger_scenario` field in the finding is the step-by-step description of how the vulnerability is reached. Translate it into code or steps.
2. **Respect the minimum access level.** The `minimum_access_required` field constrains what privileges your reproducer can assume. Do not run as root if the finding is `local_unprivileged`.
3. **Write the minimum code that demonstrates the bug.** The goal is demonstration, not a weaponized exploit.
4. **State what to observe.** Describe the crash, unexpected output, or behavior that confirms the vulnerability exists.
5. **State how to verify the fix.** Describe what changes to look for after applying the recommended fix to confirm the vulnerability is resolved.

### Reproducer Types

Choose the most appropriate type for each finding:

- `proof_of_concept` — executable code (C, Go, Python, Rust, shell) that directly triggers the vulnerable path. Prefer this for memory safety, integer errors, injection flaws, and logic bugs with callable interfaces.
- `trigger_script` — a shell command sequence that drives the target binary or API with crafted input. Prefer for CLI entry points, IPC interfaces, and network-accessible services.
- `unit_test` — a test written in the codebase's own test framework that exposes the weakness. Prefer when the vulnerable function has a clean, callable interface and the project has an existing test suite.
- `manual_steps` — numbered human-readable steps. Use only when a code-based reproducer is not feasible: race conditions requiring specific timing or multi-process orchestration too complex to script concisely.
- `not_reproducible` — when the trigger scenario requires preconditions that cannot be satisfied outside production (live credentials, specific hardware, third-party service state). Document the exact obstacle.

### Reproducer Writing Guidelines

- Keep PoC code short and self-contained. Avoid external libraries unless the finding specifically involves one.
- Include required compiler flags (e.g., `-fsanitize=address` for memory bugs), tool dependencies (valgrind, strace), or OS/kernel version constraints.
- For memory safety issues, always include a version with AddressSanitizer enabled so the failure is clearly attributed.
- For findings with original `confidence: Low`, note in `caveats` that the reproducer is speculative and may require source-level inspection to confirm.
- Do not reproduce a more severe variant of the finding than what the auditor reported. Stay within the described trigger scenario.

### File Output

Before writing the JSON output, write individual reproducer files. For each accepted finding, create a subdirectory `$AUDIT_DIR_NAME/reproducers/{finding_id}/` containing:

- **`poc.{ext}`** — the main code or script. Use `.c`, `.py`, `.sh`, `.go`, `.rs`, or `.md` (for `manual_steps` or `not_reproducible`). For `unit_test`, use the extension matching the codebase language.
- **`Makefile` or `build.sh`** — only if compilation or a multi-step build is required.
- **`README.md`** — setup instructions, how to run, expected output, and fix verification steps for this specific finding.

Write each file to disk using your file-write tool before generating the JSON summary.

### JSON Output

After writing all reproducer files, output a JSON summary conforming to this structure:

```json
{
  "summary_table": "| ID | Title | Reproducer Type | Confidence | CVSS Score |\n|---|---|---|---|---|\n| PODMAN-20260406-XXXX-001 | Buffer overflow in parse_input | proof_of_concept | High | 7.8 |\n...",
  "reproducers": [
    {
      "finding_id": "PODMAN-20260406-XXXX-001",
      "title": "short descriptive title",
      "disposition": "accepted",
      "cvss_score": 7.8,
      "reproducer_type": "proof_of_concept|trigger_script|unit_test|manual_steps|not_reproducible",
      "reproducer_confidence": "High|Medium|Low",
      "language": "c|python|bash|go|rust|text",
      "environment_requirements": "RHEL 9, gcc 11+, AddressSanitizer (libasan)",
      "setup_steps": [
        "Install build dependencies: dnf install gcc libasan",
        "Build the target from source: make -C /path/to/source",
        "..."
      ],
      "expected_output": "What crash, error message, or behavior confirms the vulnerability is present",
      "fix_verification": "What to check after applying the recommended fix to confirm it is resolved",
      "caveats": "Timing constraints, privilege assumptions, confidence limitations, or other factors affecting reproducibility",
      "files_written": [
        "reproducers/PODMAN-20260406-XXXX-001/poc.c",
        "reproducers/PODMAN-20260406-XXXX-001/Makefile",
        "reproducers/PODMAN-20260406-XXXX-001/README.md"
      ]
    }
  ],
  "skipped_findings": [
    {
      "finding_id": "PODMAN-20260406-XXXX-002",
      "title": "finding title",
      "disposition": "rejected",
      "reason": "Rejected by reviewer — not a confirmed vulnerability. No reproducer generated."
    }
  ],
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

**`summary_table`**: columns are ID | Title | Reproducer Type | Confidence | CVSS Score. Sort by `cvss_score` descending; findings without a CVSS score sort last, then alphabetically by ID within each group.

**`reproducer_confidence`**:
- `High` — the trigger scenario is concrete and the code path is fully traced; the reproducer should execute reliably.
- `Medium` — the path is plausible but not fully confirmed statically; the reproducer exercises the right code region but may need tuning.
- `Low` — the finding has `confidence: Low` in the original report, or the trigger scenario has significant precondition uncertainty.

**`cost`**: populate from API usage metadata for this phase: set `input_tokens` and `output_tokens` from usage data, set `total_tokens` to their sum, set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.

**`total_cost`**: aggregate the `cost` blocks from all phase files available at this point in the pipeline:
1. Collect the `cost` object from each of: `phase1-recon.json`, `phase2-prior-vulns.json`, `phase3-hunt.json`, `phase4-final.json`, `review.json`, and the reproducer phase's own `cost` block computed above. Do not attempt to read `cvss.json` — it has not been produced yet.
2. For each phase: if the file was missing or the `cost` key was absent, add that phase key (`"phase1"`, `"phase2"`, `"phase3"`, `"phase4"`, `"review"`, or `"reproducers"`) to `phases_missing_cost` and exclude it from numeric sums.
3. Sum `input_tokens`, `output_tokens`, and `total_tokens` across all phases with valid `cost` blocks. For `cost_usd`, sum only the non-null values; if all are null, set `total_cost.cost_usd` to `null`.
4. Set `phases_included` to the list of phase keys that contributed valid `cost` data.

Output only valid JSON. Write the JSON object to `$AUDIT_DIR_NAME/phase6-reproducers.json`.

After the JSON block, add a brief plain-text note naming the **top 3 most important reproducers** for the team to verify first, with one sentence on why each matters.
