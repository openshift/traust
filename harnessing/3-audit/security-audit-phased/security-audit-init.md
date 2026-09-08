Perform Phase 1 (Reconnaissance) of a security code audit.

If a path was provided after the command, read the source files at that path. Otherwise use the source code already present in this conversation.

Prior vulnerability reports: $ARGUMENTS (if this is a file path, read it; if empty, treat as "none provided")

Coverity static analysis scan results: $SCAN_RESULTS (if this is a file path, read it and treat its contents as Coverity defect findings to inform your analysis — these are static analysis results, not confirmed vulnerabilities; if empty, treat as "none provided")

Focus guidance: $FOCUS (if this is a file path, read it and use its contents as focus guidance; if it is a plain string, pay special attention to that area/concern during reconnaissance and prioritize it in high_priority_areas; if empty, proceed with standard full-scope reconnaissance)

Build a mental model of the codebase before looking for any specific bugs. Map:

- **Trust boundaries**: every point where external input enters the system (network, files, env vars, IPC, CLI args, DNS, config)
- **Privileged operations**: every sensitive action the code performs (memory allocation, file I/O, crypto, process exec, network, privilege changes)
- **Data flow paths**: trace each untrusted input from entry through transformations, validation, and storage to its final consumption point
- **Privilege contexts**: what privilege level each component runs at (root vs. unprivileged). Identify trust transitions — setuid binaries, privilege drops, capability boundaries — where lower-trust input crosses into higher-trust execution
- **Attack surface**: which components are reachable by an unauthenticated or low-privilege attacker
- **Deterministic pre-scans first**: run python3 -m traust.cli adapters checkov <target> -o <AUDIT_DIR>/khs.json and (when `opengrep` is on PATH) python3 -m traust.cli adapters opengrep <target> --out <AUDIT_DIR>/opengrep.json. Their facts and `tenancy_signals` are the evidence base for the manifest/config and taint observations below — cite their `file:line` instead of re-reading what they check mechanically, and record a `deterministic_steps` map (`"ran"`/`"skipped: <reason>"`) in this phase's JSON. Missing tools → full manual recon, recorded, never a stall.
- **Tenant isolation (PEACH)**: determine whether one deployment of this code serves multiple tenants (customers, namespaces, clusters, or trust domains). Seed the interface inventory from the pre-scan's `tenancy_signals` (CSV install modes, cluster-scoped RBAC, watch-scope hints, webhooks) before reading code. If so, enumerate each customer-facing interface and record its complexity (high / medium / low), whether it is shared or duplicated per tenant, and which security-boundary type separates tenants behind it (`hardware_separation`, `hardware_virtualization`, `containerization`, `data_segmentation`, `network_segmentation`, `identity_segmentation`). PEACH = **P**rivilege · **E**ncryption · **A**uthentication · **C**onnectivity · **H**ygiene — the five hardening parameters Phase 3 will test each boundary against. Methodology: the PEACH framework by Wiz, Inc. (<https://github.com/wiz-sec-public/peach-framework>); this description is original text.

Respond with a JSON object using this structure:

```json
{
  "trust_boundaries": [
    {
      "entry_point": "description of where and how input enters",
      "input_type": "network|file|env|ipc|cli|dns|config|other",
      "location": "file:function:line",
      "notes": "relevant context"
    }
  ],
  "privileged_operations": [
    {
      "operation": "description of the sensitive operation",
      "type": "memory|file_io|crypto|exec|network|privilege|other",
      "location": "file:function:line",
      "notes": "what makes this sensitive"
    }
  ],
  "data_flow_paths": [
    {
      "source": "entry point reference",
      "transformations": ["step 1", "step 2"],
      "sink": "where data is ultimately consumed or stored",
      "validation_present": true,
      "validation_notes": "description of validation, or why it is absent or insufficient"
    }
  ],
  "privilege_contexts": [
    {
      "component": "component, process, or code path",
      "runs_as": "root|unprivileged|mixed|configurable",
      "location": "file:function:line or service/binary name",
      "trust_transitions": "description of privilege boundaries this component crosses, or 'none'",
      "notes": "why this privilege level exists and whether it appears necessary"
    }
  ],
  "attack_surface": [
    {
      "component": "component or subsystem name",
      "reachable_by": "unauthenticated|low_privilege|authenticated",
      "risk_notes": "why this is of interest to an attacker"
    }
  ],
  "tenant_isolation": {
    "applicable": true,
    "rationale": "why this component is or is not multi-tenant",
    "interfaces": [
      {
        "name": "interface name (API endpoint, CRD, webhook, DB client, message consumer, file ingester)",
        "complexity": "high|medium|low",
        "shared": true,
        "boundary_type": "hardware_separation|hardware_virtualization|containerization|data_segmentation|network_segmentation|identity_segmentation",
        "notes": "where in source this boundary is implemented"
      }
    ]
  },
  "high_priority_areas": [
    "specific file, function, or subsystem to examine closely in later phases"
  ],
  "summary": "prose summary of the architecture, trust model, and most promising areas to investigate",
  "cost": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": null
  }
}
```

Output only valid JSON. After outputting the JSON, add a brief human-readable note (outside the JSON block) summarizing the 2-3 most important things you found and flagging anything you want the reviewer to confirm before proceeding to Phase 2. If no prior vulnerability reports were provided (i.e. `$ARGUMENTS` was empty or `"none provided"`), also include the following sentence in the closing note: "No prior vulnerability reports were supplied — Phase 2 will be skipped. Proceed directly to Phase 3."

Then create the directory `$AUDIT_DIR_NAME/` in the current working directory if it does not exist, and write the JSON object to `$AUDIT_DIR_NAME/phase1-recon.json`.

**Cost reporting**: Before writing the JSON file, populate the `cost` field from your API usage metadata for this phase: set `input_tokens` and `output_tokens` from the usage data, set `total_tokens` to their sum, and set `cost_usd` to the estimated cost in USD. If your runtime does not expose usage metadata, set `cost_usd` to `null`.
