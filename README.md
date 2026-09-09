# Traust

Traust is a workflow engine for automated, multi-framework security assessment of software portfolios: source repositories, container images, RPM packages, Kubernetes operators, infrastructure-as-code and the services built from them. This repository holds the skills, slash commands, schemas and prompt engineering that let an AI coding agent run consistent, repeatable audits, triage and validate what it finds, record every disposition in a signed ledger, and drive remediation — at the scale of hundreds of repositories rather than one review at a time. Traust was developed by Red Hat's Hybrid Platforms security team and is published under the Apache License 2.0.

## Purpose

Manual security review does not scale to hundreds of repositories across dozens of product releases. This workflow engine equips AI coding agents with structured methodologies to perform consistent, repeatable security audits — applying industry-standard frameworks to every repository in the portfolio.

The harness is designed to be agent-agnostic in principle, with current implementations targeting Claude Code and Crush (via shared skills and slash commands).

## Components

This repository is the **agent-facing layer** of a five-component stack, not the
whole system. Skills, slash commands and CLIs live here; the deterministic
machinery, the ledger trust root and the shared vocabulary are separately
versioned repositories, installed as pip dependencies pinned by git tag.

```
  traust     skills, slash commands, agent-facing CLIs   ← this repo
        ▼
  traust-engine          scanner adapters, corpus, metrics, reporting, validation
        ▼
  traust-ledger             finding identity, Merkle integrity, signing, ledger writes
        ▼
  traust-contracts   schemas · enums · shared models             (leaf)

  traust-sdk (Go)    typed SDK for non-Python consumers — imports the contracts,
                          calls the harness; not a dependency of it
```

Dependencies point one way, downward. The practical consequence: **a schema or
enum change belongs in `traust-contracts`, not here.** There is no local
`schemas/` directory — the `schemas/v1/…` paths referenced throughout this README
resolve inside the installed contracts package
(`traust_contracts`), and changing them means releasing that repo
and pulling the new tag up the chain.

Which repo to change for a given fix, how the git-tag pinning works (and the
`uv lock` "conflicting URLs" failure it produces when pins disagree), and the
bottom-up release order are all in **[docs/components.md](docs/components.md)**.

## How to Use this workflow engine

**Start here:** `scripts/install_traust` sets up `TRAUST_CONFIG_HOME` (the directory
holding your operational configuration, created from the `config/*.example.*`
templates), optionally installs the scanner toolchain, and `install_traust --doctor`
checks the install. Nothing runs without it — see [docs/setup.md](docs/setup.md).

**New here?** Start with [docs/getting-started.md](docs/getting-started.md) — zero to first audit report. What you need to run it (platform, agent/model tier, tools, network access) is in [docs/requirements.md](docs/requirements.md).

This harness is primarily used as an end-to-end workflow to index, scan, validate, and remediate all repositories across an organization.  That workflow looks roughly like this:
```
  Inputs ─▶ ① Inventory ─▶ ② Threat model ─▶ ③ Audit ─▶ ④ Triage ─┬─▶ ⑧ Package ─▶ ⑨ Assign ─▶ Share/Notify ─▶ File defects
 (inputs)                                    (analysis-results)    │   (progress-tracker → Drive, Slack, Jira)
                                                                   ├─▶ ⑤ Live validation  (validate-* / deploy-operator)
                                                                   ├─▶ ⑥ Fuzzing          (create-fuzzing)
                                                                   └─▶ ⑦ Remediation      (remediate-finding / patch / verify)

  Stages ③–⑦ feed the append-only disposition ledger (track-findings), gated by human countersign;
  follow-up scans (vuln-scan, verify-remediation regressions, dependency-watch) enter it directly.
  Dashboards (exec summary, trends, LoC, census …) render under progress-tracker/metrics/dashboards/.

  Standing loop (daily, after the first pass — docs/continuous-operations.md):
  fleet refresh ─▶ router ─▶ lanes: diff-scan │ deps (/dependency-watch) │ IaC │ verify treadmill │ rule mining (/mine-ledger)
                              └─ findings re-enter ④ Triage / the ledger; dashboards & drift-watch rebuild on cadence
```

Portions of the harness can be executed independently and locally.  We'll discuss both of these workflows and overview the skills (and phases of execution where they're used) below.  

Findings interchange is standards-based, in both directions: `/triage` imports **SARIF 2.1.0** from any scanner (`harnessing/4-triage/triage/scripts/normalize_input.py`, which also takes Dependabot alert exports and native govulncheck streams), and every report exports to SARIF for the adopter's own dashboard or viewer (python3 -m traust.cli reporting sarif). See [docs/sarif.md](docs/sarif.md).

Note: if you just want an index of all skills in this repository, ask your agent or see [docs/skills.md](docs/skills.md).

### Standalone Usage

For those wanting to use Traust **locally**...

"Standalone" mode refers to using any of these skills independently outside of an automated workflow. 
#### Standalone Skills

These skills work against any codebase or report files you supply _outside of the full workflow_ with minimal coaxing. The expected inputs are always listed in the "Inputs" column, but if you want all of the options, see [docs/skills.md](docs/skills.md).

Skills marked with Environment or Infrastructure requirements need access to services your organisation runs; the workflow engine names the kind of service, your deployment supplies the instance. Typical setup:
* **Employee directory** - the optional `LEDGER_DIRECTORY_COMMAND` cross-check; SSO/VPN as your directory requires
* **Jira** - MCP or CLI with access to target projects required
* **Ephemeral OCP Cluster** - any short-lived OCP cluster; if your organization runs an on-demand cluster service, that is the simplest route
* **Playwright** - the playwright MCP server and package installed and configured for web-driving support
* **Google Workspace** - the gws CLI, these skills use the Google Workspace API to modify Google Docs or Drive

Skills with no infrastructure requirement need only the workflow engine and a target codebase.

| Skill | Stage | What It Does | Inputs | Environment & Infrastructure Requirements | Minimum Viable Model |
|-------|-------|--------------|--------|----------------|-----------|
| `threat-model` | ② | Threat model from code, past vulns, or owner interview; review/update/pr modes maintain existing models; emits `<repo>-threat-model.md` gated by `lint_threat_model.py` | Any checkout or PR diff | — | mythos-class |
| `secure-code-audit` | ③ | Multi-framework security audit (OWASP ASVS v5.0, K8s Top 10, CIS, DISA STIG, SLSA, OpenSSF Scorecard) | Any Git repo (cloned automatically) | — | mythos-class |
| `secure-rpm-audit` | ③ | RPM dist-git packaging audit (Fedora Packaging Guidelines RPM01–RPM10, SEI CERT C/C++, ASVS, SLSA) | Any dist-git RPM repo (cloned automatically) | — | mythos-class |
| `secure-container-audit` | ③ (alt) | Container image audit: skopeo config/signature/tag-hygiene inspection, syft SBOM, grype CVE scan, source-drift check | Any registry image ref, payload CSV, or image list | `skopeo`, `syft`, `grype` | opus-class |
| `cloud-config-audit` | ③ (alt) | Declared-layer IaC audit (Terraform, CloudFormation, K8s/Helm, ARM/Bicep, Dockerfiles) via pinned offline Checkov — no cloud API calls by design | Any IaC checkout | `checkov` (pinned, offline) | opus-class |
| `operator-priv-profile` | ③ (adj) | Operator least-privilege assessment in three tiers: static SCC/securityContext/namespace/RBAC profile, kubebuilder-marker surplus diff, gated runtime capture | Any operator repo or bundle manifests | tier 3 only: OCP cluster + explicit authorization | opus-class |
| `pqc-readiness` | — | Post-quantum crypto readiness: pinned pqc-scan facts + NIST IR 8547 transition clocks, provenance + VULN/AGIL/PQCA/HNDL scoring, CycloneDX CBOM | Any single repo checkout | Rust toolchain (build only) | mythos-class |
| `mine-ledger` | — | Mines ledger-confirmed TPs into the opengrep rule-calibration corpus: coverage gaps, per-rule precision, authoring backlog | Any findings directory with cumulative reports | — | opus-class |
| `security-audit-phased` | ③ (alt) | Multi-phase human-in-the-loop audit: recon → prior-vuln patterns → CWE-taxonomy walk | Any local checkout | — | mythos-class |
| `vuln-scan` | ③ (alt) | Lightweight vulnerability sweep: threat-model-scoped focus areas, parallel review subagents, baseline dedupe | Any local checkout | — | mythos-class |
| `triage` | ④ | Adversarial N-vote verification, dedup, precondition-derived re-ranking, and owner routing of raw findings; citation-gated and symbol-index-accelerated | Any scanner output (directory or file) | — | mythos-class |
| `countersign` | ④ | Human sign-off inbox for the disposition ledger — self-contained decision cards for pending false-positive countersigns; LDAP-verified recording | Any findings directory | Red Hat LDAP (VPN) | opus-class |
| `validate-findings` | ⑤ (sub) | Proves/refutes findings against live environment, chains kill-chains | Any audit report | Ephemeral OCP Cluster | mythos-class |
| `validate-browser-finding` | ⑤ (alt) | Browser-based web vulnerability validation (CSRF, XSS, clickjacking) via Playwright | Any audit report | Ephemeral OCP Cluster, Playwright | mythos-class |
| `create-fuzzing` | ⑥ | Offline fuzz harnesses (Go-native default, plus Python/atheris, JS-TS/Jazzer.js, Rust/cargo-fuzz, Java/jazzer templates) for parser/decoder/templater entry points flagged in audit reports; explicitly offline — no cluster, cloud, or network | Any audit report + target checkout | — | opus-class (`fuzz-author` floor) |
| `patch` | ⑦ | Inert candidate-fix diffs per confirmed triage finding (patch subagent + independent reviewer); never applies, never writes outside `./PATCHES/` | A `TRIAGE.json`, audit report, or `*-vuln-findings.json` | — | mythos-class |
| `remediate-finding` | ⑦ | Generate remediation patches on private forks (user supplies their own fork) | Any audit report + a fork with push access | — | mythos-class |
| `verify-remediation` | ⑦ | Verifies a patched repo actually resolves prior audit findings | A previous audit report + patched checkout | — | mythos-class |
| `generate-team-report` | ⑧ | Packages component reports into team-deliverable folders with HTML dashboards | Any findings directory | — | opus-class |
| `track-findings` | — | Append-only disposition ledger (human triage + machine validation) → cumulative findings-status report | A `*-security-audit.json`, `*-cloud-config-audit.json`, or `*-container-audit.json` baseline at any path | — | opus-class |
| `check-harness-docs` | — | Doc-drift guard: checks the harness's own docs (skill/command/script/stage counts + dead links) against the tree | The harness repo itself | — | sonnet-class |
| `check-licensing` | — | Licensing gate: blocks re-imported restrictively-licensed framework text (PEACH/CIS guard, run by the pre-push hook) + license-intake checklist for new external dependencies | The harness repo itself | — | sonnet-class |
| `check-alignment` | — | Cross-skill contract guard: script refs, pre-scan recording conventions, structure-doc links, liveness sourcing, frontmatter + wiring — enforced by the pre-commit hook | The harness repo itself | — | sonnet-class |
| `check-skill-security` | — | Security-posture gate for skills: ten S-rules — allowed-tools confinement, adversarial-content doctrine, git-URL transport gates, shell-exec/token-argv//tmp-path/unpinned-install/egress-grant rules (2026-07 self-audit), repo-config isolation for headless agents (S9, from the b-lite-p5 hostile-`.claude` incident), and safe_exec routing for target builds (S10, sandbox-adoption); enforced by the pre-commit hook and CI | The harness repo itself | — | sonnet-class |
| `crypto-analysis` | — | Probe-driven crypto governance analysis: provider census across 9 ecosystems, governance chain reasoning, builder image crypto swap detection | Any Git repo | — | mythos-class |
| `portfolio-graph` | — | Queryable source-code graph (SQLite): multi-ecosystem module dependency layer (Go plus npm/PyPI/Maven/Cargo/RubyGems/NuGet manifests, language-gated, tree-discovered anywhere in a repo; C/C++ SBOM-only) plus three universal surfaces (Docker base images, GitHub Actions, Helm charts — path-discovered, not language-gated) over the repo-graph spine — CVE blast radius, shared-library fan-in, internal coupling | `repo-graph.json` + `gh` auth | `gh` | opus-class |
| `dependency-watch` | — (daily lane) | Advisory-driven deps lane end to end: feed refresh → new-advisory sweep (never drops CVE-less malicious-package/`MAL-` advisories — the Shai-Hulud class) → `/impact-analysis` reachability → `route_impact_findings.py` direct-entry filing (affected repos' findings enter baseline + ledger at `not_verified` the day the advisory lands) | optional CVE ID / `--since` | — | opus-class |
| `impact-analysis` | — | Per-repo CVE affectedness across the portfolio graph: blast radius query, L4 package-import refinement, language-specific deep scan (Go's govulncheck + ELF reachability is the strongest tier; other ecosystems get manifest-level analysis); feeds `/triage` Phase 2f, `/verify-remediation --impact-filter`, and the `/dependency-watch` filing leg | A CVE ID + portfolio-graph.db | — | opus-class |

### Campaign workflow

For those interested in how the **campaign** works...

The campaign workflow uses the above skills, plus a few additional campaign-specific skills, and works against a few fixed and private (due to data sensitivity) repositories that enable an automated data-flow from inventory through scanning to remediation.  These helper repositories are:

* **Inventory Repository** - this forms the _inputs_ to the security scan.  For operators of a campaign, this is the *-inputs repository(ies). This contains a structured inventory of all repositories in active projects/products to scan.  
* **Traust Workflow Engine** - this repository!  This contains all of the skills used throughout the campaign stages

#### Campaign-bound skills

These skills are specific to the scanning campaign. They consume the full `*-results/` and/or `*-inputs/` trees as aggregate input and produce cross-portfolio dashboards or rollups.

| Skill | Stage | What It Does | Min Model |
|-------|-------|--------------|-----------|
| `census` | — | Corpus census: report population per ownership cut, five duplication vectors, the **distinct-vulnerabilities** canonical headline, repo liveness — the denominator authority every other dashboard cites (`findings.db `repos``) | opus-class |
| `add-inputs` | ① | Ad-hoc registration of repos or whole orgs into the inputs inventory (`locations.inputs`) — the lightweight counterpart of `inventory-repositories` | opus-class |
| `inventory-repositories` | ① | Discovers every source repo shipped in a release payload image or an OLM operator bundle (segment kinds `release-payload` / `catalog` in `<inputs>/inventory.yaml`) and writes the per-segment CSV inventory + `owners.csv` | opus-class |
| `corpus-intake` | — | The only supported write path for `$TRAUST_CONFIG_HOME/corpus-config.yaml` — interview-driven registration of corpus trees/engagements with ownership tags (owned / upstream / external-bu), validated atomic writes, census refresh | opus-class |
| `financial-tracking` | — | Campaign cost over time: per-lane spend, **per-business-unit** split (bridged from transcript paths via findings.db `business_unit`; partial coverage, always stated), unit economics ($/repo, $/finding), month-over-month trend, and an `--invoice` seam. All figures are **list-price estimates, never invoiced actuals** | opus-class |
| `executive-summary-findings` | — | Cross-portfolio leadership roll-up dashboard (deterministic builder + machine sidecar for the scoreboard) | haiku-class (`render-narrate` floor) |
| `loc-dashboard` | — | Lines-of-code coverage dashboard (also reads the inputs inventory) | haiku-class (`render-narrate` floor) |
| `repo-graph` | — | Portfolio segment→product→repo→findings graph (JSON/DOT/GEXF/HTML; also reads the inputs inventory) | opus-class |
| `insecure-patterns` | — | Cross-portfolio insecure-coding-pattern roll-up (CWE → OWASP ASVS taxonomy) | mythos-class |
| `findings-trends` | — | Up/down trend dashboard by ledger replay: burndown, headline risk signals (`owasp_high_plus_pct`, `mean_cvss_open`), velocity, MTTR, accepted-risk register | haiku-class (`render-narrate` floor) |
| `validation-fuzz-dashboard` | — | Combined live-validation + fuzzing results dashboard | opus-class |
| `threat-register` | — | Fleet-wide threat roll-up from every threat-model file: open-threat exposure by product, stable `<slug>:<Tn>` keys, class-closing quick wins | opus-class |
| `isolation-review` | — | Service-level tenant-isolation review (PEACH cited by reference only): interface inventory from the portfolio graph + existing findings, per-interface complexity, five hardening dimensions with cited evidence, posture + prioritized gaps | mythos-class |
| `traust-metrics` | — | Campaign metrics scoreboard + append-only hash-chained metrics-history ledger and Executive-Trends dashboard under `progress-tracker/metrics/` | opus-class |
| `rbac-tenancy-rollup` | — | RBAC + multi-tenancy misconfiguration rollup: executive one-pager, top-misconfigurations detail, HTML dashboard, MITRE ATT&CK candidate inference | opus-class |
| `attack-coverage` | — | Fleet-wide MITRE ATT&CK coverage rollup joining observed (live-validation), modeled (threat-model), and derived (category-mapped) technique IDs into a Navigator layer | opus-class |
| `compliance-check` | — | Evidence-gated per-control compliance assessment (PCI DSS, NIST 800-53, FedRAMP, SOC 2, GDPR slice); deterministic verdicts the agent cannot override | mythos-class |
| `fleet-fix` | ⑦ (fleet) | Remediates one systemic pattern across every affected repo via a schema-validated transform spec with mandatory golden tests; MRs only after human batch approval | opus-class |
| `sla-view` | — | Per-severity resolve clocks replayed from the disposition ledgers against a schema-validated SLA policy (default: Red Hat PSIRT VMWM) — breach counts, overdue lists | opus-class |
| `findings-db` | — | Queryable SQLite projection of the findings corpus for ad-hoc leadership questions; a projection, never an authority (ledgers stay the source of truth) | opus-class |
| `drift-watch` | — | Staleness/drift report over the harness's own derived artifacts and source pairs (feeds, findings.db, graphs vs inputs) | sonnet-class |
| `refresh-dashboards` | — | One-command rebuild of every deterministic dashboard in dependency order (projections → consumers → scoreboard); packages the weekly "Dashboards rebuild" job | sonnet-class |
| `recall-benchmark` | — | Ground truth for the auditor itself: re-audits pinned pre-fix refs of repos with known-real findings and measures detection recall | mythos-class |

#### Campaign Directory Structure
Alongside runtime requirements (infrastructure requirements, orchestration), the campaign requires a very specific runtime file structure.

```
workspace/                              # Run the agent from here
├── traust/                # This repository (skills, schema, tooling)
├── *-inputs/                           # Repository inventories (CSVs, Markdown, owners)
│   ├── openshift/                      #   — campaign-bound skills only
│   ├── operator-catalog/
│   └── services/
│       └── <service>/
│           ├── <service>-repos.csv
│           └── <service>-repos.md
└── *-results/                          # Audit output
    ├── findings/
    │   ├── _manifest/                  # Campaign manifests, progress tracking
    │   │   ├── *-manifest.csv
    │   │   └── rescan-worklist.json
    │   ├── <product>/
    │   │   └── <repo>/
    │   │       ├── <repo>-security-audit.{md,json}
    │   │       ├── <repo>-findings-layer.json       # disposition ledger (track-findings)
    │   │       ├── <repo>-findings-current.{md,json}
    │   │       ├── <repo>-threat-model.md
    │   │       ├── <repo>-triage.{md,json}
    │   │       ├── <repo>-attack-plan.yaml          # validate-findings
    │   │       ├── <repo>-validation.{md,json}      # validate-findings
    │   │       ├── validation-audit.jsonl           # validate-findings
    │   │       ├── artifacts/                       # validate-findings evidence
    │   │       └── <image>-container-audit*.{md,json}  # secure-container-audit report +
    │   │                                            # its full-stem ledger artifacts
    │   └── <stream>/                    # dist-git streams (c10s, c9s) — secure-rpm-audit
    │       └── <component>/<component>-security-audit.{md,json}
    ├── oss-findings/
    │   └── <org>/<repo>/<repo>-security-audit.{md,json}
    └── validations/
        └── <slug>/                     # Per-operator/CO validation runs
```

## Documentation

| Guide | Description |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | **Start here** — from zero to your first audit report: install, point your agent, run an audit, check the output |
| [docs/requirements.md](docs/requirements.md) | **What you need** — baseline platform/agent/model requirements, CLI tools by capability, network & access tiers, campaign extras |
| [docs/setup.md](docs/setup.md) | Setup reference — `install_traust`, workspace, toolchain, storage variables, tests, contributor gates |
| [docs/language-support.md](docs/language-support.md) | **Language support matrix** — the language-agnostic agentic core vs per-language deterministic depth (rule packs, CVE reachability engines and their soundness, fuzzers, manifests, crypto census), current gaps, and the pattern for adding a language |
| [docs/external-dependencies.md](docs/external-dependencies.md) | **Every external requirement** — CLI tools, Python libraries, MCP servers, data feeds, and framework content licenses, each with verified license + citation, plus the commercialization risk assessment (CIS flagged; PEACH resolved by the v0.54.2 original-text rewrite) |
| [docs/skills.md](docs/skills.md) | Detailed reference for all 51 skills |
| [docs/validation-process.md](docs/validation-process.md) | **How live validation reaches a trustworthy verdict** — the three-purpose mission, the fail-closed gate stack (attestation → positive controls → differential probing → soundness → ledger discipline), and artifact flow |
| [docs/model-routing.md](docs/model-routing.md) | **Model routing** — the model registry, tier classes and role floors, the A12 no-hardcoded-model rule, escalation stamping, the spend-declaration command |
| [docs/components.md](docs/components.md) | **The five-component stack** — what `traust-engine` / `traust-ledger` / `traust-contracts` / `traust-sdk` each own, which repo to change for a given fix, git-tag pinning and its "conflicting URLs" failure mode, and the bottom-up release order |
| [docs/architecture.md](docs/architecture.md) | Code internals — pipeline flow, adapter system, data model |
| [docs/artifacts.md](docs/artifacts.md) | Artifacts — what each stage produces, which skills consume it, where it lands, and the one-way projections (Markdown, findings.db, SARIF, GitLab) |
| [docs/sarif.md](docs/sarif.md) | **SARIF emitter and importer** — how a harness report projects to SARIF 2.1.0 (field mapping, suppressions, fingerprints, degraded-run signal, batch sweep) and how third-party SARIF is normalised into triage claims |
| [docs/continuous-operations.md](docs/continuous-operations.md) | **The standing rescan loop** — the daily router (python3 -m traust.cli.build_rescan_worklist), lane cadences, the arrival-channel coverage model with measured residuals, event injection via `rescan-events.jsonl`, the advisory budget guard, and the **weekly-drain orchestrator contract** (harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py + one headless diff scan per tranche row) |
| [docs/continuous-scanning.md](docs/continuous-scanning.md) | Redirect stub — renamed to `continuous-operations.md` on 2026-08-17 (it carries cost routing, spend cadence and credentials, not only scanning); kept so external links resolve |
| [docs/error-model.md](docs/error-model.md) | **Type I & Type II error handling** — where false positives and false negatives enter, the asymmetric-caution doctrine (machines confirm, humans dismiss), the measured error rates behind each control, self-measurement mechanisms, the improvement loop (how measured misses become the next rules/enumerators — coverage-gap rollup, rule-candidate capture), and the residual risks a consumer should know |
| [docs/disposition-ledger.md](docs/disposition-ledger.md) | **The ledger, from first principles** — why it is append-only and event-sourced, the two disposition axes, evidence-class precedence, the five-layer false-positive discipline, replay/assurance views, and a worked finding timeline |
| [docs/deterministic-inferential-mix.md](docs/deterministic-inferential-mix.md) | How deterministic and inferential tooling are mixed — CPU for enumeration and fact-retrieval, inference for judgment and novelty; deterministic tools route, gate, tag, or index, never conclude |
| [docs/report-structure.md](docs/report-structure.md) | Shared report-structure reference for all three audit profiles (code/rpm/container) — sections, deterministic_steps conventions |
| [docs/adversarial-content-doctrine.md](docs/adversarial-content-doctrine.md) | The single-source CWE-1427 doctrine every untrusted-content-reading skill references |
| [docs/risk-rating-methodology.md](docs/risk-rating-methodology.md) | How per-finding scores become portfolio risk metrics (findings-trends) |
| [docs/signing.md](docs/signing.md) | **Ledger signing** — what is signed (format-4 payload), when (every write, stamp then sign), who needs the key, configuration variables, the `ledger` CLI, cosign v3 behaviour, rotation |
| [docs/storage.md](docs/storage.md) | Where each kind of data lives — ledgers in git, results local or in object storage, roll-ups, projections, operational config — and the variables that place them |
| [docs/routers.md](docs/routers.md) | **Authoritative index of all seven router kinds** (work/rescan, cost/budget-guard, model, findings, owner, defect, feed) plus the five worklist builders — what each may write, and links to the detail |
| [docs/findings-routing.md](docs/findings-routing.md) | **Canonical:** how a finding gets into the ledger — the findings routers, idempotence, id minting, and the baseline-ownership rule. Disambiguates the other three kinds of routing (work/rescan, owner, defect) |
| [docs/safe-exec.md](docs/safe-exec.md) | The target-build sandbox: profiles, env scrubbing, modes/bypass, gate rule S10 |
| [docs/reachability.md](docs/reachability.md) | **Reachability** — every engine (govulncheck, Joern Java/C tiers, ELF scans, taint enumerator), the evidence ladder and its soundness rules, consumers, and guardrails; pending build-out lives in `progress-tracker/plans/reachability-integration-plan.md` |
| [PROCESS.md](PROCESS.md) | End-to-end 9-stage campaign workflow |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Tooling / Structure Files

The schemas below (from the installed `traust-contracts` package) are the complete set; the scripts listed are the key entry points — packaged CLIs live under `src/traust/`, and skill-specific tooling lives alongside each skill in its own `scripts/` — under a stage directory for workflow skills (`harnessing/4-triage/triage/scripts/`), at the `harnessing/` root for the rest.

| Component | Purpose |
|---|---|
| python3 -m traust.cli util safe-exec + `$TRAUST_CONFIG_HOME/safe-exec-profiles.yaml` | Enforced sandbox for target-derived commands (argv allowlists, env scrub, shell-free pipelines) — gate rule S10; [docs/safe-exec.md](docs/safe-exec.md) |
| python3 -m traust.cli.refresh_dashboards | The packaged dashboards rebuild (projections → builders → scoreboard) — `/refresh-dashboards` |
| `traust_engine.escaping` | Shared untrusted-text helpers every emitter uses (HTML, inline-script JSON, md cells, CSV, slugs) — library import, not a CLI |
| `schemas/v1/report.schema.json` | JSON Schema (draft 2020-12) for security-audit reports |
| `schemas/v1/triage.schema.json` | JSON Schema for TRIAGE.json validation |
| `schemas/v1/vuln-findings.schema.json` | JSON Schema for vuln-scan candidate reports (`<repo>-vuln-findings.json`) |
| `schemas/v1/adapter-result.schema.json` | JSON Schema for traust-engine scanner adapter `scan()` return values (distinct from skill-level vuln-findings output) |
| `schemas/v1/validation.schema.json` | JSON Schema for live-validation reports |
| `schemas/v1/remediation.schema.json` | JSON Schema for remediation patches |
| `schemas/v1/verification.schema.json` | JSON Schema for remediation-verification reports |
| `schemas/v1/impact-analysis.schema.json` | JSON Schema for CVE impact-analysis artifacts |
| `schemas/v1/layer.schema.json` | JSON Schema for findings-disposition layers (track-findings ledger) |
| `schemas/v1/adapter-result.schema.json` | JSON Schema for adapter results (contracts v0.2.0) |
| `traust-ledger/tests/fixtures/identity-recipe-vectors.json` | Regression fixtures for the finding-fingerprint recipe (canon_repo/canon_path/primary_cwe/fingerprint, implemented in `traust-ledger/traust_ledger/identity.py`), replayed by `traust-ledger/tests/test_identity_recipe_vectors.py`. **Fixtures, not a contract**: under decision D7 (2026-08-18) only the harness computes identity, so the cross-implementation golden-vector suite that used to live at contracts `vectors/v1/` was retired in contracts 0.5.0 along with the SDK's `go/v1/identity` port. They exist so the one remaining implementation cannot change by accident across an `algo_version` bump — see [docs/components.md](docs/components.md#5-what-crosses-the-boundary). |
| `schemas/v1/isolation-review.schema.json` | JSON Schema for tenant-isolation review reports |
| `schemas/v1/cloud-config-audit.schema.json` | JSON Schema for declared-layer IaC audit reports |
| `schemas/v1/cloud-config-findings-current.schema.json` | JSON Schema for cloud-config cumulative status reports (`*-findings-current.json` from track-findings) |
| `schemas/v1/compliance-assessment.schema.json` | JSON Schema for compliance-check assessment reports |
| `schemas/v1/compliance-mapping.schema.json` | JSON Schema for the control↔check policy mapping |
| `schemas/v1/doc-variance.schema.json` | JSON Schema for documentation-variance registers (`<repo>-doc-variance.json`) — official docs.redhat.com claims contradicted by code evidence, per doc version; source URL schema-restricted to docs.redhat.com (informal inputs never mint variance records) |
| `schemas/v1/compliance-scope.schema.json` | JSON Schema for the compliance scope registry (declared boundaries; repo membership resolved via the repo-graph product mapping by `python3 -m traust.cli compliance scope`) |
| `schemas/v1/pqc-facts.schema.json` | JSON Schema for the deterministic Layer 1 crypto census (`*-pqc-facts.json`) — the contract `/patch`'s pqc ingest and the Layer 2 prepass consume |
| `schemas/v1/pqc-readiness.schema.json` | JSON Schema for PQC readiness reports |
| `schemas/v1/pqc-blockers.schema.json` | JSON Schema for the findings-shaped projection of readiness remediations (`*-pqc-blockers.json`, emitted by `build_pqc_blockers.py`) — mirrors the security-audit findings vocabulary without claiming `report.schema.json` conformance |
| `schemas/v1/pqc-decision-tree.schema.json` | JSON Schema for the PQC provenance decision tree |
| `schemas/v1/fleet-fix.schema.json` | JSON Schema for fleet-fix transform specs |
| `schemas/v1/sla-policy.schema.json` | JSON Schema for SLA policy files (sla-view) |
| `schemas/v1/model-registry.schema.json` | JSON Schema for the model registry (config/model-registry.yaml — role routing, tier floors, spend policy) |
| `schemas/v1/benchmark-target.schema.json` | JSON Schema for recall-benchmark target definitions |
| `schemas/v1/attack-mapping.schema.json` | JSON Schema for the finding-category→ATT&CK mapping table |
| `schemas/v1/adr-registry.schema.json` | JSON Schema for the architecture-decision-record registry |
| `schemas/v1/org-parameters.schema.json` | JSON Schema for org-wide parameter files |
| `schemas/v1/risk-rating-methodology.schema.json` | JSON Schema for the risk-rating methodology config |
| python3 -m traust.cli reporting validate | Validates report JSON against schema; supports `--strict` and batch validation |
| python3 -m traust.cli reporting lint | Deterministic threat-model gate — sections/columns/enums, coverage invariant, ID stability, provenance, evidence hygiene |
| python3 -m traust.migrations.repair_threat_model | Mechanical threat-model repair — row-fracture pipe escaping, enum synonym remaps; writes only when lint errors strictly decrease |
| python3 -m traust.cli reporting render | Renders validated JSON reports to Markdown |
| python3 -m traust.cli reporting sarif | Exports any report (incl. disposition-aware findings-current and cloud-config audits) to SARIF 2.1.0 for any SARIF consumer — a derived projection, dispositions become suppressions; `--results-root` batch sweep |
| harnessing/4-triage/triage/scripts/render_triage.py | Renders triage reports |
| python3 -m traust.cli.check_citations | Citation verification gate for findings |
| harnessing/4-triage/triage/scripts/lint_verdict_citations.py | Verdict citation linter |
| python3 -m traust.cli.build_symbol_index | Builds symbol index for triage acceleration |
| python3 -m traust.cli.query_index | Queries the symbol index |
| harnessing/4-triage/track-findings/scripts/baseline_claims.py | Baseline claim extraction |
| python3 -m traust.cli.emit_triage_ledger_events | Emits triage→ledger events from triage output |
| python3 -m traust.migrations.reemit_legacy_triage | Migrates legacy triage data to current format |
| python3 -m traust.cli.countersign | Countersign workflow support |
| python3 -m traust.cli.check_docs_consistency | Doc-drift detection for harness docs |
| python3 -m traust.cli.cluster_state_diff | P5 discovery sweep 1 — before/after security-state snapshots (RBAC, SCCs, webhooks, NetworkPolicies, Services/Routes) diffed into validation-discovery candidates for /triage |
| python3 -m traust.cli sweep benchmark | P7 validation-lane benchmark — vulnerable/safe-twin fixtures, confirm-recall + refute-precision + severity-accuracy floors, hybrid release-cut/monthly cadence (check-trigger + drift-watch) |
| python3 -m traust.cli.attest_target | P2 pre-flight target attestation for validation lanes — fail-closed environment gate (cluster fingerprint, CSV/pod readiness, version-in-range, URL reachability) emitting target-attestation.json |
| python3 -m traust.cli registry models | Model-registry loader/resolver — role→model resolution with floor enforcement, routing stamps, spend recording (docs/model-routing.md) |
| python3 -m traust.cli.checkpoint | Agent checkpoint support |
| python3 -m traust.cli.check_fix_propagation | Deterministic cross-repo fix-propagation check — has the original repo consumed the fixed module version (go.mod/vendor, lockfiles, shipped-image SBOMs)? Feeds verify-remediation's two-legged rule |
| python3 -m traust.cli impact analyze | CVE impact analysis across the portfolio graph — blast radius, L4 refinement, language-specific deep scan (GoAnalyzer: govulncheck + ELF, the strongest reachability tier; other ecosystems get manifest-level analyzers); `--ecosystem` seeds a non-Go blast radius, `--skip-scan` for graph-only, `--jobs N` for parallel workers |
| python3 -m traust.cli.route_regressions | Direct-ledger routing for follow-up-scan findings — transcribes verify-remediation regressions into the ledger as event-carried findings with campaign IDs (never the baseline — gate A15) (no triage precondition); idempotent |
| python3 -m traust.cli corpus precedent | Tiered FP-precedent index (human-countersigned > machine-refuted-sound) keyed by finding fingerprint — kills shared-component re-refutation; consumed by /triage and the Precision Gate |
| python3 -m traust.cli sweep | Class-generalization sweep loop: confirmed finding → candidate rule → corpus-wide sweep → triage-ready candidates |
| python3 -m traust.cli sweep mine | The /mine-ledger miner — confirmed-TP corpus, cluster coverage vs the opengrep pack, per-rule campaign precision |
| harnessing/mine-ledger/scripts/emit_rule_drafts.py | Regression-rule draft staging from resolved-at-fix-commit findings (pre/post calibration pairs) |
| python3 -m traust.cli sweep rule-lane | The weekly rule-mining lane runner — miner → sweep collect/draft → bounded draft staging → `lane-delta.{json,md}` vs the previous mine; exit 1 when the delta needs authoring attention |
| harnessing/census/scripts/check_repo_liveness.py | Census-owned repo-liveness sweep (active/archived/moved/missing, status_since ratcheting) |
| python3 -m traust.cli.check_skill_alignment | Pre-commit cross-skill contract gate (A-series rules) |
| python3 -m traust.cli.check_skill_security | Pre-commit security-posture gate (S-series rules incl. S9 repo-config isolation) |
| python3 -m traust.cli adapters crypto-audit | Unopinionated crypto data collector — source/image/cluster tiers emit `crypto-audit/v1` JSON |
| python3 -m traust.cli adapters crypto-probe | Source-level crypto provider census (imported by crypto_audit.py) |
| python3 -m traust.cli util elf | General-purpose ELF binary analyzer (linked libraries, byte scanning) |

## Versioning

The harness is versioned via the `VERSION` file using semantic versioning (`MAJOR.MINOR.PATCH`). At report time, the short git SHA is appended (e.g. `0.32.1-4dd9796`). See `AGENTS.md` for bump guidelines.

## Security and authorisation

All security testing performed by this harness is authorised. The `AGENTS.md` file establishes the following constraints:

- Only analyse repositories the user has explicitly authorised
- Analyse the exact branch or commit ref specified in the input data
- Implement scope validation before execution
- Maintain audit trails for all agent actions
- Findings are for defensive purposes only

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Portions are derivative works of third-party projects (the `triage`, `threat-model`, `patch`, and `vuln-scan` skills and python3 -m traust.cli.checkpoint derive from Anthropic's Apache-2.0-licensed defending-code-reference-harness; parts of `vuln-scan` are adapted from the MIT-licensed claude-code-security-review). See [`NOTICE`](NOTICE) for attributions and `LICENSES/` for the full third-party license texts.
