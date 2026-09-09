# Tooling and structure files

The schemas, packaged CLIs and key scripts that make up the harness's deterministic tooling.

The schemas below (from the installed `traust-contracts` package) are the complete set; the scripts listed are the key entry points — packaged CLIs live under `src/traust/`, and skill-specific tooling lives alongside each skill in its own `scripts/` — under a stage directory for workflow skills (`harnessing/4-triage/triage/scripts/`), at the `harnessing/` root for the rest.

| Component | Purpose |
|---|---|
| python3 -m traust.cli util safe-exec + `$TRAUST_CONFIG_HOME/safe-exec-profiles.yaml` | Enforced sandbox for target-derived commands (argv allowlists, env scrub, shell-free pipelines) — gate rule S10; [docs/safe-exec.md](safe-exec.md) |
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
| `traust-ledger/tests/fixtures/identity-recipe-vectors.json` | Regression fixtures for the finding-fingerprint recipe (canon_repo/canon_path/primary_cwe/fingerprint, implemented in `traust-ledger/traust_ledger/identity.py`), replayed by `traust-ledger/tests/test_identity_recipe_vectors.py`. **Fixtures, not a contract**: under decision D7 (2026-08-18) only the harness computes identity, so the cross-implementation golden-vector suite that used to live at contracts `vectors/v1/` was retired in contracts 0.5.0 along with the SDK's `go/v1/identity` port. They exist so the one remaining implementation cannot change by accident across an `algo_version` bump — see [docs/components.md](components.md#5-what-crosses-the-boundary). |
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
