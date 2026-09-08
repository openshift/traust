## v0.347.11 — 2026-09-08

### Fixed
- Link check across the five repos' Markdown (relative targets, internal
  links after export rewrite, 146 external URLs probed): two dead external
  links fixed (YARA's licence file is `COPYING`; the rustls manual moved to
  docs.rs) and two CHANGELOG-relative links given their `docs/` prefix.
  No internal-forge links remain in any doc.

## v0.347.10 — 2026-09-08

### Fixed
- `export_public_tree` converts GitLab web paths (`/-/blob/`, `/-/tree/`,
  `/-/commit(s)/`, `/-/tags/`, `/-/releases/`, `/-/merge_requests/`,
  `/-/issues/`) to their GitHub forms on every URL it rewrites to the public
  base. A rewritten link that kept the GitLab path 404ed on GitHub.

## v0.347.9 — 2026-09-08

### Changed
- AGENTS.md: the project-purpose paragraph and the security-testing context
  describe Traust for any deploying organisation (inventory from
  `locations.inputs`, targets the deployer owns or is authorised to assess)
  instead of one organisation's portfolio and clusters.

## v0.347.8 — 2026-09-08

### Changed
- README opening paragraph credits the origin: developed by Red Hat's Hybrid
  Platforms security team, published under Apache-2.0.

## v0.347.7 — 2026-09-08

### Changed
- README opening paragraph describes Traust for an adopter (what it assesses,
  what the repository holds) instead of one organisation's team and product
  lines; the License section says Apache License 2.0, matching `LICENSE`,
  instead of "internal use only".

## v0.347.6 — 2026-09-08

### Fixed — people and estate names out of the public tree (review by a colleague)
- Test fixtures and doc examples used real team members' account ids and one
  real name as the sample signer / probe user (`test_countersign.py`,
  `test_compliance_phase1.py`, `test_refutation_soundness.py`, the countersign
  CLI usage examples, a `soundness.py` comment). All are neutral placeholders
  now.
- `test_scan_internal_refs.py` tested the `jira-account-id` rule against four
  **real** account ids taken from the deleted assignee mapping. Replaced with
  synthetic ids of the same shape.
- `CODEOWNERS` named individual accounts; it names the
  `@openshift/traust-maintainers` team (adjust per fork). Same in the four
  sibling repos.
- README: the requirements list named an internal directory product; it now
  names the kind of service. A finding-id prefix example in
  generate-team-report and a calibration fixture filename in a
  compliance test no longer carry estate names.
- Three stale agent worktrees under `.claude/worktrees/` (untracked, but
  holding copies of estate config on disk) removed.

## v0.347.5 — 2026-09-08

### Changed
- `ruff format` applied to the one file the 0.347.4 lint pass left
  unformatted (`run_checkov.py`); `ruff check` and `ruff format --check` are
  both clean on the tree and on the exported tree.

## v0.347.4 — 2026-09-08

### Changed
- Made lint rules same with other projects and fixed the errors.

## v0.347.3 — 2026-09-08

### Changed
- Containerfile maintainer label is `Traust maintainers <traust@redhat.com>`,
  the project alias that also authors the public root commits (decision D2b).

## v0.347.2 — 2026-09-08

### Fixed
- `export_public_tree` reads per-component `<dir>/VERSION` files when a repo
  has no root `VERSION` (traust-sdk is versioned per language: `go/VERSION`).
  The dry-run had labelled the SDK export `v?`; it now reads
  `traust-sdk go 0.11.0 — public release`.

## v0.347.1 — 2026-09-08

### Changed
- **Crush is a supported runtime; its discovery layer is tracked.**
  `.crush/.gitignore` was `*`, so the layer only existed where someone had
  force-added it: two skill links (fixed in v0.347.0) and three command
  wrappers (`add-inputs`, `financial-tracking`, `inventory-repositories`)
  were missing from every clone. The ignore now covers only Crush's runtime
  state (`crush.db`, `logs/`); `skills/` and `commands/` are tracked; and
  alignment rule **A7** requires the `.crush/commands/<skill>.md` link too,
  tracked, alongside the other three wiring paths.

## v0.347.0 — 2026-09-08

### Added
- **`traust.migrations.export_public_tree` — the one-shot public export**
  (decisions D1/D2/D2a/D3/D6). From `$TRAUST_CONFIG_HOME/export.yaml`
  (template `config/export.example.yaml`): `git archive HEAD` per repo
  (tracked files only), strip the deployment's build plumbing, rewrite every
  private-forge URL to the public one in every text file (pins, lock, OCI
  labels, links), truncate the CHANGELOG with a provenance note, `git init`
  a fresh single-commit history, then run the scrub gate over the produced
  tree with **no** expected-internal allowance and write
  `export-report.{json,md}`. Never touches the source checkout, never
  pushes. First dry-run over all five repos: every block hit outside the
  ledger's Containerfile build shim disappears with the D1/D2 files.

### Fixed — found by the dry-run's adopter smoke test
- **Two skill links were never tracked.** `.crush/.gitignore` is `*`, so the
  `.crush/skills/{add-inputs,inventory-repositories}` links created on
  2026-09-07 existed on disk, passed the gate, and were absent from any clone.
  Force-added; alignment rule **A7** now also fails a wiring path that exists
  but is untracked.
- **Template vocabulary tripped its own rules.** With a config home installed
  from the templates, the active vocabulary is `internal-vocabulary.example.yaml`,
  whose placeholder patterns match their own text. The docs gate's estate leg
  skips that file, and `scan_internal_refs` skips vocabulary-derived rules on
  any `internal-vocabulary*.yaml` (universal rules still apply).

## v0.346.3 — 2026-09-08

### Changed
- `scan_internal_refs` `employee-uid` rule excludes language keywords
  (`next`, `make`, `new`, `get`, `find`, `lambda`, `await`, `yield`, `match`)
  after `owner`/`assignee`; it flagged `owner = next(...)` and
  `owner: make(...)` as hardcoded usernames (2026-09-08 review §7).

## v0.346.2 — 2026-09-08

### Changed
- Scrub: the docs gate's allowlist comment no longer names one organisation's
  registry repository, and five corpus-config test fixtures use
  `label: example-platform, business_unit: Example` instead of an estate
  business-unit label. Both were below the vocabulary's radar (2026-09-08
  review §7).

## v0.346.1 — 2026-09-08

### Changed
- Branding: README title and the two Containerfile `summary` /
  `io.k8s.display-name` labels say **Traust** instead of the pre-rename
  product name (the 2026-09-07 review's §5c, "safe to fix immediately").
  Remaining legacy naming — the `HarnessEngine` class, `HARNESS_*` variables
  — is not a publication blocker (decision 2026-09-08): it leaks nothing and
  breaks nothing, and is addressed as code is updated.

## v0.346.0 — 2026-09-08

### Removed
- **`validate_employee.py` leaves the harness.** The corporate-LDAP employee
  check (it read a directory attribute only one organisation's schema has)
  now lives in the Red Hat extension as the deployment's employee-directory
  command. With it go the `ldap3` dependency, the `admin validate-employee`
  passthrough, its tests, and every skill reference (track-findings tier-1
  author check, sla-view contact note).

### Changed
- **Employee-directory cross-check is the ledger's** (traust-ledger 0.21.0
  via traust-engine 0.12.3): `LEDGER_DIRECTORY_COMMAND` names a deployment
  command the SDK runs on every write path; `active` is stamped as
  `employee_status`, anything else refuses. countersign applies it once more
  up front (refusal before the queue is parsed); end-to-end smoke covers a
  terminated signer refused with nothing written and an active signer
  stamped.
- **compliance-check scope intake `--verify-identity`** verifies that the
  declarant is the ledger token holder (plus the directory cross-check).
  Until now it LDAP-looked-up the *typed* uid, which proved a name existed,
  not that the declarant held it.

## v0.345.1 — 2026-09-08

### Changed
- **countersign refuses self-minted (`identity_provider: local`) tokens
  unless `HARNESS_COUNTERSIGN_ALLOW_LOCAL=1`.** v0.345.0 accepted any token
  the SDK verifies, and a local token verifies against a key in the signer's
  own config dir — anyone with a shell could mint one for any name and record
  a human sign-off the two-person rule counts. Deployments with an OIDC
  provider leave the variable unset; solo/offline adopters opt in and their
  events already say `local`. Refusal happens before any write. End-to-end
  smoke covers refused-then-opted-in.

## v0.345.0 — 2026-09-08

### Changed
- **countersign records through the ledger SDK; the signer is the ledger
  identity token.** `apply` / `record` resolve the current token
  (`ledger auth login` for OIDC, `ledger auth local --identity <you>` for a
  local identity), verify it, and hand the human events to
  `LedgerService.submit_events`, whose handler overwrites `source.actor` with
  the token-verified actor, dedups, enforces the identity rule, finalizes and
  signs. Alias confirmations go through `patch_layer_file`. Until now the
  workbench ran its own LDAP check (`validate_employee.py`) and wrote the
  layer file with `store_layer` + `sign`, bypassing the SDK's identity path
  entirely — the OIDC-verified identity never reached a countersign event,
  and the check only worked against one organisation's directory
  (a vendor-specific directory attribute). `--identity` is now optional and must name the token
  holder; machine tokens cannot countersign.
- End-to-end smoke test (`tests/test_countersign_identity.py`, skipped
  without `cosign`): local identity token + generated keypair → `record`
  twice as two signers → both events carry the SDK-stamped actor
  (`identity_provider: local`, `identity_verified: true`), Merkle root and
  signature present, signature verifies against the public key, and
  `--identity` naming someone else is refused before any write.
- countersign and track-findings SKILLs describe the token path; the LDAP
  configuration table left the countersign SKILL.

### Remaining (not in this release)
- `validate_employee.py` still ships and is still called by
  `compliance_scope_intake.py` and the `admin` CLI group; it becomes the Red
  Hat `EmployeeDirectory` provider in the internal extension next.
- `store_layer` remains an unauthenticated raw write used by
  `build_cumulative` and nine migrations — tracked separately.

## v0.344.0 — 2026-09-07

### Added
- **Inventory descriptor (`traust.inventory`).** `<inputs>/inventory.yaml`
  declares what each inventory segment *is* — `groups` (default),
  `release-payload`, `catalog` or `services` — with an optional label,
  `release_label`, `payload_image`, `registries` and `org_teams`. The repo
  graph, the executive summary's segment priority and the IaC inventory's
  tenancy set now dispatch on the declared kind; until now three segment
  names (one organisation's product lines) were hardcoded in all three and
  every other segment fell through to the generic layout. Declaration order
  is the segment priority. A missing descriptor reads the tree exactly as
  `/add-inputs` writes it. Real-tree check: the graph built from the same
  inventory with and without the refactor is node-, edge- and label-identical.
- **`inventory-repositories` is upstream again, generic (manifest: `split`).**
  Release-payload (`oc adm release info`) and OLM bundle (`skopeo`/`podman`/
  ClusterServiceVersion) discovery keyed on the descriptor's segment kinds;
  registries, payload image and the org→team table come from the descriptor,
  never from the skill. Forge egress goes through the new
  `scripts/fetch_forge_owners.py` (`gh api` / `glab api`, URL-gated, token off
  argv) instead of raw `curl`. The deployment's service inventory, tracker
  (Jira) resolution, org-registry ownership source and mirror-registry image
  mappings live in the internal extension as `procedures/` the skill reads at
  two documented seams — no SKILL.md there, so one skill name resolves once.

### Changed
- `docs/setup.md` "Bring your own inventory" describes segment kinds instead
  of two product names; repo-graph and executive-summary SKILLs likewise.
- `/add-inputs` no longer routes repos into product segments by name and
  refuses to add ad-hoc rows to `release-payload`/`catalog` segments.
- Tree: 51 skills / 58 commands / 180 scripts.

### Fixed
- `harnessing/_lib/traust_paths.sh` resolves its interpreter as
  `$TRAUST_PYTHON`, else the harness venv beside the lib, else `python3` —
  `ensure_fork.sh` and every other `traust_load_*` caller failed with
  `ModuleNotFoundError: traust` when spawned outside an activated venv
  (five `test_p0_git_gates` cases were red on v0.343.1 for that reason).

## v0.343.1 — 2026-09-07

### Added
- **docs/setup.md "Bring your own inventory".** What `locations.inputs` must
  contain — the segment/group directory layout, the one required CSV column,
  the optional `owners.csv` — and the three ways to populate it (`/add-inputs`,
  an export from your own source of truth, or an inventory repository). The
  harness ships no inventory and no discovery; this is the contract an adopter
  meets instead.

## v0.343.0 — 2026-09-07

### Changed
- **`add-inputs` is upstream again, generic.** v0.340.0 moved it to the internal
  extension on the strength of a list rather than its profile; the skill takes
  a forge URL and writes inventory and owner rows from OWNERS files, which is
  generic. Its estate content was the inventory's name (now `locations.inputs`),
  a default clone URL on the internal forge (removed — the configured inventory
  is the default) and two tracker column names (kept as columns, left empty).
  It returns with an `allowed-tools` allowlist and the adversarial-content
  doctrine instead of the S1/S2 grandfather exemptions it used to carry.
  50 skills.

## v0.342.1 — 2026-09-07

### Fixed
- The repo-graph command wrapper still named one organisation's inventory repo.

## v0.342.0 — 2026-09-07

### Changed
- **The repository inventory has no fixed name anywhere.** The last mentions
  of one organisation's inventory repo are gone from code (the drift checker's
  graph-freshness and docs-map probes resolve `locations.inputs`, scoped to
  the workspace they are given; the doctor's sibling list; the docs-checker's
  sibling prefixes), from docs (AGENTS.md, PROCESS.md, README, setup.md and
  the skill docs say "the inputs inventory" / `<inputs>/…`), and from test
  fixtures (`inputs/`). AGENTS.md names sibling packages by repository, not
  by group path.
- **compliance-check's IaC-declaration adapters are the internal extension's.**
  `extract_app_interface_env.py` and `collect_iac_inventory.py` — the
  app-interface seam the partition manifest marks `split` — and their four
  tests moved to the internal extension repo. The skill describes the step
  generically; the runner, gate and everything else stay.

## v0.341.0 — 2026-09-07

### Added
- **`config/remediation.example.yaml`** — remediate-finding's private mirror
  organisation (`fork_org`) and naming prefix are the adopter's configuration.
  No shipped default for the org: the flow refuses until `remediation.yaml`
  (or `HARNESS_FORK_ORG`) names one — decision D5; relands what MR !101 set
  out to do. `finish_batch.sh` / `run_batch.sh` load both through the shared
  `traust_load_remediation`; `fork_map.py` resolves the owner lazily.
- **`config/campaign.example.yaml`** — `tracking_reference` and
  `display_name` for dashboards that cite an issue-tracker key. The validation
  and fuzz dashboard and the team-report template read it and omit the line
  when unset, instead of carrying one organisation's epic key.
- **`locations.inputs`** — the repository-inventory tree is a location, default
  `<workspace>/inputs`. `inputs_dir()` resolved a hardcoded sibling named after
  one organisation's repo until now; every dashboard, the graphs and the
  release-event feeder go through the key.

### Changed
- **Nineteen dashboard and roll-up skills are upstream** (census,
  corpus-intake, executive-summary-findings, findings-db, findings-trends,
  insecure-patterns, loc-dashboard, rbac-tenancy-rollup, sla-view,
  threat-register, traust-metrics, validation-fuzz-dashboard,
  refresh-dashboards, financial-tracking, attack-coverage, drift-watch,
  recall-benchmark, fleet-fix, generate-team-report). The partition manifest
  had them internal as "campaign dashboards"; they run on any adopter's
  corpus and their estate content was configuration. Residual estate names in
  them are gone: repo normalisation is forge-agnostic, the LoC dashboard
  labels GitLab-hosted repos generically, docs say "the inputs inventory".

## v0.340.1 — 2026-09-07

### Fixed
- v0.340.0 shipped with four red tests: three deploy-operator hardening
  assertions whose subject had moved (they now live in the internal extension
  repo beside the skill, like the validate-* ones before them) and one stale
  script path in PROCESS.md introduced by the move edit. Suite green.

## v0.340.0 — 2026-09-07

### Removed
- **Six Red Hat-integration skills move to the internal extension repo**
  (partition decision D4, per-skill review in the internal-refs assessment §F):
  `inventory-repositories`, `add-inputs`, `assign-findings-owners`,
  `reassign-findings-owners`, `file-security-defect`, `deploy-operator`. Each
  is an integration with one organisation's Jira, LDAP, Google Workspace,
  app-interface, product registry or validation sandboxes; nothing generic
  survives extraction, so they leave whole rather than being templated. Their
  wiring, exemptions and README rows go with them; docs that describe the
  pipeline now mark them "(internal extension)". 49 skills, 56 commands.
  The dashboard and roll-up skills the manifest had also labelled internal
  stay: they work on any adopter's corpus and are being made generic instead.

## v0.339.0 — 2026-09-07

### Changed
- **Zero campaign codenames in the tree** (outside this file). v0.338.0 left
  68 lines in internal-labelled skills on the theory that they leave at the
  partition split; the tree is what would be published today, so they are
  gone now. deploy-operator's five operator-facing variables are renamed —
  `VALIDATION_AWS_ACCOUNT`, `VALIDATION_REAL_CREDS`, `VALIDATION_GITHUB_TOKEN`,
  `VALIDATION_AZURE_SP_JSON`, `VALIDATION_GCP_SA_JSON` (were `GLASSWING_*` /
  `*_GLASSWING_*`) — and every AWS/Kubernetes name it creates or looks up
  (tags, shared bucket, IAM user/roles/policy, Route53 zone, OperatorGroup,
  CatalogSource, namespaces, spoke label, state dir) carries
  `$VALIDATION_RESOURCE_PREFIX` (default `traust`); a deployment whose sandbox
  already holds resources under another prefix sets it, and traust-internal's
  sweep defaults to that deployment's value. file-security-defect's Jira
  labels come from `defect_labels` / `legacy_defect_labels` in the deployment's
  `jira-sync.yaml` instead of the skill text. Ticket keys in code comments keep
  the phase name and drop the tracker key. Dashboards and metrics are titled
  Traust. Dummy credentials are `traust-dummy`-prefixed.

## v0.338.0 — 2026-09-07

### Changed
- **Campaign codenames scrubbed from everything that ships.** The 2026-09-07
  internal-refs review counted 198 codename hits across the publication
  candidates. Every one in an upstream- or split-labelled skill or in shared
  code is gone: rule-pack provenance strings and the fuzz target notes name
  the 2026-07 Java batch or "an engagement" rather than the customer;
  validate-findings' probe pods, SSRF marker and tools-image variable are
  `traust-probe-*`, `traust-ssrf-probe`, `VF_TOOLS_IMAGE`; the fuzz event
  emitter discovers `*-findings` trees instead of listing them; test fixtures
  use a neutral engagement; top-level branding (README, AGENTS.md,
  Containerfile maintainer, PROCESS.md) names no project; the track-findings
  MR-comment convention is `/traust <disposition> …`; deploy-operator's
  CatalogSource displayName/publisher and dummy endpoints are neutral. What
  remains is inside internal-labelled skills that leave at the partition
  split (27 hits) plus one env-var name deploy-operator's own test asserts on.
- **remediate-finding's naming prefix is configuration.** Index repos, the
  control repo, fix branches and commit subjects use `$REMEDIATION_PREFIX`
  (default `traust`); a deployment with artefacts already pushed under
  another prefix sets it for continuity. The mirror-org constant is still
  hardcoded — that is the `HARNESS_FORK_ORG` change from MR !101, tracked
  separately.
- **check_docs_consistency ships no estate marker list.** Its config-hygiene
  leg now compiles the block/review rules from `scan_internal_refs` (universal
  + the deployment vocabulary) and skips the estate leg when no vocabulary is
  configured, instead of carrying ten internal names in code (review §1).
- **Scrub gate hygiene.** Three dead `RULE_EXEMPT_PATHS` entries removed
  (review §8.1). The no-org-vocabulary test derives the names it checks from
  the deployment vocabulary's own alternation groups instead of listing them.

## v0.337.1 — 2026-09-07

### Added
- **Scrub gate blocks a person's data.** Two universal rules in
  `scan_internal_refs`: `personal-email` (an address at a consumer mailbox
  provider — gmail, yahoo, proton, icloud, …) and `jira-account-id` (the
  Atlassian `<digits>:<uuid>` shape, or a legacy 24-hex id on a line that
  names accountId/assignee). Both block. Measured against the reference table
  that shipped in the harness until v0.337.0: 2 and 6 hits respectively, where
  every gate had passed for two months. Zero hits in the current tree; the
  scanner's own positive-case fixtures are the one exempted path. 11 tests.

## v0.337.0 — 2026-09-07

### Removed
- **`sync-jira-backlog` leaves the harness for traust-internal.** The skill
  syncs one organisation's Jira project against that organisation's repos for
  that organisation's people — internal by construction, and labelled so by the
  partition manifest since plan 1.3 — yet it still shipped here with a
  reference table of eight people's corporate and personal email addresses,
  GitHub logins, and Jira accountIds. Both reference files
  (`references/assignee-mapping.md`, `references/exclusions.md`) are now one
  operational config file, `jira-sync.yaml` in `$TRAUST_CONFIG_HOME`, read
  like every other estate setting; the skill, its 13 scripts, its test, and
  the `SYNC_CLONE_ROOTS` clone-root override (which existed in
  `traust.context` only for this skill) moved with it. The parser's JSON output
  is byte-identical on all 13 keys, so nothing downstream changed. 55 skills,
  62 commands.

## v0.336.0 — 2026-09-07

### Added
- **A17 locations-note (alignment gate).** Any `harnessing/**/SKILL.md` that
  names `analysis-results/` or `progress-tracker/` must carry the paragraph
  saying those paths are the default workspace layout resolved through
  `locations.yaml` in `$TRAUST_CONFIG_HOME`. Measured 2026-09-07: 52 of 56
  skill docs wrote the trees literally while 61 scripts resolved them through
  the context layer and none read the old env vars — the code was
  configurable, the docs read as hardcoded. A reader outside this deployment
  cannot tell the difference, so the gate makes the distinction explicit and
  keeps the next skill honest. Five tests.

### Changed
- **All 52 skill docs carry the locations note** under their title
  (publish-time pass for the open-source split).
- **`cve_replay_monitor --workspace-root` states its assumption.** The flag
  is an escape hatch that assumes the default sibling layout; the help text
  now says so and points at `locations.yaml` for anything else. The two
  remaining literal defaults in the tree are documented, not silent:
  this one, and `fleet_sweep.build_worklist`'s workspace-relative argv
  default that only library callers (tests) exercise — the CLI always passes
  the configured root.

## v0.335.4 — 2026-09-07

### Changed
- **mine-ledger SKILL.md carries no campaign artifacts.** The partition
  manifest now labels the skill upstream (the miner is generic; what it
  mines is each adopter's own ledger), and a review of the skill found its
  code and example cards estate-free but its doc naming three internal
  planning documents under `progress-tracker/plans/` and one July
  confirmation run (`analysis-results/scan-testing/sxs-2026-07/`) as an
  input. Those five lines now describe the inputs and the backlog
  generically. Workspace-relative example paths (`analysis-results/…`,
  `progress-tracker/…`) stay: they are the documented defaults that
  `locations.yaml` overrides, not estate identifiers.

## v0.335.3 — 2026-09-07

### Fixed
- **Drift's sibling-README export audit imports the checkout, not the
  installed pin.** It audited the ledger README against whatever
  `traust_ledger` this venv had installed — 0.20.0 via the engine pin — while
  the checkout beside the README was 0.20.2, so a README fixed at the source
  kept reporting 36 (then 15) "absent" exports that were the old version's
  surface. The audit now runs in a subprocess with the sibling's `src/` first
  on the path, refuses (reports, never guesses) when the package resolves to
  anything but the checkout, and returns `fresh` for a README that matches
  its own code. Regression test: an older copy of the package is importable
  in-process and must not be what gets audited.

## v0.335.2 — 2026-09-07

### Fixed
- **Stale `scripts/` paths from the 2026-08-13 package restructure, swept.**
  A workspace-wide check after the project renames found no rename residue in
  this tree, but ~70 references still pointed at `scripts/*.py` files that
  moved into the `traust.cli`, `traust.ops`, and `traust.migrations` packages
  or into the engine. Fixed by consequence: **CODEOWNERS** — seven patterns
  named nonexistent files, so the alignment, security, docs, license, and
  drift gates and countersign had silently lost their owner-approval
  requirement; they now name `src/traust/cli/…`, and the sandbox row points
  at its new home in traust-engine (whose own CODEOWNERS now lists it).
  **Operator-facing messages** — ~20 runtime strings told users to run
  `python3 scripts/fetch_feeds.py`, `scripts/build_findings_db.py`,
  `traust/scripts/countersign.py` and similar; they now name the `traust`
  subcommands (`traust feeds fetch`, `traust corpus findings-db`,
  `traust admin countersign`, …). **Artifact metadata** — the org-index and
  crown-jewel builders stamped `"generator": "scripts/…"`; now the module
  path. **Self-references** — the content-license guard's own-file exemption
  and the security gate's fixture marker named their pre-move paths.
  **Docstrings and comments** in skill scripts and ~30 test modules, NOTICE,
  and docs/requirements.md (the browser-validation Playwright install line
  pointed at a requirements file that never moved with the skill).
  Test-fixture strings that intentionally name nonexistent scripts are
  untouched; the cross-repo `gen_targets.py` allowed-tools grant and its A1
  exemption are intentional and stay.

## v0.335.1 — 2026-09-07

### Fixed
- **Drift's sibling-README check resolves the ledger's module surface from the
  checkout, not a hardcoded list.** It compared README-named `traust_ledger.*`
  modules against a fixed `["identity", "events", "writer", "integrity"]`, so
  after the ledger's restructure into `api/`, `client`, `config`, `handlers`
  every correct README mention was reported as "not a module" while the four
  accepted names no longer existed at the top level. Modules now resolve by
  walking the dotted path under `src/<pkg>/` (packages need `__init__.py`,
  `_`-prefixed components are private and never resolve). The exported-names
  audit is scoped to the modules the README documents, a README-named module
  that fails to import is reported only when the missing piece is inside the
  package (a missing third-party extra is a property of the venv, not the
  README), and a sibling without a `src/<pkg>/` tree reports `unavailable`.
  `check_sibling_readmes` takes an optional `siblings` mapping for tests.
  Eight regression tests in `tests/test_check_drift.py`.

## v0.335.0 — 2026-09-06

### Fixed
- Path corrections and further scrubbing for OSS move. 
- Single point of entry to harness-engine, app side (this harness) must manage
loading the config context and passing it where needed.
- Config loader added so harness leverages a user config for all paths
and other config related items.
- Every nook and cranny of this was inspected to remove the wild west
path loading which was absolutely terrible design, may it please thee
to see that your code is cleaner.

## v0.334.13 — 2026-09-06

### Fixed
- **Dependency-watch fleet sweep routes findings through the CLI module.** The
  deep-sweep `route_argv` invoked `scripts/route_impact_findings.py`, a path that
  has not existed since the 2026-08-13 package restructure, so deep sweeps would
  have failed at the routing step. It now runs
  `python3 -m traust.cli.route_impact_findings`.

## v0.334.12 — 2026-09-06

### Fixed
- **Local checkout directory renamed to `traust/`** to match the GitLab project
  path. Code that located the harness or ledger checkout by directory name now
  tries the new name first and falls back to the old one: the metrics collector
  (`ws/traust`), the drift check's sibling-README probe (`ws/traust-ledger`),
  and the engine's rule-lane draft emitter (engine `v0.11.2`). Workspace-relative
  invocations in the dependency-watch fleet sweep and the browser-validation
  skill's clone path say `traust/`. Python module names are unchanged.

## v0.334.11 — 2026-09-06

### Changed
- **Sibling dependency URLs follow the GitLab project renames.** The five
  `hybrid-platforms-sec` projects were renamed (`traust` → `traust`,
  `traust-engine` → `traust-engine`, `traust-ledger` → `traust-ledger`,
  `ai-security-sdk` → `traust-sdk`, `traust-contracts` → `traust-contracts`).
  `pyproject.toml` pins `traust-contracts` from `traust-contracts.git` (same
  `v1.0.0`) and `traust-engine` from `traust-engine.git` at `v0.11.1`, the first
  engine release whose transitive pins use the renamed paths. Konflux `.tekton`
  repo annotations point at `hybrid-platforms-sec/traust`. Python package and
  module names are unchanged.

## v0.334.10 — 2026-09-04

### Fixed
- **docs/artifacts.md** consumer column matches declared inputs: `/countersign`
  reads the ledger, not triage.json; `/sla-view` reads findings.db;
  `/validation-fuzz-dashboard` and `/attack-coverage` dropped from rows whose
  artifacts they do not declare. Threat-model lint named by its module
  (`traust_engine.reporting.lint`); the stale `lint_threat_model.py` name
  fixed in the threat-model skill, the threat-register builder and the
  repair migration too. "Where artifacts land" replaced by "What kind of file
  is it" — classification rules only, locations deferred to storage.md; the
  alignment-rule citation removed from the prose.

## v0.334.9 — 2026-09-04

### Fixed
- SARIF is described as what it is — the standard interchange format, imported
  from any scanner into `/triage` and exported from any report to the adopter's
  own dashboard — in architecture.md (section renamed "SARIF interchange"),
  artifacts.md, report-structure.md, README and sarif.md. Vendor-dashboard
  framing (GitHub Code Scanning, GitLab SAST, an internal GitLab host) removed;
  the GitLab-format exporter under migrations/ is mentioned once, in sarif.md,
  as an example of a non-SARIF projection.

## v0.334.8 — 2026-09-04

### Changed
- **docs/setup.md** restructured in install order (install_traust →
  prerequisites → workspace + uv sync → toolchain → storage variables → env →
  tests → validate/render → contributor gates), 416 → 274 lines. Toolchain
  documented once; the per-tool table is gone (requirements.md + the manifest
  are the sources); profiles are the manifest's `consumers`; `toolchain setup`
  documented; incident narratives, bucket/runner/image-tag names, the plan
  link, the stale pre-scan script names, the `aws` row and the test count
  removed. CI runner/PyYAML notes moved to traust-internal/docs/ci-pipeline.md.
- check-licensing SKILL.md points new-tool install notes at the manifest and
  requirements.md instead of the removed setup.md table.
- README row for setup.md matches its title.

## v0.334.7 — 2026-09-04

### Fixed
- **docs/components.md**: the harness pins two direct dependencies
  (traust-engine, traust-contracts); traust-ledger is traust-engine's
  dependency, reached through `traust_engine.ledger`. Stale "Current pins"
  table removed (pins live only in pyproject.toml; commands to read them kept).
  traust-ledger / traust-engine / SDK ownership cells updated to the current
  package layouts; identity recipe path is `ledger_core/_internal/identity.py`,
  contract `docs/finding-identity.md`. Estate names (inputs repo, internal
  consumer) and decision/date/incident history removed.
- setup.md "three sibling packages" corrected; disposition-ledger.md identity
  pointers corrected.

## v0.334.6 — 2026-09-04

### Changed
- **docs/architecture.md** is architecture only: skill anatomy shows the
  two-level tree (stage dirs + root); delivery column, security-posture
  paragraph and adapter redaction count lose estate names, dates, incident
  labels and stale numbers; the 22-row Scripts table and the Modules table
  are replaced by a "Where the code lives" section pointing at the
  placement rule, module docstrings, skills.md and components.md.
- triage SKILL.md no longer cites architecture.md for `--resume` (the page
  never described it).

## v0.334.5 — 2026-09-04

### Changed
- **docs/validation-process.md** cut to what no other page owns: mission,
  the gate stack (now the single gate list, with quarantine flags and the
  `*_SINCE` grandfathering rule), artifact flow, severity validation, hard
  rules. Evidence rules, countersign interaction, fuzzing, credential
  liveness and the benchmark are one-line pointers to disposition-ledger
  §5/§6 and the create-fuzzing / validate-findings skills. "Planned next",
  the roadmap link, P-numbers, decision dates, version stamps and
  "LDAP-verified" removed; benchmark command corrected to
  `python3 -m traust.cli sweep benchmark check-trigger`.
- **docs/error-model.md §3** points at validation-process.md for the gate
  stack instead of restating it.

## v0.334.4 — 2026-09-04

### Fixed
- Test suite no longer depends on a `config/corpus-config.yaml` that the harness
  stopped shipping: `tests/conftest.py` points `TRAUST_CONFIG_HOME` at
  `tests/fixtures/config/` (a copy of the corpus-config template) when the
  environment carries no operational config, and sets
  `HARNESS_TEST_FIXTURE_CONFIG=1` so live smokes (census, install_traust doctor)
  skip under the fixture. Fixes 18 failures in test_build_census,
  test_build_repo_graph, test_corpus_intake and test_cve_replay_monitor.

## v0.334.3 — 2026-09-04

### Changed
- **docs/triage-ledger-integration.md removed**; its unique content (verdict →
  event mapping, event shape, edge cases, consumer boundaries, emitter
  command) is now `docs/disposition-ledger.md` §6b. The FP-tier, refuted
  register, λ and assurance-view sections it duplicated are single-sourced in
  disposition-ledger §6–§8.
- disposition-ledger.md: auto-accept tier states the actual predicate (≥2
  concurring FP votes, no dissent); λ table replaced by a pointer to the
  weights file plus the tenancy-profile derivation and the correct
  `--tenancy-profile` flag; "LDAP-verified" → "identity-verified" (the schema
  marks `ldap_verified` legacy); version/date/self-audit residue dropped.
- error-model.md §2 links the auto-accept bar instead of restating it.

### Fixed
- architecture.md diagram and validation-process.md no longer name
  `validate-operator-live` / `validate-core-ocp`, which are not in the tree.
- Inbound links (README, PROCESS.md, architecture.md, error-model.md, triage
  SKILL, emitter docstring, hardening-weights templates) retargeted.

## v0.334.2 — 2026-09-04

### Fixed
- routers.md and setup.md no longer claim a default location for
  `FEEDS_CACHE_DIR`; the variable must be set.

## v0.334.1 — 2026-09-04

### Fixed
- **docs/storage.md**: describes the two data repositories by role (findings
  store, metrics tree) with `analysis-results`/`progress-tracker` stated as the
  code's default names; corrects `FEEDS_CACHE_DIR`, which has no engine default
  (the same false default is removed from continuous-operations.md and
  routers.md); states the `WORKSPACE` fallback chain and the no-guessing rule.

## v0.334.0 — 2026-09-04

### Added
- **`docs/skills.md` is generated** by
  `python3 -m traust.cli.build_skills_reference` from the skill
  tree: one section per skill with its frontmatter description verbatim, stage,
  tier, slash command(s) (including the phased-audit wrappers the skill names
  as its own), and links to the SKILL.md and its Integrations section. The
  docs gate fails when the committed copy differs from a fresh render; A13 now
  asks for a regeneration (and matches stage-nested skills, which it missed).
  The 1,000-line hand-written narrative, its estate references and dated notes
  are gone with it.

### Changed
- README skill table no longer lists the two validation skills that live in the
  internal extension repository.

## v0.333.33 — 2026-09-04

### Changed
- **signing.md and signing-workflow.md merged into one `docs/signing.md`.** States
  the format-4 payload, the write-path contract (stamp then sign; a moved root
  drops a stale signature loudly), the three outcomes, key placement, the
  `LAAS_SIGNING_*` variables traust-ledger reads plus the validator's
  `HARNESS_SIGNING_VERIFY_PUBKEY`, the `ledger sign`/`verify-signature`/`verify`
  CLI (the old `ops.sign_merkle_root` module no longer exists), cosign v3
  behaviour, and rotation. Both pages had said nothing was signed; every layer
  is. Identity-verification configuration moved to the countersign skill;
  operational history (key location, backfill, port notes) moved to
  `traust-internal/docs/ledger-signing-operations.md`; OIDC provider recipes
  defer to traust-ledger's docs. Eight inbound references retargeted; the
  format-3 re-sign migration's dead doc pointer fixed.

## v0.333.32 — 2026-09-04

### Changed
- **`docs/sarif-ci.md` → `docs/sarif.md`**, now a reference for the SARIF emitter
  and importer: input/output, the field-by-field mapping in both directions,
  suppressions and fingerprints, the degraded-run signal, the cloud-config arm,
  the sweep, and how imported results become triage claims. The CI recipes
  (GitHub upload workflow, GitLab `sast` artifact) moved to
  `traust-internal/docs/sarif-ci-recipes.md`; plan references removed.

## v0.333.31 — 2026-09-04

### Changed
- **getting-started.md**: `install_traust` is step 2 (the walkthrough previously
  reached the first audit without the operational config it fails closed on);
  Python floor 3.11; contributor hooks/tests replaced by `install_traust --doctor`;
  campaign wording removed.
- **setup.md** retitled "Setup reference"; Red Hat procedures (VPN CA bundle for
  the product registry, LDAP employee check) moved to
  `traust-internal/docs/workstation-setup.md`; SCI/plan references, provisioning
  CLIs and the inputs-repo name generalised; govulncheck install points at the
  pinned toolchain instead of `@latest`.

## v0.333.30 — 2026-09-04

### Changed
- **safe-exec.md owns the execution side of untrusted-target handling.** New
  "Repo-config isolation for headless agents" section states the S9 rule as a
  launch contract, making AGENTS.md's "full contract" pointer true; doctrine
  rule 4 keeps the principle and points here for mechanics. Plan origin,
  external-project attribution, decision tags, date and the incorrect test
  count removed from safe-exec.md.

## v0.333.29 — 2026-09-04

### Fixed
- README: routers.md row says seven router kinds (feed routing was missing).
  routers.md §4 drops the internal "Phase-5" reference.

## v0.333.28 — 2026-09-04

### Fixed
- **docs/risk-rating-methodology.md**: the corpus-share measurement, the
  retirement date and the deployment ledger path are removed; the retired-series
  paragraph now states what the engine and dashboard actually do (legacy
  columns still rendered, no longer the headline). The methodology JSON's
  `schema` pointer names the contracts package instead of a path that no
  longer exists.

## v0.333.27 — 2026-09-04

### Fixed
- **docs/requirements.md**: Python floor is 3.11 (was stated as 3.10); the
  operational-config requirement (`TRAUST_CONFIG_HOME`, `install_traust`) is
  now in the baseline table; the per-skill tool mapping is attributed to
  external-dependencies.md. Estate content removed: provisioning CLIs and the
  two traust-internal validation skills, named internal systems, and the
  "Campaign mode" section (moved to `traust-internal/docs/onboarding.md`).
  Access tiers reworded generically; a ledger-signing capability row added.

## v0.333.26 — 2026-09-04

### Fixed
- **docs/report-structure.md re-aligned with the schema and the audit skills.**
  `category` is the shared kebab-case vocabulary (not free-form names);
  `origin` no longer lists the retired `fuzz-harnesses` value; eight schema
  finding fields (`dependency`, `disposition`, `effective_severity`, `passes`,
  `isolation_boundary`, `isolation_dimensions`, `pqc_classification`,
  `remediation_effort`), `disposition_summary` and
  `additional.contracts_version` are documented; `deterministic_steps` keys
  are listed per profile as the skills record them. Decision history, version
  stamps, plan references and a vendor-registry example are removed.

## v0.333.25 — 2026-09-04

### Changed
- **docs/reachability.md is the mechanism reference only.** The dated
  correction section, coverage counts, plan pointers and dated validation
  results moved to
  `progress-tracker/gap-assessments/reachability-measurements-2026-08-11.md`.
  Engines table corrected: no Java Joern tier runs (the adapter keeps the
  frontend; the pipeline invokes only C/C++); the symbol-usage scan and the
  Java entry-point expansion are listed as what actually runs; the taint
  enumerator is an unwired ops tool. `affected` via Joern is C/C++ only.
  "Validation records" now names where corpora live, not results.

## v0.333.24 — 2026-09-04

### Changed
- **`docs/public-skill-assessment.md`** (superseded snapshot, 2026-07-12) moved to
  `progress-tracker/gap-assessments/public-skill-assessment-2026-07-12.md`;
  README row and the two gate exclusion entries removed.

## v0.333.23 — 2026-09-04

### Changed
- **`docs/ops-tools.md`** (the C8 script-disposition triage record) moved to
  `progress-tracker/gap-assessments/ops-script-disposition-c8-2026-08-13.md`. README
  row removed.

## v0.333.22 — 2026-09-04

### Changed
- **`docs/onboarding.md` moved to `traust-internal/docs/`.** Onboarding
  engagements is a deployment procedure; the six references now name the
  skills each step uses instead.

## v0.333.21 — 2026-09-04

### Changed
- **docs/model-routing.md is the routing contract only.** The spend-tracking
  procedure (declared vs transcript actuals, collection chain, dashboard,
  measured figures, dated correction) moved to
  `traust-internal/docs/spend-tracking.md`. The contract keeps the one rule,
  roles and floors, enforcement layers, escalation stamping, the
  spend-declaration command and its two properties, the batch flag, and the
  add-a-model procedure — with plan references, dates and estate wording removed.

## v0.333.20 — 2026-09-04

### Changed
- **`docs/metrics-inventory.md` moved to `traust-internal/docs/`.** It inventories
  the campaign's own metrics and dashboards, which are not part of the initial
  open-source scope. README row removed.

## v0.333.19 — 2026-09-04

### Changed
- **docs/language-support.md updated to current support.** Java has no
  call-graph reachability tier (symbol-usage only); the Joern call-site tier is
  C/C++ and promotion-only; per-language rows for the harness-authored rule
  pack, impact analyzers (Go, npm, PyPI, Maven, Cargo, RubyGems, NuGet, C,
  surfaces), fuzz lanes, symbol index, tree-sitter symbols, PQC capability
  notes, route-guard and config enumerators reflect the tree. Version banner,
  measured counts, corpus paths and plan references removed; a Limitations
  section replaces the dated gap list.

## v0.333.18 — 2026-09-04

### Changed
- **`docs/joern-reachability-finding.md`** (a dated finding by its own
  description) moved to
  `progress-tracker/gap-assessments/joern-reachability-finding-2026-08-14.md`.
  Its standing conclusion — interface dispatch makes Joern promotion-only for
  Java, and the four questions to answer before re-adopting it — now lives in
  reachability.md; language-support.md points there.

## v0.333.17 — 2026-09-04

### Changed
- **`docs/findings-lifecycle.md` retired** to
  `progress-tracker/plans/findings-lifecycle-design-2026-07-11.md` as a dated
  design record; its corrected lifecycle diagram now opens `docs/artifacts.md`
  and its thirteen inbound references point at the document that owns each
  topic.
- **`docs/findings-routing.md`**: the "Outstanding" burn-down list moved to the
  baseline-immutability plan; the dated incident count, plan-status column and
  decision dates are removed. The mechanism reference is unchanged.

## v0.333.16 — 2026-09-04

### Changed
- **docs/external-dependencies.md rewritten as an inventory.** Rows for tools the
  harness does not invoke (rosa, bonfire, openshift-install — cluster
  provisioning is the deployment's concern) and the three Semgrep registry rows
  are removed; the rule-pack rows state the actual posture (harness-authored
  default pack, MIT contributor supplement, `--config auto` refused). Dates,
  version numbers, calibration figures and estate specifics are gone. The
  Commercialization assessment moved to
  `progress-tracker/gap-assessments/commercialization-assessment-2026-07-16.md`;
  the Maintenance section moved to `traust-internal/docs/dependency-maintenance.md`.
  The content-guard rules are stated in the frameworks section, which the guard
  and `/check-licensing` now cite.

## v0.333.15 — 2026-09-04

### Changed
- **docs/error-model.md sanitised.** Measured percentages and counts, dates,
  version numbers, plan/phase tags, progress-tracker paths, a real username in
  a quoted transcript, and estate terms (LDAP, VPN, campaign) are removed or
  generalised; the doctrine, gates, predicates and state names are unchanged.
  Rates are stated to live in the deployment's error-analysis record.

## v0.333.14 — 2026-09-04

### Changed
- **`docs/doc-variance.md` moved to `traust-internal/docs/`.** The lane compares
  one vendor's published product documentation against its code; it is
  estate-specific and not for general adopters. README row removed.

## v0.333.13 — 2026-09-04

### Added
- **`docs/storage.md`** — one table of where each kind of data lives (ledgers,
  results, roll-ups, projections, operational config) and the variable that
  places it; replaces the general-doc role the moved migration plan had.

## v0.333.12 — 2026-09-04

### Changed
- **`docs/report-storage.md` moved to
  `progress-tracker/plans/report-storage-migration-plan.md`.** It is a
  deployment migration plan and handoff, not general documentation; the
  README, architecture.md and disposition-ledger.md no longer reference it.

## v0.333.11 — 2026-09-04

### Changed
- **disposition-ledger.md: the "which files can be relocated" table is removed.**
  Storage location is a deployment matter documented in report-storage.md;
  the ledger design does not depend on it.

## v0.333.10 — 2026-09-04

### Changed
- **`docs/outputs.md` → `docs/artifacts.md`.** The page now does one job: map
  every scan/assessment artifact to its schema, producer, consumers, and
  destination, plus the one-way projections. Field-by-field structure tables
  (duplicating report-structure.md and the schemas), ledger rules (duplicating
  disposition-ledger.md), the CVE-replay monitor section (in
  continuous-operations.md), estate specifics, and history counts are gone.
  Seven inbound references retargeted.

## v0.333.9 — 2026-09-04

### Fixed
- **docs/disposition-ledger.md brought to current state.** The §10c failure-mode
  table still called `unconfigured` "the current state everywhere" and §10b
  described signature format 2; every layer in the corpus is keypair-signed
  at format 4. Both sections now describe formats 1–4 and what each binds
  (`audit_report_sha256` at 3, `artifact_digests` at 4). The §3 relocation
  table reflects that the content-hash half of the audit-report move has
  shipped and the object-key half has not, lists the full current metadata
  key set, and drops stale corpus counts and line-number references.

## v0.333.8 — 2026-09-04

### Changed
- **`docs/deterministic-inferential-mix.md`** states the standing principle for
  mixing deterministic and inferential tooling (CPU for enumeration and
  fact-retrieval, inference for judgment and novelty; deterministic tools
  route, gate, tag, or index — never conclude). The dated
  `deterministic-tooling-assessment.md` moved to
  `progress-tracker/gap-assessments/deterministic-tooling-assessment-2026-07-10.md`;
  every in-repo reference now points at the new document.

## v0.333.7 — 2026-09-04

### Changed
- **docs/routers.md** generalised the same way: plan references, the dated
  owner decision, the incident count and date, and estate specifics (CI
  OWNERS source, LDAP, Drive, VPN, named orchestrators) removed or made
  generic. Section numbering unchanged (`fetch_feeds.py` cites §7).

## v0.333.6 — 2026-09-04

### Changed
- **docs/continuous-operations.md describes how continuous operations work,
  not one deployment's history.** Dollar figures, measured medians, ship
  dates, version numbers, ticket and plan references, owner-decision notes,
  and estate specifics (forge hosts, network gating, scheduler and identity
  providers, product inventory paths) are removed or generalised. Section
  headings and every command are unchanged, so inbound references and the
  CLI-example gate still hold. Per-deployment numbers belong in the
  deployment's cadence plan and cost report.

## v0.333.5 — 2026-09-04

### Changed
- `docs/best-practice-assessment.md` (dated 2026-07-13 gap assessment) moved to
  `progress-tracker/gap-assessments/best-practice-assessment-2026-07-13.md`
  with the other assessments; README row and gate exclusions removed.

## v0.333.4 — 2026-09-04

### Changed
- Doctrine document: enforcement mechanics moved out; a one-line compliance
  pointer to the checker and the canary benchmark remains.

## v0.333.3 — 2026-09-04

### Changed
- **docs/adversarial-content-doctrine.md reads as a standing doctrine.** Audit
  and remediation-plan references, burndown language and the "wiring status"
  section are gone; the four rules, how skills apply them, and how S2/S9,
  the canary benchmark and `screen_injection.py` enforce them are stated as
  present-tense fact.

## v0.333.2 — 2026-09-04

### Changed
- **`install_traust` also copies `model-registry.yaml` into `TRAUST_CONFIG_HOME`**
  (never overwriting; `--force` refreshes). A deployment is now complete in
  one directory even where only traust-engine is installed — its model
  router and spend code could not find the shipped copy without the harness
  package. `--doctor` reports whether the deployment copy is present, parses,
  and whether it differs from the shipped one.

## v0.333.1 — 2026-09-04

### Fixed
- **JSON templates carry an explicit `$template` marker.** YAML templates
  announce themselves with a `# TEMPLATE` header that JSON cannot hold, so
  `install_traust --doctor` could not tell an unedited
  `hardening-risk-weights.json` from a reviewed one. The template now has a
  top-level `$template` key (ignored by the loader) that the adopter deletes
  after review; the doctor warns while it is present.

## v0.333.0 — 2026-09-04

### Added
- **`scripts/install_traust` — the starting point.** Chooses `TRAUST_CONFIG_HOME`
  (default `~/.traust/config`), copies every `config/*.example.*` template in
  under its real name without overwriting, records the variable in the shell
  profile, and offers to run `scripts/install-toolchain.sh`. `--doctor`
  checks the variable, directory, each required file (present, parses,
  template banner gone, signing key valid), that the resolver reads from
  that directory, and the toolchain. Non-interactive flags for CI.

### Changed
- **`TRAUST_CONFIG_HOME` replaces `HARNESS_CONFIG_DIR`** everywhere (code,
  Containerfiles, docs). The `.harness-config` sibling-marker discovery is
  gone; one variable is the only mechanism. traust-engine pin → v0.11.0,
  which ships no config files at all (its `model-registry.yaml` copy is
  removed; the engine reads this repo's, unless `$TRAUST_CONFIG_HOME` holds
  an override).

## v0.332.0 — 2026-09-03

### Changed
- **Deployment configuration moved out of `config/`.** Nine estate-specific
  files — `corpus-config.yaml`, `product-definitions-map.yaml`,
  `budget-policy.yaml`, `rpm-distgit-watch.yaml`, `rule-pack-allowlist.yaml`,
  `safe-exec-profiles.yaml`, `hardening-risk-weights.json`,
  `internal-vocabulary.yaml`, `ledger-signing-key.pub` — now live in the
  deployment config directory (`traust-internal/config/` for this estate,
  marked by `.harness-config`). `config/` ships only `external-tools.yaml`,
  `feeds.yaml`, `model-registry.yaml` and a `*.example.*` template per
  deployment file (Lightwell and other estate references scrubbed from
  every template and from the model-registry comment).
- **`config_path(name)` is the only way to read a deployment file.**
  Re-exported from `traust.paths`; resolves `$HARNESS_CONFIG_DIR`,
  then the marked workspace sibling, then the bundled `config/`, and raises
  `DeploymentConfigMissing` rather than running on a template. Ten call
  sites rewired (rescan worklist, drain tranche, corpus intake, CVE
  provenance, triage-ledger emitter, internal-refs scanner, format-3
  re-sign migration, drift signature check, release-events feeder, docs gate).
- **Docs gate: `config/` hygiene check.** Fails when `config/` holds anything
  but the three shipped files, templates and README, or when any of them
  carries an estate marker. `traust-internal/` added to the sibling-path
  prefixes.
- **Containerfiles** set `HARNESS_CONFIG_DIR=/harness/deploy-config`; mount
  the deployment directory there. `traust-engine` pin → v0.10.0, which
  drops its own bundled copies of the same five files.

### Fixed (v0.331.14)
- **Toolchain installer no longer uses aqua.** `config/aqua.yaml` removed;
  `scripts/install-toolchain.sh` downloads each pinned binary from its
  upstream GitHub release (checksum-verified where upstream publishes one).

## v0.331.7 — 2026-09-01

### Fixed
- **SDK boundary enforcement for test suite.** All `traust_ledger._internal`
  imports removed from tests. Stamping fixtures now go through
  `LedgerClient.sign()` instead of reimplementing Merkle internals.
  Deleted `_test_helpers.py` and `traust_ledger.testing` references.
- **Stale `LedgerService` mocks.** `test_countersign` mock updated for
  `store_layer()` (was wiring the deleted `_client._backend.store` path).
  `test_route_regressions` mock rewritten with proper `ensure_layer_file`,
  `patch_layer_file`, and `submit_events` side effects matching the real
  service API — including `audit_report_sha256` stamping on `report_path`.

### Identified (not fixed)
- `test_route_impact_findings` mock fabricates `claim_hash` pinning that
  production code never performs. Needs design decision: either the router
  should pin claims, or audit findings should be ingested as ledger events
  (making `claim_hashes` redundant — the Merkle tree would protect them).

## v0.331.6 — 2026-08-31

### Added
- **`emit_verification_ledger_events` CLI emitter.** Maps verification
  report verdicts to `disposition.resolution` events (or `validity` for
  `false_positive`), including `cross_repo.propagation == pending` →
  `fix_in_progress` override. Closes the verification→resolution
  emission gap — the ledger now tracks the full finding lifecycle.
- Tests for the new emitter (23 cases covering `map_disposition`,
  `build_events`, and `resolve_audit_path`).

### Changed
- **verify-remediation skill**: updated Phase 7b delivery and sweep
  Step 2 to use the emitter; added `route_regressions` to allowed-tools
  (pre-existing confinement gap from P1-W4).
- **track-findings skill**: added `emit_verification_ledger_events` to
  allowed-tools and mapping table; updated machine-reports section.

## v0.331.4 — 2026-08-31

### Fixed
- **traust-engine pin 0.9.3 → 0.9.4** — SARIF exports no longer stamp an
  internal host into every artifact. `informationUri` was hardcoded to the
  internal GitLab URL and written to the driver block of every exported file,
  so it travelled with the artifact to GitHub Code Scanning and downstream
  viewers. It now reads `HARNESS_SARIF_TOOL_URI` and is omitted when unset.
  The same release drops `XWING-611` from four Python opengrep rules'
  `metadata.references`, which opengrep emitted into every finding those rules
  fired.

## v0.331.0 — 2026-08-27

### Changed
- **Zero direct `traust-ledger` dependency.** All ledger access routes through
  `traust-engine`'s `LedgerService` gateway. CLI writers, migrations, and
  ops scripts rewritten to use the service layer.
- traust-engine pin **0.8.1 → 0.9.0** — brings `LedgerService` gateway
  with strict identity verification and dedup tracking fix.
- Fix dedup count tracking in `append_to_layer` (`is not None` vs truthiness).

### Removed
- `ops/sign_merkle_root.py` — operators use `ledger sign` / `ledger
  verify-signature` CLI instead.
- `test_e2e_merkle_pipeline.py` — moved to `traust-ledger/tests/` (tests
  traust-ledger internals).

### Added
- `LedgerService` mocks in unit tests (countersign, emit_validation,
  route_impact, route_regressions) — tests run without `LAAS_TOKEN`.
- `requires_ledger` marker for subprocess integration tests that need a
  real token.
- S4 exemption for `baseline_claims.py` (AST false positive on
  `shell=` dict kwarg).

## v0.330.0 — 2026-08-27

### Changed
- **traust-engine pin 0.7.9 → 0.8.1.** Brings URI-addressed storage
  (`ANALYSIS_RESULTS_URI`, `PORTFOLIO_GRAPH_URI`, `HARNESS_REMOTE_CACHE`)
  with S3-compatible endpoint support, plus the fix for an unset
  `ANALYSIS_RESULTS_DIR` silently downgrading every impact deep scan to
  `inconclusive`.

### Added
- `docs/setup.md` — remote results/graph section, including the
  S3-compatible recipe (MinIO / OpenShift Data Foundation / Ceph RGW):
  endpoint URL, path-style addressing, private CA bundle. Notes that local
  paths and `file://` import no backend, so a workstation acquires no
  dependency for a deployment feature.
- `docs/external-dependencies.md` — licence rows for `fsspec` and the
  `s3fs`/`gcsfs`/`adlfs` drivers. All four BSD-3-Clause, **verified at
  source**: `fsspec`'s PyPI record carries no licence field and no
  classifier, so the repository LICENSE is the authority, not the metadata.
  Optional extras only — the default install surface is unchanged.

## v0.329.0 — 2026-08-27

### Changed
- traust-engine pin **v0.7.9 -> v0.8.0** — URI-addressed results and graph
  locations, plus a fix for a silent scan-tier failure. The pin edit was already
  in the working tree; this commits it with the verification it needed.
- `analysis-results/fuzz-harnesses/` is now where fuzz harness sources live
  (companion: analysis-results `1b41378fd4`). `targets.json` `file:` paths are
  relative to `HARNESSES` in the fuzz Makefile.

### Notes
- 2,264 tests pass against traust-engine 0.8.0 and traust-ledger 0.15.1; docs gate
  clean. The 0.8.0 storage change is the kind that moves paths under consumers,
  so the suite was run before committing rather than after.

## v0.328.2 — 2026-08-25

### Changed
- traust-ledger pin v0.15.0 -> **v0.15.1**, traust-engine v0.7.8 -> **v0.7.9** —
  pluggable identity provider registry, machine claim fix, dead code removal.

## v0.328.0 — 2026-08-25

### Fixed
- **`validate_employee.py` reported a refused directory as "NOT found".** The
  search binds anonymously; the corporate directory answers
  `48 inappropriateAuthentication: Anonymous access is not allowed` with zero
  entries; the script read only `conn.entries` and printed
  `mchubirk: NOT found` / `status=not_found`. An **active employee** was reported
  as not existing, and `/countersign` refused their signature on that basis with
  the message *"could not be verified as an active employee"* — an accusation
  about a person caused by a missing credential.
  Now: `auth_failed` when the bind or search is refused, `not_found` only after a
  successful search that matched nothing, and a hint naming the actual fix.
  countersign distinguishes the two in its error, saying plainly that a directory
  problem is *not* a statement about the identity.
- **`--auth bind` could never reach its bind.** It did an anonymous search first
  to discover the DN, which this directory refuses. It now binds AS the user
  first (DN from `HARNESS_LDAP_USER_DN_TEMPLATE`, default
  `uid={uid},ou=users,{base_dn}`) and searches on that authenticated connection.
  The old post-search bind remains as a fallback for directories whose DN shape
  the template does not match.

### Added
- `--bind-dn` / `--bind-password-file` (env: `HARNESS_LDAP_BIND_DN`,
  `HARNESS_LDAP_BIND_PASSWORD_FILE`) — a service credential for the search.
  Password from a file, never argv, which is ps-visible to every local user.
- `HARNESS_LDAP_SERVER` / `HARNESS_LDAP_BASE_DN` — the Red Hat defaults are still
  defaults, but no other deployment has to patch a hostname out of the source.

### Changed
- traust-ledger -> **v0.15.0**, traust-engine -> **v0.7.8**.
- `docs/signing.md` states the identity model: **OIDC proves who a signer is; the
  employee-directory check is optional** and answers the narrower question of
  current employment. The two were conflated, including by me — signing-key
  material and identity verification are different problems.

## v0.327.0 — 2026-08-25

### Fixed
- **`countersign` now closes the queue entry its decision answers.** It appended
  the event and left the `needs_review` item `pending` forever, so a human could
  work the queue and it would never shrink — corpus-wide, **16,706 pending
  against 34 confirmed** while those decisions were being recorded correctly the
  whole time. `record_decisions` now resolves every pending item in the layer
  whose `suggested_finding_ref` matches, in the same in-memory layer before the
  single write, so there is no second write and no signature churn.
  `confirmed` is tried first and the shared rule refuses it unless the event is
  really in the layer; the fallback is `rejected` carrying the same rationale,
  because a mapping decision records no event and a queue entry must never claim
  a determination the ledger does not hold. `defer` leaves it pending. It never
  raises: a correctly recorded decision must not fail because its queue entry
  could not be tidied. The receipt gains a `queue <ref> (<reason>) -> <status>`
  line.
  The rule itself lives once, in traust-ledger's `resolve_review_item` — countersign
  owns its write and cannot go through `LedgerWriter` without writing twice, and
  a second copy of "confirmed requires an event" beside it is how the two would
  drift.

### Changed
- traust-ledger pin -> **v0.14.0**, traust-engine -> **v0.7.7**.

## v0.326.0 — 2026-08-25

### Added
- **`scan_internal_refs.py`** — the open-source plan's Phase-3 scrub gate, as
  a repeatable check rather than a one-off grep. Three tiers (block /
  review / note) over git-tracked files only; routes attention, never
  concludes. `--fail-on block` makes it a release gate once an export
  candidate exists.
  First run over the five publishable repos: **no leaked credentials** (every
  credential-class hit verified benign — AWS's published example key, scanner
  detection patterns, k8s CIDRs), but 20 internal Vault paths, 165 internal
  hostnames, 258 campaign-codename hits and 9 named individuals in shipped
  files. Report:
  `progress-tracker/gap-assessments/open-source-gap-analysis.md`.
  Two self-inflicted rule bugs found and fixed during that run, in opposite
  directions: `kerberos-realm` compiled with `IGNORECASE` matched every
  lowercase `redhat.com` (357 phantom block hits — over-reporting hides real
  findings), and `gdrive-id` matched any 28-char string starting `0`/`1`,
  catching sha256 digests (53 hits, all noise; now URL-anchored, and the 2
  survivors are real).

## v0.325.0 — 2026-08-25

### Added
- `migrations/bulk_close_needs_review.py` — closes queued review items as
  `rejected` with a recorded reason, through `LedgerWriter.resolve_needs_review`
  so it takes the lock and enforces the schema's rules. Dry-run by default;
  `severity_proposal` skipped unless asked for, because closing one forfeits a
  proposed re-rating rather than a non-decision.
  **Run 2026-08-25: 16,643 items closed across 3,404 layers**, leaving 63
  `severity_proposal` for a human. No disposition moved and no signature changed
  — 8,237 layers, 8,237 signed, all format 3, before and after.

### Changed
- traust-ledger pin -> **v0.13.2**, traust-engine -> **v0.7.5**.

### Notes
- Running it surfaced a bug in the function it calls: `resolve_needs_review` broke
  on the first item matching a key, so a pending item shadowed by an
  already-resolved twin was unreachable — 79 `rebaseline_mapping` items across 18
  layers survived the first full pass. Fixed in traust-ledger 0.13.2 and the second
  pass closed them. The review-item key is not unique because the schema gives
  items no id; that remains true and is worth an `review_id` in contracts if the
  queue ever gets an API.

## v0.324.0 — 2026-08-25

### Changed
- **Drift row `feeds:product-definitions` → `registry:product-definitions`.**
  The prefix is now derived from membership in `config/feeds.yaml` rather than
  hardcoded, so a row name follows the source's CATEGORY instead of the
  mechanism that fetches it. `product-definitions` is pulled by `fetch_feeds`
  but is Red Hat Product Security's product/ownership registry carrying zero
  vulnerability data; calling its row `feeds:` kept re-merging the two
  categories the registry exists to separate — it did so again in v0.323.2's
  documentation, which is what surfaced this.
  A source that cannot be classified (unreadable registry) falls back to
  `feeds:`, the conservative side: under-reporting a security source is the
  worse error.

Row-name change with **no consumers**: verified across the workspace, nothing
matches on drift row names. Only three files reference `drift-report` at all —
`check_drift.py` writes it, `check_skill_alignment.py` matches the *filename*
against its terminal-artifact regex, and the drift-watch SKILL.md documents it.
No code splits a drift item on `:` or matches a `feeds:` prefix. The report is
a human-read artifact; the stale name in
`progress-tracker/metrics/drift/drift-report.*` is overwritten on the next run.

## v0.323.3 — 2026-08-25

### Fixed
- **`drift-watch` SKILL.md described `product-definitions` as a
  `config/feeds.yaml` source.** It is not, and deliberately so — it is Red Hat
  Product Security's product/ownership registry, carrying zero vulnerability
  data. v0.323.2 listed it inside the `feeds:*` row alongside epss/kev/rh-cve/
  vex, re-merging the two categories the registry split apart. Now its own
  row, stating plainly that it is not a security feed and shares only the
  fetch mechanism (and therefore the row prefix), with its real 24h refetch /
  168h flag thresholds.

## v0.323.2 — 2026-08-25

### Fixed
- **`drift-watch` SKILL.md documented 28 of 37 live drift row families.** Nine
  rows the checker emits had no entry, so the page people consult to interpret
  a drift report was silently incomplete: `ledger:*`,
  `ledger-signature-coverage`, `yara-rules-pin`, `argus-rules-pin`,
  `threat-model`, `language-cache-freshness`, `sibling-readme:*`,
  `docs-semantic-sweep`, `docs-versions:*`. Each added beside its related row
  with the behaviour read from the check, not inferred.
- The `feeds:*` row was still written as `feeds:epss/kev`. That family now
  covers every `tier: cached` source in `config/feeds.yaml` — `epss`, `kev`,
  `rh-cve`, `vex`, plus the VPN-only `product-definitions` — at a 48h
  threshold. Generalised, with the pending-vs-unavailable rule for optional
  feeds stated.

## v0.323.1 — 2026-08-25

### Fixed
- **`docs/routers.md` §2 stated the wrong budget-guard posture.** It said the
  shipped `enforcement` is `none`; `config/budget-policy.yaml:28` has been
  `observe` since the owner decision of 2026-08-05. The operational conclusion
  was unchanged (neither posture withholds work) but the stated value was
  stale, and this page is the one people read before relying on the guard.
  Now names the config path, the current value, the full enum, and the
  XWING-628 flip.

### Verified (no change needed)
- `routers.md`: all 16 components resolve on disk (15 enumerated tokens —
  `build_rescan_worklist.py` holds the budget guard too); the rescan router's
  12 lanes match the `LANES` tuple exactly; every `python3 -m` command and
  every `/skill` reference resolves.
- `continuous-operations.md`: every `python3 -m` command imports, every
  `harnessing/*/scripts/*.py` path exists, all 18 `/skill` references resolve,
  and every drift row it names as a backstop is live in a real run — with no
  ghost rows. Its "no scheduler is configured in this repository" disclosure
  (line 87) remains accurate.

## v0.323.0 — 2026-08-25

### Changed
- **Feed refresh is the seventh router kind** (`docs/routers.md` §7), not a
  worklist builder and not a "not a router" footnote. Routers ARE the
  orchestrator-neutral seam: the same command runs identically from an
  operator session, cron, the SCI worker, Konflux, or an enterprise
  scheduler. v0.322.0 argued the refresh out of the taxonomy on the grounds
  that it maintains inputs rather than routing work, then proposed a GitLab
  scheduled pipeline — which would have bound the refresh to one orchestrator,
  exactly what the abstraction exists to prevent. Reverted; no CI pipeline.
- `fetch_feeds` docstring drops the "when CI/CD integration lands, this becomes
  one pipeline task" note for the same reason.
- **`product-definitions` stays in `fetch_feeds.py`** and gets no registry file
  of its own. The test is not "is it a security feed" but "do we author it":
  Red Hat Product Security creates it, it covers all 197 Red Hat
  `ps_products`, and we are a read-only consumer. Data we author lives in
  `hybrid-platforms-inputs`/`progress-tracker`; data we fetch lives in the
  cache. Same mechanism, different category. (Decision, Michele, 2026-08-25.)
- **`product-definitions` TTL 30d → 24h**, matching upstream's own guidance to
  consumers. The 30-day value was justified on ps_product ids being immutable
  — true, and it ignored the other half of the payload. Measured: 36 commits
  to the upstream `data/` tree in 8 days, ~1 contact/CC change per day,
  several on OpenShift; `file-security-defect` reads `private_tracker_cc` to
  answer who is already embargo-cleared, and a 2026-08-24 upstream commit
  dropped stale members from exactly that OpenShift config. Pull-through, so
  it costs a fetch only when a VPN-connected consumer runs.
- Its drift threshold 720h → 168h. Refetching at 24h while only complaining at
  720h would have hidden 29 days of contact drift; a week still tolerates a
  fortnight of off-VPN work without the row going red on something unfixable.

## v0.322.0 — 2026-08-25

### Added
- **`config/feeds.yaml` — one registry for every security-data source, cached
  or live.** Endpoint, cadence, licence block, and consumers per source.
  `fetch_feeds.py` (cached tier), `fetch_advisory.py` (live tier), and
  `check_drift.py` (`feeds:*` freshness + `feed-source:*` liveness) all read
  it. Adding a source is now a config change; a dead source is a failing row.
  Before this, four tiers were managed four ways and only the cached one had
  freshness tracking.
- **Red Hat CSAF VEX as a first-class source.** Per-CVE product impact across
  the Red Hat catalogue — `known_affected`, `fixed`, and `known_not_affected`
  with machine-readable justification flags (`vulnerable_code_not_present`),
  i.e. authoritative not-affected evidence from Red Hat Product Security.
  Sync is `indexed-lazy`: `changes.csv` (rolling 12 months, 65,447 rows) on the
  daily cadence, documents fetched on demand and cached — the full corpus is a
  293 MB zstd archive covering products we mostly do not ship. `load_vex()` /
  `vex_product_status()` are the consumer API.
- **`feed-source:*` drift rows** — liveness probes for both tiers. A definitive
  HTTP error is `drift`; a transport failure is `unavailable`, never `drift`,
  so an offline workstation does not report every source broken.

### Fixed
- **`fetch_advisory.py csaf` 404'd on every CVE, silently, for its whole
  life.** It requested `csaf/v2/advisories/<cve>.json`; Red Hat keys CSAF
  advisories by RHSA and partitions by year. Verified 404 on 3/3 CVEs before,
  200 after. Renamed `redhat-csaf` with the correct shape; the CVE-keyed
  question it was reaching for is answered by the new `vex` source. A
  `feed-source:redhat-csaf` probe now catches exactly this class — reinstating
  the old template in a scratch registry reproduces `drift` with HTTP 404.
- **Feed cache moved out of `analysis-results/`** to `FEEDS_CACHE_DIR`
  (default `<workspace>/progress-tracker/feeds`). `analysis-results/` holds
  work we authored; a mirror of third-party licensed data is a different
  provenance class with opposite retention and redistribution properties.
  ~6 MB of CC-BY/CC0 feed data had already reached this repo's git history via
  that path — untracked here and gitignored in both repos.
- **Split-brain cache.** With `FEEDS_CACHE_DIR` unset the fetcher wrote one
  tree while consumers read another: the corpus EPSS/KEV copy sat 38 days
  stale while a refresh reported success. `check_feeds` now resolves through
  the same registry helper as the fetcher, with a one-release fallback read of
  the old path so an un-migrated workspace keeps reporting real ages.

### Changed
- **`feeds:*` drift threshold 168h → 48h.** The refresh is daily; a backstop
  looser than the cadence it guards lets a dead job stay green for six days.
- **Feed refresh is a standing daily job**, not "pull-through, no dedicated job
  by design". That held only while something ran daily; nothing did. Every
  source in the registry is public, so the lane needs no VPN.
- `fetch_advisory.py` is registry-driven but **egress stays confined**: the
  resolved host is re-checked against an allowlist derived from the registry,
  so write access to `config/feeds.yaml` cannot become request forgery.
  Verified against off-host, HTTP-downgrade, and suffix-confusion URLs.
- `product-definitions` is marked `PENDING RELOCATION` in `fetch_feeds.py` and
  deliberately excluded from `config/feeds.yaml` — it is a product/ownership
  registry (ps_products, contacts, cc_lists; zero vulnerability data), not a
  security feed. All five consumers unchanged pending a decision on where it
  belongs.

## v0.321.0 — 2026-08-25

### Added
- **`grype-db` drift row — the vulnerability DB's content age, not grype's
  version.** `external-tools:grype` watches the *binary*; grype ships its
  matchers separately, so a current grype can carry a months-old CVE database
  while the version row stays green. Measured on the operator workstation
  2026-08-25: `external-tools:grype fresh — installed 0.117.0 == latest
  0.117.0`, while `grype db status` reported a DB built 2026-07-30 with
  `Status: invalid` — 26 days stale, and every container/SBOM scan on that
  machine was matching against aged CVE data with nothing flagging it.
  Threshold is grype's **own** 5-day max age (past it grype invalidates the DB
  itself), so this is the tool's policy rather than a number we picked. The row
  fires on age even while grype still reports `valid`, because the DB stops
  being useful before grype stops accepting it. Not-installed reports
  `pending`; an unparseable `grype db status` reports `unavailable`, never
  fresh — a changed output shape must not read as healthy, which is the
  failure mode the row exists to prevent. Refresh is `grype db update`, and it
  stays a human/job action: the checker routes attention and never updates a
  database mid-run.

### Fixed
- Operator workstation's grype DB refreshed (2026-07-30 `invalid` → 2026-08-25
  `valid`). Any container or SBOM finding produced between those dates was
  matched against a database missing ~4 weeks of CVEs.

## v0.320.2 — 2026-08-25

### Changed
- **`LAAS_SIGNING_KEY_PATH` is the canonical name** (Michele, 2026-08-25). The
  signing env family is read by `traust_ledger.integrity.signing`, so traust-ledger
  defines it and `traust-ledger/docs/auth.md` is now the reference; the harness
  stops maintaining a parallel table of nine variables it does not own. Docs
  renamed throughout (`docs/signing.md`, `signing-workflow.md`,
  `disposition-ledger.md`, `architecture.md`, `config/README.md`).
- **Who sets it, and why the harness needs it at all.** The variable is *read* by
  traust-ledger and *set* by whichever process signs. Two do: the ledger service
  (from its deployment) and — interim — an operator's shell running a corpus
  migration under `vault login`. In the target state the harness signs nothing
  because the ledger service holds the key (plan D6), so the harness's need for
  this variable is temporary by design. Stated in `docs/signing.md` rather than
  left to be inferred.
- `HARNESS_SIGNING_VERIFY_PUBKEY` **keeps its name** — the one variable in the
  family the harness genuinely owns, read by `traust_engine.reporting.validate`
  on the verification side, which needs only the public half. Documenting the
  ownership split is the point: duplicating traust-ledger's table here is how the
  0.11.0 rename went unnoticed on this side for a day.
- `ops/sign_merkle_root.py` and `migrations/resign_layers_format3.py` now resolve
  env names through traust-ledger's `signing_env()` instead of reading either
  prefix directly, so the apply-gate cannot refuse an operator who exported the
  canonical name.

## v0.320.0 — 2026-08-25

**Coordinated pin roll, and the regression it caught.**

### Changed
- contracts `v0.6.0` -> **`v0.7.0`**, traust-ledger `v0.10.0` -> **`v0.12.1`**,
  traust-engine `v0.7.1` -> **`v0.7.3`**. Rolled as one commit per repo, in
  dependency order, because uv resolves the sibling deps by exact git tag and a
  split tag fails the resolve outright.
  Carries: the `needs_identity` receiver-side quarantine (replacing traust-ledger
  0.11.0's server-side fingerprint backstop), 6e's populated projection columns,
  and the corrected identity descriptions in `report.schema.json` /
  `layer.schema.json`.

### Fixed
- The roll surfaced a **live signing regression** and it is worth recording where
  the catch came from: traust-ledger 0.11.0 renamed the `HARNESS_SIGNING_*` env
  family to `LAAS_SIGNING_*` with no alias, so this harness — which exports the
  old names from its docs, its four signing migrations and its CI — would have
  configured **no signer** and written unsigned layers, with
  `HARNESS_SIGNING_REQUIRED=1` no longer read either. Fixed upstream in
  traust-ledger 0.12.1 (both prefixes honoured, current one preferred).
  `tests/test_e2e_merkle_pipeline.py::test_e2e_ci_merkle_pipeline` failed on
  step 15 — *"signature-stripped layer should produce an ERROR"* — which is the
  self-audit `-006` control doing exactly its job. Nothing in traust-ledger caught
  it, because every test there already speaks the new name.

## v0.319.0 — 2026-08-25

### Added
- `identity:colliding-fingerprints` in the drift sweep — findings that share an
  identity with **another finding in the same report**. This is the false-MERGE
  dual of the rows added in 0.317.0 and invisible to every one of them: both
  stamps recompute perfectly, they simply name the same thing. Measured on the
  live corpus: **1,632 of 75,111 findings (2.17%)**, e.g. *"Interactive SSO
  credentials injected as plaintext"* and *"Slack webhook URL handled as plaintext
  template param"* in one repo — same file, same primary CWE, different
  vulnerability, one name.
  Reported as `info`, not `stale`: it is a property of the recipe
  (repo + path set + primary CWE distinguishes nothing between two such findings)
  rather than a regression, and it is contained today because dispositions key on
  `(layer_id, finding_ref)` rather than identity (**D9**) and rebaseline tier-1
  refuses a non-unique candidate (`finding_identity.py:199`). It bites only where
  something DOES key on the fingerprint — SCI's ladder, which takes
  `prevFindings[0]` unconditionally (GH #46 part B), and cross-repo joins over the
  projection's new fingerprint column.
  Degenerate findings are excluded from the count: they collide by construction
  and the `degenerate-findings` row already owns them, so including them reported
  one defect twice and inflated this row by 96.

## v0.317.0 — 2026-08-24

**A boundary gate for finding identity.** Every identity check lived in the
producing session — the audit skill's stamp step, then the validator erroring on
an absent or non-reproducing value. `analysis-results` has no git hook and no CI,
so a report written outside the skill path (hand-edited, migration-reserialised,
imported from a non-harness producer) met no gate on the way in. The corpus being
100% stamped was evidence the in-session path holds, not evidence a gate exists.

### Added
- `check_drift.check_finding_identity` — corpus-wide sweep recomputing every
  finding's `fingerprint` against the installed `traust_ledger.identity` recipe.
  Three rows: `identity:unstamped-findings` (**drift**), `identity:non-reproducing-stamps`
  (**drift**), `identity:degenerate-findings` (**stale** — the burndown counter
  for the `fingerprint(strict=True)` flip, plan item 4b). ~3s over 8,235 reports;
  reports that will not parse surface as `unavailable` rather than passing
  silently. `--fail-on drift` makes it CI-gateable.
  First run: **75,111 findings, 0 unstamped, 0 non-reproducing, 432 degenerate** —
  the 432 matching `4b-needs-classification.json` exactly.

### Fixed
- `render_md` raised `ValueError: tuple.index(x): x not in tuple` on any report
  containing an `info` row. Two checks emit that status
  (`dashboards:builders-uncovered` since 0.307.0, `ledger:colliding-layer-ids`
  since 0.313.0) and the corpus fires the second one today, so the markdown half
  of the drift report has not been written since 0.313.0 — the JSON was fine,
  which is how it went unnoticed. `info` joins the status vocabulary, and the sort
  now tolerates an unknown status instead of aborting the whole report.

## v0.304.0 — 2026-08-20

**CVE provenance is now collected on the weekly cadence.**

### Added
- `refresh_dashboards` stages `cve-feed` and `cve-provenance`, both ahead of
  `findings-db` so the projection picks up stamps written the same cycle.
  Consumer tier deliberately: an off-VPN or rate-limited feed must not abort
  a dashboard rebuild, and the reconciler is idempotent so it catches up.
- Rolling metrics file `progress-tracker/metrics/first-discovery/
  first-discovery-current.json` — distinct CVEs, confirmed vs probable, match
  rows, and the full match list. Rewritten in place each run; git carries the
  history.

### Changed
- traust-engine pin -> v0.6.0 for the `provenance` table in `findings.db`
  (118 rows / 53 distinct CVEs on the first build), so the metric is a query
  rather than a walk over every layer.

### Notes
- No dashboard surface by decision: the baseline is still in triage, so the
  number is not yet accurate enough to publish. Collected now so the series
  starts accumulating; the surface can come later.
- The figure grows on its own — each weekly run stamps newly published CVEs
  that match findings already filed, with lead time recorded.

# Changelog

## v0.302.1 — 2026-08-20

### Fixed
- `reconcile_cve_provenance`: a relative `--results-root` silently produced
  **zero** reports. The corpus resolver walks nothing when handed a relative
  path, so the run printed "0 matches" and exited 0 — a no-op that reads like
  success. Root is now resolved before the walk, with a regression test.

## v0.302.0 — 2026-08-20

**CVE-provenance reconciler.** Closes the loop opened by v0.301.0: the feed
answers "what did Red Hat publish", this answers "which of those were already
ours" — and writes the answer down.

### Added
- `reconcile_cve_provenance.py` — joins the `rh-cve` feed to the corpus and
  stamps `metadata.external_refs` (contracts v0.5.4) on each findings-layer.
  Dry-run by default.

### Changed
- Pins: contracts v0.5.3 -> v0.5.4, traust-ledger v0.7.1 -> v0.8.1,
  traust-engine v0.4.0 -> v0.4.1 (uv resolves contracts by exact git tag, so
  the workspace has to move together or resolution fails).

### Backfill (applied)
**53 distinct CVEs** matched — 50 confirmed, 3 probable — stamped as 118 refs
across 70 layers. Median 80 days ahead of publication (range 2–94).

### Notes
- **Counts distinct CVEs, not rows.** One component audited on N release
  branches matches N times: `console` matched 11 branch reports for a single
  CVE. Each layer legitimately gets its own stamp, but reporting rows would
  have doubled the headline (119 vs 53).
- **CWE promotes, never blocks.** It corroborates 80% of true matches, but the
  disjoint 20% are the same issue under a sibling weakness (RH CWE-312 vs our
  CWE-522). A hard CWE gate would drop 19% of true matches including
  CVE-2026-66792, the 9.9.
- **Both bands auto-stamp; no human in the loop.** Zero false matches across
  53 hand-adjudicated at >=0.55, and a wrong stamp mislabels a metric rather
  than closing a finding. Review stays where state changes are decided.
- Sequence ratio alongside token-Jaccard: the CVE's "no_auth" vs our "noauth"
  scored 0.457 on tokens alone and would have been dropped.
- **Never writes the audit baseline** (gate A15) and never the event chain.
- Automated total is 53 where the manual 2026-08-20 pass reported 59; the
  difference is exactly the six sub-threshold matches a human promoted.

### Known gap (pre-existing, unrelated)
Every findings-layer fails `layer.schema.json`: `merkle_signature_format` is
3, the schema allows `[1, 2]`. Stamped layers validate cleanly once that is
neutralised — 70/70. Owned by the ledger-signing work, not fixed here.

## v0.301.0 — 2026-08-20

**Red Hat CVE feed — the missing input for first-discovery measurement.**

A 2026-08-20 analysis asked a question the harness could not answer from its
own data: of the CVEs Red Hat published against code we audited, how many had
we already reported? `findings.db` carries no CVE linkage and no discovery
date, and the feeds cache held only EPSS and KEV — neither of which carries a
CVE publication date. The comparison had to be run against a live API by hand.
It found **59 CVEs whose text matches a finding we filed first**, median 80
days ahead. This makes that repeatable.

### Added
- `fetch_feeds.py` feed **`rh-cve`** — Red Hat Security Data CVEs (CC-BY-4.0,
  public endpoint, in `--feed all`). Carries `public_date` and the
  `component: title` bugzilla convention, which are the two join keys
  first-discovery reconciliation needs.
- `load_rh_cves(cache)` — splits `bugzilla_description` into component and
  title (stripping Red Hat's doubled-component echo) so consumers do not each
  re-derive the same parse.
- Generic **`paginate`** and **`incremental`** support in `fetch()`, plus
  `MAX_FEED_PAGES` as a runaway guard.

### Notes
- **Pages within the window.** Red Hat published 1000+ CVEs in the week of
  2026-08-10 against a weekly median of 245, so a one-page-per-window fetch
  would have silently truncated the busiest weeks — the ones that matter most.
  Measured before writing the loop; a short page terminates it.
- **Incremental, merging onto the cache.** Each run asks only for what
  published since the stored watermark; overwriting would discard every
  earlier window. Backfill runs from the campaign start (2026-05-01):
  8,183 records, 1.9 MB; steady state is ~77 KB/week.
- **Stored as a 6-field projection, NOT filtered to audited components.**
  Filtering would cut the cache to ~90 KB, but the feed would then be blind
  to any repo audited afterwards, and it would couple a feed refresh to the
  corpus resolver. 3.8 MB/yr is cheaper than that coupling; the component
  join belongs in the consumer.
- `/drift-watch` picks the feed up with no change — `watched_feeds()` is
  driven from `FEEDS` precisely so a new feed cannot go unmonitored.
- `--feed all` now covers `rh-cve`, so a cache without it reports UNUSABLE
  exactly as a missing EPSS copy would. The test fixture was updated to match.

## v0.300.0 — 2026-08-20

**`corpus-manifest.json` retired.** A 13.6 MB artifact, committed on every dashboard
refresh, that **measurably nothing read**: every dashboard — census included —
resolves the population in-process via `corpus.resolve()`. Its two appearances in
dashboard code were *display strings* in the population block, not data access.

Its fields were already a subset of `findings.db` `repos`, which additionally carries
`repo_key`, `repo_url`, `ref` and `audit_date`; traust-engine **0.4.0** adds the six
artifact refs that were the manifest's only unique contribution — stored
root-relative, so they survive reports leaving the checkout (plan §4.4.0).

- `/census` stops writing it; both denominator strings now cite ``findings.db `repos` ``;
  docs, skills and the resolver docstring updated.
- `corpus.resolver.build_manifest` is **deprecated**, not deleted — still available for
  an on-demand snapshot.
- Adopts traust-engine 0.4.0.

2164 tests pass.

## v0.299.1 — 2026-08-19

**Stack pin sync** — contracts 0.5.3, traust-ledger 0.7.1, traust-engine 0.3.3.

- Pins: `traust-contracts` v0.5.3, `traust-ledger` v0.7.1, `traust-engine` v0.3.3.
- Disposition merge now flows through `traust_ledger.disposition` via traust-engine 0.3.3.

## v0.299.0 — 2026-08-19

**Identity model sync** — traust-ledger 0.7.0, contracts 0.5.2, traust-engine 0.3.2.

- `countersign.verify_identity` stamps the OIDC-era actor fields
  (`identity_verified`, `identity_provider`, `identity_subject`,
  `employee_status`) and canonicalizes human identity to lowercased email.
- `build_cumulative` two-person rule uses `traust_engine._util.actor.is_actor_verified`
  (checks `identity_verified` first, falls back to legacy `ldap_verified`).
- Pins: `traust-engine` v0.3.2, `traust-ledger` v0.7.0, `traust-contracts` v0.5.2.

2163 tests pass.

## v0.298.1 — 2026-08-19

**Documents the five-component split.** Since the harness was modularized into
`traust-engine`, `traust-ledger`, `traust-contracts` and `ai-security-sdk`,
nothing in this repo said so: the README read as though it were the whole system,
and `ai-security-sdk` appeared **zero times** across README, docs/ and PROCESS.md.

- New **`docs/components.md`** — what each of the five repos owns, the one-way
  dependency direction, a which-repo-do-I-change table, git-tag pinning and its
  `uv lock` "conflicting URLs" failure mode, bottom-up release order (including
  how `traust` and `ai-security-sdk` each differ), and what genuinely
  crosses the boundary.
- **README.md** — new `## Components` section above the workflow, plus a docs-table
  row. States plainly that there is no local `schemas/` directory, so the
  `schemas/v1/…` paths it references resolve inside the installed contracts package.
- **`docs/setup.md`** — disambiguates its two senses of "sibling" (data repos that
  are cloned vs packages that are installed).
- **`docs/architecture.md`** — scope note, since it references `traust_engine.*`
  and `traust_ledger.*` modules that live in other repositories.

Fixes a stale reference the D7 doc sweep missed: the README's tooling table still
pointed at contracts `vectors/v1/finding-identity-golden-vectors.json`, deleted in
contracts 0.5.0 when D7 retired the cross-language oracle. Repointed to the
surviving regression fixtures in `traust-ledger/tests/fixtures/`, with the
fixtures-not-a-contract distinction made explicit.

Also relocks `uv.lock`, which still carried `version = "0.297.0"`.

## v0.298.0 — 2026-08-18

**Signature format 3 adopted** (traust-ledger 0.6.0 + traust-engine 0.1.17) — plan
§4.4.0a. The signed payload now binds `audit_report_sha256`, so a signature covers
events, claims **and** the bytes of the report the layer annotates. Format 2 left
that digest outside the signature: provenance, not tamper-evidence.

- New `migrations/resign_layers_format3.py` — dry-run by default, idempotent and
  resumable, verifies each fresh signature against the committed public half before
  writing, skips unsigned layers (that is P8's question), and refuses to sign a layer
  whose root is stale rather than silently signing over the discrepancy. Dry run:
  **8,508 layers to re-sign.**
- `test_sign_merkle_root` asserted `merkle_signature_format == 2` as a literal and
  broke on the bump; it now tracks `SIGNATURE_FORMAT_CURRENT`, like the traust-ledger
  fixture that had the same problem.

The corpus is not invalidated by this release: verification reconstructs the payload
for whichever format a layer records, so format-2 layers stay valid until re-signed.

2164 tests pass.

## v0.297.0 — 2026-08-18

**Step 1 of the storage move: the layer's link to its report is content-addressed**
(plan §4.4.0). Reports go to object storage, the ledger stays in git — this is the
prerequisite that lets the report leave the directory without breaking the join.

- Five layer writers now record `metadata.audit_report_sha256` at the moment they
  write: `route_impact_findings`, `route_regressions`,
  `emit_triage_ledger_events`, `emit_validation_ledger_events`, and
  `baseline_claims.py record`. Idempotent, so it also upgrades layers written before
  the field existed.
- `build_cumulative` **warns** on a digest mismatch and never heals it. A mismatch
  means the annotated bytes were rewritten — legitimate after a re-audit or a corpus
  migration (today's v1→v2 re-stamp rewrote 361 reports without touching one claim) —
  so `verify_claim_hashes` remains the thing that refuses, and `baseline_claims.py
  record` is the deliberate re-record path.
- **Backfilled all 8,507 layers** whose report is present (1 has no report beside it
  and was skipped rather than given an invented reference). Verified afterwards
  across the 8,257 layers under `findings/`: **signatures intact 8,257, Merkle errors
  0, digest mismatches 0** — because neither field is inside
  `merkle_signature_payload`, so nothing re-stamped and nothing re-signed.
- Migration: `migrations/backfill_report_digest.py` — dry-run by default, idempotent,
  and it refuses to overwrite a differing digest (that is the signal, not a defect).

2164 tests pass.

## v0.296.1 — 2026-08-18

**B9, second pass — the same stale prose in the docs, not just the skills.**

0.296.0 fixed the 7 `SKILL.md` files and 4 passages in `docs/skills.md`. Re-running
the hardened detector across all 37 docs plus `README.md`, `AGENTS.md` and
`PROCESS.md` found **6 more sites** — including 3 further ones in `docs/skills.md`
that the first pass missed:

- `README.md` and `docs/architecture.md` — the `route_regressions` rows still said
  it "appends the finding to the repo's baseline audit", which B4 stopped.
- `docs/findings-lifecycle.md` — "sanctioned append to the repo's baseline".
- `docs/skills.md` ×3 — `/validate-findings` novel routing, `/verify-remediation`
  regression routing, and the `/track-findings` ingest row.

Also widened `BASELINE_WRITE_MD_NEG_RE` to cover **remedial** phrasings
("… rather than a write to the baseline", "carried on its ledger event"). The gate
flagged this change's own corrected wording, which is the right failure to have:
the lookaside must know how a fix is phrased, not only how a violation is.

Sweep now reports **0 unqualified baseline-write sites** across 95 docs and skills.

## v0.296.0 — 2026-08-18

**B9 — the baseline-write audit across the other 55 skills** (plan queue item 6).

Result: **7 non-owner skills instructed a baseline append, and A15 passed all of
them clean with zero exemptions.** Not one was a live code violation — B3/B4 had
already stopped both routers writing baselines (verified: they write only the layer
and the verification report). Every one was **stale prose**, which in an
agent-driven harness is not a documentation nit: `SKILL.md` *is* the instruction to
the model, so an agent following `/verify-remediation` today would have hand-written
the baseline the gate exists to protect.

Why the gate missed them — each a phrasing detail, not a new idea:

| miss | example |
|---|---|
| verb inflection | "**appends** each regression to the baseline" |
| interposed word | "append **it** to the baseline" |
| `to` vs `into` | "appends the transcribed finding **to the** baseline" |
| adjectival, no verb | "the **amended** `*-security-audit.json` finding" |
| possessive target | "routes every regression into the **repo's** baseline" |

### Changed
- `BASELINE_WRITE_MD_RE` widened to verb stems + inflections, interposed words,
  `to`/`into`, possessives and adjectival forms, with a new
  `BASELINE_WRITE_MD_NEG_RE` so sentences *stating* the rule (and the fixes' own
  "never written — gate A15" text) do not trip it.
- All 7 skills rewritten to the flow that actually shipped: the finding rides on
  its ledger event (`event.finding`, contracts >= 0.4.4), `build_cumulative` unions
  event-carried findings with the baseline's (B2), the baseline is untouched.
- `tests/test_a15_baseline_ownership.py` pins all 8 verbatim phrasings, the
  negative lookaside, and the presence of the A15 marker in each fixed skill — so
  reverting a skill re-arms the gate.

2164 tests pass.

## v0.295.0 — 2026-08-18

deps: contracts **0.5.0** + traust-ledger **0.4.1** + traust-engine **0.1.15** —
the cross-language identity oracle is retired (plan D7, queue item 5).

Only the harness computes identity, so the shared golden-vector suite had no port
left to hold: contracts 0.5.0 removed it along with `paths.vectors_dir()`, and
`ai-security-sdk` 0.5.0 pruned `go/v1/identity`. Coverage was **ported before
deletion**, not after — all 12 cases now live in
`traust-ledger/tests/fixtures/identity-recipe-vectors.json`, recomputed under
`algo_version` v2 with each case retaining its v1 value so a recipe move stays
visible.

Docs corrected here, both of which described the retired arrangement as current:
`docs/report-structure.md` called the fingerprint a "cross-language contract …
pinned by the golden-vector oracle" and named three paths that no longer exist;
`docs/setup.md` said contracts ships golden vectors.

2161 tests pass; no harness behaviour change.

## v0.294.0 — 2026-08-18

**Location paths must identify an artifact — layer three of three** (plan queue
item 4).

A finding's ledger identity is `repo | sorted canonical paths | primary CWE`, so a
location of `.` or `/` canonicalizes to empty and collapses identity to
`(repo, '', cwe)`. Measured: **433 fingerprints shared by 1,397 findings** —
"no SECURITY.md" and "not onboarded to OpenSSF Scorecard" in one repo were one
identity, so a disposition on either silently covered both.

Three layers, because each fails alone — P0.1 had the rule and only checked
presence (606 forged stamps passed for months); `event.fingerprint` had the code
and no schema (every stamped layer failed validation):

1. **contracts 0.4.5** declares the rule and the `repo-scope-path` vocabulary.
2. **traust-ledger 0.3.1** `fingerprint(strict=True)` refuses at stamp time — the
   one point nothing bypasses, since nothing enters the ledger without identity.
3. **`check_location_paths`** (new, this release) catches reports whose producer
   skipped validation, before the values reach a ledger.

Corpus-wide today: 8,136 reports, **3,119 repo-root markers, 174 paths over 120
characters, 52 containing newlines**. Enforcement is staged exactly as P0.4 → P6
was: warnings now, `--strict` after the migration.

## v0.293.0 — 2026-08-18

deps: traust-ledger v0.2.0 + traust-engine v0.1.13 — fingerprint `algo_version`
**v2** (plan decision D8, queue item 2).

A location path that canonicalizes to empty (`.`, `/`, `./`, `/./`) is dropped
from the hashed path set instead of contributing an empty component. Measured
against the installed recipe across **75,170 stamped findings: exactly 364 move**,
in 259 repos — matching the prediction made before the change. The 2,762
repo-root-only findings do not move.

**Expected consequence until the re-stamp runs:** `check_finding_identity`
recomputes and compares, so those 364 read as mismatched. That is the deferred
migration (queue item 3), not corpus damage — it rewrites signed layers and so
waits on the signing key reaching the write path (P8). Worklist with every
`(report, finding, v1, v2)` tuple:
`progress-tracker/plans/identity-differential-2026-08-17/v2-restamp-worklist.json`.

Also carried, both zero-impact: ASCII-only case folding, and `primary_cwe`
returning `CWE-0` for a blank value.

## v0.292.0 — 2026-08-18

**Ledger plan §0 items 1 and 2 — P9 and P9b.** The last two writers outside the
contracts every other writer already met.

- `finding_identity.rebaseline()` (traust-engine 0.1.12) stamps before writing.
  It mutated the layer and wrote with a plain `json.dumps`, leaving the declared
  `merkle_root` stale — an ERROR since traust-ledger 0.1.3.
- `build_cumulative` confines the layer path. It took a bare `Path(args.layer)`
  and wrote a ledger wherever it was told, including outside `analysis-results/`
  and through a symlink; `emit_triage_ledger_events`,
  `emit_validation_ledger_events` and `countersign` all refused that already.
  New `--findings-root`; default roots are the audit report's directory and the
  cwd. Both writers share `traust_engine._util.layer_paths.confine_layer_path`
  rather than a fourth copy of the same check.

## v0.291.0 — 2026-08-18

deps: traust-ledger v0.1.7 + traust-engine v0.1.11 — a write that moves the
Merkle root now drops the signature it invalidated.

`stamp_merkle_metadata` used to overwrite `merkle_root` and leave
`merkle_root_signature` in place, so any write to a signed layer without a
configured key left a signature verifying against a root that no longer existed
— worse than unsigned, because a present-but-invalid signature is
indistinguishable from tampering. Found on 9 layers of the Ex-Wing 5.0 embargo
backfill (2026-08-17).

The six writers that call `stamp_and_sign` (`build_cumulative`, `countersign`,
`route_regressions`, `route_impact_findings`, `emit_triage_ledger_events`,
`emit_validation_ledger_events`) now print `SignAttempt.warning()` instead of
each hand-rolling the same `status == "failed"` conditional — one renderer,
covering both a broken signer and a dropped signature, so neither can go silent.

`docs/signing-workflow.md` §4.1 documents the behaviour and its consequence for
P8 sequencing: until the key reaches the write path, every write to a signed
layer de-attests it — now visibly.

## v0.290.0 — 2026-08-17

B5 + B6: the last two A15 violators cleared. **The burn-down list is empty and the
gate now stands on its own.**

**B5 — `/vuln-scan`.** The append instruction is gone. Verified new findings become
**one event per finding** on the repo's layer, carrying the claim in
`event.finding`: `source.type: vuln_scan_report`, machine actor,
`disposition: {resolution: "open"}`, claim hash pinned add-only, layer stamped and
signed. The transcription mapping (`cwe` → `cwes[]`, `file`/`line` → `locations`,
`recommendation` → `remediation`) is unchanged — it lands on the event instead of
the baseline.

**B6 — `/track-findings`.** Both routing passages corrected: `regressions[]` route
into *this layer* as findings-carrying events, explicitly not the baseline.

**Three further instances the plan had not catalogued.** B5/B6 were filed as three
line numbers; the stale claim was in three more places:

- **`/vuln-scan`'s frontmatter `description`** — the text an agent reads when
  *choosing* the skill. Leaving it saying "enter the baseline" would have kept
  producing exactly the behaviour A15 forbids: the instruction and the enforcement
  disagreeing at runtime. The most consequential copy of the four.
- `/vuln-scan` SKILL.md's "supplements the baseline" bullet
- `docs/skills.md`'s vuln-scan entry (the public reference)

**A15 is fully burned down.**

```
un-exempted A15 findings: 0
A15 exemptions:           0
```

Both remaining exemptions and the entire burn-down preamble are removed. The tests
now pin **zero violators and zero exemptions**, and the failure message says why: an
exemption reappearing means someone reintroduced a baseline write and grandfathered
it rather than fixing it.

That closes the loop this work opened. The invariant was prose; prose did not hold;
1,709 findings got in. It is now a gate with an empty exception list.

Full suite 2,151 passed; reference integrity clean.

## v0.289.0 — 2026-08-17

docs: `continuous-scanning.md` → **`continuous-operations.md`**; `routers.md` now
covers all **15** routing components; four stale `model_registry` paths fixed.

**The rename.** A doc where a component **drops queued work to fit a dollar
ceiling** is not describable as "continuous scanning". It also carries spend-capture
cadence, credentials for autonomous runs, and the standing dashboard/drift jobs.
31 referencing files swept (docs, 12 `SKILL.md`, 4 CLI modules, 2 config YAMLs,
`PROCESS.md`, `README.md`, tests) — zero residual references. A **redirect stub**
remains at the old path so external links resolve, and states why the rename
happened rather than only pointing away.

**`routers.md` completed.** It claimed four kinds and was missing the two that
matter most for spend:

- **Cost routing** — the budget guard inside `build_rescan_worklist.py` drops
  lowest-tier table-routed full audits to fit `config/budget-policy.yaml`, listing
  them in `dropped_for_budget`; `budget_shadow.py` does observe-mode accounting.
  **Documented with the caveat that the shipped `enforcement` posture is `none`** —
  the ceiling is a documented artifact, not a control. "There is a budget guard"
  and "spend is capped" are different claims and only the first is true today.
- **Model routing** — `traust_engine.registry.models` + `config/model-registry.yaml`,
  which already had [model-routing.md](docs/model-routing.md) and was simply not linked.

Plus a second table for the five **worklist builders** (`emit_drain_tranche`,
`build_verify_sweep`, `build_pqc_worklist`, `fleet_sweep`, `run_impact_sweep`),
listed because each is a selection decision that can silently drop work. The doc
now states both counts — 6 kinds / 15 components — and enumerates the 15, because
"six kinds" next to an earlier 12-component census read like half had been dropped.

**Four stale `model_registry` references.** `scripts/model_registry.py` has not
existed since the package restructure. The reference-integrity gate caught the one
I had just written into `routers.md`; chasing it found three more, two of them
**inside alignment rule A12's own text and failure message** — so a gate was
telling anyone who tripped it to go read a file that no longer exists. The gate
only scans docs, which is why the `.py` occurrences had stayed invisible.

Full suite 2,151 passed; reference integrity clean.

## v0.288.0 — 2026-08-17

docs: `routers.md` — the authoritative index of all four router kinds; and
`continuous-operations.md` brought up to date.

**`docs/routers.md` (new).** One page naming every router, what each may and may
not write, and where its detail lives:

| Kind | Routes | Detail |
|---|---|---|
| Work routing (*rescan router*) | repos → 12 scan lanes | continuous-operations.md |
| Findings routing | producer findings → ledger events | findings-routing.md |
| Owner routing | packages → teams/maintainers | those skills |
| Defect routing | findings → Jira | those skills |

It closes with the distinction that actually caused a defect: the rescan router
and the findings routers are the two most easily confused and do **opposite**
jobs — one answers *what should we scan?* and may never author a finding, the
other answers *what did we find?* and may never write a baseline. They meet at one
point, and it is the point that broke: appending to a baseline recorded a finding
against a commit it was not found at, without the router's re-baseline decision.

**`continuous-operations.md` — three stale claims corrected.** It still said
findings "enter the baseline and disposition ledger", which stopped being true in
v0.284.0/v0.285.0:

- the standing-jobs row for `/dependency-watch`
- §"From signal to accountability" — agent lanes filing findings
- §"Filing" — the dependency-watch chain

All now say the claim rides on the **event** and the baseline is never written
(gate A15), and the dependency row records that dedupe must read event-carried
findings or a daily re-run would re-file.

**Kept the filename.** A rename to cover "all continuous routing" was considered
and rejected: the doc's content genuinely is the rescan loop and its standing
jobs — owner and defect routing are not in it, so a broader name would be less
accurate, not more. It also has 19 inbound references plus external links, and
the ambiguity it was meant to fix is already fixed by `routers.md`. Instead it
gained a scope banner stating which kind of routing it owns and pointing at the
index and its opposite number.

## v0.287.0 — 2026-08-17

docs(findings-routing): correct an overreaching scope claim — it is not the only
kind of routing.

The doc opened by calling itself "the canonical reference for **every** routing
path". That is false, and the name change to `findings-routing.md` was the clue:
four distinct things in this harness are called routing, and only one is in scope.

| Kind | Routes | Implementation |
|---|---|---|
| **Findings routing** | producer findings → ledger events | `route_regressions.py`, `route_impact_findings.py` |
| **Work routing** (*rescan router*) | repos → one of 12 scan lanes | `build_rescan_worklist.py` |
| **Owner routing** | findings packages → teams and maintainers | `/assign-findings-owners`, `/reassign-findings-owners` |
| **Defect routing** | findings → Jira | `/file-security-defect`, `/sync-jira-backlog` |

The scope statement is narrowed, and a table points at where each of the other
three is documented — so a reader who lands here looking for the rescan router is
sent to [continuous-operations.md](docs/continuous-operations.md) instead of concluding it
is undocumented.

Also states the distinction that actually matters, because the rescan router and
the findings routers are easy to confuse and do **opposite** jobs: the rescan
router decides *what work to do* and never authors a finding, verdict or audit;
the findings routers *record work already done* and never decide what to scan.
They meet at exactly one point — the rescan router's authority over when a new
baseline is cut is what a producer appending to a baseline used to bypass.

## v0.286.0 — 2026-08-17

docs: `routing.md` → **`findings-routing.md`**, linked both ways, and §3's
"immutable baseline" finally corrected.

Three fixes to yesterday's routing doc, all from review:

- **Renamed.** `routing.md` sat next to `model-routing.md` — a real collision, and
  "routing" is overloaded here (owner routing, model routing, lane routing). The
  doc is specifically about how a **finding** reaches the ledger.
- **Linked from `disposition-ledger.md`.** The link was one-way: the routing doc
  pointed at the ledger doc, but nothing pointed back, so a reader starting from
  the ledger design would never find the producer side. §10c now links to it.
- **Intro widened.** Routers do more than move findings — they mint campaign ids,
  pin claim hashes, enforce idempotence, write provenance back to the producer's
  report, and stamp and sign the layer. The intro said only "turns findings into
  events".

**And the correction that matters most:** `disposition-ledger.md` §3 *still* called
`<repo>-security-audit.json` "the immutable baseline". I had recorded that fix as
done in the plan; it was not — I added the relocation section to §3 and never
touched the wording. A new subsection now states the precise meaning: only the
three `secure*audit` skills may write one (gate A15); they *do* rewrite it on
re-audit, so what is fixed is the claim set **for a given commit**, which is what
`claim_hashes` pins; and the invariant was not honoured until 2026-08-17, when
1,709 producer-appended findings were found — undetected precisely because the code
called the write "sanctioned" while this document called the baseline immutable.

That pairing is the whole lesson: a doc claiming an invariant and code contradicting
it are individually plausible and jointly invisible. Only the gate closes it.

## v0.285.0 — 2026-08-17

B4: `route_regressions` stops writing the baseline · `docs/routing.md` · one real
defect found while documenting.

**B4.** The second A15 burn-down. This router appended **664 findings** into
`*-security-audit.json`; they now ride on their ledger events, unioned back by
`build_cumulative` at replay. Burn-down **3 → 2** (both remaining are prose).

The `/verify-remediation` "classification rule" the plan called its only
undecided logic turned out to be a non-question: a verification report already
separates `verified_findings[]` (per-finding verdicts → plain disposition events,
already working) from `regressions[]` (audit-grade **new** findings). This router
only ever touched the latter, so B4 is structurally identical to B3.

The genuine decision, now implemented: a regression whose **fingerprint** matches
an existing baseline finding stays a *new* finding at the patched sha — the id
records when it returned and against which commit — but the original's id is
appended to `source_findings`, making the link explicit rather than inferable.
Resolution state is deliberately not consulted: a fingerprint match is the same
vulnerability either way, and the ledger already records whether the original was
resolved.

**A test caught a bug this change introduced.** The baseline append used to
accumulate within the routing loop, so `next_sequence` saw ids minted earlier in
the same run. Without it, two regressions in one report both minted `-001`. The
birth event is now appended to `layer["events"]` **in-loop** rather than after.

**Defect found while writing the docs.** `route_impact_findings` was the only
layer writer that never called `stamp_and_sign` — it relied on
`rebuild_cumulative`, so with `--no-rebuild` it left a **stale merkle_root**,
which traust-ledger v0.1.3 made an ERROR rather than a warning. Fixed, with a test
asserting the written layer is rooted at `leaf_format 2` and verifies clean.
Enumerating the writers for a documentation table surfaced this; reading the code
had not.

**`docs/routing.md`** — canonical routing reference: the baseline-ownership rule
and its 1,709-finding history, all seven layer writers with a stamps/signs column
(which is what made the gap above visible), both findings-carrying routers, all
three idempotence mechanisms and why each had to learn about event-carried
findings, id minting's two failure modes, arrival semantics, and outstanding
items. Also corrects `findings-lifecycle.md`, which still called `/vuln-scan` a
"Step-5 baseline supplement" and described both routers without noting they write
no baseline.

Full suite 2,151 passed.

## v0.284.0 — 2026-08-17

B3: `route_impact_findings` stops writing the baseline.

The first burn-down of gate A15. Until today this router appended **986 findings**
directly into `*-security-audit.json`, mutating the claim set with no event
recording it — replay could not reconstruct a baseline's history and the rescan
router's authority over *when* a new baseline is cut was bypassed. The claim now
rides on the ledger event (`event.finding`, contracts v0.4.4) and
`build_cumulative` unions it back at replay (v0.283.0), so the finding is exactly
as visible while the baseline stays the fixed claim set only the three
`secure*audit` skills may write.

**Two helpers had to move with it**, both of which read `audit["findings"]` and
would otherwise have failed silently:

- `already_filed` — dedupe now also scans event-carried findings. Without it every
  daily `/dependency-watch` re-run would re-file the same CVE+module, because this
  router's own prior filings no longer live in the baseline.
- `next_sequence` (shared with `route_regressions`, so this pre-fixes B4) — id
  minting now counts event-carried ids. Without it the same `NNN` would be
  re-issued at the same sha and collide.

The layer is now loaded **before** dedupe and id minting rather than after, since
both need to see it.

Nine existing tests asserted the finding landed in the baseline — that was the
contract, and it changed deliberately; they now read it off the event via a
`_routed_finding` helper. One new end-to-end test proves a routed finding is
**visible in the cumulative projection** with the baseline untouched: B3 without
B2's union would file findings no dashboard could see, which is tenet 5.

A15 exemption for this router **removed** — burn-down 4 → 3, with the population
test pinned at 3 so a regression fails loudly. Full suite 2,138 passed.

## v0.283.0 — 2026-08-17

B2: `build_cumulative` unions event-carried findings with the baseline's own.

Completes the read side of the baseline-immutability work. Only the three
`secure*audit` skills may write an audit baseline (gate A15, v0.282.0), so a
finding discovered BETWEEN audits rides on its event in an `event.finding` block
(contracts v0.4.4 `$defs/event_finding`). Without this union such a finding would
be recorded, signed, and **invisible to every dashboard** — the failure tenet 5
exists to prevent.

**Three integration points, not one.** The obvious union (the `findings` lookup
dict) only stops arrival events raising "IDs not in the audit report". The report
itself is a deep copy of the *audit*, so an arrival event resolved cleanly and
still never appeared in any output; `verify_claim_hashes` separately reported a
pinned event-carried claim as "missing from the audit report", the opposite of the
truth. All three now union. The middle one was caught by a test, not by reading.

**Precedence: the baseline wins** (`setdefault`, not `update`). Once a re-audit
baselines the same id, the baseline's claim is authoritative and the event-carried
copy is a stale duplicate. This is what lets a supplement be absorbed at re-audit
with no migration — the event stays in history, the baseline takes over.

Release chain, all required because the layer validator loads schemas from the
INSTALLED contracts package: contracts **v0.4.4** -> traust-ledger **v0.1.6**
(`findings_from_events`) -> traust-engine **v0.1.10** -> this.

Census parity verified on 60 real baseline+layer pairs from the corpus: 60/60
project identically, 0 changed, 0 errors, and 0 layers carry event findings today
(the correct expectation, since nothing writes them until B3-B5).

## v0.282.0 — 2026-08-17

gate(A15): only the three secure*audit skills may write an audit baseline.

The disposition ledger's core tenet is **events, not state** — the baseline is the
fixed claim set and every change to what we believe is an event. That invariant
existed only as prose, and prose does not hold: **1,709 findings had been appended
directly into `*-security-audit.json` baselines** by three non-audit producers
(`impact-analysis` 986, `verify-remediation` 664, `vuln-scan` 59). No event records
those additions, so replay cannot reconstruct a baseline's history, and the rescan
router's authority over *when a new baseline is cut* was bypassed.

Three reasons it went unnoticed, each fixed or recorded:

- `route_regressions.py:21` called the write **"the same sanctioned-append flow"** —
  named as sanctioned in code, so no reviewer questioned it
- `docs/disposition-ledger.md` §3 simultaneously called the baseline "immutable", so
  doc and code each looked correct in isolation
- **no gate checked it** — this release closes that

A15 flags any non-owner skill or script that writes a baseline, catching both forms:
the shared `_write(audit_path, audit)` helper the two routers use, and SKILL.md prose
instructing an append. It deliberately does **not** flag reads (producers must still
read the baseline to dedupe) or layer writes (the correct behaviour).

Four EXEMPTIONS grandfather the known violators, each citing the workstream in
`progress-tracker/plans/baseline-immutability-plan.md` that removes it. They are
exemptions rather than failures on purpose: removing an append before
`build_cumulative` can union event-carried findings would make those 1,709 findings
invisible to every dashboard — tenet 5, wrongly dismissing silently deletes real
risk. The list must only ever shrink.

Nothing is lost in the meantime: every appended finding carries `origin` +
`source_findings` and its ID embeds the discovering scan's shortsha, so extraction is
mechanical.

## v0.281.0 — 2026-08-17

deps: contracts v0.4.3 + traust-ledger v0.1.5 + traust-engine v0.1.9 — layer
files with stamped events validate again.

`$defs.event` is `additionalProperties: false`, but the ledger write path
stamps `fingerprint`/`fingerprint_algo` onto every event it writes, so every
stamped layer file failed `traust_engine.reporting.validate`. Undeclared in
contracts 0.3.0 and 0.4.2 alike — not a 0.4.x regression. Measured effect on
the corpus: 49 stamped layer files, of which the 40 untouched by today's
embargo backfill now pass. The other 9 fail on an unrelated stale
`merkle_root_signature` (their Merkle root moved when the backfill appended
events, and `HARNESS_SIGNING_KEY_PATH` is unset per plan P8, so nothing
re-signed them) — see docs/signing-workflow.md §4.

No harness code change; 2115 tests pass.

## v0.280.0 — 2026-08-17

deps: contracts v0.4.2 + traust-ledger v0.1.4 + traust-engine v0.1.8 — the
`disposition.embargo` axis is now writable.

The axis shipped in contracts 0.4.0 on 2026-08-14 but was unusable: both
siblings required `traust-contracts>=0.3,<0.4` and declared their own
`tag = "v0.3.0"` source, so bumping this repo's pin alone failed twice over —
on the version constraint, and on uv's refusal to accept two git URLs for one
package. Adoption was a release train, not a pin bump: traust-ledger 0.1.4 →
traust-engine 0.1.8 → this.

Schemas resolve through the installed package
(`traust_contracts.paths.schema_dir()`), so `disposition` now validates
`embargo` alongside `validity`, `resolution`, and `severity`. No harness code
change; 2115 tests pass unmodified.

## v0.278.0 — 2026-08-14

deps: traust-ledger v0.1.3 + traust-engine v0.1.6 — the last two P6 enforcement
flips now actually enforce.

`verify_merkle_integrity` had warned, not errored, on two conditions:

    metadata.merkle_root absent   a layer with NO tamper-evidence at all
    leaf_format 1 (or absent)     root binds only event_id values, so event
                                  content is editable under a verifying root

Both are errors as of traust-ledger v0.1.3. Neither severity had a test, which is
the same "the check exists but does not enforce" shape the ledger-integrity plan
exists to fix — so the new tests assert the severity itself and were confirmed
to fail when the flips are reverted.

**Why this took three repos.** traust-ledger v0.1.3 was tagged and pushed, but
`traust-engine` v0.1.5 pinned traust-ledger at v0.1.2 in its own
`[tool.uv.sources]`, so `uv lock` refused the resolution outright. The version
bound (`>=0.1.1`) was never the constraint — the git tag was. traust-engine
v0.1.6 repins, and this bump follows it. Until that chain moved, the flips were
tagged but inert everywhere the harness ran.

Test fixtures updated in both repos, for the right reason rather than to go
green: `_valid_layer()` builds an unstamped layer, which is no longer valid, so
`_mutate()` now stamps *after* the mutation — otherwise the merkle error leaks
into every test in the class and masks the condition each one is asserting
(that is what broke `test_occurred_at_before_recorded_at_ok`, which has nothing
to do with Merkle). `test_legacy_layer_without_merkle_warns` and
`test_missing_merkle_root_warns` are renamed to `..._errors` and assert the
error *and* that it is not also emitted as a warning.

Gate prerequisite, worth recording: the flips were blocked on the P3 backfill,
which was recorded as "100% of layers" but had swept `findings/` only — 143
layers in the other corpus trees were unstamped and would have failed the flip
(`analysis-results 486ed6b543` swept them; corpus now 8,508/8,508 rooted at
`leaf_format 2`). Signing remains at zero layers, gated on P8 / XWING-1145.

## v0.277.0 — 2026-08-14

fix(drift): retarget the submodule-staleness guard to pip dependency pins —
the failure class survived the C8 restructure, only its mechanism changed.

C8 swapped the `contracts`/`traust-ledger` git submodules for pip dependencies,
which made `check_submodules` vacuous (it now always reports "repo declares no
submodules"). Deleting it would have been wrong: the class was never "submodules
are stale", it was **"a dependency is not the version this tree expects, and
imports break with an error naming neither the dependency system nor the fix."**

    submodules (2026-08-13): 18 test modules died at collection after v0.267.0
                             bumped traust-ledger -> "cannot import name
                             'stamp_and_sign'"
    pip deps   (2026-08-14): harness_engine simply absent from the venv until
                             `uv sync` -> "No module named 'harness_engine'"

- `check_submodules` -> **`check_dependency_pins`** (`dependency-pins:*` rows):
  compares `importlib.metadata.version()` against the git-tag pins in
  `pyproject.toml` `[tool.uv.sources]`. Absent = `NOT INSTALLED`, mismatch =
  `VERSION SKEW`, refresh hint `uv sync`. Fails open (`unavailable`) on an
  unreadable pyproject — never a false `fresh`.
- Verified against both real failure modes by simulating them, not just by
  reading the logic: absent dep and version skew each report `drift` with the
  right message; the live tree reports fresh/fresh/fresh (contracts 0.3.0,
  traust-ledger 0.1.2, traust-engine 0.1.5, all matching).
- **CI does not cover this**: CI builds its own venv with
  `uv pip install --require-hashes`, guaranteeing the CI environment, not the
  operator workstation where every skill actually runs.
- Docs: drift-watch SKILL + `docs/skills.md` rows (the restructure had dropped
  the old `submodules:*` rows while keeping the code, so docs were already out
  of sync).
- 6 tests replace the 7 submodule ones.

**Known gap.** The point-of-use half of the guard is gone: the restructure
removed `tests/conftest.py`, which failed the suite fast before it could emit
18 confusing collection errors. The drift row catches this on cadence only.

**Unrelated pre-existing failure**, verified against pristine main:
`tests/test_p2_hardening.py::test_p3_sweep_engine_dir_prefix` expects
`../traust-engine/src/harness_engine/sweep/engine.py` — a sibling checkout that
no longer exists now that traust-engine is a pip dependency.

## v0.276.0 — 2026-08-14

refactor(harness): C8 package layout — scripts and shared core move behind
installable modules; skills keep co-located `harnessing/<skill>/scripts/`.

- **Layout:** multi-skill CLIs → `src/traust/cli/` and
  `src/traust/{ops,migrations}/`; scanners, corpus, sweep,
  impact, and adapters → **`traust-engine`** (`python3 -m traust_engine.*`);
  ledger kernel → **`traust-ledger`**; schemas/enums → **`traust-contracts`**
  (pip git deps in `pyproject.toml` / `uv.lock` — no git submodules).
- **Invocation:** skills and docs updated from `scripts/<name>.py` to
  `python3 -m traust.cli.<name>` or the matching
  `harness_engine` module; `check_drift` `rule-mining` refresh points at
  `traust_engine.sweep.rule_lane`.
- **Docs:** `reachability.md` restores the drift-watch coverage note and the
  2026-08-11 Joern usage-vs-reachability correction; `AGENTS.md` lists the
  three sibling package repos and pins.
- **Fix:** `baseline_claims.py` drops the unused `CLAIM_FIELDS` import (lives
  in `traust_ledger.events`; only `compute_claim_hash` is needed).
- **Pins:** `traust-engine` v0.1.5 (rule-lane `emit_rule_drafts` discovery),
  `traust-ledger` v0.1.2, `traust-contracts` v0.3.0.

## v0.275.0 — 2026-08-13

integrity: rebaseline aliases become events, closing the last unprotected replay
dependency (ledger-integrity-remediation-plan P2).

**The gap.** `metadata.finding_aliases` mapped superseded finding ids to their
successors and was resolved at replay. It was **mutable, outside the Merkle
tree, and had no verifier anywhere in the codebase** — unlike `claim_hashes`,
which self-checks against the report. Anyone able to edit it could re-point a
`false_positive` or `accepted_risk` verdict at a different finding and the root
would still verify. **1,418 layers carried one.**

**What changed.** `contracts` adds source_type `rebaseline` and an `alias` block
on `$defs/event`; `traust-ledger` adds `make_alias_event()` /
`aliases_from_events()`; `build_cumulative` merges event-derived aliases **over**
the legacy table, so events are authoritative and the table becomes a
rebuildable projection.

**No migration is forced.** Replay reads both, so layers convert as they are
rewritten — the same rollout shape as `leaf_format 2`. A sweep can convert the
1,418 in bulk later, naturally paired with P3.

**Design points.** An alias states a MAPPING, not a determination, so forcing it
to carry a disposition would pollute validity/resolution counts with fabricated
verdicts; `disposition` therefore accepts an empty object, **gated by if/then to
rebaseline events only** so every other event still requires one. Append-only:
confirmation or rejection is a LATER event for the same `finding_ref`, never an
edit, and replay folds them in order.

Tested: re-pointing `new_finding_ref` breaks the Merkle root, and so does
upgrading `matched_by` to forge a confirmation. Verified on a real layer with 14
legacy aliases — legacy replay still works, and an event supersedes the table.

## v0.274.0 — 2026-08-13

integrity: the fingerprint is now IN the ledger, inside the Merkle tree
(ledger-integrity-remediation-plan P1).

**The gap this closes.** Events bound dispositions to `finding_ref`, which is
scan-scoped and changes on every re-audit. The break was repaired at replay
through `metadata.finding_aliases` — a mutable table, **outside** the Merkle
tree, with no verifier anywhere in the codebase. Measured before this change:
**0 of 122,982 events carried a fingerprint**, so an event could only be
interpreted by consulting an unsigned report plus an unprotected table. That is
not meaningfully an append-only record.

**What changed.** `contracts` gains `fingerprint` + `fingerprint_algo` on
`$defs/event`; `traust-ledger` gains `fingerprint_index()` / `attach_identity()`;
`build_cumulative` stamps every event before stamping the Merkle root.

**It is tamper-evident for free.** Under `leaf_format 2` the leaf is the
canonical JSON of the whole event, so the fingerprint lands inside the tree with
no change to `merkle.py`. Proven by test: editing a fingerprint breaks the root,
and so does editing the `fingerprint_algo` marker — a recipe change cannot be
backdated silently.

**`fingerprint_algo` closes a real versioning gap.** The stamped value in report
JSON is a bare 64-hex hash with no version marker, so without this field a future
recipe bump would be indistinguishable from v1 and migration would be impossible.

**Design constraints held deliberately:**
- Identity is **read**, never recomputed — the harness is the sole producer
  (decision 3D), so a consumer that recomputes is a second implementation
  waiting to diverge.
- An existing value is **never overwritten**. An event is a historical
  observation: if identity later changes, that is a NEW event, because "at time
  T this finding's identity was X" stays true forever.
- `event_id` is **untouched** — it is the validator-enforced idempotency key, and
  re-keying it would orphan every existing event.
- Not added to `required`: historical events do not carry it.
- `LayerEvent` in the Pydantic bindings had to declare both fields even though
  `ContractModel` sets `extra="ignore"` — otherwise a round-trip would silently
  DROP the identity and writing it back would break the root.

First real layer stamped: 21 of 21 events, verified clean, and a tampered
fingerprint correctly breaks the root.

## v0.273.0 — 2026-08-13

fix(gates): scan for unresolved git conflict markers — the gap that let a
conflicted CHANGELOG.md reach main.

Yesterday a rebase-resolution script failed silently (its regex did not
match), `git rebase --continue` committed the conflicted file anyway, and
`052b24c` pushed six conflict markers to main. All four gates passed,
because not one of them looked for markers.

- `check_docs_consistency.conflict_marker_failures` — scans every tracked
  text file (binary extensions skipped, unreadable files ignored) and
  fails on `<<<<<<< ` or `

  a conflicted file makes the other checks emit confusing downstream noise.
- **`=======` is deliberately not a trigger**: it is a legitimate Markdown
  setext H1 underline, so triggering on it would false-positive on
  ordinary docs. The two directional markers have no legitimate line-start
  use, and a conflict always carries at least one. Verified both ways — it
  catches the exact CHANGELOG shape that shipped, and passes a setext
  heading.
- Opt-out `docs-check: allow-conflict-markers` for docs that legitimately
  demonstrate conflict resolution; fails open when git cannot list files.
- +7 tests.

## v0.272.0 — 2026-08-13

metrics: fix the one dashboard the symlink trap actually broke, and correct
yesterday's over-broad guard.

**Correction to v0.270.0.** That release claimed 22 committed scripts carried
the symlink trap and that several dashboards' totals were likely inflated. The
guard flagged the wrong shape. Measured on Python 3.14 against the real corpus:

| Enumeration | Hits | Distinct | Inflation |
|---|---|---|---|
| `glob.glob("findings/**/…", recursive=True)` | 21,929 | 8,270 | **2.65x** |
| `Path("findings").rglob("…")` | 8,235 | 8,135 | **1.01x** |

`glob.glob` with `**` follows directory symlinks; **pathlib's `rglob` does not**
(3.13+). Of the 22 flagged, 21 were pathlib or directory-scoped and materially
fine — a 1.2% overcount from ~100 file-level symlinks in real directories, worth
fixing in anything that publishes a number but not a catastrophe. **Exactly one
was really wrong: `build_insecure_patterns.py`.** Flagging the wrong shape is
worse than not flagging, because it buries the one real defect in noise, so the
guard now matches `glob.glob(..., recursive=True)` only and the 22-entry burndown
is deleted rather than carried.

**`build_insecure_patterns.py` switched to `corpus.walk_reports()`.** Measured
delta on the published dashboard:

| Metric | Before | After | Change |
|---|---|---|---|
| Reports scanned | 21,929 | 8,135 | **−62.9%** |
| Total findings | 195,322 | 73,682 | **−62.3%** |
| Source-code findings | 78,652 | 29,806 | **−62.1%** |
| Reports with dispositions | 8,136 | 3,710 | −54.4% |

**The rankings were approximately right; the totals were not.** 217 of 332 CWE
rows are byte-identical, and the largest per-CWE shifts are ~10% (CWE-22
408→368, CWE-1104 763→744, CWE-295 922→909) — because occurrences were already
deduped by `(repo, cwe, path)`, which absorbed most of the duplication. But 11
CWE rows disappear entirely and the top-25 ORDER does change, so this is a real
correction to a published artefact, not a cosmetic one.

**New: `corpus.walk_reports(root, suffix)`** — drop-in replacement for
`root.rglob("*" + suffix)` that yields each physical report once.

fix: close the submodule-staleness trap — a stale pin silently broke a
third of the test suite.

**The incident (2026-08-13).** v0.267.0 bumped the `traust-ledger` pin. A
working copy still on the old commit failed 18 test modules at collection
with errors naming neither git nor submodules:

    ImportError: cannot import name 'stamp_and_sign' from
                 'traust_ledger.integrity'
    ImportError: cannot import name 'RESULT_LINE' from 'countersign'

The pre-push docs gate already REQUIRED the submodules initialized (it
resolves backtick paths into `contracts/schemas`), so the trap was
half-built: initialization was mandatory, but the *commit* was never
verified. Two guards now close it, at both the point of use and on the
cadence:

- **`tests/conftest.py`** (new) — a `pytest_configure` guard that reads
  `git submodule status --recursive` and refuses to start the suite when
  any submodule is uninitialized (`-`), off the pin (`+`), or conflicted
  (`U`), printing the drifted paths and `git submodule update --init
  --recursive`. Converts 18 confusing collection errors into one
  actionable message. **Fails open** on missing git / missing
  `.gitmodules` / unreadable status — a tooling problem must never block
  the suite.
- **`check_drift.check_submodules`** → `submodules:*` rows, the cadence
  backstop for a checkout nobody has run tests in. Reports `unavailable`
  rather than a false `fresh` when git cannot answer.

Verified by reproducing the incident: desynced `traust-ledger` to its
parent commit, confirmed the drift row reports OUT OF SYNC and pytest
refuses to run, then restored the pin. +7 tests.

## v0.271.0 — 2026-08-13

fix: close the submodule-staleness trap — a stale pin silently broke a
third of the test suite.

**The incident (2026-08-13).** v0.267.0 bumped the `traust-ledger` pin. A
working copy still on the old commit failed 18 test modules at collection
with errors naming neither git nor submodules:

    ImportError: cannot import name 'stamp_and_sign' from
                 'traust_ledger.integrity'
    ImportError: cannot import name 'RESULT_LINE' from 'countersign'

The pre-push docs gate already REQUIRED the submodules initialized (it
resolves backtick paths into `contracts/schemas`), so the trap was
half-built: initialization was mandatory, but the *commit* was never
verified. Two guards now close it, at both the point of use and on the
cadence:

- **`tests/conftest.py`** (new) — a `pytest_configure` guard that reads
  `git submodule status --recursive` and refuses to start the suite when
  any submodule is uninitialized (`-`), off the pin (`+`), or conflicted
  (`U`), printing the drifted paths and `git submodule update --init
  --recursive`. Converts 18 confusing collection errors into one
  actionable message. **Fails open** on missing git / missing
  `.gitmodules` / unreadable status — a tooling problem must never block
  the suite.
- **`check_drift.check_submodules`** → `submodules:*` rows, the cadence
  backstop for a checkout nobody has run tests in. Reports `unavailable`
  rather than a false `fresh` when git cannot answer.

Verified by reproducing the incident: desynced `traust-ledger` to its
parent commit, confirmed the drift row reports OUT OF SYNC and pytest
refuses to run, then restored the pin. +7 tests.

## v0.270.0 — 2026-08-13

integrity: enforce what the campaign has been measuring — both identity gates
become errors, and the symlink trap that inflated every count is now guarded.

**Two gates flipped from warning to ERROR.**
- **Absent `fingerprint`** (plan P6). It was advisory while the corpus still
  held unstamped findings; it no longer does. Without the flip P0.4's backfill
  was a snapshot rather than a floor — nothing stopped the next unstamped report
  from landing, which is the mechanism-without-enforcement pattern this campaign
  exists to break.
- **Malformed `metadata.repository`** (plan P0.2). It shipped soft only because
  45 org-stub reports would have failed the corpus; those were dropped
  (`analysis-results cc936d062c`), so the corpus holds **zero** malformed values.

Verified against a 60-report random sample of the deduped corpus: 60/60 pass
under both.

**`normalize_repository()` at the stamping boundary.** 211 corpus reports
carried a valid URL wrapped in markdown autolink brackets, so `<` and `>` were
hashed into finding identity. `annotate_report` now repairs the field — and
writes the repaired value back — before hashing, so a transcription artefact
cannot survive long enough to reach the hash. Only unambiguous repairs are
applied (autolink brackets, missing scheme); an org-only URL or free prose is
left alone for the validator, because guessing a missing repository name would
fabricate identity rather than repair it.

**This is deliberately NOT in `canon_repo`.** Making the hash function tolerant
would change the recipe and re-identify the entire corpus. The recipe has been
byte-stable since `c329ea8` (2026-07-16) and stays that way; this repairs the
DATA, so the stored value and the hash always agree.

**Symlink guard: `corpus.iter_report_paths()` + `corpus.canonical()`, and
`tests/test_corpus_glob_guard.py`.** `findings/_orgs/` is a symlink index, so a
recursive glob counts the same physical file many times — measured **22,306 glob
hits against 8,513 distinct reports**, a 2.6x inflation. Git also refuses to
traverse those paths, so a symlinked report reads as untracked or brand-new.

The guard found **22 committed scripts** with the same trap, several of which
aggregate (`build_insecure_patterns`, `build_loc_dashboard`,
`build_rescan_worklist`, `mine_ledger_truepositives`, `countersign`) — so their
totals are very likely inflated today, the "duplication" vector in
`metrics-reconciliation.md`. They ship as a **dated burndown allowlist** rather
than a day-one failure, and the guard blocks new ones and refuses to let the
list grow.

## v0.269.0 — 2026-08-13

integrity: validate `metadata.repository`, the first field of the fingerprint
payload (ledger-integrity-remediation-plan P0.2).

**Why:** the fingerprint is `sha256(canon_repo | sorted paths | primary_cwe)`,
so a malformed repository silently yields a wrong cross-scan identity — and
under decision 3D the downstream platform reads that stamp as authoritative
rather than computing its own. The field is schema-typed as a bare string with
no pattern, and `canon_repo(None)` returns `""`, so a report with no repository
stamps happily over an empty repo component.

**Found:** 258 audit reports carried a malformed value — three distinct
problems, not one:
- **211** wrapped in markdown autolink brackets (`<https://github.com/org/repo>`)
  — a valid URL whose brackets were being hashed into the identity.
- **2** missing the `https://` scheme.
- **45** pointing at an **org** rather than a repo. Not fixed, deliberately:
  every one is a stub conversion (finding id `NONE-000`, locations `(none)`,
  scope "converted from Markdown audit report"). Inventing a repo URL would
  fabricate precision they never had. Whether they belong in the corpus is a
  data-quality question, not an identity one.

The first two groups were corrected and re-identified in `analysis-results`
(`1c1ab74e09`, 109 distinct files), verified lossless first: the 213 layers
beside them reference none of the old fingerprint values. Corpus remains
199,583 findings, 100.0000% stamped, 0 mismatched.

**Check added as a WARNING, not an error.** Those 45 stubs still validate
today, so an error would fail the corpus — which is how a check gets reverted
instead of respected. The flip is gated on resolving them.

reachability: library-side entry-point expansion — the missing hop, built
with promotion OFF (operator decision "d").

**The problem it addresses.** The 2026-08-11 measurement showed 0 of 120
maven in-range pairs promoting to `affected` even after every tier defect
was fixed, because the first-party CPG cannot contain the library's
internal methods that advisories actually name. Spring4Shell's symbol
sits THREE hops below the nearest public API, inside spring-beans.

- **`scripts/expand_advisory_entry_points.py`** (new) — advisory symbol →
  library JAR from Maven Central (pinned, sha256 recorded) → CPG of the
  library alone → transitive PUBLIC callers. Verified end to end on
  Spring4Shell/spring-beans 5.3.17: **depth 3 → 2 entry points**
  (`BeanUtils.getPropertyDescriptors`, `getPropertyDescriptor`),
  **depth 5 → 14** (adds the far broader `copyProperties` plus
  reflection-mediated frames). Depth is therefore a PRECISION DIAL, not a
  constant, and every artifact records the depth it used.
- **PROMOTION IS OFF** (decision "d"): an entry-point hit is
  `symbol-usage` (ceiling `likely_affected`), never `symbol`/`affected`,
  until a calibration run measures precision and coverage and an owner
  enables it. Declared in the artifact itself and asserted by test, so a
  consumer cannot read the output and promote. Same posture as the B4
  taint enumerator — routing weight in proportion to measured agreement.
- **CPG cache keyed by `artifact@version + joern version`** — a CPG is
  per library, never per advisory or per repo. Measured: second run is a
  cache HIT in 5.5s (no download, no rebuild). A joern upgrade changes
  the key, so a stale graph is never served silently.
- **Cross-JAR limit named on every artifact** (`coverage_gaps`):
  expansion sees only the downloaded artifact, so Spring4Shell's canonical
  `DataBinder.bind` (spring-context, a DIFFERENT jar) is invisible.
  Coverage is partial by construction and says so.
- **JDK <= 21 gate**: jimple2cpg's bundled Soot/ASM cannot read newer
  class files ("Unsupported class file major version 70" on JDK 26) — the
  script validates up front and skips with the reason rather than
  emitting an empty result that reads like "no path exists". Verified on
  Temurin 21.0.12+8, pinned by sha256, selected per-lane via
  `JIMPLE_JAVA_HOME` (never the workstation default).
- **docs/external-dependencies.md**: the JDK row now covers the **JVM
  runtime every Joern tier has implicitly required since v0.231.0** — the
  subprocess scan never sees `java` because joern ships shell wrappers, so
  the row was incomplete for two weeks; plus a new `jimple2cpg` row and
  the JDK-21 pin with its reason.
- +8 tests.


## v0.268.0 — 2026-08-13

refactor: package layout, git-tag sibling deps, and CI install via uv.

**What:** multi-skill CLIs move from `scripts/` to `src/traust/`
(`cli/`, `ops/`, `migrations/`); per-skill scripts consolidate under
`harnessing/<skill>/scripts/`. `contracts/` and `traust-ledger/` submodules
drop in favour of pip git-tag deps (`traust-engine`, `traust-contracts`,
`traust-ledger`) in `pyproject.toml` / `[tool.uv.sources]`. CI installs the
editable package with `uv pip install -e .` (plain `pip` cannot resolve the
git sources). Reachability tools from v0.264 (`resolve_advisory_symbols`,
`run_impact_sweep`) land under `src/traust/cli/` with `-m` entry
points. Rebased onto main v0.267.0–v0.268.0 (ledger signing, integrity guards,
`metadata.repository` fingerprint check ported to `traust-engine`).

integrity: validate `metadata.repository`, the first field of the fingerprint
payload (ledger-integrity-remediation-plan P0.2).

**Why:** the fingerprint is `sha256(canon_repo | sorted paths | primary_cwe)`,
so a malformed repository silently yields a wrong cross-scan identity — and
under decision 3D the downstream platform reads that stamp as authoritative
rather than computing its own. The field is schema-typed as a bare string with
no pattern, and `canon_repo(None)` returns `""`, so a report with no repository
stamps happily over an empty repo component.

**Found:** 258 audit reports carried a malformed value — three distinct
problems, not one:
- **211** wrapped in markdown autolink brackets (`<https://github.com/org/repo>`)
  — a valid URL whose brackets were being hashed into the identity.
- **2** missing the `https://` scheme.
- **45** pointing at an **org** rather than a repo. Not fixed, deliberately:
  every one is a stub conversion (finding id `NONE-000`, locations `(none)`,
  scope "converted from Markdown audit report"). Inventing a repo URL would
  fabricate precision they never had. Whether they belong in the corpus is a
  data-quality question, not an identity one.

The first two groups were corrected and re-identified in `analysis-results`
(`1c1ab74e09`, 109 distinct files), verified lossless first: the 213 layers
beside them reference none of the old fingerprint values. Corpus remains
199,583 findings, 100.0000% stamped, 0 mismatched.

**Check added as a WARNING, not an error.** Those 45 stubs still validate
today, so an error would fail the corpus — which is how a check gets reverted
instead of respected. The flip is gated on resolving them.

## v0.267.0 — 2026-08-12

integrity: make "ledger signatures are never published" a config-declared policy
with an enforcing guard, not just a flag.

**Why:** the v3 port suppressed cosign's public-transparency-log default with
`--use-signing-config=false --tlog-upload=false`, but flags are not a durable
defence — `--tlog-upload=false` alone is *rejected* under v3's default signing
config, and `--output-signature` went from deprecated to hard-failing. The
contract changed once and can change again. Publishing the timing of every
disposition-ledger write to an irrevocable public log is not a recoverable
mistake.

**What:** three layers.
1. Flags (as before) — necessary, fragile.
2. **Declared policy** — `config/external-tools.yaml`, cosign entry:
   `signing_policy.transparency_log: forbidden`, with the hazard documented
   inline where a version-bumper will actually read it, plus `ledger-signing`
   added to the tool's consumers (it was listed only for
   secure-container-audit).
3. **Post-condition (traust-ledger `ad25f9e`)** — `CosignBackend.sign` inspects
   the emitted bundle and **discards** any signature carrying `tlogEntries` or
   RFC3161 timestamps unless `rekor=True` was explicitly requested. Version-
   independent: it verifies the artifact rather than trusting the CLI. Losing a
   signature is recoverable; leaking is not.

If a cosign bump starts failing with `REFUSING the signature`, that is the guard
working — fix the flags, never relax the guard.

**Also corrected:** getting signatures into SCI is not the "one config step"
previously described. It needs an `sci-api` controller change (secret volume +
`HARNESS_SIGNING_KEY_PATH` + `COSIGN_PASSWORD`), **cosign added to the worker
image** — currently absent, so signing cannot run there even with the key
mounted — and the app-interface namespace entry. Filed as XWING-1145 and added
to the plan as workstream P8.

## v0.266.0 — 2026-08-12

integrity: port the cosign backend to v3, commit the ledger signing public key,
and default verification to it. **The ledger can now actually be signed**
(ledger-integrity-remediation-plan P4).

**Signing works.** Verified end to end against the real key in Vault: a stamped
layer signs, the signature verifies against the committed public key, and a
tampered `merkle_root` is rejected. Previously 0 of 22,206 layers were signed
and nothing could have signed them.

**The cosign v3 port.** v3 changed three things:
- `--output-signature` hard-fails; the signature arrives inside a Sigstore
  bundle written to a file (no stdout mode), so the backend round-trips through
  a temp dir and compacts the JSON to one line for layer metadata.
- **Without `--use-signing-config=false`, v3 uploads to the PUBLIC
  `rekor.sigstore.dev` by default.** For an internal security ledger that
  publishes the timing of every ledger write to an irrevocable public log, makes
  signing depend on Sigstore's availability, and inflates the bundle from ~390
  bytes to ~3.8 KB (~84 MB vs ~9 MB across the corpus). The backend now signs
  offline unless `rekor=True`; a regression test asserts zero `tlogEntries`.
- Verification accepts a v3 bundle or a v2 bare signature, so anything signed
  under the old contract stays verifiable.

**Public key committed** at `config/ledger-signing-key.pub`, and
`validate_report.py` falls back to it when neither `--signing-pubkey` nor
`HARNESS_SIGNING_VERIFY_PUBKEY` is set — verifying a signed layer must never
require a Vault token. It lives in `config/` rather than either submodule so
rotation is one commit rather than a submodule commit plus a pointer bump, and
so key and verifier cannot version-skew.

`config/README.md` documents the fingerprint
(`c206b98f...8c7bb8ec`), rotation, and why the fingerprint is also recorded
outside this repo: a public key committed to the repository whose output it
verifies is only as trustworthy as write access to that repository.

**Private key** lives in Vault at
`app-interface/data/source-code-intelligence/prod/ledger_key` (fields `key`,
`password`, `pub`). The orchestrator maps `key` to a file for
`HARNESS_SIGNING_KEY_PATH` and `password` to `COSIGN_PASSWORD`.

## v0.265.0 — 2026-08-12

integrity: wire signing into the ledger write path, and fix the cosign
`sign-blob` invocation that meant keypair signing had never worked
(ledger-integrity-remediation-plan P4).

**Why:** every writer stamped a Merkle root; nothing ever signed one. Signing
lived only in `scripts/sign_merkle_root.py`, whose method and key are CLI flags,
and no write path invoked it. Measured result: **0 of 22,206 corpus layers
signed**. An unsigned root detects an accident but not an adversary — anyone who
can edit events can restamp and the root verifies again.

**What:** new `sign_if_configured(layer)` and `stamp_and_sign(layer)` in
`traust_ledger.integrity`. All five writers (`countersign`, `route_regressions`,
`emit_triage_ledger_events`, `emit_validation_ledger_events`,
`build_cumulative`) now call `stamp_and_sign`, so "stamped" and "signed" cannot
drift apart and the stamp-then-sign ordering can't be open-coded backwards.

Three outcomes, deliberately distinguished: `unconfigured` is a silent no-op
(the current state — no key is provisioned, so wiring is safe); `signed` writes
the signature metadata; `failed` warns on stderr and writes nothing. `failed` is
never silent, because a configured-but-broken signer that degrades quietly is
how a ledger ends up unsigned while everyone believes it is signed. Enforcement
stays with the validator (`HARNESS_SIGNING_REQUIRED`), not the writer — a writer
that refused to emit an unsigned layer would stall ingestion.

**Bug found while wiring:** `CosignBackend.sign` piped the payload on stdin but
never passed the positional blob argument, so every invocation failed with
`requires at least 1 arg(s), only received 0`. `verify` always passed its `-`;
only `sign` was missing it. Keypair signing had therefore never succeeded from
the CLI either — the other half of why no layer carries a signature. Fixed.

**Still blocked (documented, not fixed):** with that corrected, cosign **v3.1.3**
rejects the rest of the invocation — `--output-signature` is deprecated in favour
of `--bundle`, and `--tlog-upload=false` now requires a `--signing-config` with
no Rekor URLs. The backend was written against v2.x. Either pin v2 or port to
v3's bundle format, which is a signature-format migration rather than a flag
swap. `docs/external-dependencies.md` now records cosign as the signing backend
with the v2-only constraint — it previously listed cosign only for
container-audit signature checks, with no version pin, which is why the drift
went unnoticed.

**Not done:** no signing key is provisioned. Until one exists the write path
stamps and does not sign, by design.

## v0.264.0 — 2026-08-11

reachability: two tier defects fixed, symbol resolver + sweep executor
added, and the Joern tiers' capability corrected in the docs after the
first-ever measurement.

**The measurement.** A full 52-advisory Maven sweep promoted **0 of 120**
in-range pairs to `affected` — before AND after fixing every defect found.
Root cause is architectural: the CPG holds first-party sources only, but
advisories name library-INTERNAL methods
(`CachedIntrospectionResults#introspectInterfaces`), which first-party
code never calls directly. The call site cannot exist in the graph. This
applies to every language, so a Python/JS frontend would inherit it.

- **Wrong Joern frontend (bug).** `run_joern_reachability.py` never passed
  a frontend to joern-parse. Auto-detect reports `language: JAVA` and
  invokes **jimple2cpg** (BYTECODE) whenever compiled artifacts are
  present — it failed outright on konveyor/rulesets and syndesisio/
  syndesis (41 of the sweep's tier outcomes). Worse is the silent case:
  jimple2cpg emits different methodFullName shapes, so patterns miss and
  the tier reports an honest-looking `no_call_sites_found`. Now explicit
  (`JAVASRC`/`NEWC`; both `newc` and `c` map to c2cpg, so C was
  unaffected). **Tier errors 41 -> 0.**
- **Wrong Maven package prefix (bug).** The group-id heuristic emitted
  `com.fasterxml.jackson.core.` for jackson-databind, whose classes are in
  `com.fasterxml.jackson.databind` — 20 of 52 advisories querying a
  package that cannot exist (same for `com.h2database:h2` -> `org.h2`,
  tomcat-catalina -> `org.apache.catalina`). Replaced with
  `derive_packages_from_imports()`: prefixes the tree ACTUALLY imports,
  ranked by coordinate-token specificity so a weak one-token match
  (`io.quarkus.jackson`) loses to the real package. **Call-site evidence
  12 -> 48.** Group heuristic retained as a labelled last resort.
- Bare `Class#method` symbols could never match (methodFullName is
  package-qualified vs a startsWith query) — added a `~` contains mode.
- **`scripts/resolve_advisory_symbols.py`** (new) — advisory -> fix commit
  -> changed method declarations, package-qualified from the file path.
  Aliases only, never `related` (following it pulled a com.amazon.redshift
  symbol into a pgjdbc advisory — a foreign symbol in a promotion query is
  how a wrong `affected` gets minted). Alias walk is bidirectional: the
  fix commit lives on whichever form the curator populated. Coverage on
  the real Maven set: **29% resolved**, 40% `no_symbols_in_diff` (the fix
  is data — a deny-list entry — not code), 31% no commit reference.
  Correctly built, and blocked by the architecture above.
- **`scripts/run_impact_sweep.py`** (new) — the missing consumer of the
  `impact_argv` arrays `fleet_sweep.py` has always emitted. Nothing ever
  ran them, which is why 219 of 220 pypi+npm advisories had never been
  analyzed. Resumable, error-streak gated, `--out-dir` so a measurement
  run cannot clobber the baseline it is compared against.
- **docs corrected**: `reachability.md` and `language-support.md`
  described the Java/C tiers as symbol-level reachability. They deliver
  `symbol-usage` (usage evidence). Only Go delivers reachability, because
  govulncheck analyses dependency code too. Closing this needs dependency
  code in the graph — for Java that is jimple2cpg, the frontend this
  release stops using by accident and should start using on purpose.
- +8 tests (3,039 pass).

## v0.263.0 — 2026-08-11

integrity: `check_finding_identity` verifies the fingerprint instead of
merely noticing one is present (ledger-integrity-remediation-plan P0.1).

**Why:** the check tested `if not f.get("fingerprint")` — presence only —
and the schema pattern `^[0-9a-f]{64}$` constrains shape only. Any 64 hex
characters passed both. That was tolerable while every consumer recomputed
identity for itself; it is not tolerable under the 3D decision, where the
downstream platform stops computing and reads this stamp as authoritative.
A stamp nothing verifies is not an identity.

**What:** absent `fingerprint` still warns (flipping that to an error is
gated on the re-stamp backfill, plan P0.4/P6); a fingerprint the recipe
does not reproduce is now an **error**. Verification needs nothing
external — the value is a pure function of the report's own contents, so
the check recomputes it via `traust_ledger.identity.fingerprint`.

**Found on first run.** Across 22,351 audit reports / 197,658 findings:
195,245 correct, 1,807 absent, and **606 mismatched across 58 report files**
(19 distinct, duplicated across product directories). Every mismatching
report has `metadata.harness_version` unset, 56 of 58 use non-canonical
finding ids, and 8 have some findings correct and some not — which
`annotate_report` cannot produce. The recipe has never changed (single
commit c329ea8, 2026-07-16, before its extraction into traust-ledger), so
these are not a migration artifact: they are stamps the recipe never
wrote. They are **not** re-stamped by this change, because re-stamping
alters those findings' cross-scan identity and needs a
disposition-continuity check first (plan P0.4).

Tests: the suites that asserted a fabricated stamp validates clean now
assert the opposite; added coverage for single-character tampering,
absent-and-mismatched reported separately, and `metadata.repository` being
re-pointed after stamping (which silently re-identifies every finding).

## v0.262.0 - 2026-08-11

refactor(contracts): extract the contract surface and ledger kernel into
pinned git submodules — `contracts/` (traust-contracts: `schemas/`,
`enums/`, golden identity vectors, `validate.py`) replaces the repo-root
`schema/` directory, and `traust-ledger/` (the `ledger_core` package)
replaces `scripts/integrity/` plus the identity recipe formerly inlined
in `scripts/finding_identity.py`.

- **Layout:** every schema path is now `contracts/schemas/<name>.schema.json`;
  the golden-vector oracle lives at
  `contracts/vectors/finding-identity-golden-vectors.json` with its digest
  pinned by `contracts/tests/test_compat.py`. The identity recipe
  (`canon_repo`/`canon_path`/`primary_cwe`/`fingerprint`) and the
  merkle/signing/event code are edited in traust-ledger; harness scripts
  import them, never redefine them.
- **Import seam:** new `scripts/repo_paths.py` is the single source of
  truth for the submodule layout (`SCHEMA_DIR`, `schema_path()`,
  `ensure_ledger_core_importable()`); the previously hand-rolled
  `sys.path` inserts across scripts, harnessing, and tests now route
  through it and fail closed with a `git submodule update --init` hint
  on an uninitialized clone.
- **Tests:** merkle, sigstore, and identity suites moved to traust-ledger
  (242 tests there); the harness keeps its integration seams. Harness
  baseline is now 2767 passed / 3 skipped.
- **CI:** submodules fetched with `GIT_SUBMODULE_STRATEGY: normal`
  (top-level only — traust-ledger's nested contracts pin is never
  materialized in harness CI).

## v0.262.0 — 2026-08-11

reachability: close the two loose ends left by the 2026-07-31 Joern
landing, and scope the Python/JS pilot the language-support gap list has
been pointing at.

**Why:** the reachability investment to date landed on the minority of
the advisory surface. Per the dependency-exposure dashboard (generated
2026-08-06), pypi (129) + npm (91) hold **220 of 346 live dependency
advisories (64%) with no symbol-tier engine**, against 109 (31%) in the
two ecosystems that have one. By portfolio language mass the inversion is
the same shape: Java (98 dominant repos) and C/C++ (20) got tiers while
Python (599), TypeScript (226), and JavaScript (80) did not.

- **`config/external-tools.yaml`: joern freshness row** — joern was an
  externally-pinned PATH tool with no `external-tools` row, so nothing
  noticed a stale local install the way it does for govulncheck. Three
  real hazards found and handled while wiring it:
  - `version_regex` MUST anchor on joern's banner (`Version:\s*…`).
    joern has no working `--version` (the arg is unrecognized, so the
    launcher banners and drops into the REPL) and the surrounding output
    quotes OTHER semvers — the brew Cellar install path and the bundled
    `scala-library-3.8.3.jar`. The bare-first-semver heuristic read the
    Cellar path version by luck on this workstation and would read
    3.8.3 on any layout without it: a wrong number compared against a
    real upstream tag.
  - `_installed_tool_version` now **DEVNULLs stdin** — a REPL-
    fallthrough probe would otherwise read the drift run's own input.
    Applies to every probed tool, not just joern.
  - new `_UNTAGGED` sentinel: a probe answering with a build marker
    (`HEAD`/`SNAPSHOT`/nightly) instead of a release semver reports
    `unavailable` with the reinstall-a-tagged-release action, rather
    than being compared as a version. Extends the existing unstamped-
    `go install` v0.0.0 precedent; the brew HEAD joern hits it.
  - `joern` added to `_VERSION_CMD_BINARIES` (without it the whole
    roster load fails loudly and every external-tool row goes blind).
- **New drift check `check_reachability_coverage`** (rows
  `reachability-coverage:*`, `reachability-watch:review`) — the sibling
  of `language-coverage:*` one rung up the evidence ladder: that row asks
  whether a language's dependency graph is built, this one whether a
  finding in it can ever reach `affected`. A language dominant in >=
  `REACHABILITY_COVERAGE_THRESHOLD` (50) repos with no
  `REACHABILITY_ENGINES` entry and no no-deps excuse = **drift**,
  reported with its repo mass so the priority ordering is visible. Fires
  today on Python/TypeScript/JavaScript. Wiring an engine means adding
  its language to the map — an un-updated map keeps flagging (loud)
  rather than silently claiming coverage. Language-mass parsing factored
  into a shared `_language_mass()` so the two tripwires cannot disagree.
- **`progress-tracker/configs/reachability-watch.yaml`** (new, sibling
  repo) — the dated review clock for the W3 revisit triggers (does OSV
  carry call-graph data; has a permissively-licensed engine matured).
  W3 filed these as a "drift-watch A-class candidate" that was never
  wired, so nothing would have reported a fired trigger — and meanwhile
  one of W3's own premises expired: it listed Java as having no
  adoptable equivalent, and Java shipped via Joern. Reviewed-date
  convention matches the compliance catalogs.
- **`progress-tracker/plans/joern-python-js-reachability-pilot-plan.md`**
  (new, sibling repo) — SCOPED, NOT STARTED. Phase 0 ground-truth corpus
  is the gate; Phase 1 publishes numbers before any wiring. Key framing:
  under promotion-only semantics **precision gates the pilot and recall
  does not** (a missed site costs nothing; a false site fabricates
  `affected` with a `joern_witness`), the viability crux is the
  unresolved-callee share on dynamically-typed calls, and stopping at
  Phase 1 with a published negative is a successful outcome. Licensing is
  explicitly NOT the blocker — pysrc2cpg/jssrc2cpg are in the same
  Apache-2.0 binary already in use; frontend maturity is.
- docs: `reachability.md` (coverage now tracked, not just documented),
  `language-support.md` gap entry, drift-watch SKILL row,
  `external-dependencies.md` joern row (C/C++ + taint-enumerator
  consumers were also missing) — plus stage 4a in
  `reachability-integration-plan.md`. +18 tests (3,033 pass).

## v0.260.2 — 2026-08-11

fix(ci): enable a runner for the gate pipeline — the 2026-07-31 server-side
gate boundary had never executed a job.

- **Root cause:** no job in `.gitlab-ci.yml` declared `tags:`, so every
  pipeline queued indefinitely for an untagged runner that never claimed
  it. No project in `hybrid-platforms-sec` used runner tags at all. The
  non-bypassable gate was declarative only.
- **Runner:** `tags: [itup-alm-x86]` in the `default:` block — the
  IT-managed shared runners, zero registration. Their limits don't bind
  this pipeline (no privileged containers needed; 6h cap vs a ~1min
  pipeline). Documented in-file: C4 non-production, so no release/deploy
  job may be added, and no CI variables or secrets belong on a
  multi-tenant runner.
- **Two defects only a never-run pipeline could hide, both fixed:**
  `tests:pytest` installed just PyYAML + pytest while seven test modules
  import `jsonschema` at module scope (several also `referencing`) — the
  job would have failed at collection on its first real run; and the
  inline pins had drifted from `requirements.lock` (`pytest` 8.3.4 vs
  9.1.1, PyYAML 6.0.2 vs 6.0.3).
- **Install split:** `default:` installs pinned PyYAML (all the gates
  need); `tests:pytest` overrides it with
  `pip install --require-hashes -r requirements.lock`. The split isolates a
  PyPI-egress failure to one job.
- **PyYAML is load-bearing for the gates, despite appearances.**
  `check_skill_alignment.py` and `check_skill_security.py` import `yaml`
  *lazily inside* their frontmatter parsers, so a top-of-file import grep
  says they are stdlib-only. They are not, and both FAIL CLOSED per rule
  A11 — the symptom of a missing PyYAML is every skill reported as
  unparseable frontmatter, not an ImportError. This is now stated at the
  top of `.gitlab-ci.yml`; the first runner-enabled pipeline went red on
  exactly this. `check_docs_consistency.py` and
  `check_content_licenses.py` are genuinely stdlib-only.
- **Resilience:** `interruptible: true` plus `retry` scoped to
  `runner_system_failure`/`stuck_or_timeout_failure` for a K8s executor on
  a shared pool.
- **`gates:pinned` no longer makes a network call.** Its
  `git fetch --depth 1 origin <target>` failed with `SSL certificate
  problem: self-signed certificate in certificate chain` —
  gitlab.cee.redhat.com presents a Red Hat internal CA chain that is not in
  the UBI trust store. (`pip install` is unaffected; PyPI uses a public CA.)
  The fetch was redundant: the runner already populates the remote-tracking
  refs at checkout. The job now resolves the target revision locally
  (`origin/<target>`, else `CI_MERGE_REQUEST_TARGET_BRANCH_SHA`, else
  `CI_MERGE_REQUEST_DIFF_BASE_SHA`) under `GIT_DEPTH: 0`, and **fails closed**
  if none resolves. Deliberately NOT fixed with `GIT_SSL_NO_VERIFY` or
  `http.sslVerify=false` — insecure TLS is lab-target-only per the repo Code
  Standards, and this is production infrastructure.
- **`safe.directory`, then a fail-closed assertion that it worked.** Two
  separate environment problems turned out to be in play, and fixing either
  alone leaves the pipeline red:
  - The build container (uid 1001) does not own the checkout the helper
    container created, so git refuses it ("detected dubious ownership") and
    every git call in the job fails. Established empirically on the runner
    rather than assumed — `gates:mr-tree` is green with
    `git config --global --add safe.directory "$CI_PROJECT_DIR"` (pipeline
    16982588) and red without it (16982724). Scoped to the project dir,
    never `safe.directory *`.
  - The checkers call `git ls-files` but **catch** the failure and fall back
    to a filesystem walk, so a broken git does not produce a red job — it
    produces a **green** job that judged a directory walk instead of the
    tracked tree. Pipeline 16982454 is probably exactly that. A silently
    degraded pass is worse than a failure, so the pipeline now asserts git
    works instead of trusting the fallback.
  Both live in a `.git_ready` block pulled in via `!reference` so
  `tests:pytest`'s `before_script` override cannot silently drop them.
- **Still open (project settings, not a commit):** `main` is protected, but
  `only_allow_merge_if_pipeline_succeeds` and `code_owner_approval_required`
  are both `false` — a red pipeline does not yet block a merge. See
  `docs/best-practice-assessment.md` §5.1.


## v0.255.0 — 2026-08-06

feat(pqc): first-party TLS listener census + findings-shaped projection —
closes the file-integrity-operator class of miss (first-party TLS server
invisible to the who-sets-tls walk, misattributed as `language_defaults`).

- **Rules:** `HP_TLS_LISTENER_{GO,PY,JS,RUST}` + `HP_TLS_SERVER_CONFIG_GO`
  (`rules/hp_supplement.yml`) — info-tier census facts anchoring in-process
  TLS servers (`ListenAndServeTLS`, `http.Server{TLSConfig}`,
  `SecureTLSConfig`, `TlsAcceptor`/`SslAcceptor`, …) so the control-chain
  walk sees them even with no quantum-vulnerable tokens. `HP_TLS_` IR 8547
  prefix reused (non_quantum_risk).
- **Playbooks:** all four `tls-ke-server/*.md` now state the observer
  doctrine explicitly (watch the profile, never one-shot read) with each
  language's concrete hot-reload mechanism — Go `GetConfigForClient`,
  Python `sni_callback`/context swap/worker recycle, Node
  `setSecureContext()`, Rust acceptor swap via `tokio::sync::watch`
  (openssl/native-tls preferred over rustls for FIPS).
- **Adapter 1.4.0 (`pqc_facts.py`):** `HP_GOV_*` governance facts are now
  first-party only — vendored API type definitions (openshift/api
  `TLSSecurityProfile` et al.) are not consumption evidence; they stay in
  the CBOM. `l2_prepass.py` gov-rule counting filtered the same way.
- **SKILL.md:** inverse governance check — platform offers a managed TLS
  profile + first-party listener facts + no first-party profile
  consumption ⇒ `who_sets_tls: this_app` + a profile-non-adherence
  remediation (do_next distilled from the tls-ke-server playbooks).
- **New emitter `build_pqc_findings.py`:** deterministic projection of
  readiness `remediations[]` into `<slug>-pqc-findings.json` using the
  security-audit findings *vocabulary* (id/title/severity/cwes/locations/
  description/remediation/category/validation_status/pqc_classification) —
  deliberately parallel to `report.schema.json`, not conformant (shape
  convergence deferred to the contracts-data-model effort). Own contract:
  `schema/pqc-findings.schema.json`, gated at write. Location-less
  remediations excluded and recorded, never silent. `/patch` prefers it
  over raw `*-pqc-facts.json` filtering (now the 4b fallback).
- Tests: `tests/test_build_pqc_findings.py` (projection mapping, schema
  gate, governance first-party regression, listener-pattern fixtures).

## v0.250.0 — 2026-08-06

feat(pqc): surface graph-discovered cross-language crypto dependencies in
the PER-PRODUCT PQC reports (`build_pqc_product_reports.py`) — previously
they reached only the portfolio roll-up.

- Each per-product report gains an additive **Cross-language crypto
  dependencies** section: the product's repos' crypto-library hits
  (package / version / ecosystem / manifest / PQC posture) with a
  per-product posture rollup whose `classical-only` count is the
  migration-relevant total. Reuses `scan_crypto_deps_graph.discover()`
  and the graph `ships` repo→product mapping so it stays consistent with
  the roll-up's portfolio-level section; the worst-first index gains a
  Crypto-deps (classical) column.
- TLS-readiness content is unchanged (additive only). Untrusted
  repo/package/manifest text routes through `scripts/escaping.py`;
  the section degrades to a "no data" line — never a crash — when the
  graph or its multi-ecosystem `depends_on` layer is absent.
- New capability card `notes/capabilities/native-tls.yaml` for the Rust
  `native-tls` crate (thin platform-delegating wrapper — SChannel /
  Secure Transport / OpenSSL; inherits the platform PQC posture). The
  crypto-packages seed flips `cargo native-tls` from `unknown` to
  `inherits` + that card — no seed now remains `unknown`.
- Extended the curated crypto-packages seed list (+31 well-established
  crypto-relevant packages across npm / pypi / ruby / maven / cargo /
  nuget — signing / KEM / JWT / hashing / KDF libraries, tagged
  conservatively).

## v0.246.0 — 2026-08-06

feat(pqc): graph-backed cross-language crypto-dependency discovery
(`harnessing/pqc-readiness/scripts/scan_crypto_deps_graph.py`). Reads the
portfolio graph's NEW multi-ecosystem `depends_on` edges
(`repo -[depends_on {version, ecosystem, manifest}]-> pkg:<eco>/<name>`
for npm/pypi/maven/cargo/ruby/nuget) to surface crypto-relevant
dependencies across languages — not just the Go/TLS surface
`pqc_facts.py` already covers.

- Curated STARTER seed list `notes/crypto-packages.yaml` — per-ecosystem
  crypto packages, each mapped to a PQC `posture` (classical-only /
  pqc-capable / inherits + `capability_card` / unknown) and a note;
  documented and easy to extend.
- Emits `analysis-results/pqc/_manifest/crypto-deps.{json,md}` (repo,
  package, version, `manifest` provenance, posture per hit) and is folded
  into the portfolio roll-up by `build_pqc_rollup.py` (imports
  `discover()`), which renders a cross-language crypto-dependency section.
- Read-only against the graph (opened `mode=ro`), no network; a missing
  or legacy graph db is a clean logged skip, never a crash.

## v0.237.0 — 2026-08-05

feat: YARA known-malware-family pre-scan engine (`scripts/run_yara.py`).
A candidate-generator deterministic pre-scan (same doctrine as
run_opengrep — facts, never verdicts; recall bounded to *known*
families), invoked as a `yara` CLI subprocess over an
already-materialized blob tree. Rule packs are a swappable input via
`--rules <path|git-url@40hex-SHA>` (https-only, immutable-SHA pin,
cache pin/cleanliness verification, no-follow-symlinks on hostile
rootfs); the default is the ReversingLabs YARA rules pack (MIT), fetched
at run time and pinned by SHA — never vendored, per the run_opengrep
rule-pack contract.

- Wired into `secure-container-audit` (over the exported rootfs — a
  known-malware view complementing grype's known-CVE view) and
  `secure-rpm-audit` (over the prepared source tree — a supply-chain
  implant tripwire feeding RPM06/RPM08). Both record
  `deterministic_steps["yara"]` and route dismissed matches through
  `scanner_correlation`; carrier paths (test corpora, AV samples) are
  flagged, not dropped.
- `yara` engine registered in config/external-tools.yaml (floor 4.5.8)
  and docs/external-dependencies.md (BSD-3-Clause engine; MIT rule pack
  in the frameworks table).
- New `/drift-watch` row `yara-rules-pin`: the pinned pack SHA vs
  upstream `develop` HEAD (the malware pack ages faster than the
  engine; a frozen pin silently stops matching new families).
- tests/test_run_yara.py (rule indexing, output normalization, rules
  resolution / pin enforcement).

## v0.236.4 — 2026-07-31

docs: sqlite3 row added to external-dependencies (CLI granted in
/findings-db and /impact-analysis allowlists, stdlib module used by
14 scripts; Public Domain / PSF-2.0 — registry-charter gap surfaced
by operator review).

## v0.236.3 — 2026-07-31

docs: disposition-ledger gains §11b — findings.db is the SQL window,
never the ledger (operator question exposed the gap: the doc never
explained the record-vs-projection relationship, inviting the
reasonable-but-wrong inference that the ledger lives in SQLite).
"Not a database" added to §11; pointer row to /findings-db.

## v0.236.2 — 2026-07-31

Docs-queue P3 currency sweep (docs-verification 2026-07-31, item 11 —
closes the last open docs-queue item):

- **safe_exec gets a real documentation home**: new docs/safe-exec.md
  (threat model, profiles table, SAFE_EXEC_MODE/DISABLED semantics,
  blocked-step behavior, CLI) — the mandatory commit-gated sandbox was
  described in exactly one doc line; linked from README (docs table +
  tooling rows for safe_exec/refresh_dashboards/escaping), AGENTS.md
  Code Standards (S9/S10 bullet), setup.md, architecture.md (gate
  section now lists all ten S-rules; adapter section documents
  safe_exec step vetting + kubeargv), and the skills.md
  validate-findings entry.
- **external-dependencies gate is YAML-aware**: safe-exec profile
  `allow` lists now count as dependency surface (coreutils ignored) —
  the check found 7 undocumented toolchain binaries on its first run
  (gofmt, gradle, javac/jar, node/npx, rustc); rows added.
- **public-skill-assessment re-bannered SUPERSEDED**: its "portable
  eight" headline is measured false for 6 of 8 skills; the open-source
  upstream plan's partition inventory is the successor.
- **deterministic-tooling-assessment**: trufflehog and Semgrep
  recommendations corrected (both evaluated and rejected — gitleaks and
  the opengrep packs are what shipped).
- **adversarial-content-doctrine**: "three rules" → four; honest note
  that S2 verifies a doctrine block exists (keyword detection), not
  content fidelity.
- **Stale numbers/paths corrected**: AGENTS pytest-native share
  (~39%/two modules → ~30%/many modules) + dashboard advice now points
  at /refresh-dashboards + drift rows; setup test count and gh-consumer
  row (portfolio-graph, rescan router); requirements model tiers
  (three → four, MVM defined as the registry floor of the primary
  role); README fuzz row (five ecosystems, fuzz-author floor),
  dashboard-tree block (metrics/dashboards home), ledger line
  (stages ③–⑦), MVM rows reconciled to registry floors
  (exec-summary/loc/trends → render-narrate haiku floor), trends row's
  retired risk-index claim; outputs.md remediation filename
  (<rem_id>-) + auto-detect list matched to detect_schema_path;
  skills.md: dependency-watch index row (entry existed, row didn't),
  refresh-dashboards self-contradiction (ATT&CK rollup IS in-chain),
  repo-graph segments (auto-discovered) + node/edge list (repo-ref,
  context, doc-product), insecure-patterns oss-findings cut,
  remediate-finding required tools (curl not gh).

Full suite 2,466 green; all gates green.

## v0.236.1 — 2026-07-31

docs: reachability reference/plan split (operator direction)

`docs/reachability-integration-draft.md` mixed executed reality with
proposed work and had gone stale (its "Stage 4 non-Go: PROPOSED" was
delivered 2026-07-31 via the Joern tiers, by a different route).
Split per the assessment-vs-plan convention:
- **`docs/reachability.md`** (new) — the current-state reference:
  every engine (govulncheck, Joern javasrc2cpg/c2cpg, ELF scans, the
  B4 taint enumerator), the evidence ladder and per-engine soundness
  (only Go may demote on a negative), consumers (impact-analysis
  classify, Precision Gate, triage annotation + native ingestion,
  verify-remediation impact filter, the fuzz/live promotion ladder),
  guardrails, and validation-record pointers.
- **`progress-tracker/plans/reachability-integration-plan.md`** (new,
  sibling repo) — the still-proposed stages 2–3, the deferral
  rationale, stage 4 restated honestly as partially-delivered-
  differently, and the open owner decision points.
- Draft retired; all 6 in-tree references repointed (README,
  architecture, skills, deterministic-tooling-assessment,
  run_govulncheck docstring, triage SKILL).

## v0.236.0 — 2026-07-31

Shared escaping library (assessment 2026-07-31 root cause 4 — the P2
epic's first workstream): `scripts/escaping.py` with `esc_html`,
`json_script` (inline-<script> JSON with </script>/<!-- neutralized),
`md_cell` (column forgery, row breaks, link/image defanging),
`fence_untrusted` (variable-length fences that out-length embedded
backtick runs), `csv_cell` (CWE-1236 formula-injection guard, numerics
untouched), and `safe_slug` (path/API-segment allowlist). The controls
existed before — each in exactly one sibling (validation-fuzz esc(),
insecure-patterns pipe-escaping, loc-dashboard slug guard) while the
neighbors lacked them.

Wired at every sink the assessment flagged:
- exec-summary + findings-trends: hostile titles (and accepted_by)
  into MD tables → md_cell; inline `const D = {json.dumps(...)}` →
  json_script (F8 + the <script> gaps)
- sla-view: team names, accountable contacts, repo/finding keys in the
  escalation digest → md_cell (F8)
- rbac-tenancy rollup: unescaped `<td>` pattern/repo labels → esc_html
  (F7 XSS)
- repo-graph: vis-network tooltip URL + href, NODES/EDGES inline JSON
  (</script> breakout), header ARGS, hub-table md link label →
  esc_html/json_script/md_cell (F4)
- remediation manifest CSV: all string cells → csv_cell (finding
  titles quoted from audited repos are live formulas in Sheets)

AGENTS.md Code Standards gains the untrusted-text-never-raw rule
pointing at the library. All five wired dashboards rebuilt clean
end-to-end; 6 library tests; full suite 2,466 green.

## v0.235.4 — 2026-07-31

drift-watch findings.db row: generator-newer-than-artifact check. The
projection bakes schema/views in at build time, so a builder code
change left existing artifacts serving old definitions while the data
looked fresh (measured: the v0.235.2 v_open fix shipped while the
production projection kept hiding 751 in-progress findings until a
manual rebuild). The row now also flags stale when
build_findings_db.py is newer than the artifact's built_at stamp.

## v0.235.3 — 2026-07-31

Docs-verification sweep reports relocated to
progress-tracker/gap-assessments/ (review reports, not metrics — beside
their companion security assessment). check_drift's docs-semantic-sweep
row now globs gap-assessments/ with a legacy metrics/ fallback; all
path references updated (AGENTS, check-harness-docs, drift-watch,
skills, continuous-scanning).

## v0.235.2 — 2026-07-31

Docs-queue P0 stragglers (docs-verification 2026-07-31, items 2-4):

- **P0-2 auto-accept tightened**: `is_auto_accept` now requires >=2
  concurring false-positive votes — a lone FP vote (including the
  anchor_absent reduced-tier shape) is not corroboration and routes to
  the countersign queue. Doc passages describing the predicate updated
  in findings-lifecycle / error-model / triage-ledger-integration.
- **P0-3 findings-db v_open fixed**: the whitelist said 'in_progress',
  a value that does not exist in the layer schema's resolution enum
  ('fix_in_progress' does) — every in-progress finding silently
  dropped out of v_open. The view now uses the census's exact open
  convention: anything not resolved/risk_accepted.
- **P0-4 emitter leg**: both ledger emitters
  (emit_triage_ledger_events, emit_validation_ledger_events) now name
  cloud-config layers with the SHORT <repo>-findings-* stem —
  matching every production cloud-config ledger, so a triaged
  cloud-config baseline appends to its existing ledger instead of
  creating an orphan second layer — keeping the full stem only when a
  code audit shares the directory (companion IaC baseline).
  track-findings SKILL documents both conventions; countersign's
  baseline_for (v0.235.0) already resolves all shapes.

Regression tests for each; full suite 2,460 passed.

## v0.235.1 — 2026-07-31

Assessment low-impact remediation batch (F10-F12/F15/F16/F18 — see
commit e94caf5): team-report HTML escaping + CSP, Jira data-fencing +
post-create security-level verification, provisional owners barred
from access grants, container/wasm adapter redaction, core-OCP token
TTL + per-CO cred-leak scrub, VF_OAUTH_TOKEN probe-soundness keep_env.
Full suite 2,457 passed.

## v0.235.0 — 2026-07-31

Docs fix queue P1+P2 (docs-verification 2026-07-31) — the six queue
items landed as five commits (d1e3b7c, 773e97d, 163f750, 7d25f20,
969c02a):

- **Q6 safety claims:** "audit skills never build/run target code"
  corrected in getting-started/requirements (probe_sanitizers --run,
  govulncheck, and remediation checks execute target code only through
  safe_exec/containers); signing.md's HARNESS_SIGNING_REQUIRED=1
  documented as the fail-closed ERROR it is; pyproject gained
  version + build-system (was uninstallable) and the version-sync
  guard now fails when the field is absent (it was silently dead —
  and caught the parallel session's 0.234.1 bump within the hour).
- **Q9 wiring joints (8):** threat-model findings-tree copy is a
  contract; triage writes next to the input report (never CWD) and
  Phase 2f reads analysis-results/impact/; PATCHES.json declared a
  terminal human-review packet; inventory segment CSVs documented as
  secure-code-audit input shape 4; build_remediation_manifest reads
  tracking/opened-tickets.md (was silently losing every Jira key) and
  warns on miss; assign-findings-owners/remediate-finding tracking/
  paths fixed; continuous-scanning rule 3b downgraded to coverage
  classification (nothing consumes deps-lane rows); crypto delegation
  records deterministic_steps.crypto.
- **Q8 scoreboard truth:** build_executive_summary emits a machine
  sidecar (Executive-summary-findings.metrics.json) and the scoreboard
  collector prefers it — headline metrics no longer regex-couple to
  markdown sentence wording; scoreboard SKILL's source table now
  mirrors all 11 collector sources; the fictional spend-harvesting
  section rewritten (no such code ever existed).
- **Q7 lifecycle docs:** audit valve (salted hash, fail-closed),
  auto-accept (actual is_auto_accept predicate, not "unanimous"),
  retired λ-CVSS risk index, single-artifact tenancy profile with its
  silent single_tenant default, refuted-register gaps (countersign
  writes no entries; machine asserted_by only), impact_report class +
  human-actor demotion rule — corrected across findings-lifecycle /
  error-model / disposition-ledger; triage-ledger-integration
  rewritten as a contract (decision-record artifacts dropped,
  consumer-boundary table, Verified view = all class≠1 events).
  Plus the P0-4 code fix: countersign baseline_for() resolves all
  three layer conventions — container/cloud-config ledgers were
  silently skipped in queue scans and cumulative rebuilds.
- **Q5 PROCESS.md rewrite:** the doc described the retired pre-ledger
  campaign (no triage/ledger/countersign/threat-model/fuzz/
  remediation); now ①–⑨ shared verbatim with README, architecture,
  and skills.md; stage count de-circularized into a declared
  CANONICAL_STAGE_COUNT constant in check_docs_consistency.py (the
  old gate derived the expectation from PROCESS.md's own headings).
- **Q10 A9/A10 rework:** structured **Emits:**/**Consumes:**
  declarations are authoritative (verb/arrow production heuristic
  suppressed), A10 requires a real Integrations heading, terminal
  auto-exemptions shrunk, and 8 primary skills gained real
  Integrations sections.

Full suite 2,457 passed; all four gates green.

## v0.234.1 — 2026-07-31

taint enumerator v4 — calibration run 2 fixes (the judge pass caught
the enumerator AND the smoke-leg eyeball)

The 16-judge code-grounded precision pass measured run 1's sql-family
emissions at **0/16 real data paths**: every flow was receiver-object
taint (tainted jsessionid → HashMap session lookup → taint on the
Statement RECEIVER of constant-SQL executions), refuting the smoke
leg's "16 correct flows" claim. v4 fixes, canary-verified with zero
recall loss on direct flows:
- sink arguments exclude the receiver (`argumentIndex > 0`);
- identifier-free constant expressions pruned (pure literal/operator
  trees cannot carry runtime data — caught the 8 constant-concat
  survivors);
- new NAMED coverage gap: store-then-fetch flows (request value
  stored in session/heap state, executed on a later fetch — the
  H2-console shape) are invisible to per-request reachableByFlows;
- depth bound + per-family sessions + 14g default heap (v2, this
  release ships them together).
B4 remains calibration-gated opt-in; verdicts + judge transcripts in
analysis-results/scan-testing/taint-calibration/run2-2026-07-31.json.

## v0.234.0 — 2026-07-31

P1 gate rework (security assessment 2026-07-31, root causes 1–3) —
four waves, all landed today:

- **W1 — check_skill_security semantic rework.** S3 checks EVERY git
  network call site with continuation-line windows and per-site gate
  proximity, including SKILL.md fenced blocks (12 real sites pinned
  with `GIT_ALLOW_PROTOCOL=https` + scheme gates, zero new
  exemptions). S4 gains an AST leg for .py (`sh|bash|zsh|ksh|dash -c`
  argv with non-literal payloads, `shell=<expr>`, `os.exec*/spawn*`);
  pod-side `sh -c` sites carry cited exemptions (the shell runs inside
  the scoped target pod). S1 parses frontmatter YAML fail-closed
  (body-prose `allowed-tools:` no longer counts) and the privilege/
  untrusted token sets widened (podman/skopeo/docker/tar -x/checkov/
  govulncheck/clone-sweep/gh api; hostile/image-rootfs/IaC-checkout)
  — ten previously unconfined skills now carry scoped `allowed-tools`
  (secure-container-audit, crypto-analysis, cloud-config-audit,
  portfolio-graph, check-alignment, check-licensing, drift-watch,
  loc-dashboard, mine-ledger, file-security-defect) and doctrine
  sections were added where missing. S10 counts govulncheck
  invocation shapes as target builds; `run_govulncheck.py` now routes
  through safe_exec (new `go-scan` profile — scrubbed env for hostile
  build tags/cgo). `check_drift.py` vets `version_cmd` against a
  binary allowlist with flag-only args (config write is no longer
  code exec in every drift run).
- **W2 — alignment gate structural rework.** Frontmatter is parsed
  with `yaml.safe_load`, fail-closed (five live SKILL.md frontmatters
  were unparseable and invisible to every frontmatter rule — fixed
  with block scalars). A11 walks the parsed allowed-tools list, so
  flow-style lists, quoted entries, `python3.11`, and
  `/usr/bin/python3` no longer evade it; broad-head set gains
  git/find/open/env/make. New rule A14: interpreter grants may not
  start the script pattern with a bare `*` (any planted same-name
  file matches); existing shapes are an exemption-tracked burn-down
  queue.
- **W3 — gate boundary.** `.githooks/pre-commit` and `pre-push` fail
  CLOSED when python3 or a checker is missing (deleting a gate script
  was a one-commit bypass). New `.gitlab-ci.yml`: MR + default-branch
  pipelines run all four gates + pytest, and a pinned job replays the
  TARGET branch's checkers against the MR tree so an MR editing a
  gate is still judged by yesterday's gate. New CODEOWNERS puts
  gates, safe_exec + profiles, countersign, hooks, and the CI file
  behind owner approval. (Residual: enable protected-branch +
  CODEOWNERS merge checks in the GitLab project settings.)
- **W4 — grant migrations.** All eight `Bash(git:*)` holders moved to
  subcommand-scoped grants (countersign and impact-analysis dropped
  git entirely; skills with `-C`-shaped commands keep a documented
  `Bash(git -C:*)` residual pending command-shape rework). The four
  pre-A11 `Bash(python3:*)` grandfathers (census, corpus-intake,
  insecure-patterns, repo-graph) retired for anchored per-script
  grants. verify-remediation gained a full allowlist (S1 exemption
  retired); threat-model's `Bash(find:*)` dropped (Glob covers it).

Net exemption movement: security gate 30 → 29, alignment gate
grandfathers −12 (A11) with a new explicit A14 burn-down queue of 17.
Full suite 2,452 passed; regression tests added for every new gate
leg (S1/S3/S4/S10, A11 evasion shapes, A14, drift version_cmd vet).

## v0.233.0 — 2026-07-31

deep-fn B4: Joern taint-flow enumerator (calibration-gated opt-in) +
docs/language-support.md

- `scripts/enumerate_taint_flows.py` — enumerate-then-judge taint
  facts via Joern reachableByFlows: Java servlet→{cmd-exec, sql, path,
  xml}, C {read/recv/getenv}→{cmd-exec, overflow-copy, path}. Judged
  rows carry the path excerpt, `passes_through`, and a
  `sanitizer_hint` (canary-verified: sanitized flows are reported WITH
  the sanitizer visible for the judge); longest-path dedupe per
  (source, sink); explicit `omitted` ledger and named coverage_gaps.
  OPT-IN until the Phase B4 calibration pilot clears the ~50%
  precision bar (deep-fn plan) — deliberately NOT wired into
  /secure-code-audit yet.
- `docs/language-support.md` — the language-support matrix (agentic
  core language-agnostic vs per-language deterministic depth,
  reachability soundness per engine, gaps, add-a-language pattern),
  breadcrumbed from README and architecture.md (operator directive
  2026-07-31). +8 tests.

## v0.232.0 — 2026-07-31

Joern C/C++ reachability tier (second frontend for the v0.231.0
wrapper)

- `run_joern_reachability.py --language c`: c2cpg frontend with
  EXACT function-name matching (prefix matching on short C
  identifiers over-matches); canary-verified (EVP_EncryptUpdate /
  strcpy resolved to exact file:line:caller).
- /impact-analysis: the joern tier is now a shared `_run_joern_tier`
  used by JavaAnalyzer and CAnalyzer; the C gate requires
  include/linked evidence AND advisory-named symbols. Same
  promotion-only asymmetry (C function pointers hide edges the way
  Java DI does).
- /secure-rpm-audit: the vendored-source reachability gate documents
  the C tier for prepared source trees (call-site facts for
  advisory-named functions, caller-function authoritative).
- docs/skills.md updated for both skills. +3 tests.

## v0.231.0 — 2026-07-31

Java coverage closed: Joern reachability tier + pinned-jazzer fuzz
automation (operator directive 2026-07-31)

- **`scripts/run_joern_reachability.py`** — the Java analogue of
  govulncheck's symbol tier: joern-parse CPG over first-party sources,
  resolved call sites for the advisory's vulnerable symbols
  (class#method) and package prefixes, test-path tagging, explicit
  omission caps. Facts only; every artifact states the evidence
  asymmetry (found path promotes, absent path never demotes — Java
  DI/reflection) AND the line-attribution caveat (javasrc2cpg line
  numbers are approximate; file + caller method authoritative,
  measured on the Lightwell validation).
- **/impact-analysis Java tier**: JavaAnalyzer runs the wrapper when
  the cheap tiers find the module (in-range pin / textual usage);
  vulnerable-symbol call → evidence `symbol` + classification
  `affected` with `joern_witness`; package-level call → `manifest` →
  `symbol-usage`; `no_call_sites_found` recorded honestly, demotes
  nothing; joern absent → tier skipped, never faked.
- **Lightwell validation** (operator-approved corpus):
  `analysis-results/scan-testing/joern-validation/` — dnsjava
  TSIG.verify re-found at the EXACT audited SHA; jline3
  CursorSupport.getCursorPosition re-found at upstream HEAD; jackson
  Class.forName resolved to its true choke point
  (TypeFactory.classForName) with zero false sites on a ~2,300-file
  CPG. Line-skew measured and encoded as a consumer-facing caveat.
- **fuzz-harnesses Java lane automated**: `make fuzz-<id>` for
  `language=java` — downloads jazzer **v0.30.0 pinned by sha256**
  (Apache-2.0 verified AT THE TAG, 2026-07-31), builds via
  maven/gradle, runs FUZZTIME-bounded. Was "manual for now".
- docs: external-dependencies rows (joern/joern-parse new; jazzer
  re-verified at the pinned tag), impact-analysis + fuzz-harnesses
  SKILL.md, docs/skills.md. +10 tests (2,385 pass).

## v0.230.0 — 2026-07-31

P0 security batch — harness-security-assessment-2026-07-31 criticals
and highs (all six execution-confirmed findings closed)

- **countersign** (C1 + docs-#5): decision-forgery tokens neutralized in
  all untrusted card text; DECISION parse line-anchored, single-match
  enforced; signer identity in source_ref ends the same-day two-signer
  event-id collision.
- **validate-findings** (F1–F4): verb table is a floor — kube-argv
  content classifier (adapters/kubeargv.py) makes `oc delete` under
  verb=raw destructive; execute-time scope checks every argv-derived
  Action and denies cluster/credential override flags; ns_allowed(None)
  requires explicit "*"; OffLimit fails closed; control-plane lock
  covers openshift-* and cluster-scoped resources; structure-aware
  Secret redaction (data/stringData wholesale, prefixed keys, b64-PEM,
  forge tokens); TLS recon projects public certs only.
- **remediate-finding** (C2 + H2 + L2): .git read-only in the container
  leg; sanitize_worktree_git purges hooks + code-exec config keys after
  checks on both legs and re-asserts the env-reading helper;
  finish_batch $BATCH numeric-guarded via sys.argv; token redaction
  covers all GitHub token classes.
- **dependency-watch** (H1): worklists emit charset-gated argv arrays;
  rejected inputs surfaced, never silent; SKILL executes rows as
  argument vectors.
- **recall-benchmark** (scan-C1): bare-interpreter/git grants replaced
  with per-script anchored grants; misclassified A11 exemption removed.
- **safe_exec**: curl file-read/upload/config denial + kubectl/oc
  override-flag denial (F5/F2 defense-in-depth).
- ~50 new regression tests, each derived from the assessment's
  confirmed reproduction inputs.


## v0.229.3 — 2026-07-31

docs: model-floor enforcement layers + runtime gap recorded

- **docs/model-routing.md**: new "Where the floor is enforced — and
  where it is not" subsection: resolution-time (hard), commit-time
  (hard, schema + A12), provenance (soft); the execution-time gap named
  explicitly (interactive sessions, ledger_validity_writer is
  documentation not a gate) with the WS3 circuit-breaker fix pointer.
- **config/model-registry.yaml**: header note carrying the same record.
- lightwell-adoption-plan WS3 scope extended (user directive
  2026-07-31): budget_guard preflight will also refuse launch on a
  below-floor session/agent model; lands with the budget leg.

## v0.229.2 — 2026-07-31

patching roles default to mythos (registry floors raised)

- **config/model-registry.yaml**: `patch-author`, `patch-reviewer`, and
  `remediation` floors raised opus-class → mythos-class (approved:
  claude-mythos-5 only, matching validation-planner's shape). The
  resolver picks by floor tier, so these roles had been defaulting to
  claude-opus-4-8 while README's minimum-viable column already said
  mythos-class — config lagged docs. User directive 2026-07-31.
- README remediate-finding row: "(opus often sufficient)" parenthetical
  dropped — opus is no longer resolvable for the role.

## v0.229.1 — 2026-07-31

S10 precision fix + inert profile additions (zero-runtime-impact batch)

- **S10 escape token tightened** to `safe_exec.py` — the bare
  `safe_exec` substring false-passed remediate-finding/run_checks.sh
  via its "safe_executer_test" comment. run_checks.sh now carries a
  reviewed exemption: its build/test leg is container-sandboxed
  (rootless podman, cap-drop, --network=none tests; P2.11) — stronger
  containment than argv validation.
- **config/safe-exec-profiles.yaml**: rust-fuzz profile added (inert
  until the fuzz-harnesses integration lands) + D2 network-posture
  note (dependency-manager egress approved 2026-07-31).
- WS1 integration scoping recorded in lightwell-adoption-plan v1.2:
  /patch build-free by design, /remediate-finding already
  container-sandboxed, /verify-remediation no build blocks; the
  /fuzz-harnesses SKILL routing is drafted but deferred to a
  calibrated warn-mode run (zero-impact rule 2026-07-31).

## v0.229.0 — 2026-07-31

safe_exec sandbox: enforced validation/execution for target-derived
commands (Lightwell-adoption WS1, approved scope)

- **scripts/safe_exec.py** + **config/safe-exec-profiles.yaml**:
  profile-allowlisted argv validation (hard-deny binaries/shells never
  grantable, interpreter grants explicit), git hardening (network
  subcommands + 18 dangerous `-c` config-key classes denied), protected
  env-assignment checks, raw-pattern denies (substitution, /dev/tcp,
  ANSI-C), recursion cap; execution is shell-free — pipelines run via
  subprocess chaining with a scrubbed environment. SAFE_EXEC_MODE
  warn|enforce for calibration; SAFE_EXEC_DISABLED bypass shouts to
  stderr + per-user 0700 log, and library callers never honor it.
  38 tests (tests/test_safe_exec.py), incl. fallback↔config sync.
- **validate-findings adapters/base.py**: PoC-derived string steps now
  validate AND execute through safe_exec (validation-step profile) —
  the residual `bash -c` pipeline path is gone; **closes P2.13 / audit
  C2** and its S4 exemption is removed (exemption list shrinks).
- **check_skill_security S10**: target-build invocations
  (make/mvn/gradle/go build/npm/cargo in execution contexts) must route
  through safe_exec; 10 grandfathered exemptions cite the
  lightwell-adoption-plan WS1 integrations that remove them. SKILL.md
  rule table also gains the previously undocumented S9 row.


## v0.228.0 — 2026-07-30

Escalation-contact logic propagated to the other ownership skills

The v0.222.0 registry integration stopped at /assign-findings-owners;
the owners mapping meanwhile gained a 10th Escalation column
(progress-tracker, 2026-07-30) and 130 escalation contacts hold Drive
commenter access. Two of the gaps this closes were active hazards, not
missing features.

- reassign-findings-owners: full registry integration. New Step 1b
  (product_definitions.py context — lifecycle gate surfaced, never
  auto-skipped; slug advisory; unavailable degrades). Step 5a now
  documents the 10-column owners-mapping row — the prior 9-column
  format would have silently dropped the Escalation cell on the next
  rewrite — with refresh rules (registry ladder → one-hop manager →
  new Owner 1's manager; grammar owned by the tracking file,
  referenced not restated). Step 6 gains an escalation-grant guard:
  commenter permissions are classified (owner / escalation contact /
  unknown) before any delete, an outgoing owner who is also the
  escalation contact keeps the grant, and the ~130 escalation grants
  are never read as stale. Step 4 confirmation table and Step 8 report
  show the Escalation cell + registry status; the three assign Step 6
  hard rules ported by cross-reference; Integrations section added
  (the last ownership skill without one).
- Escalation-contact access policy stated affirmatively across the
  ownership skills: a non-contingent escalation contact **receives the
  findings folder** as a commenter (2026-07-30 decision) — reassign
  Step 6d grants it on an Escalation-cell refresh (LDAP-gated, adapted
  notification, displaced contact's grant reported not auto-revoked,
  share-config regeneration flagged); a contingent contact is named in
  the cell/table but never shared with (assign Step 7 rule, PROCESS.md
  Stages 4–5).
- track-findings: the tier-1 authority gate states an escalation
  contact is not an owner and confers no disposition authority —
  their comments queue as tier-2 insufficient_authority.
- sla-view: escalation-digest rows carry accountable_contact
  (kerberos, tier, field, embargo_cleared copied from the resolver,
  ps_product, match_tier) joined via product_definitions.py at
  mapped/repo-url tiers only — a slug guess never lands in an
  unattended artifact. --pd-cache-dir flag; metadata records
  source_status; an absent/off-VPN cache degrades to null contacts
  with every counter unchanged (5 new tests). Markdown gains an
  Accountable column with the not-an-owner caveat.
- inventory-repositories + add-inputs: owners.csv gains a trailing
  Escalation Contact column (bare Kerberos ID, never a GitHub
  username; blank is valid, never fabricated; trailing because
  operand_setup.py parses positionally). Migration mirrors the Jira
  columns convention; repo-graph ingest tolerance locked in by test.
- Consumer lists updated (product_definitions.py docstring, map YAML
  header, docs/external-dependencies.md, README, docs/skills.md,
  PROCESS.md Stage 4, architecture supporting-skills).


## v0.227.3 — 2026-07-30

doc-variance P3 complete: repo-graph context/doc-product layers

- build_repo_graph.py derives two new node layers from committed
  inputs: context:* (standing product-context files under
  adhoc/<product>-context/) and doc-product:* (docs-product-map slugs
  with enumerated versions + confirmed flag), with documents edges to
  mapped product nodes. Derived at build — graphs resolve, never
  store. Live rebuild: 1 context node (aro), 9 doc-products, 9 edges.
- P3 is now fully shipped: drift version-watch (v0.226.1), emitter
  contracts (v0.227.1), threat-register cut (v0.227.2), graph layers
  (this). Remaining lane work: P1 verification in flight, P2
  version-dimension run, P4 human-gated rollout.


## v0.227.2 — 2026-07-30

doc-variance P3: threat-register variance cut

- build_threat_register.py: doc_variance_cut() aggregates every
  <repo>-doc-variance.json register into the fleet register — open
  records per product, overclaim counts, oldest-open list — rendered
  as a "Documentation variance" section (tested helper; section
  appears only once registers exist). Leadership scoreboard harvests
  it with the rest of the register on the normal cadence.


## v0.227.1 — 2026-07-30

doc-variance P3: emitter contracts in threat-model + secure-code-audit

- threat-model Step 0b: context passes that verify official
  docs.redhat.com claims emit structured variance records via
  emit_doc_variance.py alongside threat rows (threat_refs cross-join);
  informal-context conflicts stay threat rows only — the writer's
  schema refuses non-official sources.
- secure-code-audit: opportunistic documentation-claim capture — audit
  evidence contradicting a consulted official-doc claim emits a
  variance record (finding_refs join, deterministic_steps count);
  systematic doc coverage stays with the extraction lane.
- docs/skills.md updated for both (A13).


## v0.227.0 — 2026-07-30

doc-variance: register writer (the only write path) + fetcher anchor fix

- scripts/emit_doc_variance.py (new): schema-gated append/supersede
  writer for <repo>-doc-variance.json registers — idempotent re-emits,
  silent rewrites refused (--update supersedes, history preserved),
  whole-register validation on every write. The official-docs-only
  rule is enforced HERE structurally: a record sourced anywhere but
  docs.redhat.com fails the schema at the writer (test-pinned with a
  Google-Docs URL refusal). 5 tests.
- fetch_product_docs.py: heading anchors now resolve via the embedded
  copy-link widget (docs.redhat.com puts ids on wrappers, not h-tags)
  and titles drop the copy-link cruft — canonical section URLs like
  .../index#tls-security-profiles now correct; OCP security guide
  refetched at 4.19 + 4.22 for the P2 pilot (641/687 sections).


## v0.226.1 — 2026-07-30

drift-watch: docs-product-map version watch (doc-variance P3 rule —
catches FUTURE product-doc versions)

- check_drift.py gains check_docs_product_map: declared map versions vs
  the live docs.redhat.com landing pages per product — new-beyond-window
  versions and retired versions are drift; below-window historical
  versions ignored (window-aware compare, so OCP 3.x noise never buries
  the 4.23 signal); network failure reports unavailable, never fresh;
  map older than 30d is stale. First live run caught a real map defect
  (mis-enumerated ROSA 'latest' label — fixed, inputs 8622389).
- drift-watch SKILL description + docs/skills.md enumerate the check.
- 6 offline tests (tests/test_check_docs_product_map.py — separate
  module; the 2 pre-existing test_check_drift.py failures belong to
  another workstream, untouched).


## v0.226.0 — 2026-07-30

doc-variance lane P1 foundation: official-docs fetcher
(plan: progress-tracker/plans/doc-variance-plan.md v1.0; XWING-894)

- scripts/fetch_product_docs.py (new): deterministic docs.redhat.com
  fetcher — guide enumeration from the product-version landing page,
  single-page HTML to plain text with canonical section-URL anchors
  (the citation substrate for ≤600-char attributed quotes), cached
  work-dir + manifest, fail-loud (no partial-silent manifests; stock
  curl client shape — the CDN 403s python-urllib and custom UAs).
  Structures only; never extracts claims or judges. Work dir is
  scratch — no doc mirroring (CC-BY-SA discipline).
- Pilot smoke: openshift_cluster_manager/1-latest → 1 guide, 130KB
  text, 84 anchored sections. 4 offline tests.
- Next per plan P1: claims extraction + verification against the
  resolved repo@refs, emitting schema-valid variance records.


## v0.225.1 — 2026-07-30

doc-variance lane, part 2: doc-version → repo@ref resolver

- scripts/resolve_docs_version_refs.py (new): (product slug, doc
  version) → repo@ref pairs via three declared modes —
  graph-release (OCP 4.19 → 161 repo@release-4.19 pairs, the audited
  window), ref-pattern (reads ref nodes AND branch-suffixed findings
  slugs; ACM 2.17 → release-2.17), head (rolling docs). Unconfirmed
  map rows resolve but carry confirmed:false for consumer labeling;
  zero-pair resolutions refuse loudly. version_to_refs rules declared
  in the docs-product-map (inputs 6690c94). 5 tests.
- Script count bumped.


## v0.225.0 — 2026-07-30

documentation-variance lane, part 1: official-docs-only schema + the
docs.redhat.com product/version map (user directive 2026-07-30: the
variance corpus is OFFICIAL product documentation, versioned — informal
inputs inform threat models but never mint variance records)

- **schema/doc-variance.schema.json** (new): per-repo variance
  registers — {source: docs.redhat.com product/version/guide/url/quote,
  claim, code_evidence[] (repo/ref/path — doc version joins release
  branches via metadata.ref), variance class (overclaim/underclaim/
  omission/contradiction/stale), disposition (open/doc_corrected/
  code_fixed/accepted/superseded), finding_refs/threat_refs}. The
  official-docs restriction is schema-enforced (source.url pattern
  ^https://docs.redhat.com/). A record is a claim-vs-evidence
  discrepancy, never a vulnerability verdict.
- **hybrid-platforms-inputs/adhoc/docs-product-map.yaml** (sibling
  commit 5314d56): the docs-slug <-> repo-graph-product join, DECLARED
  with every row confirmed:false (4 exact-normalized + 5 curated
  proposals incl. OCP 4.12-4.22 = the audited release-branch window);
  full 108-product index snapshot alongside.
- Remaining parts (planned, not built): claims-extraction lane over the
  mapped products' security/architecture guides; emitter contracts in
  threat-model/audit skills; threat-register variance cut; repo-graph
  context/doc nodes; drift re-enumeration of doc versions.


## v0.224.2 — 2026-07-30

threat-model: standing product-context auto-discovery (Step 0b)

- Every mode now auto-ingests hybrid-platforms-inputs/adhoc/
  <product>-context/*.md before running — owner-supplied product docs
  become structural context instead of a remembered --context flag.
  Verify-don't-trust rules unchanged (doc-vs-code conflicts become
  findings); provenance headers respected and carried into the model;
  stale/headerless docs surface in open questions, never skipped
  silently. First instance: aro-context (end-user system
  interactions doc, fetched 2026-07-30).


## v0.224.1 — 2026-07-30

compliance interview: rail zero (owner-only intake) + evidence-order
membership in the question sequence

- SKILL.md interview mode: rail zero stated — the interviewee IS the
  product owner or delegate; no owner, no interview (boundaries are
  never assessor-seeded; the machinery exercises against the
  labeled-fiction fixture). Question-sequence step 3 now chooses the
  membership source in evidence order: deployment-iac first (IaC
  citations), repo-graph assertion second (named as assertion to the
  owner), explicit last.
- docs/skills.md interview paragraph updated to match.


## v0.224.0 — 2026-07-30

compliance scope: deployment-iac resolution mode (evidence over
assertion — adopted from the OCM-boundary withdrawal, 2026-07-30)

- **resolve_compliance_scope.py `resolves_via: deployment-iac`**: a
  boundary's membership can now come from a declared deployment
  inventory ({services: {<name>: {repos: [{url, source}]}}}) — the
  repos an app-interface-style IaC checkout declares as deployed for
  the service, every resolved repo carrying its IaC source citation in
  the result's `evidence` block. Graph edges are what a product CLAIMS
  to ship; deployment IaC is evidence of what deploys — prefer this
  mode whenever the inventory exists. Fail-loud additions: missing
  inventory/service, uncited rows (the citation is the point), empty
  declarations. include/exclude semantics unchanged.
- schema/compliance-scope.schema.json: `deployment-iac` in the
  resolves_via enum + the `deployment_evidence` block.
- 5 new tests, labeled-fiction fixtures only (evidence-grounded-choices
  rule: machinery is exercised by fiction, never by drafts borrowing
  real product names).
- The inventory EXTRACTOR (app-interface checkout → deployment
  inventory JSON) deliberately lands with the first real engagement —
  it needs a real checkout to be built honestly.


## v0.223.1 — 2026-07-30

product-definitions map backfill — 156 reviewed package -> ps_product
entries in config/product-definitions-map.yaml (previously shipped
empty). Proposals came from the built-in slug matcher (43 packages, all
held), a fuzzy sweep over product ids/names and module ids, a short-id
exact pass for the 2-3 character product ids the sweep's length floor
missed (mtv/mta/mtr/jws/amq), and manual corrections where a matcher
proposal pointed at the wrong product but the right one existed. Each
entry was reviewed against the registry's contacts and lifecycle and
the package's own audit-report repo URLs, per the file's header
procedure. 22 plausible-but-unconfirmed mappings are documented as
comments in the file rather than mapped, so the next reviewer starts
from the open questions instead of rediscovering them. Config-only:
scripts/product_definitions.py is untouched; with the map in place
`--all` resolves 156/492 packages at the trusted `mapped` tier (was
0 mapped / 43 advisory slug).

## v0.223.0 — 2026-07-30

compliance efficacy benchmark — end-to-end seeded target (plan Phase
8a, XWING-893; complements the per-check fixture gate and the
idempotence gate, which prove isolation-correctness and determinism
but never the composed pipeline)

- **scripts/score_compliance_efficacy.py** (new): runs the full
  assessment pipeline against a seeded composed target
  (progress-tracker/configs/compliance/efficacy/seeded-target/) whose
  expected verdicts are true BY CONSTRUCTION (answer key authored with
  the snapshots, never bootstrapped from the tool), then diffs computed
  vs constructed truth. Failure classes severity-ordered: GUESSING
  (an honesty probe — deliberately absent collector — received a
  verdict) > WRONG_VERDICT > MISSING > INCOHERENCE (declared crosswalk
  pairs disagree). findings-db leg materialized from JSON rows into a
  temp sqlite (no committed binary). Exit 1 on any failure — CI-able.
- **First run: PASS — 24/24 controls** across 800-53/PCI/SOC 2/GDPR,
  both honesty probes held (absent crypto_audit collector stayed
  not_assessed), 7/7 crosswalk pairs coherent. Report at
  progress-tracker/metrics/dashboards/compliance/compliance-efficacy.*
- 7 tests incl. proofs the scorer can fail (a benchmark that cannot
  fail measures nothing).
- Script count bumped in README/architecture.


## v0.222.0 — 2026-07-30

feat: Red Hat Product Security product registry as an ownership source for
/assign-findings-owners

- **New `scripts/product_definitions.py`** joins a findings package, repo URL
  or product id to the `prodsec/product-definitions` registry and emits the
  ownership slice: security-contact **Kerberos IDs** tagged by source field,
  plus the product lifecycle window. This collapses the skill's worst
  friction point — the registry supplies Kerberos IDs directly, so candidates
  sourced from it skip the GitHub→Kerberos hop that a hand-maintained 13-row
  table was carrying.
- **Contact ladder**, highest confidence first: `private_tracker_cc`
  (+ component override) → `component_cc` → `default_cc`. Only tier 1 is
  `embargo_cleared`; `default_cc` is a public-bug notification list and
  treating it as embargo-cleared would be a disclosure event. A contact in
  more than one field keeps its best tier.
- **Match tiers:** `mapped` (a reviewed entry in the new
  `config/product-definitions-map.yaml`) > `repo-url` (exact
  `managed_service_components[].git_repo_url`) > `slug` (advisory only,
  never feeds an owner decision) > `none`.
- **`unavailable` is not `none`.** A missing cache reports
  `source_status=unavailable` with `match_tier=null`; a present cache that
  matched nothing reports `ok`/`"none"`. Exit status is 0 in every case — a
  corroborating source must not make a network condition look like a failed
  run.
- **Ownership-only field allowlist.** `bts.key` (Jira/Bugzilla), `cpe`,
  `errata_product_tags`, `team` and `business_unit` are not emitted at all,
  and no free text (`public_description`) ever reaches the caller. Contact
  values are gated on `^[a-z0-9._-]{1,64}$` — the same discipline
  `countersign.py` applies — because they become argv to
  `validate_employee.py`.
- **Ingestion reuses `fetch_feeds.py`** rather than adding a second
  staleness story. The payload is deliberately NOT vendored (unlike the
  sha256-pinned ATT&CK table): it is internal personnel data, and every
  consumer already needs the same VPN as the LDAP check, so a committed copy
  would buy no off-VPN capability.
- **Internal feeds are excluded from `--feed all`,** behind a new
  `--include-internal`. `--feed all` is what unattended lanes invoke —
  `dependency-watch` runs `fetch_feeds.py` bare on a daily cadence and
  `main()` returns 1 for an unusable feed — so a VPN-only feed in the default
  set would have failed that lane on every off-VPN run. The same hazard was
  found and fixed in `enrich_findings_cves.py`, which iterated `ff.FEEDS`
  directly; it now uses `public_feeds()`.
- **`check_drift.py` drives its feed list from `fetch_feeds.FEEDS`** instead
  of a literal `("epss", "kev")` tuple, which is how a newly added feed went
  silently unmonitored — the one failure mode a staleness checker must not
  have. Per-feed thresholds added (30 days for product-definitions, since
  its ids are immutable upstream and contacts churn on reorg); an optional
  VPN-only feed nobody has fetched reports `pending`, not `unavailable`.
- **`/assign-findings-owners`**: new Step 1b resolves ownership context
  before the five-source chain, so an EOL or unreleased product is caught
  first (surfaced for the user to decide — never auto-skipped). Step 1b also
  hoists repo-URL extraction out of Step 3a, where it was described but
  needed by Steps 2, 3 and 4 alike. New Step 5g documents the Kerberos-seed
  path. Step 6 gains three hard rules: `default_cc` is never
  embargo-cleared, a contact never fills an owner slot on contact evidence
  alone (an owner email becomes a Google Drive grant via
  `/reassign-findings-owners`), and a contingent worker is never an owner
  however well corroborated. Step 7 gains an "Ownership context &
  escalation" table where manager- and director-titled contacts land — the
  two owners stay hands-on. Plus Source 8, a managed-services row, four
  gotchas, and an `## Integrations` section.
- Drive-by while adjacent: Source 2's documented clone target moved off a
  fixed `/tmp` path to `"${TMPDIR:-$HOME/.cache}/hps-release"`.
- **Measured coverage, stated in the skill so nobody over-trusts it:** of
  570 modules, `private_tracker_cc` covers 14, `component_cc` 11,
  `default_cc` 173; repo URLs exist only for managed services and join ~1%
  of the audited corpus. This is a corroborating source, not a primary one.
  Deliberately out of scope: all tracker/inventory use of `bts.key` — see
  the plan's Deferred notes for the measured reasons (only 387/570 modules
  are Jira-backed; the other 183 are Bugzilla products).

## v0.221.2 — 2026-07-30

fix: LDAP gate stops reporting contingent workers as `not_found`

- `validate_employee.py` filtered on `(&(uid=…)(employeeType=Employee))`,
  which collapsed "absent from LDAP" and "not badged as an employee" into
  one answer: `not_found`. Real, currently-engaged staff came back
  indistinguishable from a typo or from a GitHub username passed in place
  of a kerberos id — and the owner skills treat `not_found` as a blocking
  disqualification. Measured against the prodsec product-definitions
  security-contact population: **114 of 331 people (34%)** are
  `employeeType=Contingent Worker`, including long-tenured engineers
  (`adinn`, `ansmith`, `akostadi`); **zero** of the 331 are actually
  terminated.
- The lookup now filters on `uid` alone and a new pure `classify()`
  decides employment from the returned attributes, adding
  `status=contingent`. Ordering is deliberate: CN-region exclusion first,
  then a separation date (a terminated contingent worker is `terminated`),
  and `active` requires `employeeType` to be exactly `Employee`. A missing
  `employeeType` classifies as `contingent` — fail-closed.
- **`status=active` still means `employeeType=Employee` and nothing else.**
  `countersign.py` accepts that token as proof of employment when signing
  disposition events; it exact-matches `status=active`, so contingent
  workers remain refused for countersigning. Adding a status *value* is
  parser-safe (`RESULT_LINE` captures `status=(\S+)`); adding a *key* would
  not be.
- Exit code is unchanged in practice — contingent workers previously exited
  1 as `not_found` and still exit 1 — but the docstring now states that
  only `active` yields 0 and that the exit code cannot distinguish the
  failure modes.
- `tests/test_validate_employee.py` is new: this blocking security gate had
  **no test coverage at all**. Covers the classification ordering, the
  fail-closed default, the uid-only filter (with an injection case), and
  the `RESULT` line against `countersign.py`'s real `RESULT_LINE` parser
  rather than a copy of it.
- Owner-skill docs updated in step: `assign-findings-owners` and
  `reassign-findings-owners` both documented the output table and both were
  missing the new row. A contingent worker is disqualified from an owner
  slot in the former and blocked outright in the latter, since reassignment
  grants Google Drive access to findings content.

## v0.221.1 — 2026-07-30

fix: restore a green baseline — drift refresh hints name their builder
again, and complete the Crush discovery wiring

- `check_drift.py`: the v0.217.1 change that repointed stale-refresh
  hints at the packaged `refresh_dashboards.py` dropped the underlying
  builder from the scoreboard and spend-actuals hints, which
  `tests/test_check_drift.py` asserts on (2 failures). Both hints now
  name the packaged command first *and* the concrete builder
  (`harnessing/traust-metrics/scripts/collect_harness_metrics.py`,
  `scripts/collect_session_spend.py --append`), so v0.217.1's intent
  holds without losing the single-builder escape hatch. The scoreboard
  hint also promotes `--only scoreboard` from prose into the command.
  No test assertion was changed — the tests were right.
- Crush discovery wiring completed: added the 3 missing
  `.crush/skills/` symlinks (`check-skill-security`,
  `dependency-watch`, `impact-analysis`) that failed alignment rule A7,
  plus the 6 missing `.crush/commands/` wrappers (those 3 and
  `crypto-analysis`, `reassign-findings-owners`,
  `verify-remediation`). Crush now matches Claude at 57 skills and 64
  commands. Note the command wrappers were NOT caught by A7 — only the
  skill symlinks were — so the 58-vs-64 command gap had gone unnoticed.

- `version.args` bumped alongside `VERSION` (the Konflux build-arg mirror
  the doc gate's version-sync check pins).

`python3 -m pytest tests/` 3 failed → **2246 passed, 18 skipped**;
alignment gate exit 1 → 0; docs/security/licensing gates unchanged at 0.

## v0.221.0 — 2026-07-30

Spend dashboard: monthly budget-vs-actual tracking. New `monthly_budget`
block in config/budget-policy.yaml ($23K/mo central, $19–27K band, from
progress-tracker/metrics/rescan-cost-report-2026-07.md list prices);
build_spend_dashboard.py renders a per-month table — priced actuals vs
band, run-rate projection for the current month, unpriced-model
coverage gaps called out per month (never silently $0). Visibility
layer only (L2): budget-policy.yaml remains unenforced; its header now
names the dashboard as its sole consumer. `--budget` flag overrides the
policy path. Tests: tests/test_build_spend_dashboard.py (5).

First rebuild immediately surfaced a real signal: July 2026 actuals
$122.6K vs the $19–27K band, driven by the Jul 24–27 opus-5 experiment
bursts (factorial matrix, PQC regeneration, deep-FN Phase-A) priced at
an unverified registry rate — caveats now rendered in the section.

## v0.220.0 — 2026-07-30

compliance interview intake — self-service /compliance-check interview
mode with attestation rails (compliance-check plan Phase 7, XWING-892)

- **compliance-check SKILL.md interview mode**: bounded owner interview
  (identity → frameworks → boundary walked repo-by-repo with mandatory
  edge rationale → owner context per assessable domain → close with
  run-now-or-hand-off). Three rails, never waived: (1) attestations are
  EVIDENCE, never verdicts — verbatim attributed statements informing
  evidence_review judging only, may upgrade not_assessed →
  evidence_review, may never touch a deterministic verdict or set
  satisfied; (2) the boundary declarant is LDAP-verified — verification
  failure fails closed to draft:; (3) intake and assessment separable.
- **scripts/compliance_scope_intake.py** (new): the ONLY sanctioned
  interview write path into the scope registry — schema-validates the
  resulting document, dry-run-resolves the boundary (unresolvable
  declarations are refused, not recorded), refuses silent overwrites
  (--update required), enforces repo=REASON rationale on every
  include/exclude, and verifies declarant identity via
  validate_employee.py's machine-readable RESULT line. 9 tests.
- **compliance-assessment.schema.json**: `metadata.owner_attestations`
  defined (id/topic/verbatim statement/applies_to/attested_by/
  ldap_verified/attested_at) with the rail-1 contract in the schema
  description.
- README/architecture script count 88 → 89.


## v0.219.1 — 2026-07-30

- **docs/metrics-inventory.md** (new, operator request): the metrics
  surface in one page — every metric per dashboard (campaign outcome /
  harness-QA / cost tables with lens, builder, and refresh path), what
  `/refresh-dashboards` deliberately excludes, and a dated known-gaps
  register (7 gaps: precision-over-time, pipeline latency, router
  telemetry trend, cost-per-finding trend, countersign queue depth,
  drift trend, corpus blind spots — each with its cheapest credible
  fix). Linked from the README doc index.

## v0.219.0 — 2026-07-30

compliance scope registry — boundary-level framework scoping
(compliance-check plan Phase 6, XWING-891)

- **schema/compliance-scope.schema.json** (new): declared compliance
  boundaries — frameworks scope SYSTEMS, not repos; each boundary is a
  signed service/product-level declaration (`declared_by`/`declared_at`
  dated provenance; `draft:` prefix = unsigned) with include/exclude
  edges that each carry rationale ("doesn't apply" lives here with a
  reason, never as silent omission).
- **scripts/resolve_compliance_scope.py** (new): boundary → repo set
  via the repo-graph product mapping (the /isolation-review
  resolution); graphs resolve scope, never store it. Fail-loud
  contract: unknown boundary/product, ambiguous label, stale exclude,
  empty resolution = errors — a mis-scoped compliance run is worse
  than no run. 10 tests.
- **run_compliance_check.py --boundary <id>** (+ `--frameworks
  boundary`): resolves scope from the registry (mutually exclusive
  with --repos — the registry is the scope authority), defaults
  target-kind/product, and stamps `metadata.target.scope` provenance
  (boundary, declarant, exclusions, draft flag, raw-bytes registry
  hash — canonical-JSON hashing would mask whitespace edits to a
  signed declaration and chokes on bare YAML dates) into the artifact;
  `target.scope` defined in compliance-assessment.schema.json.
- **build_compliance_dashboard.py**: "Declared boundaries — in-scope
  coverage" section — per boundary: in-scope repos, repos with
  campaign evidence, exclusions, last-assessed, DRAFT labeling;
  resolution failures render as rows, never dropped.
- Starter registry with one worked DRAFT boundary
  (ocm-fedramp-moderate → 45 repos, 16 with campaign evidence) in
  progress-tracker/configs/compliance/compliance-scope.yaml; smoke:
  full boundary run end-to-end (fedramp correctly skipped product-only,
  800-53 assessed, citation gate green).
- README/architecture script count 87 → 88; schema table row.


## v0.218.1 — 2026-07-29

docs: continuous-scanning "Dashboards rebuild" row label names the full
covered set (was still the pre-extension five-dashboard list)

## v0.218.0 — 2026-07-29

refresh-dashboards covers ALL deterministic dashboards: sla, compliance,
attack-coverage, loc stages added

- The v0.217.0 chain only packaged the doc's historical "Dashboards
  rebuild" list, leaving sla/, compliance/, attack-coverage/, and
  loc-dashboard.html stale in the same folder after a "full" refresh —
  exactly the confusion it was built to remove. Now added as consumer
  stages: `build_sla_view.py`, `build_compliance_dashboard.py`,
  `build_attack_coverage.py`, `build_loc_dashboard.py --no-fetch`
  (committed language cache only — the API sweep stays with
  /loc-dashboard per the fleet-sweep constraints).
- Still excluded, documented in the skill: threat-register (agent
  judgment) and campaign-lane outputs that share the dashboards folder
  (pqc, operator-least-priv, rbac-openshift-platform, fuzz, benchmark —
  they update when their lanes run).

## v0.217.1 — 2026-07-29

refresh-dashboards wiring completion: stale-refresh pointers now name
the packaged command

- **scripts/check_drift.py**: `dashboards:harness-scoreboard`,
  `dashboards:spend`, and `dashboards:spend-actuals` refresh hints
  point at `refresh_dashboards.py` (full chain or `--only` stage)
  instead of the raw per-artifact builders.
- **drift-watch SKILL**: `dashboards:*` row names `/refresh-dashboards`
  as the packaged refresh.
- **traust-metrics SKILL**: refresh-sources table
  cross-references the full chain for multi-stale cases.

## v0.217.0 — 2026-07-29

/refresh-dashboards: the weekly "Dashboards rebuild" job packaged as one
command (`scripts/refresh_dashboards.py` + skill wrapper)

- **scripts/refresh_dashboards.py**: sequential deterministic chain in
  dependency order — projections (`build_findings_db.py`, census) fail
  hard, per-dashboard consumers (exec summary, trends,
  insecure-patterns, validation-fuzz, rbac-tenancy, spend)
  continue-on-error, scoreboard last because it harvests the others.
  `--only/--skip/--list/--dry-run` stage selection; `--note` forwarded
  to the metrics-history snapshot; spend-*actuals* leg stays opt-in
  (`--spend-actuals`, operator workstations only) so the default job is
  orchestrator-portable.
- **harnessing/refresh-dashboards/**: skill + command wrapper +
  discovery symlinks; allowed-tools scoped to the one script.
- **docs/continuous-operations.md**: "Dashboards rebuild" standing job now
  names the packaged command instead of the raw builder sequence.
- Agent-built views (threat register, attack coverage) intentionally
  excluded — rebuilt by their owning skills.

## v0.216.3 — 2026-07-29

self-audit residuals closed: triage allowlist anchoring + future-dated
event rejection (findings -011/-015 — the last two open items from
harness-integrity self-audit run 1)

- **triage SKILL allowlist** (-011): `Bash(find:*)` removed (`-exec`
  is arbitrary execution; enumeration uses Glob/`ls -R`), and every
  harness-script grant anchored on the harness directory name
  (`python3 *traust/scripts/<name>.py`) so a hostile
  repo-shipped `scripts/validate_report.py` lookalike no longer
  matches the permission; absolute-path invocation discipline + rule
  S9 close the nested-dir residual.
- **validate_report layer gate** (-015): events with `recorded_at`
  more than 24h in the future are ERRORs — recorded_at is
  emitter-declared and adjudication is latest-wins within an evidence
  class, so a future-dated event would pin the disposition forever
  (backdating was already rejected by the chronological check). +1
  test.

## v0.216.2 — 2026-07-29

- **docs/setup.md + docs/requirements.md**: the two install-guidance
  docs now point at `config/external-tools.yaml` as the version source
  for the unpinned scanners (workstation and job-image installs land on
  the manifest floors instead of "whatever brew gives you") — closes
  the doc-coverage gap on the v0.216.0 manifest.

## v0.216.1 — 2026-07-29

repo-graph: keep full GitLab subgroup paths in `canon_repo` (bug fix).
Group/subgroup/repo URLs were truncated to two path segments, which (a)
collapsed all 60+ `lightwell/lightwell-builds/*` repos into a single
graph node (last-write-wins attrs) and (b) minted a phantom
`aap-cpaas/source` node whose truncated URL flowed through the
portfolio graph into the week-2 rescan-worklist bootstrap rows and was
dispatched as an unclonable audit target (week-2 batch, 2026-07-28).
GitHub identities are unchanged (still exactly `org/name`; deeper
`/tree/…` segments still dropped). `repo_from_row`'s org/name fallback
now treats everything between host and repo name as the namespace.
Regression test: `TestGitLabSubgroupPaths` (68 affected inventory URLs
at fix time). Downstream consumers compare canonical ids symmetrically,
so GitLab subgroup repos self-heal on the next /repo-graph +
/portfolio-graph rebuild.

## v0.216.0 — 2026-07-29

External-tools manifest: `config/external-tools.yaml` becomes the
single source of truth for the unpinned PATH scanner roster (operator
decision) — one entry per tool with version command, upstream source,
consumers, and an `expected` version floor that doubles as the platform
orchestrator's job-image install list, so the image and the checker can
never disagree.

- **config/external-tools.yaml** (new): 9 scanners seeded with the
  2026-07-29 verified versions; checkov/bicep/pqc-scan deliberately
  absent (hard-pinned in their runners, own drift rows). Advancing
  `expected` is a deliberate reviewed config change.
- **scripts/check_drift.py**: `external-tools:*` reads its roster from
  the manifest (hardcoded EXTERNAL_TOOLS constant removed; unloadable
  or partially-malformed manifest = one loud `unavailable` row, never a
  silently shrunk roster). New comparison: installed below the
  manifest's `expected` reports **drift** (environment disagrees with
  declared config), ahead of the expected-floor check the existing
  installed-vs-latest **stale** logic runs unchanged. 6 new tests
  (37 total in the module).
- **scripts/collect_session_spend.py**: docstring records the planned
  extension — read centralized session transcripts once the
  orchestration platform lands, unbinding the spend-actuals leg from
  operator workstations (operator request; continuous-operations.md
  dashboards row documents the residual).
- drift-watch SKILL row, docs/skills.md, external-dependencies.md
  Maintenance, and the continuous-scanning job-image row now all point
  at the manifest.

## v0.215.4 — 2026-07-29

- **docs/continuous-operations.md**: the standing-jobs dashboards row now
  defines the orchestrator contract (operator request): weekly
  scheduled rebuild as one sequential deterministic job (findings.db →
  census → per-dashboard builders, ~$0, no agent), spend rebuild ≤4d,
  drift `dashboards:*` rows as the dead-timer backstop. Documents the
  one leg that cannot move to the platform: spend-actuals ingestion
  reads Claude Code session transcripts on operator workstations and
  stays operator-side until transcripts centralize.

## v0.215.3 — 2026-07-29

- **docs/continuous-operations.md**: new "Credentials & service accounts
  for autonomous runs" section (operator request) — the environment the
  platform orchestrator must provide for headless standing jobs:
  dedicated GitHub service identity (quota + secondary-ban notes),
  GitLab token + VPN path, ambient-helper clone credentials,
  model-platform credentials + spend recording, scanner binaries in the
  job image (tagged govulncheck), unauthenticated feeds, and TBD rows
  (LDAP binding, Jira service account, gws) for the pending
  service-account review. Deterministic/concluding division of labor
  restated.

## v0.215.2 — 2026-07-29

docs: the improvement loop documented in the error model

- docs/error-model.md gains §6 "The improvement loop — how measured
  misses become detectors": the six capture channels (ledger mining,
  syntactic sweeps, semantic precedent cards, coverage-gap rollup,
  benchmark rule-candidate extraction, CVE-replay/near-miss ground
  truth) with their artifacts, plus the two boundary rules (benchmark
  isolation preserved — identity-only capture; volume ≠ expressibility).
  Later sections renumbered; README error-model row updated.


## v0.215.1 — 2026-07-29

docs: standing-jobs orchestration inventory + currency pass over docs/
(operator directive 2026-07-29 — every automated/scheduled/cadenced job
must be discoverable in docs/, and this week's shipped changes reflected
in the reference docs)

- **docs/continuous-operations.md**: new "Standing jobs — the complete
  inventory" section — the superset of the Lane cadences table: every
  cadenced job (fleet refresh/router, release-event feeder,
  /dependency-watch, EPSS/KEV pull-through, weekly drain tranche, verify
  treadmill, rule-mining lane, CVE-replay monitor, /drift-watch, census +
  repo-liveness, fp-precedent cache, validation + recall benchmarks,
  class-sweep rotation, threshold re-derivation, dashboards, IaC
  re-baseline, portfolio-graph rebuild, pin advances, docs semantic
  sweep) with cadence, trigger, runner, and output-gate/drift-backstop
  per row. Honest current state stated: no scheduler is configured
  in-repo; timer rows are operator/cron-run (orchestrator-neutral), and
  the named drift rows make a dead timer visible. Deliberate
  human-decision jobs get "human-decision, drift-flagged" rows instead
  of omission.
- **docs/error-model.md**: Precision Gate row now reflects all four
  scanning skills + the `metadata.additional.precision_gates` record
  (v0.194.0); triage row notes the tiered FP-precedent annotations
  (live v0.193.0); self-measurement gains the class-generalization
  sweep engine.
- **docs/report-structure.md**: code-profile delta documents
  `metadata.additional.precision_gates` (shape, empty-fired legitimacy,
  incomplete-run rule; rpm/container record the same block, /vuln-scan
  stamps supplements).
- **docs/findings-lifecycle.md**: birth-path producer table gains
  /dependency-watch (route_impact_findings.py direct entry, v0.197.0) —
  five non-audit producers, not four.
- **docs/architecture.md**: scripts table gains route_regressions.py and
  route_impact_findings.py (the direct-entry convention rows).
- **docs/deterministic-tooling-assessment.md**: roadmap item 5
  (diff-driven incremental re-audit) marked substantially shipped
  (/vuln-scan --diff resolver + context packets, v0.190–0.192);
  sweep_engine.py §7.1 description corrected to the class-generalization
  engine it actually is; statuses line re-dated.
- **docs/setup.md**: tool table gains govulncheck, checkov (pinned), and
  bicep (pinned transpile fallback) rows — requirements.md names this
  table authoritative and it lacked the cloud-config-audit toolchain.
- **portfolio-graph SKILL.md + docs/skills.md**: L2/L3/L4 layers are
  implemented, not planned (frontmatter + reference were stale); refresh
  cadence corrected from "quarterly /mine-ledger pass" (the lane is
  weekly since v0.213.0) to human-decision drift-flagged, cross-linked
  to the standing-jobs inventory.
- **drift-watch SKILL.md**: cadence section cross-links the
  standing-jobs inventory.

## v0.215.0 — 2026-07-29

improvement-capture channels: coverage-gap rollup + benchmark rule-candidate
extractor (closes the two capture gaps named in the 2026-07-29 deep-fn
baseline review: enumerator gaps had no fleet roll-up, and benchmark-run
rule-expressible shapes evaporated because benchmark reports never enter
the ledger)

- **scripts/build_coverage_gap_rollup.py** (new): aggregates coverage-gap
  statements across the corpus via the corpus.py resolver (harness-qa
  trees centrally excluded, branch re-audits deduped, population block
  stated) at three signal tiers — structured
  `metadata.additional.coverage_gaps` (new recording convention, see
  below), skipped pre-scans in deterministic_steps, and narrow
  negative_results prose signatures (never fabricates from unrecognized
  prose; language aliases collapse) — into a repos-affected-ranked
  enumerator-expansion backlog: coverage-gap-rollup.{json,md} under
  progress-tracker/metrics/coverage-gaps/. First real run: 12 gap
  families over 4,307 reports (priv-profile skips 107 repos, opengrep
  javascript 7, sanitizer-probes non-python...). 7 tests.
- **secure-code-audit SKILL.md**: the three enumerator pre-scan
  record-the-run steps now also copy the artifact's coverage_gaps into
  `metadata.additional.coverage_gaps` ({tool, system, reason, count}) —
  the structured tier the rollup prefers.
- **scripts/extract_benchmark_rule_candidates.py** (new): post-scoring
  benchmark step — routes benchmark-run audit findings through
  sweep_engine.classify (the same deterministic rule-expressibility
  router the ledger tier uses), clusters by (CWE, language), marks hps
  pack coverage, and emits an IDENTITY-ONLY rule-authoring artifact
  (banner: never ingest as findings; no ledger contamination) to
  progress-tracker/metrics/rule-mining/benchmark-rule-candidates.{json,md}.
  First real run over the 8 deep-fn baseline reports: 23 expressible
  clusters, 13 uncovered by the pack (rust entirely, CWE-89/go
  identifier injection, CWE-330/go math/rand, CWE-94/yaml CI injection...).
  5 tests.
- README/architecture script count 84 → 86.


## v0.214.0 — 2026-07-29

Version-tagged container images — released images now carry the harness
version as a registry tag alongside the git SHA tags:

- **`Containerfile`**: declare `ARG VERSION` (previously the
  `version="${VERSION:-0.0.0}"` label always stamped 0.0.0 because the
  ARG was never defined) and stamp the standard
  `org.opencontainers.image.version` label, which the Konflux release
  pipeline's `{{ oci_version }}` tag template reads.
- **`version.args`** (new): `VERSION=x.y.z` build-args file consumed by
  the Konflux build via the `build-args-file` param (added to both
  `.tekton/` PipelineRuns). Regenerate it whenever VERSION is bumped —
  the doc-consistency gate fails on drift.
- **`scripts/check_docs_consistency.py`**: version-sync check now also
  asserts `version.args` matches `VERSION`. +tests.

The companion konflux-release-data MR adds `"{{ oci_version }}"` to the
traust ReleasePlanAdmission tag list, so each release lands
in quay tagged `<git sha>`, `<short sha>`, `sha256-<digest>`, and the
harness version (e.g. `0.214.0`).

## v0.213.0 — 2026-07-29

Mine-ledger lane automation — the rule-mining loop becomes a standing,
scheduler-runnable lane (user directives 2026-07-29):

- **`scripts/run_rule_mining_lane.py`** (new): orchestrator-neutral
  lane runner in the dependency-watch pattern — miner
  (`mine_ledger_truepositives.py`) → `sweep_engine.py collect --force`
  + `draft` → bounded `emit_rule_drafts.py --skip-existing --limit N`
  staging → **delta report** vs the previous `rule-mining.json`
  (new/resolved/changed uncovered clusters, precision movements
  crossing the ~50% gate, TP-corpus growth, drafts staged) written to
  `progress-tracker/metrics/rule-mining/lane-delta.{json,md}`.
  Deterministic stages only — no model calls; exit 0 quiet / 1
  attention needed / 2 stage failure; a baseline first run is
  inventory, not news (release-events convention). Fixture-based tests
  for the delta computation, rendering, and exit semantics.
- **drift-watch `rule-mining` row**: `check_drift.py` compares
  `rule-mining.json` age against the newest `*-findings-layer.json`
  mtime across analysis-results (the fp-precedent-cache freshness
  idiom, shared `_newest_by_suffix` helper) — stale when ledger
  changes are >7 days newer (`RULE_MINING_LAG_DAYS`); this row is the
  lane's post-wave trigger. +tests.
- **`emit_rule_drafts.py --skip-existing`** (new flag, the lane's
  mode): never re-stages an existing draft dir, so
  authored-but-unpromoted patterns survive scheduled re-runs (the
  default rmtree-and-restage behavior clobbered them). +test.
- **mine-ledger SKILL.md**: new *Scheduled lane* section (runner
  contract, cron example) records the **standing user delegation
  (2026-07-29)** — scheduled runs proceed through rule authoring and
  the full test-and-calibrate gate (fixtures fire/silent, whole-pack
  regression, TP-rediscovery calibration) without asking; the
  mechanical gate is the promotion criterion; sweep hits and mined
  candidates still route to /triage, the lane never auto-files
  findings. Cadence line replaced (quarterly → weekly lane +
  drift-row post-wave trigger); Integrations name the lane-delta
  consumers (scheduled session + drift row).
- Docs: continuous-scanning "Lane cadences" gains the rule-mining lane
  row; drift-watch SKILL row table + docs/skills.md updated; README
  entry-points table gains the lane runner (standing-loop diagram
  already showed the lane since 7133330).

## v0.212.0 — 2026-07-29

Opengrep rule-pack v1.7: the 2026-07-29 mined tranche + precision
recalibration (from the post-orphan-backfill `/mine-ledger` run —
8,286 confirmed TPs, 458 uncovered clusters; proposals in
`progress-tracker/plans/opengrep-ruleset-plan.md` "Backlog refresh —
2026-07-29", now marked authored-and-calibrated with the full
calibration matrix):

- **6 new rules**, each specified by tp-corpus finding entries and
  calibrated by re-cloning corpus repos at the recorded commits:
  go/resource-management (http-client-no-timeout,
  http-server-no-timeouts, unbounded-request-body-read — CWE-400/770,
  9/9 corpus repos rediscovered), go/authentication
  (forwarded-identity-passthrough — CWE-290, oauth-proxy FIND-003
  rediscovered at oauthproxy.go:113/185), go/secrets-management
  (credential-in-metric-label — CWE-522, configmap-reload:131 +
  s3-reload:122 rediscovered), python/data-exposure (secret-in-log —
  CWE-532, LOW-tier by design, 3/3 expressible corpus repos
  rediscovered).
- **7 flagged low-precision rules fixed** (no retirements; every
  known ledger TP re-verified firing post-tightening): bash xtrace
  0.07→credential/remote-source co-occurrence; go ssrf 0.07→gen-file
  path exclusion + url.Parse sanitizers (both taint TPs preserved);
  python yaml-unsafe-load 0.00→ruamel + literal-path exclusions,
  demoted LOW; yaml auth-disabled 0.00 + empty-password 0.00→scoped
  to non-k8s YAML (apiVersion docs excluded — KHS duplication was the
  dismissal mass); java variable-format-string 0.00→CONSTANT_CASE
  exclusion (all 7 autotune dismissal sites silenced, post-fix class);
  go secret-in-log 0.10→metadata-suffix exclusion extended, demoted
  LOW (3/3 azure promoted sites still fire).
- **Data-quality**: run_opengrep.py `bare_rule_id` strips opengrep's
  dotted path prefix from check_id (the 19 dotted-path
  scanner_correlation ids); SKILL.md correlation spec now forbids
  pack-level aggregate rule_ids ("hps-pack (all rules)" — 5 entries)
  and requires one entry per judged fact.
- Full calibration matrix (rule × repo × fired/missed, 26 rows) in the
  plan's backlog section; pack fixture suites all green (go 18/18,
  python 14/14, bash 5/5, java 8/8, yaml 5/5, ts 4/4).

## v0.211.0 — 2026-07-29

Bicep-transpile fallback (license-gated intake PASSED: bicep CLI is
MIT, verified upstream 2026-07-29) + IaC fleet-fix campaign specs:

- **run_checkov.py**: parse-failed `.bicep` files are transpiled with
  the pinned bicep CLI (`PINNED_BICEP_VERSION` 0.45.15, sha256 pin
  recorded; resolution $CCA_BICEP → PATH → ~/.cache/cca-tools, wrong
  version treated as absent) via `bicep build --no-restore` — offline
  always, external registry modules never fetched — and re-scanned
  through the arm framework; fact paths alias back to the source
  .bicep (line ranges refer to the generated ARM template, recorded in
  metadata.bicep_transpile_fallback); CLI absent → loud NOT-ASSESSED
  gaps unchanged. Fact rows now dedupe on fact identity
  (framework|check|file|resource — a module instantiated N times in
  transpiled ARM collapses to one row; raw counts preserved). Parsing
  gap message annotates transpile recovery. 6 new tests (all mocked).
  Live validation on ARO-HCP: 71/75 parse failures recovered, 1,213
  prior facts carried with identical fact_ids, 12 new facts →
  CCA-ARO-HCP-088/089/090.
- **fleet-fix specs** (IaC campaign, diffs-only stage complete; MRs
  gated on operator batch approval): specs/gha-workflow-permissions
  .yaml (CKV2_GHA_1, 15-repo uniform-subset apply, 38 workflows),
  specs/tls-verify-enable.yaml (ansible validate_certs, 4 repos/14
  files), specs/ssh-cidr-restrict.yaml (CKV_AWS_24, 5 of 7 repos;
  amq-cob + rosa-govcloud-quickstart recorded no-match shapes). All
  schema-valid with passing inline goldens.
- docs: external-dependencies bicep row (MIT, subprocess, sha256),
  requirements install note, SKILL.md limitation rewritten to the
  fallback contract, docs/skills.md entry updated (A13).

## v0.210.0 — 2026-07-29

drift-watch now covers the external deterministic toolchain
(`external-tools:*`): nothing previously noticed when an unpinned
PATH-invoked scanner fell behind and its detection content silently
aged (user request — "drift check should check for drift or
out-of-date external tools").

- **scripts/check_drift.py**: new `check_external_tools` — installed
  version of each unpinned PATH scanner (opengrep, gitleaks, syft,
  grype, osv-scanner, cosign, skopeo, govulncheck, pip-audit) vs its
  latest upstream release (GitHub releases / PyPI / Go module proxy;
  GITHUB_TOKEN honored, header-only). Version-lag signal with a
  14-day grace window (`EXTERNAL_TOOL_LAG_GRACE_DAYS`) so normal
  release churn stays quiet; unknown release date errs loud.
  Not-installed → `pending`; unparseable version output or unstamped
  `go install` builds self-reporting v0.0.0 → `unavailable`
  (govulncheck's first bare semver is the Go toolchain version — the
  scanner version is anchored on `govulncheck@v`). Checkov stays with
  its own age-based `checkov-pin` check. Routes attention only:
  upgrading is a deliberate toolchain change, re-verify one
  known-good target before a sweep. 8 tests.
- drift-watch SKILL table + docs/skills.md + the
  docs/external-dependencies.md Maintenance section now state the
  toolchain-freshness coverage split (pinned via pin checks, unpinned
  via external-tools).

## v0.209.1 — 2026-07-29

Cloud-config live re-baseline fixes (first real-Checkov run of the
v0.207.0 Containerfile-alias scan tree, on rhoim-bootc-images):

- **run_checkov.py**: the alias scan tree now mirrors EVERY real
  directory as a real directory (files as symlinks) — Checkov's file
  discovery does not descend through directory symlinks, so the
  partial mirror (real dirs only on Containerfile paths) silently
  dropped every framework whose files lived elsewhere (live run lost
  all 32 kubernetes+terraform facts; the mocked tests could not see
  this). Regression test added (off-path dirs real, source dir
  symlinks preserved for loop safety). Re-run verified: 35 failed /
  304 passed across all three frameworks, 32 prior facts carried with
  identical fact_ids + 3 new Containerfile facts.
- **validate_report.py**: `*-cloud-config-audit.json` now routes to
  schema/cloud-config-audit.schema.json in sweeps instead of failing
  the code-audit schema (128 bogus errors observed); code-audit
  cross-checks and strict checks gated off for it — run_checkov.py
  --validate-report remains the canonical content gate. 2 tests.
- Recorded-gap verification: both live container-audit findings-current
  files PASS the default route (report.schema.json-shaped, as
  documented) — no dedicated container-audit current schema needed;
  their one warning (image-digest ref in metadata.repository) is
  cosmetic and correct for image targets.

## v0.209.0 — 2026-07-29

deep-fn Phases C+D groundwork: crown-jewel selection query (DRAFT tier
list) + semantic precedent-card compiler prototype (plan §3 Phases C/D;
both explicitly gated — the tier list on open question 2 sign-off, the
cards on the 20-repo yield pilot)

- **scripts/build_crown_jewel_tiers.py** (new): deterministic
  composition of portfolio-graph dependency fan-in (log-normalized),
  threat-register open-threat impact, derived operator-privilege tier
  (0-3 from rbac/SCC/privileged-workload signals — the priv-profile
  "tier" field is capture tier, not privilege), and open crit/high
  finding load from findings.db into a documented weighted score;
  emits crown-jewel-tiers.{json,md} (tier1/tier2/watch) stamped
  "DRAFT — unsigned (deep-fn open question 2); Phase-C dispatch must
  not consume until signed". Missing sources degrade with a stated gap
  + weight renormalization, never crash; no graph db is fatal. Known
  caveat recorded in the artifact: slug-level join inflates repos
  recurring across product trees (kube-rbac-proxy threat count).
  8 tests.
- **scripts/compile_precedent_cards.py** + 
  **harnessing/mine-ledger/precedent-cards/pilot.yaml** (new): the D6
  "compiles to worklists or is rejected" rule made mechanical — a
  semantic precedent card is a predicate AST over a shipped
  enumerator's actual output schema (config-matrix triples,
  route-guard rows, sanitizer-probe entries, symbol-index queries)
  plus a per-row judge question; prose checklists, unshipped
  enumerators, and unknown fields are REJECTED with reasons.
  Sanitizer run-only fields require an explicit execution
  acknowledgment (run: true). Output is sweep-candidates-semantic.json
  in the sweep-engine generic-candidate shape (/triage ingests it
  unchanged; origin: semantic-sweep, card provenance attached). Pilot:
  4 valid cards (unguarded-route class from the ux-backend/UnifAI
  shape, DSN plaintext defaults, anon/bind-all listener defaults,
  sanitizer-bypass survivors) + 1 deliberate prose reject pinning the
  rejection contract. 22 tests.
- README/architecture script count 81 → 83.
- Phase-D residue (documented, not shipped): 20-repo per-card yield
  pilot + corpus driver; enumerator coverage_gap passthrough.


## v0.208.0 — 2026-07-29

deep-fn Phase B3: sanitizer micro-probes — execution-gated bypass-corpus
lane tool (deep-fn-technique-plan §3 Phase B3, the lab-free D4 slice;
acceptance shape = bt-awx-001 residual #3, the ASCII-only sanitize_jinja
whose fullwidth/dunder bypasses reading alone missed)

- **scripts/probe_sanitizers.py** (new): static discovery of
  sanitizer-shaped single-arg Python functions (`--list`, the default —
  executes nothing); explicit `--run` executes each candidate in an
  isolated subprocess (python3 -I, cleared env, CPU/AS rlimits, hard
  timeout, scratch cwd) against a 15-payload curated bypass corpus
  (SSTI + fullwidth/dunder variants, path traversal ×3, null byte,
  XSS ×2, SQL, shell ×2, CRLF, bidi), recording per-payload
  transcripts. Verdicts are soundness-gate aligned: `survived` = judged
  candidate, `error`/`skipped` = INCONCLUSIVE never safe.
- **secure-code-audit SKILL.md**: sanitizer micro-probe section —
  execution gate (audit-sandbox only, /fuzz-harnesses doctrine),
  call-convention check before filing survived candidates, Python-only
  applicability recording, deterministic_steps + scanner_correlation.
- 11 tests incl. the acceptance fixture (ASCII-stripping sanitizer:
  `{{7*7}}` neutralized, fullwidth and `__class__` payloads survive).
- README/architecture script count 80 → 81.


## v0.207.0 — 2026-07-29

(Renumbered from a planned v0.205.0 — the concurrent session took
v0.206.0 while this entry was staged; v0.205.0 was never tagged.)

IaC gap build-out — four workstreams landed together (workflow-parallel
build, single verify; router-lane-coverage-plan items: Checkov gap
register, validator schema gap, item 3 companion stamp, item 4 event
feeders):

- **Checkov coverage gaps** (`harnessing/cloud-config-audit/scripts/run_checkov.py`):
  Containerfile/prefix-named Dockerfile scan-tree aliasing (path aliases
  normalized before fact-ID hashing so IDs match native scans);
  `detect_coverage_gaps()` emits a per-run `gaps[]` register into the
  facts file (zero-check frameworks, OpenShift Templates, `.tekton/`
  PipelineRuns, packaged Helm `.tgz`); SKILL.md documents engine-FP
  classes (CKV_AWS_27/SqsManagedSse, CKV2_GCP_18, CKV2_AWS_19) and the
  intake-gated Bicep limitation; `UPSTREAM-ISSUES.md` (new) holds 8
  draft upstream issues — filing is a human decision.
- **Cloud-config findings-current validator**
  (`schema/cloud-config-findings-current.schema.json` new +
  `scripts/validate_report.py`): detect_schema_path routes cloud-config
  cumulative currents (content-peek on `source_audit` /
  sibling audit) to a dedicated schema with CCA-ID uniqueness,
  effective-severity, and disposition-reconciliation cross-checks;
  91/91 live currents pass; code/container-audit routing unchanged
  (container-audit currents share the old gap — recorded, not fixed here).
- **Companion-lane stamp (plan item 3)**: secure-code-audit SKILL.md
  tree survey stamps `metadata.additional.companion_lanes:
  ["cloud-config-audit"]` for first-party TF/CFN/Bicep surfaces
  (declare-and-route, never skill-invokes-skill);
  `build_rescan_worklist.py` `companion_rows()` post-pass emits
  additive `iac-baseline` rows (rule `lever-6-companion`) when a stamp
  exists and no cloud-config baseline does. Also fixes a latent
  `ValueError` in the decisions sort (`TIER_ORDER.index(None)` on
  tier-less lever-6 rows) that would have crashed the first real
  router run with iac rows — tier-None now sorts as P3.
- **Release/dist-git event feeders (plan item 4, v1)**:
  `scripts/build_release_events.py` (new) — container leg diffs
  `*-payload-repos.csv` inventory digests against
  `release-events-state.json` (no registry polling in v1); dist-git leg
  `git ls-remote`s active https URLs from `config/rpm-distgit-watch.yaml`
  (new, operator-curated, inert by default) with S3 transport gating;
  appends release events to `rescan-events.jsonl`; `--dry-run`;
  idempotent; state seeded 2026-07-29 (12,732 keys, zero events by
  design). docs/continuous-operations.md gains an Event feeders
  subsection + daily-cadence row.
- Tests: +11 (Containerfile/gaps), +29 (validator), +21 (router stamp +
  feeders); docs script counts 77→79; README schema table gains the new
  schema row; docs/skills.md updated for both touched skills (A13).

## v0.206.0 — 2026-07-29

deep-fn Phase B2: route×guard matrix pre-scan — structural
enforcement-asymmetry lane (deep-fn-technique-plan §3 Phase B2 / D2;
targets the ~80%-FN enforcement-asymmetry class from the AWX probe)

- **scripts/enumerate_route_guards.py** (new): enumerates route
  registrations and the authn/authz guards actually applied — go-http
  (net/http, gorilla, chi/echo/gin verb styles, receiver-scoped `.Use`
  middleware) and django-drf (urls.py registrations, permission_classes
  + decorators, DEFAULT_PERMISSION_CLASSES baseline, AllowAny as an
  explicit unguard marker) — flags asymmetry groups (guarded/bare
  siblings in one file, the AWX miss shape), emits other detected
  frameworks as coverage_gaps, optional symbol-index handler
  resolution. Name-based over-inclusive guard recognition by design;
  the judge decides enforcement.
- **secure-code-audit SKILL.md**: route×guard pre-scan section — judge
  every judgement_required row (finding candidate / intentionally
  public with reason / dead with evidence), spot-check that recognized
  guards actually enforce, asymmetry groups judged as groups, the lane
  may NOT close with unjudged rows (remainder → negative_results),
  deterministic_steps + scanner_correlation recording. allowed-tools
  entries.
- 13 tests. Smoke: odf-operator surfaces the 6 ux-backend routes with
  zero in-process guards — mechanically reproducing the shape of the
  confirmed wave-3 ux-backend sidecar-bypass critical.


## v0.204.0 — 2026-07-29

deep-fn Phase B1: config-matrix pre-scan — effective-defaults expander
(deep-fn-technique-plan §3 Phase B1 / D3; targets the measured
config/DSN recall floor of 0.25–0.50 that the yaml rule pack alone
could not lift)

- **scripts/expand_config_matrix.py** (new): pure-static expansion of
  effective deployed defaults into (key, effective default, consuming
  sink) triples — helm values*.yaml chains with `.Values.*` sink
  resolution, kustomize generator literals, compose service
  environments, k8s workload env + ConfigMap data, and code-side
  fallback chains (Go os.Getenv/if-empty + cmp.Or + viper.SetDefault,
  Python environ.get/getenv, JS process.env ||/??). TLS/DSN/auth/
  listener/debug/secret classes get `judgement_required: true` with
  `weak_default` ordering; unexpandable systems (render-gated charts,
  TOML/INI, CRD config, triple-cap truncation) emit `coverage_gaps`.
  Deliberately execution-free: no helm/kustomize subprocess — chart
  templates are adversarial input, render tier deferred. No override
  cross-product (single documented overrides only, plan D3 risk c).
- **secure-code-audit SKILL.md**: config-matrix pre-scan section with
  the bounded judging protocol (judge every relevant triple; benign
  needs a reason; coverage gaps must surface in negative_results;
  deterministic_steps + scanner_correlation recording; accelerator
  never precondition) + allowed-tools entries.
- 19 tests (fixtures mirror the measured miss shapes: trustee helm
  chain, ocm-service-log code branch, compose/k8s literals); yaml
  rule-pack tests unaffected (76 pass). Smoke: odf-operator 35 triples
  / 4 judged / 3.4s.


## v0.203.0 — 2026-07-29

iac-lane: /cloud-config-audit wired into the continuous-scanning
router + leadership scoreboard (router-lane-coverage-plan lever 6 /
item 2b)

- build_rescan_worklist.py: IAC_RX detection (Terraform / cfn-dir /
  ARM+Bicep — mirrors the Phase-0 census patterns) over stage-2
  changed files; ADDITIVE `iac-lane` / `iac-baseline` rows emitted
  alongside the table's lane (a full-audit never runs Checkov's
  TF/CFN/Bicep policies, so one lane would silently drop the other);
  baseline split from findings.db report_kind='cloud-config'.
  change_metrics gains `iac_files`. 2 new tests (125 pass).
- docs/continuous-operations.md: iac-route row in the decision table
  (dispatch = /cloud-config-audit, ~$10/target measured; quarterly
  re-baseline rides drift-watch checkov-pin advances).
- collect_harness_metrics.py: Lens-1 cloud-config rows (IaC audits +
  findings by severity from findings.db, never blended into code-audit
  counts, Phase-0 step-change annotation baked in).


## v0.202.0 — 2026-07-28

integrity self-audit residuals: signature format 2, verified rule
cache, path gates (findings -005b/-006/-009/-012/-013/-014)

- **Merkle signature format 2** (`integrity/ledger.py`,
  `sign_merkle_root.py`, layer schema): the signed payload now binds
  the root PLUS leaf_format, epoch, size, the pre-epoch checkpoint,
  and a digest of `metadata.claim_hashes` — a bare-root (v1) signature
  could be transplanted, replayed after rollback, or re-scoped under
  the same signature, and left the claim pins self-referential. v1
  signatures verify with a content-unbound warning; re-sign to
  upgrade. Under `HARNESS_SIGNING_REQUIRED=1` a missing signature is
  now an ERROR (deleting the signature is not a downgrade path).
- **opengrep rule cache verified on reuse** (`run_opengrep.py`): a
  cached rule clone is trusted only when HEAD equals the pinned SHA
  and the worktree is pristine; otherwise it is discarded and
  re-cloned (poisoned rules could silently blind future scans while
  reports recorded the pinned SHA).
- **checkpoint.py**: dot-path components (`.git/config` → fsmonitor
  exec) and symlinked targets refused inside the confinement root;
  only `*-state` scratch dirs may be dot-dirs.
- **run_one.sh**: `REM_ID` gated to the campaign-id charset before it
  becomes a log/progress filename component.

## v0.201.0 — 2026-07-28

SCI-suite cross-review worklist: remaining worker-pr3 H-series ports +
ledger-pipeline defects found while mapping (completes the reconciliation
started in v0.200.0; SCI PRs sci#2/console#2/worker#2/worker#3 commented
2026-07-28)

- **Renderer/screen hardening ported** (worker pr3 H-series):
  `render_report.py`/`render_triage.py` escape untrusted report text
  before Markdown (control/bidi strip, table-pipe escaping, fences sized
  past the longest backtick run); `screen_injection.py` screens the
  fields that exist and drops two attacker-removable exemptions —
  zero-findings now flags regardless of agent-claimed `loc_reviewed`,
  audit-time-FP flags regardless of a `disposition_summary` key (tests
  repinned).
- **emit_validation_ledger_events.py**: `--build-cumulative` refuses a
  build_cumulative.py resolving outside the harness root or absent from
  the tree (H12); E3/ungraded-confirmation quarantine and severity
  proposals now emit schema-valid review items (`quote`, enum
  `queue_reason`s `weak_confirmation`/`ungraded_confirmation`/
  `severity_proposal` added to layer.schema.json) — previously every
  such layer failed the schema gate and crashed the cumulative render
  (`KeyError: 'quote'`; render now also tolerates legacy `note` items).
- **layer.schema.json**: `source.type` gains `impact_report` — the
  /dependency-watch lane emitted it since v0.19x while the enum lacked
  it, so every routed layer failed track-findings Phase 4; and
  `route_impact_findings.py` now creates fresh layers in the canonical
  `{metadata, events, needs_review}` shape (claim hashes under
  `metadata.claim_hashes`) instead of the ad-hoc pre-0.200 shape. The
  routing test now schema-validates the written layer.
- **build_cumulative.py event_class**: actor beats source — a human
  false_positive recorded on a verification_report event (the SKILL.md
  verification mapping) is class 2 and takes effect; previously it was
  filtered out of exec_decisive and the finding pended forever.
- **Adversarial-content doctrine in the triage verifier prompts** (full
  + compact templates) and the verify-remediation outside-the-repo rule:
  `risk_accepted` needs an acceptance record from outside the audited
  repo; in-repo claims carry zero weight.
- **config/model-registry.yaml**: `claude-fable-5` (10/50) and
  `claude-opus-4-6` (5/25, SCI-empirical) rows added so SCI's ratecard
  can consume the registry instead of hand-copying it.
- **schema/finding-identity-vectors.json** (+ replay test):
  cross-implementation conformance vectors for finding_identity.py
  (canon_repo/canon_path/fingerprint incl. pre-hash payloads) — the
  contract SCI's Go fingerprint port pins against.
- **model_registry.py spend**: embedded-environment gate — a workspace
  with no progress-tracker/ sibling skips the declaration cleanly (exit
  0) instead of minting an orphaned hash chain; the SCI worker can drop
  its SPEND_NOTE prompt override. `HARNESS_REQUIRE_SPEND_LEDGER=1`
  hard-fails for campaign CI. docs/model-routing.md updated.

## v0.200.0 — 2026-07-28

integrity P0s: content-bound Merkle leaves + authenticated countersign
(harness-integrity self-audit run 1, findings -001/-002/-004; design
reconciled with the SCI worker security-hardening branch so the
vendored tree can re-vendor upstream and DROP its divergence —
operator directive 2026-07-28)

- **Merkle leaf format 2** (`scripts/integrity/merkle.py`): leaves are
  the canonical full-event JSON, so any edit to any event field —
  actor, rationale, timestamps, `auto_accept_tier` — breaks the root.
  Legacy format-1 layers verify with a loud content-unbound warning
  and upgrade on any recording-tool write; `metadata.leaf_format` in
  the layer schema. Stamping REFUSES out-of-range `merkle_epoch`
  (truncation can no longer restamp silently); a missing pre-epoch
  checkpoint is an ERROR.
- **Authenticated countersign** (`countersign.py`,
  `validate_employee.py`): the signer proves credential possession via
  LDAP simple bind (`--auth bind`, getpass — never argv/env), exact
  machine-readable `RESULT uid=` matching replaces substring checks,
  and the verification strength is recorded on the event actor
  (`identity_verification`). `HARNESS_COUNTERSIGN_ALLOW_LOOKUP=1` is
  the recorded, operator-chosen downgrade.
- **Salted fail-closed FP audit valve**
  (`emit_triage_ledger_events.py`): sampling keyed on secret
  `HARNESS_VALVE_SALT`; unset salt queues EVERY auto-accepted FP for
  human review. `--lint`/`--layer`/`--register-out` path confinement
  (`--findings-root`).
- Countersign queue hardening: title/id sanitization in card markers,
  `layer=` write confinement (`--root`), hardened track-findings
  import (no ambient sys.path hijack).
- docs/disposition-ledger.md updated (§6/§6a/§10b). +11 tests
  (test_integrity_p0_fixes.py); merkle/countersign suites updated.

## v0.199.2 — 2026-07-28

router: secondary-ban circuit breaker (rate_limit is blind to bans)

Measured live: quota read 4,996 while 3,345/3,648 stage-1 calls
errored — a GitHub anti-scraping secondary ban, invisible to the
rate_limit preflight. Stage 1 now trips a consecutive-error breaker
(threshold 50): remaining GitHub repos get status `ban-suspected`
instead of churning failures (which prolongs the ban), the MD summary
carries a RUN ABORTED warning forbidding change-lane dispatch, and the
next daily run retries. The banned run's worklist was discarded
(restored from git); the rule-1 bootstrap portion (zero API calls) was
unaffected and valid.


## v0.199.2 — 2026-07-28

Rebaseline treadmill: superseded claim pins + namespaced-alias replay
(week-1 nested-path repair sweep)

- scripts/finding_identity.py rebaseline: migrates the layer's
  claim-hash pins to the new baseline — old ids absent from the new
  report are unpinned only when covered (aliased to a successor, or
  unmatched with a queued needs_review decision; batch
  --no-review-queue keeps unmatched pins). Also repoints
  metadata.audit_commit to the new report's commit. Previously every
  post-rebaseline build_cumulative run refused with "baselined finding
  missing from the audit report" (the state the 2026-07-27
  week1-fullaudit batch left 100+ dirs in).
- track-findings/build_cumulative.py: event replay now resolves the
  namespaced alias keys rebaseline writes ("<slug>:FIND-NNN" — events
  keep the bare id); ambiguous namespaced matches park rather than
  guess. Unmatched old ids with a pending rebaseline_unmatched
  needs_review item park their events instead of refusing the rebuild
  ("history stays under the old id until a human maps or closes it");
  refs with no alias and no queued decision still fail loudly — the
  tamper guard is unchanged.
- scripts/corpus.py: nested duplicate-dir guard — warns when the same
  report base exists at a dir and a direct child
  (`<x>/<repo>/<repo>/`), the signature left by a batch agent treating
  a repo_key (tree/[product/]repo_dir/base) as an output directory
  (week1-fullaudit: 6 of 110 re-audits; repaired 2026-07-28).
  Canonical product dirs named after their repo are not flagged.
- docs/report-structure.md "After writing a report" step 3 documents
  the claim-pin migration.
- 8 new unit tests (4 build_cumulative, 2 finding_identity, 2 corpus).

## v0.199.1 — 2026-07-28

router: rule-1 never-audited bootstrap (lever 1d) — fresh-repo ingestion

Cadence rule 1 was policy text only: a repo newly added to inventory
was invisible to the daily loop until a human campaign session noticed
(138 such repos at implementation). The router now diffs the
portfolio-graph repo spine (built from hybrid-platforms-inputs;
/drift-watch polices freshness) against the audited baselines and
emits `rule-1-bootstrap` full-audit rows for never-audited repos —
zero API calls (fleet-sweep-ban aware): exposure from the curated
designation only, private default; the first audit self-heals the repo
into change detection, the graph, and dependency watch. MD summary
gains a never-audited section; `--no-bootstrap` / `--graph-db` flags;
5 new tests (2,014 green).


## v0.199.0 — 2026-07-28

iac-lane Phase 0: portfolio-wide IaC discovery census
(router-lane-coverage-plan.md §3)

- scripts/build_iac_inventory.py: one recursive-tree API call per
  GitHub repo over the router's deduped HEAD-audit population;
  classifies Terraform / CloudFormation / ARM+Bicep (lane triggers)
  vs Helm/Dockerfile (SCA-covered, informational); emits
  iac-inventory.json + priority-ordered iac-baseline-worklist.{json,md}
  (exposure band > managed-services tenancy relevance > tier > live
  crit/high). Quota preflight + floor, resume cache, GitLab rows
  counted as gitlab-unchecked (visible gap, v1). Census only — no
  clone, no Checkov, no verdicts; the baseline sweep dispatch remains
  a budgeted user decision.
- 5 unit tests (pattern classes, lane-trigger exclusion of
  SCA-covered files, priority ordering, tier simplification).


## v0.198.3 — 2026-07-28

schema: origin enum actually gains impact-analysis (v0.197.0 no-op fix)

The v0.197.0 enum extension silently no-oped: the schema formats enum
values one per line and the single-line string replace matched nothing
— twice, unverified. Line-targeted insert with a post-edit assertion;
validator now passes impact-analysis filings. Lesson encoded: verify
the artifact, not the edit script's exit code.


## v0.198.2 — 2026-07-28

route_impact_findings: never file into derived artifacts (corruption fix)

The bootstrap's 49 "filings" all landed in *-findings-current.json:
findings.db report_path is the repo's PREFERRED representation, which
for md-only/converter repos is the derived findings-current — and the
layer-path suffix replace silently no-opped, treating the same file as
the ledger. 35 mutated files reverted in analysis-results. Fix:
resolve_baselines only ever returns *-security-audit.json (swapping a
findings-current path for its sibling audit when present, else the
repo reports `no-audit-json` — same self-heal class as no-pinned-sha);
hard assert on the filing target suffix; 2 regression tests proving
derived files stay byte-identical.


## v0.198.1 — 2026-07-28

route_impact_findings: read the REAL artifact shape (metadata-nested)

The bootstrap's 20 filing runs all failed: run_impact_analysis.py nests
cve/module/range under metadata, and both the router and its test
fixtures assumed top level — green tests proved fixture-fidelity, not
reality. Router now reads metadata-nested with top-level fallback;
fixtures corrected to the real shape with a regression note.


## v0.198.0 — 2026-07-28

/dependency-watch bootstrap mode: fleet_sweep.py (full-baseline sweep)

Operator feedback on the first full-baseline run: the advisory-set
enumeration was about to run as session scratch code — codified
instead as the skill's bootstrap mode. `harnessing/dependency-watch/
fleet_sweep.py`: clone-free fleet inventory (portfolio-graph
`depends_on` pairs × the OSV batch API; CVE-alias dedupe;
severity-banded) persisted as
`analysis-results/impact/fleet-osv-worklist-<date>.json` with staged,
ready-to-run impact/filing commands. Built-in staging discipline:
blast radius > --deep-scan-cap (default 100 repos) → graph-only
artifacts now (dashboard-visible exposure), deep scans operator-staged;
bounded CVEs → deep scan + filing. First live sweep: 14,006 dependency
pairs, 555 distinct CVEs (28 critical / 185 high). 5 new tests.


## v0.197.1 — 2026-07-28

(mislabeled v0.196.2 in commit 179222b — concurrent-session version
collision, repaired forward)

model-registry: correct the VERTEXAI_PROJECT characterization — the env
var is in active use for separate Vertex work (user statement), not
vestigial; it simply does not route Claude Code campaign billing
(CLAUDE_CODE_USE_VERTEX disabled).


## v0.197.0 — 2026-07-28

/dependency-watch: advisory-driven dependency lane, filed and accountable

Closes the impact→ledger filing gap (operator directive 2026-07-28):
a newly disclosed dependency CVE becomes an owned, SLA-clocked finding
the day the advisory lands — orchestrator-neutral, no UI dependency.

- **NEW `scripts/route_impact_findings.py`** — third instance of the
  v0.196.0 direct-entry convention (route_regressions sibling): per
  `affected` repo in an impact artifact, mints a campaign ID at the
  baseline sha, appends a `supply-chain` finding (`origin:
  impact-analysis`, CWE-1395, severity from the advisory — never
  invented, reachability evidence transcribed), pins the claim hash,
  appends a ledger birth event (`source.type: impact_report`, class-3
  machine-static), rebuilds the cumulative pair. Idempotent per
  repo+module+CVE; no-baseline repos listed, never dropped.
- **NEW `/dependency-watch` skill** — the chain end to end: feeds →
  new-advisory sweep → `/impact-analysis` (portfolio-graph freshness
  precondition stated) → filing → per-run routing report. A11-narrow
  allowed-tools; A9/A10 integrations wired both directions
  (impact-analysis SKILL names the new consumer).
- **Schemas (additive):** `origin` gains `impact-analysis`
  (report.schema.json); ledger `source.type` gains `impact_report`
  (layer.schema.json, class-3 per existing actor/exec-set semantics —
  no build_cumulative change needed).
- **Executive summary: "Dependency Exposure by CVE"** — per-advisory
  fleet cut joining analysis to accountability (affected vs filed vs
  resolved); parser retains `origin` + CVE back-reference.
- 9 new tests (1,990 total green); continuous-operations.md filing-gap
  section rewritten as closed; docs/skills.md + README + counts synced.


## v0.196.3 — 2026-07-28

docs: impact->ledger filing gap named (operator-identified)

affected classifications reach findings.db impact table but not the
findings pipeline (no owner/SLA/Jira) until a full audit files K07 —
closure planned as emit_impact_ledger_events.py (wiring plan lever 1c).


## v0.196.2 — 2026-07-28

docs/continuous-operations.md: signal-to-ledger path + new-dependency channel

Operator feedback: the doc never explained where lane outputs land or
how deterministic hits become issues people address. Added "From signal
to accountability" (router rows = routing; agent lanes file into the
ONE baseline+ledger pipeline; diff-scan findings enter at not_verified;
deterministic dependency outputs land as escalations/impact artifacts,
never verdicts — no per-lane findings layers), and the coverage model
gains the missing arrival channel: a newly added dependency with no
advisory yet (today osv-only until the next full audit; planned lever
1b reputation tripwire closes it to ≤1 day).


## v0.196.1 — 2026-07-28

model-registry: billing-channel caveat made channel-neutral

- the rate-card comment named Vertex terms as the verify-against
  channel; billing is confirmed Anthropic first-party API (2026-07-28:
  CLAUDE_CODE_USE_VERTEX disabled; VERTEXAI_PROJECT env var vestigial).
  Caveat now channel-neutral (enterprise agreements and partner
  channels can differ from list, whatever the channel) with the
  confirmed channel recorded. Companion corrections in
  progress-tracker cost docs (continuous-scanning, rescan-cost-report).


## v0.196.0 — 2026-07-27

Regressions become first-class ledger findings — the verify-remediation
Phase-5 `regressions[]` routing gap is CLOSED (explicit user directive,
2026-07-27). The measured defect: `{SLUG}-{sha7}-REG-{NNN}` ids fail the
campaign finding-ID regex, no consumer was wired (an A9-class unwired
artifact predating the integration rules), and the disposition ledger /
cumulative machinery never saw them — 23 regressions from the 2026-07-27
jira-harvest verify sweep (incl. LIFT-47bbd1e-REG-001, CRITICAL:
unauthenticated sushy-tools Redfish BMC emulator on 0.0.0.0) existed
only inside verification reports.

Design decision (binding): regressions enter the ledger DIRECTLY — no
/triage precondition — parity with the full scanning skills, whose
findings enter reports/ledger at birth as `not_verified` with triage
adjudicating downstream.

- NEW `scripts/route_regressions.py` (idempotent, deterministic; routes
  and records, never authors a verdict): per regression, mints a
  campaign ID at the patched sha (`{REPO_SLUG}-{PATCHED_SHA7}-{NNN}`,
  numbering continuing where the baseline's findings at that sha leave
  off — sha-scoped, collision-free), appends the transcribed finding to
  the baseline `*-security-audit.json` (`validation_status:
  not_verified`, `origin: "verify-remediation"`, finding_identity
  fingerprint, REG id + verification report in `source_findings`,
  summary counts kept validator-consistent), pins the claim hash
  (add-only), appends a ledger birth event (`resolution: open`,
  verification report as evidence_ref, canonical event_id dedupe),
  writes `routed_id` back onto the regression entry (provenance both
  ways), and rebuilds the cumulative pair.
- Schemas, additive only (MINOR): `report.schema.json` finding gains
  optional `origin` (sanctioned-append producer enum);
  `verification.schema.json` regression gains optional `routed_id`.
  `validate_report.py` adds routed_id cross-checks (one-to-one routing,
  sha-segment match).
- verify-remediation SKILL: Phase 7a2 (mandatory routing step), sweep
  Step-3 wiring, REG-id provenance note, Integrations section.
  track-findings SKILL: regressions[] mapping-table row, ingest step,
  allowed-tools grant, Integrations section.
- vuln-scan SKILL aligned to the same convention: verified new findings
  enter the baseline + ledger directly at `not_verified` (no triage
  precondition; DO-NOT-REPORT list and never-drop contract untouched).
  validate-findings SKILL: executed novel findings get the same routing
  statement (campaign IDs at the validated sha, direct ledger entry,
  validation report as class-1 evidence; discovery-sweep candidates
  still triage-first) + Integrations section.
- Docs: findings-lifecycle birth-paths table, disposition-ledger /
  baseline_claims add-only wording, report-structure `origin` row,
  skills.md entries for all four touched skills.
- LIVE ROUTING: the 23 stranded regressions from the 2026-07-27 sweep
  (analysis-results 0c668ce10d, 11 reports) routed — incl.
  LIFT-47bbd1e-001 (critical) and the four LIFT highs,
  MODELS_AS_A_SERVICE-57f9ece-{001,002} (high),
  MAAS_BILLING-2f11985-001 (high) — ledgers + cumulatives rebuilt and
  validated in analysis-results.
- Tests: tests/test_route_regressions.py (8 cases — ID compliance,
  numbering continuation, fingerprint/claim-hash canonicality, ledger
  event shape, idempotent re-ingest, cumulative visibility).

## v0.195.0 — 2026-07-27

weekly drain: orchestrator entry point + documented contract

The drain is becoming a standing schedule under an external
orchestrator (operator direction 2026-07-27); tranche 1 was selected
ad-hoc, which a standing job must not repeat. New
`scripts/emit_drain_tranche.py`: deterministic weekly tranche
selection from the routed worklist (`drain_order < weekly_rate`,
`--include-immediate` for the diff-scan lane), fail-closed on a stale
(>48h) or pre-preroute worklist and on a second tranche in the same
ISO week (`--force` to override), emitting a dated
`drain-tranche-<YYYY-Www>.json` manifest that embeds the dispatch
contract. docs/continuous-operations.md gains the "Standing weekly
drain — orchestrator contract" section (daily router → weekly
tranche → per-row headless diff scan; S9 isolation, no
token-in-URL clones, refusals are outcomes not failures, measured
planning rates, ledger append); README table row points at it. +6
tests.

## v0.194.2 — 2026-07-27

docs: refresh measured diff-lane base rates; remove a leftover
hard-gate sentence

`docs/continuous-operations.md`'s lane-cost table still read "target
≤$5 — gate currently failed" — the framing the operator corrected
2026-07-27 (reference target, not a gate). The table row and the
fleet-dispatch paragraph now carry all three measurements (pilot
$6.67 pre-packet; context-packet re-pilot $4.73/−29%; drain tranche 1
heavy mix $6.24 with refusals at $0.81, ≈$220–260/week planning
rate). vuln-scan SKILL.md and docs/skills.md updated with the same
base rates.

## v0.194.1 — 2026-07-27

rescan pre-route: imminent-row horizon + honest tree-failure counting
(drain tranche-1 lesson)

Tranche 1 dispatched 51 pre-routed rows and still hit 16 file-ratio
refusals: the build's unscoped ratio sweep (466 tree calls after
~4,500 stage-1/2/tripwire calls) exhausted the GitHub quota mid-run,
and failed fetches were silently left unverified behind
`checked_ratio=466 / 0 hits`. Fixes: the ratio leg now checks only
dispatch-imminent rows (every immediate diff-scan + quarterly rows
inside the next 2 weekly tranches, same risk sort the drain uses;
deeper rows are checked as they surface), the changed-file floor
drops 8→3 (a 5/10-file refusal was observed), and tree-fetch
failures are counted (`tree_failed`, per-row `preroute_tree_error`)
and called out in the MD — never silent. +1 test (116 pass).

## v0.194.0 — 2026-07-27

Precision Gate ported to the three sibling scanning skills — the
pre-registered residual of the v0.191.0 FP-persistence fix
(fp-persistence-analysis §5) and the dominant measured FP path: 19 of
the 38 leg-2 recurrences came through skills that never received the
gate (secure-container-audit 12, vuln-scan 6, secure-rpm-audit 1).
Ported by adaptation, not copy-paste; gate vocabulary, severity floors
(verification-disable / credential-transport, high minimum), do-not-
report boundaries, downgrade-not-drop posture, and the mandatory
`metadata.additional.precision_gates` record match secure-code-audit's
semantics exactly. Non-transferable rules are stated as non-applicable
per skill, never silently omitted. Expected effect: closes the 19/38
sibling-skill recurrence path; re-measurement = next benchmark/matrix
cycle (FP-persistence should also be reported severity-conditioned per
the analysis's scorer note).

- secure-container-audit: full Precision Gate section with the
  dependency and advisory gate as centerpiece (its 12 recurrences were
  all uncapped dependency-CVE re-filings at HIGH/CRITICAL, R1/R5
  classes) in image/SBOM semantics — artifact reachability where
  determinable (installed vs base-image-inherited layer attribution,
  entrypoint/linkage/exposure signals, govulncheck binary mode),
  Red Hat CSAF/OVAL vendor applicability (affirmative evidence only),
  SBOM-match-only lint (bare version match = dependency_audit, capped
  at medium when reachability undeterminable); crit/high reporting bar
  (chain-completion for dependency findings only — explicitly n/a for
  oci-config findings); path pre-filter over image pseudo-paths;
  fp-precedent gate for shared base-image/sidecar components;
  scoped-baseline gate stated n/a (the artifact IS the shipped
  product); negative_results precision; precision_gates record.
- vuln-scan: new Step 3c adds ONLY what its DO-NOT-REPORT list (0
  refuted FPs historically — stays authoritative where it overlaps)
  lacked: compensating-control sweep, privilege-delta test,
  by-design/opt-in check, chain-completion-at-critical with the shared
  severity floors, fp-precedent check on vendor-root candidates
  (match-mode-only allowlist entry added), coverage-note precision
  (the negative_results rule adapted to category=none notes), and the
  precision_gates record. Consistent with the skill's never-drop
  contract, the only fired action is "downgraded"; dependency/advisory
  and scoped-baseline gates stated non-transferable (the list already
  excludes dependency findings outright).
- secure-rpm-audit: full gate in packaging semantics —
  vendored-source reachability (%build/%bcond/subpackage closure),
  downstream-backport + CSAF applicability (check the patch stack and
  %changelog for the CVE id before filing NVR matches), manifest-only
  lint; scoped-shipment (built-RPM closure) analog of scoped-baseline;
  execution-context check (-tests/-doc subpackages, dead code);
  crit/high bar with patch-stack-as-compensating-control, scriptlets-
  are-root-by-design privilege-delta, chain-completion (n/a for
  RPM02/03/04/06 spec-construct findings); %files path pre-filter +
  packaging mechanism verification (macro expansion, autosetup);
  fp-precedent gate for vendored bundles; do-not-report by reference
  to secure-code-audit (spec/scriptlet/patch findings explicitly
  outside its "build scripts" bullet); precision_gates record.
- All three reference the tiered FP-precedent cache the way
  secure-code-audit does since v0.193.0: human-countersigned
  precedents are citeable gate evidence, machine-tier context only,
  downgrade-not-drop, missing cache = silent skip.
- docs/skills.md: the three entries updated in the same commit (A13).

## v0.193.0 — 2026-07-27

Phase 4 fleet mechanisms LIVE: tiered FP-precedent cache + sweep-engine
triage wiring (error-correction plan §6; plan §0 table wrongly carried
Phase 4 as "not started" — both mechanisms shipped dormant in v0.151.0;
this release activates them)

- build_fp_precedent_cache.py: tiered population rule replaces the
  v0.151.0 human-countersigned-only rule that kept the cache permanently
  empty (0 entries) while the shared-component re-refutation treadmill
  ran on. `strength: human_countersigned` (LDAP-verified interactive
  countersigns AND Jira-harvest decision-maker events — the 2026-07-27
  batch's 22 cards now seed) > `strength: machine_refuted_sound`
  (triage/verification protocol adjudications + live refutations that
  PASS the Phase-1 soundness gate, re-derived per event against the
  referenced validation report) > machine-refuted-UNSOUND = EXCLUDED
  (soundness-flagged or unresolvable — the measured ~70%-unsound class
  never seeds). Guards: P6 conflict (any confirmed event) and stale
  disposition (fp_overridden/reopened/confirmed) exclude; hardening
  verdicts cached alongside FPs; evidence_refs + verdict + countersign
  status per precedent; FP-persistence taxonomy join (phase2_rule /
  failure_class via Jira ticket id). Live build: 12,147 component
  entries — 29 human-countersigned + 15,609 machine-refuted-sound
  precedents across 8,206 layers (72 unsound / 396 contested / 151
  stale excluded). Measured treadmill: 4,104 of 16,698 adjudication
  events were re-adjudications of an already-adjudicated claim (1,608
  cross-repo + 2,496 same-repo, incl. the kube-rbac-proxy 82× class) —
  all now carry citeable precedent. 27 tests (was 16).
- triage SKILL.md 2g/3b: strength-tiered routing — human_countersigned
  match keeps the reduced 1-vote tier; machine_refuted_sound match is
  annotation-only at full votes; FP-PRECEDENT block carries strength +
  adjudicator; PRECEDENT DISAGREEMENT escalates to /countersign only
  against human-tier precedents. Precedent is citeable prior
  adjudication, never an auto-verdict (downgrade-not-drop unchanged).
- secure-code-audit SKILL.md: fp-precedent gate in the Precision Gate
  flow — vendor-root crit/high candidates check the cache before
  filing; a human_countersigned match is citeable gate evidence
  (recorded in precision_gates.fired, downgrade-not-drop); machine-tier
  matches stay triage-side; missing/empty cache = silent no-op.
- drift-watch: fp-precedent-cache staleness row (metadata.generated vs
  newest findings-layer mtime) + SKILL.md table row; check_drift.py
  check_fp_precedent_cache + test.
- sweep-engine wiring COMPLETE (plan §6 item 2): triage SKILL.md gains
  "Note — class-generalization sweep candidates" defining the
  sweep-candidates.json ingest (candidates[] mapping, origin: sweep,
  provenance-as-context, test_path demotion, cross-repo grouping) and
  `candidates` joins the generic-container array list; mine-ledger
  SKILL.md names the cross-reference. The A9 exemption for
  mine-ledger:sweep-candidates.json is REMOVED (consumer now wired;
  exemption list shrinks). The confirmed-TP flow mine-ledger →
  sweep_engine → corpus sweep → sweep-candidates.json → /triage is now
  end-to-end documented; no new runner needed (stages run via the
  mine-ledger skill's documented CLI).
- docs: skills.md (triage/secure-code-audit/mine-ledger/drift-watch),
  findings-lifecycle.md, triage-ledger-integration.md,
  deterministic-tooling-assessment.md updated to the tiered rule.

## v0.192.1 — 2026-07-27

resolve_baseline: strip userinfo from origin URLs (credential hygiene)

The re-pilot's lightwell row was cloned with a token-in-URL remote
(`https://oauth2:<token>@gitlab...`); `repo_origin_url()` passed the
credential through into the scope package, the refusal message, and
the findings.db lookup (which stores clean URLs — so the lookup also
failed and the row refused spuriously). Userinfo is now always
stripped before normalization. The leaked scratch/transcript copies
were scrubbed same-day; the token was recommended for rotation. +1
test.

## v0.192.0 — 2026-07-27

vuln-scan diff mode: deterministic context packets (pilot follow-up)

The 50-repo pilot showed diff-scan cost tracks fixed exploration
overhead, not diff size (median 640 changed lines → $6.67/run). New
`harnessing/vuln-scan/scripts/build_diff_packet.py` (Step 0b) folds the
agent-side scope choreography into one deterministic artifact per run:
changed hunks (`git diff -U10`, byte-capped with an explicit `omitted`
ledger), direct callers of changed-file symbols (symbol index, ±3
lines context per site), and pre-sliced baseline findings — grouped by
the resolver's clusters so each review subagent's brief is
self-contained. SKILL.md gains the packet-first review discipline
(read embedded evidence first; open files only to verify) and a
small-diff fast path (C < 1,000 and ≤2 clusters → `--single` with
inline confidence scoring, no per-finding scorer subagents). The stale
"acceptance gate ≤$5 / not fleet-authorized" paragraph is replaced
with the operator-decision framing and measured pilot base rates
(operator clarification 2026-07-27). A9 exemption for the
self-consumed `*-diff-packet.json` scratch artifact. +8 tests.

## v0.191.0 — 2026-07-27

secure-code-audit: FP-persistence fix — Precision Gate re-calibration
(error-correction plan next-cycle item, §0.1)

Leg 2 measured 38/62 baseline-adjudicated FPs recurring in the P5
matrix despite the v0.143.0 Precision Gate. Taxonomy
(`analysis-results/scan-testing/sxs-2026-07/fp-persistence-analysis.{json,md}`):
19 recurrences flowed through sibling skills that never received the
gate (secure-container-audit 12 at high/critical, vuln-scan 6, rpm 1 —
portage is named next-cycle work, out of this change's scope); 9
recurred on secure-code-audit targets at *downgraded* severity
(downgrade-not-drop working; scorer counts any-severity matches); 8
were raw-arm-only control noise; 2 were runner skips (arm E filed
refuted classes with zero gate evidence). The 2026-07-27 countersign
batch added 22 human-adjudicated FPs: 8 covered by existing rules
(audits predate the gate), 7 a new non-production-execution-context
class, 7 a new scoped-consumer-reachability class.

Changes (all downgrade-not-drop; pre-registered in the analysis doc):

- **Gate-application record (mandatory):** reports stamp
  `metadata.additional.precision_gates` (crit/high candidates
  evaluated + per-fired-gate action) — makes gate application
  observable; targets the runner-skip class.
- **New gate — scoped-baseline reachability:** shared repos audited
  under a product-scoped tree verify consumption-closure reachability;
  out-of-closure findings file as informational upstream notes with the
  scope-NA rationale (never deleted — valid for the upstream cut).
- **New check — execution context:** dev-mode-gated, CI-only, and
  dead-code paths downgrade to informational with the gating condition
  cited; keep-severity boundaries stated (low-priv-enableable toggles,
  silent fallbacks, dev artifacts shipped to production).
- **Mechanism-verification channel fix:** affirmative mechanism
  refutations route to `negative_results`, never a low finding
  (measured: refuted zipfile zip-slip recurred as a low finding).
- **Do-not-report:** non-production-execution-context bullet.
- **opengrep pack v1.6:**
  `hps-python-path-traversal-tar-extractall-nofilter` no longer matches
  zipfile receivers (was mechanically re-seeding the refuted
  zip-slip-on-zipfile class); zipfile `ok:` fixtures added (13/13 pack
  tests pass).

Re-measurement = next benchmark cycle (leg-2-style paired matrix or
/recall-benchmark FP-proxy rows) per measure→change→re-measure.

## v0.190.0 — 2026-07-27

rescan router: refusal pre-route for the diff lane (pilot follow-up)

The 50-repo diff-mode pilot measured a 32% refusal rate — rows the
router placed in a diff lane that the resolver then refused at
dispatch after a clone (~$1.86 wasted per refusal, plus a fan-out full
audit). Root causes: the router's C is computed from capped compare
payloads (GitHub 300 files / GitLab diffs[] cap), so `truncated`
compares undercount churn; and the resolver's >30%-of-first-party-
files refusal rule had no router-side counterpart. New pre-route pass
in `build_rescan_worklist.py` (runs after the tripwire, before drain
ordering): truncated diff-lane rows re-route to full-audit for free;
rows with ≥8 changed first-party files get one quota-aware GitHub
tree call to evaluate the file ratio, re-routing >30% rows. GitLab
rows skip the ratio leg honestly. Rows carry `rule: <orig>+preroute`
and a `preroute` evidence block; summary/MD gain a preroute stats
line; `--no-preroute` disables. Routes only — the resolver remains
the dispatch-time authority. +8 tests (115 pass).

## v0.189.0 — 2026-07-27

repo-config isolation doctrine + gate rule S9 (b-lite-p5 incident)

Scanned repos shipping their own `.claude` hooks/`CLAUDE.md` killed —
and could have injected — headless scan workers whose cwd was the
clone (b-lite-p5 sweep, 2026-07-26; 63 affected repos re-scanned).
Doctrine added as adversarial-content rule 4 (canonical doc +
secure-code-audit + recall-benchmark run step): headless/batch agents
run with cwd outside the untrusted checkout; target-supplied agent
config is never loaded as configuration — it is data under audit.
`check_skill_security.py` gains rule S9 enforcing the doctrine on any
file that launches a headless agent (`claude -p/--print`, `crush run`,
`opencode run`); +2 tests. Zero current violations, zero exemptions.

## v0.188.3 — 2026-07-27

tripwire: byte-safe patch handling (observed 28MB invalid-UTF-8 diff)

First tripwire-enabled live run crashed on a compare diff containing
invalid UTF-8 in text-mode subprocess decoding. Patch fetch now
captures bytes and decodes tolerantly after capping; gitleaks stdin
input is encoded tolerantly. Regression test added.


## v0.188.2 — 2026-07-27

exposure model: curated repository exposure designations; public defaults external

Two operator corrections to the v0.188.1 exposure model:

- **"External" is a repository exposure designation** (does the code
  reach customers / externally-facing services), NOT the corpus
  ownership/BU tag — the `external-bu` regex is removed. Designations
  are operator-curated in
  `findings/_manifest/exposure-designations.json` (`--designations`;
  exact-URL or org-prefix matches; values `external` /
  `internal-tooling`); the router consumes read-only.
- **Public visibility defaults to `public-external`** — public ≈
  productized in this portfolio; the explicit `internal-tooling`
  designation demotes to `public-internal`. Upstream-elevated private
  repos do NOT ride this default (rank 3 undesignated; rank 1 only if
  also designated external).


## v0.188.1 — 2026-07-27

exposure classes corrected to the operator's 2×2 ground truth

Externality dominates visibility (v0.188.0 had public unconditionally
first): `public-external` (product code available to customers — scan
the most) > `private-external` (private tooling powering customer-
facing services) > `public-internal` (world-readable but not
productized) > `private-internal` (never reaches customers — scan the
least). A public upstream elevates a private repo on the visibility
axis. Ceiling tightening and the 14-day drain target now follow the
external band, not raw visibility.


## v0.188.0 — 2026-07-27

exposure reduction: exposure classes + secrets tripwire + trickle-drain

Session 4 levers 1+2 of the continuous-scanning wiring plan (§6b/§6c;
cadence policy v1.4 §2.1b — user risk directive: public/external most
exposed, a public upstream elevates private repos):

- **Exposure classes** on every worklist row — `public` / `external` /
  `internal-public-upstream` / `internal-private`, computed at zero
  marginal API cost (stage-1 `visibility`/`fork`/`parent` fields +
  corpus-config ownership). Exposure is now the primary sort key inside
  every lane; `public`/`external` tighten the rule-4 ceiling one notch
  (P1 270→180d, P2 365→270d); a private fork of a public upstream is
  elevated because the upstream is attacker-readable and its vulns
  propagate on rebases/bumps.
- **Tripwire (lever 1, v1: secrets-on-patch):** gitleaks runs over the
  change's patch text for every below-threshold routed row — GitLab
  patches captured free in stage 2, GitHub via one quota-aware call —
  and any hit escalates the row to an immediate diff-scan (rule
  `tripwire`). Exposure for leaked-secret changes collapses from ≤90
  days to ≤1 day, at ~$0. Routes only; the diff scan adjudicates.
  `--no-tripwire` disables; scanner-missing and quota-skipped rows are
  counted, never silent. KHS/opengrep tripwires land with the session-4
  screener (need raw fetches/checkouts); manifest-only changes already
  reach osv via rule 3b.
- **Trickle-drain (lever 2):** `diff-scan-quarterly` rows carry
  `drain_order` (risk sort: exposure → tier → S_lines → C); weekly
  dispatch takes `drain_order < --drain-rate` (default ceil(pool/13) —
  same quarterly volume/cost, short stable queue instead of a 90-day
  batch tail). Public/external rows undrained past 14 days are flagged
  overdue in the MD summary. Dispatch remains gated on the diff lane's
  cost-gate re-negotiation.
- 21 new tests (1,932 total green); docs/continuous-operations.md updated
  (exposure section, tripwire row, weekly-trickle cadence).


## v0.186.3 — 2026-07-27

docs/continuous-operations.md: decision criteria in detail + lane weights

Answers "what exactly triggers a rescan, and how heavy is each scan":

- **Decision table expanded** from a summary paragraph to a full
  reference: per-rule trigger, exact threshold, lane, and the measured
  empirical basis for each threshold (churn-population percentiles,
  FN-yield calibration, error-analysis FN classes); signal definitions
  (C first-party filter, narrow sensitive matcher scope, DEPS list);
  tier definitions; no-pinned-sha and quota-deferred special routes;
  provenance pointer to the deriving plan + quarterly re-derivation.
- **New "Lane weights" section**: per lane — what it actually reads,
  measured median cost, and discovery power (recall, intercept,
  class-sweep blind-spot recovery), plus the hand-dispatch rule of
  thumb the router encodes.
- **Diff lane marked NOT fleet-authorized**: the 2026-07-27 50-repo
  pilot failed the ≤$5 cost gate (median $6.67; 32% correct refusals);
  quarterly diff batches stay unscheduled until the gate passes or is
  re-negotiated (options in the diff-mode plan).
- Budget-knob order synced with the verified batch-discount finding
  (one-shot restructuring + committed-use, not "Batch API everywhere").

## v0.186.2 — 2026-07-27

docs + skills: rescan frequency is the router's decision, everywhere

Wires the continuous-operations router into every doc and skill that
speaks about when to rescan, so no surface implies calendar- or
judgment-driven re-audits:

- `PROCESS.md` — new "Continuous Operation" cross-stage section: after
  the baseline, the router (not a calendar) routes repos back into
  Stage 2.
- `secure-code-audit` SKILL — Batch Execution now states that
  which-repos-when is the router's call (consume the worklist's
  `full-audit` rows); `metadata.commit` documented as the router's
  change-detection anchor (the 211-report lesson).
- `verify-remediation` SKILL — full-sweep positioned as the weekly
  verify lane; router owns fresh-discovery frequency, verify remains
  the only finding-resolving lane.
- `secure-container-audit` / `secure-rpm-audit` SKILLs — "Re-audit
  cadence" sections: release-event/dist-git-commit-driven via the
  router's `release-passthrough` lane, ceilings as the only calendar
  backstop.
- `drift-watch` SKILL — `rescan-worklist` staleness item added to the
  checks table (shipped in check_drift.py at v0.185.0, table lagged).
- `docs/skills.md` — all five entries synced (A13);
  `docs/getting-started.md` — "keep audits fresh" pointer.

## v0.186.1 — 2026-07-27

router: stage-2 quota deferral (a full fleet run brushes the 5K/hr cap)

The v0.186.0 preflight was right to refuse quota-starved runs but wrong
about arithmetic: a full run needs ~5.3K GitHub calls against a 5K/hr
quota, so a 2×-repos preflight would refuse every complete run. Split
the guard: preflight covers stage 1 only (hard refusal, exit 4);
stage 2 checks the remaining quota itself and marks compares that do
not fit `quota-deferred` — honest rows (lane `none`, dedicated rule +
MD notice) that the next daily run classifies. Convergence within a
day; nothing silently lost.

## v0.186.0 — 2026-07-27

/vuln-scan --diff mode + router rate-limit hardening

Session 2 of the continuous-scanning wiring plan
(`vuln-scan-diff-mode-plan.md`): the measured middle lane. As shipped,
/vuln-scan costs 2.5× a full dual-pass audit ($73.49 vs $29.69 median,
2026-07 matrix transcripts) — diff scoping is what makes the middle
lane economically real (target ≤$5/run, pilot-gated).

- **`harnessing/vuln-scan/scripts/resolve_baseline.py`** — deterministic
  diff-mode resolver: repo identity via git remote + corpus
  normalization, baseline = newest valid HEAD code-audit in findings.db
  (router-identical query), anchor from the report's `metadata.commit`
  (`--since`/`--baseline` are explicit overrides, provenance recorded),
  `git diff --numstat` scope package with router-parity first-party /
  sensitive / deps classification (asserted identical in tests).
  Refuses → `recommend: full-audit` (exit 3) on >30% files changed,
  C≥8K, no baseline, or unreachable anchor — never a whole-repo
  fallback.
- **SKILL.md "Diff mode (--diff)"**: resolver replaces recon; scope =
  changed files + symbol-index callers + baseline threat-model rows;
  clusters as focus areas; changed-set-only pre-scanners; fingerprint +
  fuzzy dedupe (fingerprints measured unstable across runs, median
  overlap 0.14); `metadata.additional.coverage_diff` + `spend` stamps;
  NOT fleet-authorized until the 10-tile recall check and the 50-repo
  ≤$5 pilot pass. Schema: `metadata.additional` added (additive).
- **Router (first-live-run hardening):** GitHub quota preflight — exits
  4 instead of emitting a legitimate-looking garbage worklist (observed
  live: 2,041/3,648 errors on a quota-starved run); `--ignore-rate-limit`
  override; per-row `error` messages in the output; >5% error rate adds
  a loud MD warning.
- 35 new tests (1,910 total green).

## v0.185.1 — 2026-07-27

rescan router: no-pinned-sha self-heal + GitLab warning wording

First-live-run findings (3,648 repos, 2026-07-27): 211 converter-era
reports carry no recoverable anchor SHA, so stage-2 compare can never
run and rules 2/3/5/6 can never fire — those repos were silently
routed `none` as "dormant" forever. Fail-safe fix: a no-pinned-sha repo
with a stage-1 push signal now routes to **full-audit** ("anchor
re-establishment" — the new report stamps `metadata.commit`, so the
class self-heals); without a push signal it waits, with an honest
reason. Also clarified the MD GitLab warning (unreachable **or
errored**, already counted in the population totals).

## v0.185.0 — 2026-07-27

continuous scanning: rescan router + event lanes + operational guide

Session 1 of progress-tracker/plans/continuous-scanning-wiring-plan.md
(cadence policy: rescan-cadence-plan.md v1.3, thresholds derived from
the measured churn population and the FN-per-churn calibration):

- **`scripts/build_rescan_worklist.py`** — deterministic daily router.
  Two-stage change detection (`gh api` pushed_at → compare, and the
  GitLab lane via `glab api` for gitlab.cee/gitlab.com; VPN-down runs
  mark GitLab repos `unreachable` and the summary says so), risk tiers
  P0–P3 from live crit/high counts in findings.db, decision table
  rules 2–7 encoded as data, event injection from
  `findings/_manifest/rescan-events.jsonl` (external-report →
  full-audit+validate ahead of the table; methodology/cve/release
  lanes), advisory budget guard with listed drops — no silent
  truncation. Routes only; never authors a verdict. Emits
  `rescan-worklist.json` + MD summary.
- **Drift-watch:** `check_rescan_worklist()` — stale when the worklist
  is missing or older than 3 days.
- **`docs/continuous-operations.md`** — the operational guide: loop
  diagram, arrival-channel coverage table (dependency CVEs / code
  changes / audit FNs / methodology / external reports), lane cadences,
  event record format, budget knob order, measured residuals.
- 79 router tests + 3 drift tests; all doc/alignment/security gates
  green.

## v0.184.0 — 2026-07-25

docs-drift prevention: A13 + partial-enum/as-of gates + sweep cadence

The remaining prevention layer from the 2026-07-25 docs sweep (the
CLI-example gate shipped in v0.183.0):

- **Alignment rule A13 (skills-doc sync):** a staged
  `harnessing/*/SKILL.md` change must ship with a staged
  `docs/skills.md` update — the sweep found ~25% of reference entries
  lagging their skill. Pre-commit-only (`HARNESS_PRE_COMMIT=1`, exported
  by the hook), so tests and tree checks are unaffected; waive
  doc-irrelevant changes with `SKILLS_DOC_WAIVER=<reason>`.
- **Docs check: partial enum quotes.** A maintained-doc line naming an
  enum-bearing schema field that quotes 3+ of its values but not all is
  a lagging enumeration (the `validation_status`-missing-`hardening`
  class). Only fields whose enum is identical everywhere it appears in
  schema/ are tracked — ambiguous names like `verdict` are excluded.
- **Docs check: as-of banners.** `docs/*assessment*.md` / `*draft*.md` /
  `*comparison*.md` must carry a dated as-of banner so point-in-time
  judgments never read as live status.
- **Quarterly semantic sweep institutionalized:** procedure documented in
  the check-harness-docs SKILL (reviewer fan-out → verified findings →
  fix agents, report to progress-tracker/metrics/docs-verification-*);
  /drift-watch gains a `docs-semantic-sweep` item flagging the newest
  report when older than 92 days.
- AGENTS.md gains a Documentation-upkeep section stating the four
  conventions; skills.md entries for check-alignment (thirteen rules),
  check-harness-docs, and drift-watch refreshed — satisfying A13 on its
  own introduction commit.

## v0.183.0 — 2026-07-25

docs: fix the 2026-07-25 verification-sweep findings + CLI-example gate

- **All ~60 verified discrepancies from the docs-verification sweep fixed**
  (report: progress-tracker/metrics/docs-verification-2026-07-25.md).
  Highlights: every broken `validate_report.py --validate` example
  rewritten to the real CLI (setup, getting-started, outputs); the
  inverted ledger-precedence claim corrected to evidence-class order with
  the v0.179 E0/E1 grade condition (outputs + the ledger trio, which also
  gain the soundness gate as the sixth FP control, the cross-repo
  two-legged rule, the FP-precedent cache, SARIF intake, and countersign
  override modes); setup.md's hook section now describes the real
  pre-commit gates; skills.md refreshed for pqc-readiness (v0.162
  contract), secure-code-audit (8 frameworks, dual-pass, Precision Gate),
  verify-remediation (cross-repo), triage (canonical output names) and 8
  more entries incl. dashboard paths; signing.md rewritten around the
  real CLI flags (dead env-var config dropped); risk-rating-methodology
  documents the v1.1.0 threat-intel factor; reachability draft's status
  table corrected and dated; deterministic-tooling roadmap updated + the
  nine newer deterministic tools listed; error-model recall figures
  qualified single- vs dual-pass; external-dependencies gains the NVD API
  feed row, a cargo row, and attribution fixes;
  public-skill/best-practice assessments get dated-snapshot banners with
  false claims corrected in place; adversarial-content doctrine now
  actually referenced by all its carriers (4 SKILL.md pointers added);
  A11/A12 label drift fixed in the registry header + checker comment.
- **New docs gate (check 9): CLI-example flag drift.** Every
  maintained-doc line invoking an in-repo Python script has its `--flags`
  verified against the script's source — the class where
  `validate_report.py --validate` survived ~150 releases. Zero false
  positives on the fixed tree (one prose case reworded); fixture + 
  live-tree tests added; check-harness-docs SKILL now documents all nine
  checks.
- check-harness-docs allowed-tools narrowed to its one script per A11
  ("next substantive edit" clause exercised); its grandfather exemption
  removed — six remain on the burndown.

## v0.182.0 — 2026-07-25

validation P5 (sweep 1) + P8: state-diff discovery + replayable probes

- P8: step_result.replay block (script_ref, inputs_ref, attestation-
  fingerprint sha) — every probe records a self-contained replay
  artifact; countersign humans re-run instead of trusting transcripts
- P5 sweep 1: scripts/cluster_state_diff.py — normalized before/after
  snapshots of security state (RBAC, SCCs, webhooks, NetworkPolicies,
  Services/Routes); unexpected deltas become finding candidates with
  origin: validation-discovery, declared probe side-effects excluded,
  routed to /triage generic ingest (never straight to the ledger).
  Sweeps 2-4 (anonymous-surface, privesc-chain search, browser matrix)
  land per-sweep per the plan.
- validate-findings SKILL documents both; triage SKILL recognizes
  discovery candidates as first-class input (origin flows to
  dashboards); counts updated (72 scripts)

## v0.181.0 — 2026-07-25

validation P7: lane benchmark — fixtures, floors, hybrid cadence

- harnessing/validate-findings/benchmark/: 4 vulnerable/safe-twin
  fixture pairs (RBAC over-grant, privileged-SCC grant, secret
  exposure, fail-open webhook) with planted CVSS vectors + expected.json
  floors (confirm_recall 0.9, refute_precision 0.9, severity ±1.0)
- scripts/run_validation_benchmark.py: plan (worklist +
  benchmark-findings.json, no cluster) / check-trigger (exit 10 when
  validation-lane paths changed since the last benchmarked tag — the
  release-cut leg) / score (per-variant scorecard, flagged verdicts
  count as misses, metrics-ledger rows, below-floor exits 1) / scorecard
- drift-watch gains the monthly leg: scorecard older than 35 days flags
  stale; results tree = analysis-results/scan-testing/ (harness-QA,
  excluded from campaign metrics)
- Hybrid cadence decision (2026-07-25) recorded in
  docs/validation-process.md; validate-findings SKILL documents
  benchmark mode as a first-class input

## v0.180.1 — 2026-07-25

docs: retire the guild-comparison doc; skill docs carry the capabilities

- `docs/threat-model-guild-comparison.md` removed (user decision:
  executed plans/comparisons don't live in docs/). The /threat-model
  capabilities it described are already documented in the skill's
  SKILL.md, README, and docs/skills.md; the "deliberately not adopted"
  design rationale (no file:line threat citations, no narrative-first
  output, no coarse likelihood scale, no broad allowed-tools) is
  preserved as a Design-decisions section in
  harnessing/threat-model/README.md. History retains the full
  comparison at the pre-v0.180.1 tree.

## v0.180.0 — 2026-07-25

validation P9: severity validation + evidence/countersign rules documented

- schema severity_validation (demonstrated CVSS components as
  observations, signed delta, machine PROPOSAL) + chain_context on
  validated findings; |delta| >= 1.0 from E0/E1/E2 evidence queues a
  countersign severity proposal (queue_reason severity_proposal); E3
  never proposes; machines never write disposition.severity
- P9 recording rules in all three validation SKILLs; chain membership
  cited as severity evidence in proposal rationales; downgrades valued
  equally with upgrades. Trends chain-weighting = remaining follow-up.
- docs/validation-process.md: dedicated "Evidence rules" table (full
  E0-E3 -> class/override/emitter contract incl. the E2-is-not-human
  class nuance and legacy grandfathering) and "Countersign interaction"
  section (quarantine != dismissal; conflict suppresses unopposed-FP;
  override earned/narrow/loud; severity stays human-decided)

## v0.179.0 — 2026-07-25

validation P4+P6: evidence grades (E0/E1-only override) + conflict routing

- P4: validated_finding.evidence_grade (E0 observed effect, E1
  authenticated exploit success, E2 strong inference, E3
  error-message inference) + grade_rationale. Emitter: E3 never
  auto-confirms (any age); ungraded confirmations quarantine at/after
  GRADES_SINCE (0.179.0). build_cumulative.event_class: E2/E3 demote
  to machine-static — ONLY E0/E1 keep class-1 override power over
  human FP signatures (decision 2026-07-25, recorded in error-model
  and validation-process docs). Events carry evidence_grade
  (layer schema extended).
- P6: derive_disposition conflict routing — confirmed + false_positive
  both in evidence suppresses the unopposed-FP countersign queue; the
  finding adjudicates as the conflict card countersign already renders
  (both transcripts, DECISION markers).
- docs/validation-process.md: gate table rows 0d/1b, and a "How
  fuzzing interacts with validation" section (fuzzing validates AND
  discovers; offline gates = build + deterministic reproduction; E0 by
  construction; participates in P6 conflicts).

## v0.178.0 — 2026-07-25

validation P3: differential probing + docs/validation-process.md

- schema differential_probe + step_result.differential: authz
  refutations probe the claimed action AND a neighbor with a
  known-different expected outcome; identical outcomes quarantine as
  non-discriminating-oracle at ANY report age; authz refutations
  without a discriminating pair quarantine post-0.178.0
  (missing-differential-probe) — DIFFERENTIAL_SINCE grandfathering
- differential-pair templates in all three validation SKILLs (RBAC
  verb/subject neighbors; browser route pairs)
- NEW docs/validation-process.md: the single reference for the
  validate* lanes — three-purpose mission, the full fail-closed gate
  stack (attestation -> controls -> differential -> soundness ->
  ledger discipline) with shipped versions, artifact flow, hard rules;
  breadcrumbed from README, docs/architecture.md, and PROCESS.md Stage 8

## v0.177.0 — 2026-07-25

validation P1: positive-control probes — assay validity for refutations

- schema: positive_control def + step_result.controls[] (name, kind
  must_succeed|must_deny, verb/target/observed, ok)
- soundness.controls_flag: failed control quarantines a refutation at
  ANY report age; missing passing control quarantines at/after
  CONTROLS_SINCE (0.177.0) — grandfathered like the attestation gate
  (shared _report_version_at_least helper in the emitter)
- control-pairing conventions written into all three validation SKILLs
  (RBAC known-allowed action, planted canary secret, session-validity /
  known-open+known-closed endpoint pairs)
- docs/error-model.md records the control gate as control #0b

## v0.176.0 — 2026-07-25

validation P2: pre-flight target attestation — fail-closed environment gate

First item of progress-tracker/plans/validation-improvement-plan.md:

- scripts/attest_target.py: machine-checkable target-attestation.json
  before any probe — cluster fingerprint, CSV Succeeded, pods Ready,
  version-in-affected-range, feature gates, URL reachability (browser
  lane); the FILE is the gate, exit code is not
- emit_validation_ledger_events: attested=false voids EVERY verdict in
  the run (confirmed and refuted alike) -> needs_review as
  environment_invalid; reports at/after 0.176.0 with no attestation
  route as attestation_missing; pre-0.176.0 reports grandfathered
  (attack_refs-style)
- Step-0 wiring in validate-findings / validate-core-ocp /
  validate-browser-finding SKILLs; validation schema gains optional
  metadata.target_attestation; countersign cards render attestation
  status (and its absence, for legacy runs)
- The rhoso.v2 class (34 false "refuted" from a never-installed
  operator) now produces 0 verdicts at the front door

## v0.175.2 — 2026-07-25

docs: error-model.md — Type I & Type II error handling, documented for
consumers

- where FP/FN enter the pipeline; the asymmetric-caution doctrine
  (machines confirm, humans dismiss; bounded auto-accept exception);
  the measured rates behind each control (70% unsound refutations, FP
  rate by severity, bimodal recall); self-measurement mechanisms; the
  residual-risk register; a consumer table of what each disposition
  actually means. Linked from the README docs index.


## v0.175.1 — 2026-07-25

fix(triage): SKILL prose said `./TRIAGE.json`; the contract is
`<repo>-triage.{json,md}` (repo-slug prefixed)

- doc drift, not behavior drift: the live corpus has 5,846 repo-prefixed
  `*-triage.json` and ZERO bare `TRIAGE.json` — runs already followed the
  corpus convention; the skill text now matches (naming-contract note in
  Step 6b: corpus.py keys triage companions on the prefixed name; a bare
  file is invisible to corpus resolution).
- /patch + triage README references updated; legacy bare name remains
  read-accepted by validate_report and /patch, never written.


## v0.175.0 — 2026-07-25

corpus: `harness-qa` ownership class (registered-but-not-corpus) +
drift burndown to zero

- new ownership tag `harness-qa` for harness self-measurement trees
  (probes, benchmarks, side-by-side sweeps): registration silences the
  unregistered-tree drift warning, but `corpus.resolve()` never walks
  the tree, so its report-shaped artifacts can never enter any metrics
  lens. Enforced centrally in resolve(), not per consumer.
- `scan-testing/` registered as the first harness-qa tree (AWX FN
  probe, cve-replay-monitor, sxs-2026-07 — four scripts write there by
  path, so relocation was not an option).
- drift burndown (all 9 items → fresh): findings.db, repo-graph,
  portfolio-graph rebuilt; 5 ADR pins reviewed and advanced
  (hcm-architecture +ADR-008 Polarion replacement; gcp-hcp +4 new / 2
  modified decisions; qontract-reconcile / agent-control-plane /
  lvm-operator had no decisions-path changes); ADR index re-run (219
  decisions across 8 registers).


## v0.174.0 — 2026-07-25

drift-watch: dashboard-staleness backstop (`check_dashboard_staleness`)

- new drift items `dashboards:harness-scoreboard` (Generated stamp >7d),
  `dashboards:spend` (stamp >4d), `dashboards:spend-actuals` (newest
  session-actuals row >4d — catches a rebuilt dashboard hiding an
  un-appended ledger); each stale item carries its exact refresh command.
- motivating incident: the scoreboard sat 6 days / 88 versions stale
  (0.85.0 -> 0.173.x) because generated dashboards only refresh on
  demand. Scheduled-loop folding deliberately deferred (user decision);
  this is the visibility backstop until then.
- 3 new tests (fresh/stale, stale-actuals-behind-fresh-stamp, pending).


## v0.173.1 — 2026-07-25

fix(pqc-readiness): zero-hit template follows the v0.162 report contract
(landed as commit 6e91db1 mislabeled "v0.162.2" — a concurrent-session
version collision that also regressed VERSION/pyproject from 0.173.0;
repaired here, no code change beyond the version files)

- `bulk_prescan.zero_hit_report()` still emitted the pre-v0.162 report
  shape; the rewritten `validate_readiness()` rejected it, and the
  runner's unlink-on-invalid then DELETED the zero-hit readiness report
  instead of refreshing it — the v0.162.0 corpus refresh silently
  removed 656 zero-hit reports this way. Template now carries the
  required readability keys (`summary`, `status: not_applicable`,
  `who_sets_tls`/`quantum_ready: unknown`, empty `why_not`/`do_next`/
  `capabilities`). The 656 reports were regenerated and re-validated
  from their refreshed facts.

## v0.173.0 — 2026-07-24

spend declaration wired harness-wide (VVAH plan P3 / XWING-626 accrual
enablement):

- 16 model-heavy per-target skills gain a standard "Spend declaration
  (calibration tuple)" section (secure-container-audit, secure-rpm-audit,
  cloud-config-audit, security-audit-phased, threat-model, pqc-readiness,
  crypto-analysis, isolation-review, compliance-check, vuln-scan, triage,
  verify-remediation, remediate-finding, patch, fuzz-harnesses,
  validate-findings) — previously only secure-code-audit carried it.
- docs/model-routing.md: declaration contract stated as harness-wide;
  per-skill calibration semantics documented (2 stamped batches of
  skill X calibrate X only); unknown skills fall to the budget policy's
  default ceiling.


## v0.172.2 — 2026-07-24

model-registry rate-card fill (published Anthropic first-party list
prices, USD/MTok):

- claude-mythos-5: null → 10/50 (same rate card as claude-fable-5) —
  mythos-5 session actuals now render Est. cost USD on the spend
  dashboard instead of n/a.
- claude-opus-4-8: corrected 15/75 → published 5/25 (the old value was
  the Opus 4.1-era rate; opus daily cost estimates were ~3x inflated).
- claude-opus-5: kept at 15/75 but flagged unverified — that ID is not
  on the published rate card.
- claude-mythos-preview rows remain unpriced (retired model, no
  published rate; historical actuals only).
- test_model_registry: null-cost assertion for mythos replaced with a
  priced-cost assertion.

## v0.172.1 — 2026-07-24

budget-policy: bands + default ceilings approved as drafted (Michele
Chubirka, 2026-07-24; calibration basis = workspace-wide actuals +
full campaign corpus). `enforcement: none` unchanged — Phase 3
(XWING-628) remains the switch.


## v0.172.0 — 2026-07-24

spend calibration step 2 + budget policy artifact (VVAH plan P3;
budget-policy-implementation-plan.md)

- model_registry spend gains `--repo`/`--loc` — the per-run
  attribution that turns ledger rows into calibration tuples
  (spend, repo, size); docs/model-routing.md contract updated.
- secure-code-audit Step 5: declare per-repo spend after every audit
  (real tokens when known, 0 otherwise — attribution never skipped).
- config/budget-policy.yaml: draft governance policy shipped with
  `enforcement: none` and the four-layer model embedded (L1 driver
  advisory → L2 visibility → L3 billing backstop → L4 central agentic
  platform, the enforcement target). NOTHING reads it yet by design;
  implementation phases live in
  progress-tracker/plans/budget-policy-implementation-plan.md.
- Historical session-actuals backfill verified idempotent (28 rows,
  2026-06-24..07-23, landed with v0.170.0's telemetry).


## v0.171.2 — 2026-07-24

docs-coverage gate: every docs/*.md must be linked from the README

- check_docs_consistency enumeration coverage now includes docs/ — an
  unlinked guide is invisible to harness users and fails the gate
- five previously-orphaned docs linked from the README table
  (report-structure, adversarial-content-doctrine,
  risk-rating-methodology, signing, reachability-integration-draft)

## v0.171.1 — 2026-07-24

model-routing discoverability: breadcrumbs + A12 renumber

- model-registry gate rule renumbered A11 → A12 (collision with the
  broad-allowlist A11 that landed in parallel); check-alignment SKILL
  table documents A12
- breadcrumbs to docs/model-routing.md in AGENTS.md (agent-facing "never
  hardcode a model ID"), docs/architecture.md (Model routing & spend
  section), docs/setup.md, docs/onboarding.md, and PROCESS.md

## v0.171.0 — 2026-07-24

Spend visibility: session-actuals collector, real-time view, dashboard + docs made loud

- scripts/collect_session_spend.py: aggregates Claude Code transcript
  usage (per-message model + token categories, cache-aware) — default
  invocation IS the real-time view (today's running totals across all
  workspace sessions); --append records completed days into the
  hash-chained ledger (source model-spend:sessions, idempotent). 28 days
  of actuals backfilled on first run.
- Two-source design documented loudly (docs/model-routing.md "How spend
  is tracked — read this first" + README docs table): drivers DECLARE
  per-skill spend, the collector records ACTUALS; declared-vs-actual
  drift is itself a signal.
- build_spend_dashboard.py renders both sections; traust-
  metrics scoreboard gains spend as a standing source.
- Preliminary COST: registry carries published list prices (opus 15/75,
  sonnet 3/15, haiku 1/5 USD/MTok; cache read x0.1, write x1.25;
  mythos-class unpriced pending rate card) — cost_usd() is cache-aware,
  spend CLI gains --cache-read/--cache-creation, and the dashboard costs
  every session-actual row with an all-days total. List prices are
  estimates, not billing truth; verify against the rate card.

## v0.170.0 — 2026-07-24

Model registry + spend telemetry (multi-model-strategy-plan M0/M1)

- config/model-registry.yaml: the ONLY home for vendor/model identifiers —
  roles with tier floors, approved/candidate models, ledger-validity-writer
  guards, claude_code_only runtime-dependency annotations, escalation
  triggers. Schema-gated (schema/model-registry.schema.json).
- scripts/model_registry.py: validate / list / resolve (floor-enforced,
  never tier-down) / stamp (metadata.additional.model_routing with
  registry sha) / spend (hash-chained metrics-ledger rows, cost computed
  when prices present).
- Alignment rule A12 (renumbered from A11 after collision with the
  broad-allowlist rule): hardcoded model IDs outside the registry fail
  the pre-commit gate (attribution/license prose excluded).
- scripts/build_spend_dashboard.py -> progress-tracker/metrics/dashboards/
  spend/ (skill x model tokens/cost; MTTA-per-dollar joins when both
  series exist). docs/model-routing.md documents the whole contract.
- Purely additive: no existing skill behavior changed; drivers adopt
  resolve/stamp/spend incrementally.

## v0.169.0 — 2026-07-24

VVAH comparative plan: P1 gap-closures, P2 write-time redaction,
P7 MTTA query, P8 doctor preflight
(progress-tracker/plans/vvah-comparative-improvement-plan.md)

- export_sarif (P1, extends XWING-623): ledger resolution=resolved →
  `baselineState: "absent"`; degraded runs (negative_results /
  deterministic_steps recording skipped/unavailable/tool_missing) →
  `invocations[].executionSuccessful: false`. 4 new tests.
- scripts/lib/redact.py (P2): single-source write-time redaction —
  team-report Step-7 patterns promoted + Luhn-gated payment cards,
  SSNs, URL credentials, Azure/GCP key classes; JSON-escape-tolerant;
  first-5-chars + ...REDACTED convention; HIGH_CONFIDENCE split.
  validate_report --strict now ERRORS on structured-token secrets and
  WARNS on heuristic classes (calibrated: 400-report dry run — 0
  structured hits, 14 heuristic evidence quotes). 8 tests.
- findings-db SKILL (P7): MTTA canned query (first ledger event →
  first verification/validation-backed resolved event, per severity);
  validated live (critical 36.1d mean). Executive-Trends chart wiring
  handed to the metrics-builder owner.
- scripts/doctor.py (P8): environment preflight — siblings, venv +
  hash-locked deps, pinned tools (incl. pqc-scan binary sha), forge
  auth, VPN probe, the three gates, hooks-enabled; --quick/--json.
- Plan updated with per-item status; P4 flagged as overlapping the
  language-coverage campaign (XWING-610) — fold, don't parallel.


## v0.168.1 — 2026-07-24

security remediation P3: opportunistic hardening (plan P3; CI
enforcement recorded as TO DO pending environment)

- credential_liveness --endpoint host gate: recovered secrets may only
  be probed against canonical service endpoints or ROE-declared
  clusters — https required; anything else refused.
- sweep_engine: scan-in-place now requires the explicit `dir:` prefix
  (a URL that happens to name a local path no longer silently aliases);
  clones gated https + GIT_ALLOW_PROTOCOL; unsupported URLs recorded.
- gh-api path constraints in check_repo_liveness and loc-dashboard
  (CSV org/name/slug shape-validated before entering API paths).
- recall-benchmark canaries default off shared /tmp to the per-user
  cache; bulk_prescan zero-hit markdown fences scanner-derived text;
  checkpoint per-skill CHECKPOINT_ROOT pattern documented.
- AGENTS.md Code Standards codify: curl auth via --config stdin (S5),
  insecure-TLS flags lab-target-only, git transport gates (S3),
  install pins (S7), per-user state dirs (S6).
- 5 P3 regression tests; sweep_engine fixtures moved to the dir:
  contract.
- Plan updated: **CI enforcement marked TO DO (awaiting environment)** —
  MR pipeline for the three gates + pytest, gitleaks job, license
  guard, protected main. Everything locally actionable in P3 is done.


## v0.168.0 — 2026-07-24

SARIF plan P2: cloud-config arm, GitLab exporter, batch sweep, CI recipes (XWING-623)

- `scripts/export_sarif.py`: cloud-config-audit arm — detects the
  declared-layer schema (`assessment_mode`/`facts_ref`), Checkov
  `check_id`s become SARIF rules, audit-time `status: suppressed`
  becomes a suppression carrying the auditor's rationale,
  `needs_review` rides in properties, `file_line_range` → regions,
  IaC `resource` → logicalLocations, and the run is labeled
  declared-configuration (never an observation claim). Plus
  `--results-root`/`--out-dir` batch sweep: walks a findings tree with
  corpus-style hygiene (symlink aliases + hidden/state dirs skipped),
  prefers the disposition-aware findings-current over its raw report,
  mirrors the tree into the out-dir, never writes beside the reports.
- `scripts/export_gitlab_sast.py` (new, stdlib-only): GitLab
  security-report (SAST v15) counterpart for gitlab.cee Vulnerability
  Reports, which don't ingest SARIF — deterministic UUIDv5
  vulnerability ids (stable re-upload dedup), severity enum mapping,
  identifiers from campaign finding ID + CWEs, `false_positive`
  dispositions excluded by default with the count recorded in
  scan.messages (`--include-false-positives` overrides), disposition
  note appended to descriptions.
- `docs/sarif-ci.md` (new): GitHub `upload-sarif` recipe (category,
  fingerprint dedup, severity thresholds), GitLab `sast` report
  artifact recipe, batch-sweep usage; records the deliberate decision
  NOT to wire a drift-watch staleness check until exports become a
  maintained store.
- `docs/outputs.md` + README: both exporters + sweep documented;
  script counts 64 → 65.
- Tests: cloud-config arm (rules/suppressions/declared labeling/
  regions), sweep (cumulative-supersedes, hidden-dir skip, tree
  mirroring, arg validation), GitLab exporter (structure, determinism,
  identifiers, FP exclusion, severity enum, pseudo-path skip, CLI).
- Smoke-tested on real artifacts: terraform-repo-template cloud-config
  audit (4 results), console container findings-current → GitLab
  report (3 vulnerabilities), 65-report sweep of the ACM product tree.

## v0.167.0 — 2026-07-24

security remediation P2: privileged-skill hardening
(harness-security-remediation-plan.md P2.11–P2.15; audit C1/C2/C3,
D1/D2/D5/D6, E2/E3/E4/E7/E9, B2, F7/F8)

- C1 full: run_checks.sh containerized check runner — default when
  podman exists: rootless, --cap-drop=ALL, --network=none test phase,
  digest-pinned toolchain images (golang/node/rust/python), tmpfs HOME,
  networked-but-scriptless dependency prefetch phase; native fallback
  keeps env-strip + shims and warns that shims are not a boundary.
  fleet-fix inherits it; A11 un-grandfathered with per-script grants
  (D5).
- C2: validate-findings step-text execution rewritten — shlex
  punctuation-aware vetting replaces bash -lc + substring denylist:
  binary allowlist per pipeline segment, |-only pipelines, no
  operators/substitution/path-form commands; blocked steps return
  rc=126 recorded, never crash. Token-based classify() (routes review;
  the vet is the boundary).
- C3: fuzz Makefile — atheris/jazzer pinned, install output no longer
  suppressed, Go build/fuzz run GOPROXY=off after sumdb-verified
  prefetch.
- D1: remediate-finding — tight allowed-tools; Phase 5b independent
  reviewer (diff + location only, never finding prose) gates the push,
  REJECT blocks; doctrine block; "authoritative rationale" reworded to
  verify-against-code.
- D2/D6: deploy-operator doctrine (vendor-controlled metadata rules,
  fetch host allowlist enforced by new fetch_rh_docs.sh wrapper —
  no raw curl grant) + allowed-tools; scoped allowlists for
  track-findings, validate-findings, validate-operator-live,
  validate-core-ocp.
- E2/F8: GitHub tokens via curl --config stdin everywhere; JSON bodies
  via json.dumps; the wrong "argv isn't visible" comment corrected.
- E3: openshift-install tarball sha256-verified against the channel's
  sums (refuses unverified). E4/F7: install dir 0700 + umask 077 for
  the whole provision run (pull secret was 0644), AWS creds via
  AWS_SHARED_CREDENTIALS_FILE (never overwrites ~/.aws), Azure SP
  backed up, IC_API_KEY off /tmp with ownership check. E9: pqc-scan
  build in per-user cache. B2: real_creds state in ~/.cache/glasswing
  O_EXCL 0600. E7: ldaps:// + LDAP filter escaping.
- Exemption bookkeeping repaired: the P1 burndown script had failed
  before writing (assert-then-write bug) — all 57 stale/unused entries
  now actually deleted; EXEMPTIONS is 27 declared / 19 firing, every
  entry cited.
- 22 P2 regression tests (exec-gate matrix, source-level assertions,
  fetch-wrapper host tests); soundness-gate fixtures updated to the
  vetted command form; echo/printf added to the step allowlist
  (payload-pipe pattern).


## v0.166.2 — 2026-07-24

SARIF discoverability pointers (XWING-623 follow-up)

The exporter was documented only in docs/outputs.md — no agent-facing
surface named it. Three single-source pointers, no restating:

- `docs/report-structure.md` intro: any report (incl. findings-current)
  projects to SARIF via `scripts/export_sarif.py` — inherited
  transitively by every audit skill through the existing A4
  link-don't-restate rule.
- `harnessing/track-findings/SKILL.md` Phase 4: hand the
  disposition-aware `findings-current` to SARIF-speaking consumers
  (FPs arrive as suppressions, not re-alerts).
- `README.md`: findings-interchange line after the workflow diagram
  (OSS-release visibility) + `export_sarif.py` row in the scripts
  table.

## v0.166.1 — 2026-07-24

Internal rebrand: Project Glasswing → Project Ex-Wing

Prose, headers, dashboard titles, and forward conventions renamed across
AGENTS/PROCESS/docs/skills: new Jira label ProjectExWing (legacy tickets
keep ProjectGlasswing — sweep JQL with both), fix-branch prefix ex-wing/
(legacy branches keep glasswing/), MR-comment command /exwing (legacy
/glasswing still accepted on ingest), engagement ids ex-wing-core-ocp-*.
Deliberately unchanged: the hybrid-platforms-glasswing Drive name and the
Glasswing Ownership Tracker Google Doc title (real resource identifiers),
CHANGELOG history, published team-report packages, claim-hashed generated
reports, runtime probe markers/env vars in validate-findings k8s adapter
(operational identifiers needing coordinated rename), and references to
Anthropic's public Project Glasswing initiative.

## v0.166.0 — 2026-07-24

triage external-input normalizer: SARIF + Dependabot + govulncheck (P1, XWING-623)

- `harnessing/triage/scripts/normalize_input.py` (new, stdlib-only): one
  deterministic normalizer for the three input formats triage's generic
  Phase 1a rules cannot trivially parse, emitting the standard
  `{findings: [...]}` container with canonical field names:
  - **SARIF 2.x from any producer** — CodeQL, Semgrep, Snyk, Trivy,
    Bandit, Coverity 2023+, and the harness's own deterministic tools
    run standalone with SARIF output (opengrep/gitleaks/osv-scanner/
    checkov/grype/govulncheck). Inverse severity mapping per the SARIF
    plan (`security-severity` buckets, `level` fallback), CWE
    extraction from rule/result tags, CodeQL `precision` →
    `scanner_confidence`, suppressed results skipped + counted
    (`--include-suppressed` to keep). Round-trips `export_sarif.py`
    output (tested).
  - **Dependabot alerts JSON** (GitHub REST export) → supply-chain
    findings with GHSA/CVE ids, advisory CWEs, manifest path,
    first-patched-version recommendation.
  - **govulncheck native `-json` stream** (concatenated records, same
    shape `run_govulncheck.py` consumes) → per-OSV findings with
    call-graph reachability (`symbol_reachable`/`module_present`),
    deepest-frame file/line; severity never guessed when absent.
  All arms label output as machine-static claims under the
  track-findings trust policy — normalization never sets a verdict.
- `harnessing/triage/SKILL.md` Phase 1a: normalizer-first rule
  (never hand-parse the three formats) + a deterministic-tooling
  coverage map documenting the triage path for every harness scanner.
- `check_skill_alignment.py`: cited A8 exemption for triage's coverage
  map (names run_checkov.py without running it — drift-watch
  precedent).
- `tests/test_normalize_input.py`: all three arms, mapping/suppression/
  round-trip/CLI cases.

## v0.165.0 — 2026-07-24

SARIF 2.1.0 exporter (SARIF plan P0, XWING-623)

- `scripts/export_sarif.py` (new, stdlib-only): one-way read-only
  projection of any `report.schema.json` report (`*-security-audit`,
  `*-container-audit`, `*-findings-current`) to SARIF 2.1.0 for GitHub
  Code Scanning, SARIF viewers, and downstream aggregators. Severity →
  `level` + GitHub `security-severity` (9.5/8.0/5.0/2.0/0.5;
  `effective_severity` override wins); finding ID + finding_identity
  fingerprint → `partialFingerprints` (stable re-upload dedup);
  file locations → `physicalLocation` with parsed line regions,
  container/package pseudo-paths (`pkg:`, `oci-config:`, `layer:`) →
  `logicalLocations`; ledger dispositions → suppressions
  (false_positive validity, risk_accepted resolution) with the full
  disposition block mirrored in `properties` — the report + ledger
  stay authoritative, nothing round-trips back.
- `tests/test_export_sarif.py`: structural SARIF-subset conformance
  (GitHub upload requirements), mapping/region/pseudo-path/suppression
  cases, determinism, CLI naming.
- `docs/outputs.md`: SARIF export section; script counts 63 → 64.
- Plan: `progress-tracker/plans/sarif-integration-plan.md` (P1 = /triage
  SARIF ingest; P2 = CI recipe, cloud-config arm, GitLab format).

## v0.164.0 — 2026-07-24

security remediation P1: public-release blockers
(harness-security-remediation-plan.md P1.5–P1.9; audit E1, D3/D4/D7,
B3/B4/B5/C4, E5/E6/E8/E11, E10 code part)

- E1: requirements.lock (uv pip compile --generate-hashes, 302 hashes);
  setup/getting-started/requirements docs install with
  --require-hashes. Dry-run resolved in a scratch venv.
- D3: secure-code-audit gains the tight allowed-tools allowlist
  (mirrors vuln-scan; every script individually scoped, LoC/scanner
  binaries enumerated) — the flagship no longer reads hostile repos
  with unrestricted tools.
- D4: docs/adversarial-content-doctrine.md (single-source CWE-1427
  doctrine) wired into vuln-scan (subagent briefs), verify-remediation
  (had none), threat-model, security-audit-phased. Remaining P1.6-batch
  skills stay grandfathered in the S2 burndown.
- D7: impact-analysis Bash(curl:*) replaced by scoped
  scripts/fetch_advisory.py (3 fixed advisory hosts, CVE-id
  validation); threat-model's unused Bash(gh api:*) dropped.
- B4: symbol-index cache moves to per-user 0700 XDG dir with ownership
  check; B5: symlink-skip in build_symbol_index, pqc_facts, and all 21
  crypto_probe walkers; C4: ctags --options=NONE; B3: bulk_prescan
  slug fullmatch.
- E6: run_opengrep URL rule sources require a 40-hex commit SHA +
  https (bare fork URL now actually gets the documented pin — the
  unused FORK_RULES_SHA claim is finally true); E5: Containerfile
  digest-pinned; E11: go install docs pinned to v0.48.0.
- E8: pre-commit hook no longer writes into $HOME — skill linking is
  the explicit scripts/link_skills.sh; hook prints a hint only.
- E10 (code part): real_creds.py AWS account guard + GitHub sink repo
  are env-required with no shipped defaults (fail closed); .env.example
  documents both. Doc-level hostname scrub stays deferred to the
  open-source partition (plan P1.9 note).
- 11 regression tests (tests/test_p1_hardening.py); 7 more exemptions
  burned this release (34 → 27; cumulative burndown since the gate
  shipped: 40 → 27).


## v0.163.0 — 2026-07-24

security remediation P0: the git-transport RCE class is dead
(harness-security-remediation-plan.md P0.1–P0.3; audit A1/A2/A3/A4,
B1/F6, C1-interim)

Data-compatibility dry run FIRST (per the agreed smoke protocol):
22,213 audit reports → 2 non-normalizable repository fields (one
scheme-less repo, self-heals on re-audit); 0/111,091 finding ids
rejected by the new fid gate; no manifests on disk affected.

- A1 (CRITICAL, confirmed-exploitable): apply_fleet_fix.ls_remote_sha —
  https-only URL gate, safe-ref gate, `--` separator,
  GIT_ALLOW_PROTOCOL=https + GIT_TERMINAL_PROMPT=0 env.
- A2: build_verify_sweep — raw metadata.repository fallback DELETED
  (normalize-or-skip); ls_remote_head gains the same gates.
- A3: ensure_fork.sh — upstream must be https on
  github.com/gitlab.cee.redhat.com; audited-sha hex-gated;
  GIT_ALLOW_PROTOCOL exported.
- A4: credential_liveness — commit hex-gated at both git-show sites.
- Sweep: operator-priv-profile clone gates + timeout; fuzz Makefile and
  sweep-grep-all.sh export GIT_ALLOW_PROTOCOL; run_one.sh ditto.
- B1/F6: build_remediation_manifest rejects unsafe finding ids
  (FID_RE); emit_remediation_report refuses to write outside
  analysis-results/remediations (resolved-path containment); run_one.sh
  validates LOGICAL/REPO before rm -rf/mkdir.
- C1 interim: run_checks.sh strips all credential env vars
  (GITHUB_TOKEN, AWS_*, API keys, KUBECONFIG…) from target build/test
  execution; push tokens exist only at push time via the credential
  helper. Full containerization remains P2.11.
- 26 regression tests (tests/test_p0_git_gates.py): every audited
  attack shape (ext::, --upload-pack, ssh, dash-options, traversal
  ids/paths) must be rejected before subprocess; live smokes prove
  ensure_fork rejects hostile upstreams and target test code cannot
  see tokens.
- check-skill-security burndown: 9 exemptions removed (all S3 KNOWNs +
  run_checks S4) — 40 → 31; the P0 rows in the burndown are now empty.


## v0.162.1 — 2026-07-24

fix: clear the gate failures the v0.162.0 MR merge introduced (MRs
bypass local pre-commit hooks — CI enforcement is the open follow-up)

- run_pqc_readiness.sh: S3 — https-only URL gate + GIT_ALLOW_PROTOCOL +
  `--` separator on clone; S6 — output/repos dirs move from fixed
  /tmp names to ~/.cache/pqc-readiness (0700), overridable via
  PQC_OUTPUT_DIR/PQC_REPOS_DIR; slug validation rejects traversal.
  Smoke-tested: syntax, posture gate, four malicious-URL negative
  tests, end-to-end run against a public repo (facts schema-valid,
  zero-hit assertion present), idempotent re-run path.
- check_skill_alignment ARTIFACT_SKIP_RE: notes/ joins tables/ as a
  config location (the MR moved the pqc tables to notes/reference/,
  un-skipping the version matrix from the A9 artifact graph).
- pqc-readiness SKILL.md / notes/language.md: A9 produce-line reword +
  dead backtick path.
- check_drift.py: stamp parser tolerates the parenthesized
  ADAPTER_VERSION form.
- test_crypto_probe.py: JDK/Node capability tests updated to the
  corrected matrix v2 thresholds (JDK 27 per JEP 527; Node 22.20+) —
  the matrix is the single source of truth the tests must follow.


## v0.162.0 — 2026-07-24

pqc-readiness: capability cards, dataclass refactor, notes reorg, fact corrections

- **13 capability cards** (`notes/capabilities/*.yaml`): researched and
  verified PQC readiness floors for Go, OpenSSL, JDK, Node, rustls,
  AWS-LC, BoringSSL, GnuTLS, NSS, .NET, Python, Ruby, RHEL. Each card
  documents `by_default` / `if_configured` version floors, FIPS notes,
  and unsupported items.
- **Go FIPS/ML-KEM correction**: ML-KEM *is* CMVP-validated in Go 1.24,
  but X25519MLKEM768 as a hybrid has no standalone CMVP record — strict
  auditors should prefer SecP* hybrids from Go 1.26+. Decision tree,
  capability card, and version matrix updated.
- **JDK version matrix fix**: `pqc_kex_default` corrected from `"24"`
  (API only) to `"27"` (TLS KEX default). Node corrected to `"22.20"`.
- **Rust TLS coverage**: capability card and decision tree now
  distinguish `rustls` (pure Rust, aws-lc-rs backend) from apps using
  the `openssl` crate (covered by the OpenSSL card).
- **`pqc_facts.py` dataclass refactor**: replaced raw dict access with
  typed dataclasses (`Fact`, `IR8547Mapping`, `Coverage`,
  `FactsDocument`). Integrated mchubirk's `validate_facts()` schema
  gate and remediations validator into the new structure.
- **`tables/` → `notes/` reorg**: reference data moved to
  `notes/reference/`, schemas to `notes/schemas/`, agent-facing files
  at `notes/` top level. All internal and cross-skill path references
  updated.
- **Platform-agnostic remediation guides**: all server/client
  remediation MDs rewritten to lead with generic principles, OCP as one
  example among many.
- **Explicit `do_next.how` + `locations`**: `how` is owner-facing prose
  distilled from remediation playbooks (no harness paths). `locations`
  carry repo `file:line` anchors so owners can map actions to their
  tree. Playbooks remain agent-only; `/patch` loads them via
  `index.yaml`. MD companions show Locations, never Playbook paths.
  `fact_ids` stay on `scores`/`clock_items` only — not on
  `remediations[]` / `do_next[]`.
- **Test fixes**: `test_backfill_remediations.py` `_minimal_report()`
  updated with new required readiness fields; Playbook MD lines removed.
- Schema updates: `capability-card.schema.json` extended for
  `depends_on_note`, `versioning_note`, structured `unsupported` items.
  `who_sets_tls` and report schemas: `openshift_cluster` → `platform`.
  `do_next` schema/validator accept `how` + `locations`.

## v0.161.0 — 2026-07-24

check-skill-security: the security-posture gate for skills (skill #55)

- scripts/check_skill_security.py — eight S-series rules, each a
  generalized finding class from the 2026-07-24 pre-release self-audit
  (progress-tracker/plans/harness-security-remediation-plan.md):
  S1 allowed-tools confinement for privileged skills, S2
  adversarial-content doctrine for untrusted-content readers, S3
  git-transport gates (the confirmed-RCE class), S4 shell-exec, S5
  token-in-argv, S6 fixed /tmp paths, S7 unpinned installs, S8
  raw-egress grants. Scans git-tracked files only; fixtures excluded.
- EXEMPTIONS grandfather today's 37 known violators, each citing the
  remediation-plan item that removes it (KNOWN) or a reviewed design
  rationale — the list must only shrink; a test enforces the citation
  format, another asserts the live tree stays clean.
- Wired into .githooks/pre-commit alongside the alignment gate; skill +
  command wrappers; 12 tests (all rules positive + negative, untracked
  exclusion, live-tree assertion).


## v0.160.1 — 2026-07-24

New docs: requirements + getting started

- **docs/requirements.md** — tiered requirements overview: baseline
  (platform/Python/agent), model-tier guidance, CLI tools by capability,
  network & access tiers (offline → public internet → VPN → Jira →
  ephemeral cluster → Google Workspace), campaign extras, authorization
  ground rule. Cross-links setup.md (install steps, authoritative tool
  table) and external-dependencies.md (license inventory) instead of
  duplicating them.
- **docs/getting-started.md** — zero-to-first-audit walkthrough:
  requirements check, clone/install/hooks, agent discovery
  (.claude/.crush symlink trees), first /threat-model + /secure-code-audit
  run, output validation/rendering, optional deterministic pre-scanners,
  where-to-next table.
- README links both (top of "How to Use this Harness" + two leading rows
  in the Documentation table); setup.md cross-links them and its stale
  "~430 tests" claim corrected to ~1,600.

## v0.160.0 — 2026-07-24

A11 broad-allowlist gate + vuln-scan allowed-tools completion

- **New alignment rule A11** (`scripts/check_skill_alignment.py`,
  pre-commit gate): an allowed-tools entry may not grant a whole
  interpreter or shell (`Bash(python3:*)`, `Bash(bash:*)`, `Bash(*)`,
  node/perl/ruby/sh/npx/uv/...). An unscoped interpreter is arbitrary
  code execution — a skill that reads untrusted target checkouts can be
  steered by scanned content into running it. Scope each script
  (`Bash(python3 *<script>.py:*)`). Applies to skill SKILL.mds and
  command wrappers; anchored to list-entry lines so prose/comments about
  the pattern never match. Prompted by an unattributed working-tree edit
  that widened vuln-scan to `Bash(python3:*)` (since reverted).
- Seven pre-A11 harness-internal tooling skills (census,
  check-harness-docs, corpus-intake, fleet-fix, insecure-patterns,
  recall-benchmark, repo-graph) are grandfathered via printed
  exemptions — each to be narrowed on its next substantive edit; new
  exemptions for target-facing skills are off the table.
- **vuln-scan**: allowed-tools now scopes all three scripts the skill
  actually runs (`validate_report.py`, `scan_k8s_hardening.py`,
  `run_opengrep.py` — the latter two were missing), with a frontmatter
  warning at the point of temptation; body invocations normalized to
  `python3` to match the grants.
- check-alignment SKILL rule table gains the A11 row; 3 new tests
  (broad entries fail across interpreters, scoped+comment passes, body
  prose ignored).

## v0.159.0 — 2026-07-24

KHS-N04: OpenShift-specific network policy kinds

- `scripts/scan_k8s_hardening.py` now inspects the OpenShift network
  objects KHS-N03 left uncovered:
  - **AdminNetworkPolicy / BaselineAdminNetworkPolicy** — new **KHS-N04**
    fires on `action: Allow` rules with a match-all `namespaces` peer, a
    match-all `pods` peer, or `networks: 0.0.0.0/0`/`::/0`. Deny and Pass
    rules never fire (they restrict/delegate).
  - **EgressFirewall / EgressNetworkPolicy** — KHS-N04 fires on
    `type: Allow` of the entire address space; the correct trailing
    `Deny 0.0.0.0/0` default-deny pattern is never flagged.
  - **MultiNetworkPolicy** (k8s.cni.cncf.io secondary networks) — shares
    the NetworkPolicy spec verbatim, so it runs through the existing
    KHS-N03 logic with its own kind label.
- New `openshift_network_policies` tenancy signal (kind/file/name/
  permissive). None of these kinds suppresses KHS-N02 — they are not
  pod-level primary-network default-deny.
- secure-code-audit SKILL: K05 rubric row and PEACH-C signal table
  extended (an ANP Allow overrides namespace denies cluster-wide).
- 7 new tests (ANP both shapes, ANP Deny/Pass/labelled negatives, BANP
  pods peer, EgressFirewall positive+negative, MultiNetworkPolicy via
  N03, N02 non-suppression).

## v0.158.0 — 2026-07-24

KHS-N03: permissive NetworkPolicy detection

- `scripts/scan_k8s_hardening.py`: new **KHS-N03** check ("NetworkPolicy
  allows all traffic (permissive)", severity hint medium, K05). Flags the
  allow-all shapes a shipped policy can take: empty `ingress:`/`egress:`
  rule `{}`, a rule with ports but no peers, a match-all
  `namespaceSelector` peer (without a narrowing podSelector), and
  `0.0.0.0/0`/`::/0` ipBlocks. Default-deny policies (declared policyType
  with no rules) are never flagged. Closes the inversion where one
  allow-all policy silenced KHS-N02 and scored better than shipping none.
- `network_policies` tenancy signal entries now carry `permissive: true|false`.
- secure-code-audit SKILL: K05 rubric row lists the permissive shapes; the
  PEACH signal table instructs that a `permissive: true` policy fails
  PEACH-C and must not be counted as a mitigating control.
- cloud-config-audit SKILL: tenant-separation step told not to credit
  allow-all policies as network segmentation.
- KHS-N03 flows automatically to every scanner consumer (/vuln-scan,
  /threat-model bootstrap, /security-audit-phased, /compliance-check) —
  they consume KHS-* facts generically.
- 5 new tests (allow-all both directions, broad peers, scoped-policy
  negative, default-deny negative, N02 suppression unchanged).

## v0.157.1 — 2026-07-23

pqc-readiness legend: on every report unconditionally

- The v0.157.0 refresh skipped the 688 minimal ready/not-applicable pages
  (no scores displayed); the user directive is ALL reports — the skip is
  removed and the legend now upserts unconditionally.
- Corpus refresh: 3,162/3,162 MDs carry the legend, 0 duplicates.

## v0.157.0 — 2026-07-23

pqc-readiness MDs: scoring-domain legend on every report (user-requested)

- Standard '### What the domains mean' block (VULN/AGIL/PQCA/HNDL — the
  question each answers and its 0-100 scale, the Overall weighting, and
  the bucket thresholds) added to the SKILL.md MD template and upserted
  idempotently by backfill_remediations.py --refresh-md: under '## Scores'
  when the section exists, appended when domains are referenced without
  it, skipped on minimal ready/not-applicable pages that display no
  scores.
- Corpus refresh: 2,454/2,454 score-bearing reports carry the legend
  (685 minimal pages correctly untouched), 0 duplicates.
- Bug fixed en route: the Remediations section re-render only recognized
  h2 as the next heading and swallowed a following h3 (40 reports affected
  transiently); regex now stops at h2 or h3, regression-tested.
- 4 new tests (placement, append, minimal-skip, refresh integration).

## v0.156.0 — 2026-07-23

pqc-readiness remediations: globally unique ids (secure-code-audit
convention; user-requested)

- Id format is now <SLUG_UPPER max 24>-<7-hex short sha of
  metadata.commit>-REM-NNN (e.g. HELMET-f1b2984-REM-001); reports without
  a pinned commit use u+6-hex sha256(repository) as the provenance
  component, still deterministic and repo-unique. Bare REM-NNN ids are
  rejected by both the schema pattern and pqc_facts.py
  --validate-readiness.
- backfill_remediations.py mints the prefix from the report's own
  metadata; --force re-mint + --refresh-md executed over all 3,162
  reports: 1,102 remediation ids corpus-wide, 0 duplicates (verified),
  JSON and MD companions carry the same ids.
- Dashboards/rollups audit: build_pqc_dashboard.py, build_pqc_rollup.py,
  and build_pqc_product_reports.py surface only counts/effort fields —
  no id display anywhere reflected the old non-unique numbering, so no
  consumer changes were needed.
- SKILL.md contract + MD template updated; tests re-pinned to the new
  scheme (16 tests, incl. bare-id rejection).

## v0.155.0 — 2026-07-23

pqc-readiness MD companions: Remediations section rendered, Facts columns
removed (user-requested)

- SKILL.md MD template gains a '## Remediations' section mirroring the JSON
  array one-for-one (REM ids referenceable in tickets), and an explicit
  rule: never put fact-ID ('F0001'-style) columns in the .md — fact ids are
  the JSON's citation mechanism, meaningless to the developer audience.
- backfill_remediations.py --refresh-md: idempotent MD pass that strips any
  'Facts' table column (both legacy shapes: check tables and clock tables)
  and upserts the rendered Remediations section (before '## Scores' when
  present). Executed over all 3,162 report MDs, 0 errors.
- 4 new tests (column-strip both shapes + summary-line preservation,
  section render incl. empty, upsert placement + idempotency, append).

## v0.154.0 — 2026-07-23

pqc dashboard: remediation counts (follow-on to v0.153.0)

- build_pqc_dashboard.py surfaces the structured remediations sections:
  per-repo count + by-category breakdown in the JSON sidecar, a
  remediation-actions line in the MD Action items (fix-now / upgrades /
  waiting-on-upstream / deadline-bound), an "Actions" column in the
  per-org worst-first tables, and pqc_remediations_total /
  pqc_remediations_fix_now in the shared metrics ledger.
- First regeneration over the backfilled corpus: 1,102 actions across 610
  repos (all deadline-category — the backfill's fix-now/upgrade parsing
  found little in pre-template MD companions; new reports author all four
  categories per the SKILL contract).

## v0.153.1 — 2026-07-23

drift-watch: document the pqc-facts provenance checks

- The check code itself (scripts/check_drift.py
  check_pqc_facts_provenance + 3 tests) shipped inside the v0.153.0
  commit alongside the remediations work; this entry records it and the
  SKILL.md rows land here. Two items per run: `pqc-facts-stamps`
  (corpus stamps vs ADAPTER_VERSION / PQC_SCAN_COMMIT pins, head-read
  cheap, stale = re-scan routing) and `pqc-facts-schema` (bounded
  newest-25 sample vs schema/pqc-facts.schema.json — the write gate
  covers new files; a violation means the schema tightened after the
  fact). First live run: 3,228 files, all stamps current, sample
  conforms.
- drift-watch SKILL.md: checks table + description gain both items.

## v0.153.0 — 2026-07-23

pqc-readiness: structured `remediations` report section + deterministic
backfill (user-requested)

- schema/pqc-readiness.schema.json: optional `remediations[]` — REM-NNN
  entries with category (fix-now / upgrade / waiting-on-upstream /
  deadline) mirroring the MD companion's "What you need to do" routing,
  fact_ids, locations, recipe (remediation/index.yaml playbook path),
  target, remediation_effort/blast_radius (clock-item enums), NIST IR 8547
  deadline year, blocked_on. Optional for pre-0.153.0 reports; mandatory
  for new reports per SKILL.md.
- pqc_facts.py --validate-readiness: validates the section when present
  (id format/uniqueness, category enum, waiting-on-upstream requires
  blocked_on, deadline requires 2030/2035).
- harnessing/pqc-readiness/scripts/backfill_remediations.py: derives the section
  for existing reports from material they already carry (parsed MD
  fix-now/upgrade/waiting sections + clock_items → deadline entries),
  idempotent, per-report validation with rollback. PQC reports have no
  disposition ledger (posture artifacts), so backfill is regenerate-in-
  place.
- 12 tests (validator matrix, MD parsing, clock-item derivation +
  dedup-vs-MD, backfill idempotency/dry-run/rollback).

## v0.152.0 — 2026-07-23

pqc-facts schema: the Layer 1 crypto census gets a write-time contract

- New schema/pqc-facts.schema.json (draft 2020-12): pins the envelope
  (artifact const, repository, reproducibility stamps, coverage incl.
  the zero-hit assertion, summary count maps) and the consumer-critical
  fact fields (rule_id, file, line, path_class enum, detail/match,
  pqc_capable, ir8547 qclass/usage/clock) that /patch's pqc ingest and
  the Layer 2 prepass key on; permissive on additions so adapter
  version bumps don't break old files.
- pqc_facts.py: validate_facts() gates its own output at write time
  (refuses to write a violating document); new --validate-facts flag
  re-checks an existing file. Artifact shape unchanged
  (ADAPTER_VERSION stays 1.3.0); all 3,225 corpus facts files validate
  clean against the schema.
- pqc-readiness SKILL.md gains an Integrations section (A10) mapping
  every emitted artifact to its consumers; /patch's ingest entry and
  the README schema table now cite the contract.

## v0.151.0 — 2026-07-23

Phase 4 fleet mechanisms: FP-precedent cache (dormant) + class-generalization
sweep engine (error-correction plan v2.0 §6)

- scripts/build_fp_precedent_cache.py: corpus-wide extraction of HUMAN-
  COUNTERSIGNED refutations only (LDAP-verified interactive countersign
  markers; machine refutations, auto-accept-tier FPs, and confirmations are
  excluded by test-pinned rule), keyed by finding fingerprint + repo-
  independent vendor-normalized component signature; soundness guard drops
  precedents whose current disposition is no longer false_positive; match
  subcommand for deterministic triage lookups. SHIPS DORMANT: live run over
  8,200 layers → 0 countersigned refutations → valid empty cache
  (analysis-results/graph/fp-precedent-cache.json); consumers no-op on
  empty/missing cache. Populates automatically once /countersign verdicts
  exist. 16 tests.
- triage SKILL.md: pre-vote precedent lookup (annotation-only, reduced
  1-vote tier like the citation gate); precedent disagreement keeps the
  verifier's verdict and escalates to /countersign — never auto-refutes.
- scripts/sweep_engine.py: resumable collect → draft → sweep → emit
  pipeline extending mine-ledger — confirmed findings (ledgers + all
  Phase-0 artifacts) classified rule-expressible via deterministic CWE
  router, uncovered classes drafted into rule-drafts/ with provenance,
  bounded corpus-wide opengrep sweeps, results emitted as TRIAGE INPUT
  (analysis-results/scan-testing/sweeps/) — the engine never files
  findings. Dry run on the real corpus: 7,257 confirmed → 2,204
  rule-expressible across 171 classes, 137 uncovered by the pack
  (top: CWE-532/python 69 TPs, CWE-295/bash 50, CWE-78/yaml 48). 10 tests.
- mine-ledger SKILL.md: sweep stages wired into the backlog flow with the
  run-by-default policy and named human gates (pattern authoring, pack
  promotion, triage verdicts).
- script counts 59→61; one reviewed A9 exemption (sweep-candidates.json
  consumer cross-ref pending in sibling-owned triage SKILL.md).

## v0.150.0 — 2026-07-23

skill-alignment gate: artifact producer/consumer graph (A9) + Integrations-section requirement (A10)

- A9: every hyphenated data artifact a skill emits must have a consumer
  in another skill, be terminal-classed (dashboards/rollups/summaries),
  or carry a reviewed exemption — catches under-wired new skills (the
  operator-priv-profile / impact-analysis launch gap)
- A10: skills emitting non-terminal artifacts must document consumers in
  an ## Integrations / Downstream section
- 7 skills gained Integrations sections (executive-summary-findings,
  fuzz-harnesses, mine-ledger, repo-graph, security-audit-phased,
  validate-browser-finding, validate-operator-live); 7 reviewed A9
  exemptions recorded with reasons
- AGENTS.md "Adding a new skill" gains step 6: wire the integrations
  (diff inputs/outputs against the harness before landing)
- add-inputs: new Step 7 checks config/corpus-config.yaml after an
  inventory addition and reminds the user to register the output tree
  via /corpus-intake when none covers it — the mirror of corpus-intake's
  Step 5 inventory reminder (docs/onboarding.md + docs/skills.md
  updated to match)

## v0.149.3 — 2026-07-23

docs: onboarding walkthrough for new engagements

- New docs/onboarding.md: the end-to-end sequence — input-side
  registration (/add-inputs or /inventory-repositories), output-side
  registration (/corpus-intake with ownership-tag semantics), census
  confirmation, repo-graph rebuild, pipeline handoff, and the census +
  drift-watch safety nets. Linked from the README docs table, PROCESS.md
  Stage 1, and the hybrid-platforms-inputs README intake section.

## v0.149.2 — 2026-07-23

docs: document the inventory intake paths in PROCESS.md Stage 1

- PROCESS.md Stage 1 now names both intake paths —
  `inventory-repositories` (automated discovery) and `add-inputs`
  (ad-hoc registration) — explains the `corpus-intake` output-side
  handoff, and corrects stale segment counts (11 releases, ~230
  operators, ~99 services). Pairs with the hybrid-platforms-inputs
  README's new "Adding repositories (intake)" section.

## v0.149.1 — 2026-07-23

patch: name `*-pqc-facts.json` everywhere the skill lists its inputs

- Doc-drift follow-up to 04a2b15 (pqc-facts ingest): the frontmatter
  `description`, Phase 0 findings-path argument list, Phase 0b
  static-mode detection list, and the `.claude/commands/patch.md`
  wrapper now all name the `*-pqc-facts.json` input the ingest table
  already handles. No behavior change.

## v0.149.0 — 2026-07-23

impact-analysis wiring completed: rpm-audit, live validation, remediation, findings-db projection

- `/secure-rpm-audit`: vendored-dependency CVE hits cite the source
  repo's impact classification (K07 convention parity).
- `/validate-findings`: impact artifacts as target selection —
  `affected` + `attacker_influence: plausible` prioritizes cluster
  time; the govulncheck trace names the interface to drive.
- `/remediate-finding`: dependency-bump remediations consult the trace
  for fix placement; upstream fixes pair with check_fix_propagation.py
  + `/verify-remediation --fix-repo`.
- findings-db: new `impact` table projecting
  analysis-results/impact/*.json — per-CVE affectedness becomes SQL.

## v0.148.0 — 2026-07-23

standing CVE-replay FN monitor: permanent model-external oracle
(error-correction plan v2.0 §5 item 3.4)

- scripts/cve_replay_monitor.py (stdlib-only, cron-able, offline-tolerant):
  incremental mode queries OSV for advisories newly published against the
  audited corpus (corpus.py discovery + fallback walker, per-ecosystem
  published-date watermarks) and runs the deterministic hit-check per
  report — CVE/GHSA id-match in findings/negative_results = detected,
  affected-area overlap = unclear (recorded, never guessed), neither =
  missed. Misses append idempotently to
  progress-tracker/metrics/trends/fn_cve_replay_missed.jsonl (JSONL,
  metrics-history convention) and the human-gated benchmark ground-truth
  queue at analysis-results/scan-testing/cve-replay-monitor/. Network
  failure never advances the watermark, exit 0.
- --backfill ingested the Phase-0a adjudicated artifacts (203 rows → 51
  trend misses + 62 queue rows; re-run appends 0 — idempotency verified).
- 18 tests (OSV mocked); docs/outputs.md ops note (daily cron line);
  architecture table row; script counts 58→59.

## v0.147.0 — 2026-07-23

config/DSN deterministic pre-scan layer: rule-pack extensions for the 75%-FN
class (error-correction plan v2.0 §5 item 3.1 — gap-built after coverage
evaluation; committed-key class found already covered by gitleaks defaults)

- opengrep hps-pack: new yaml/ config-defaults tranche (auto-activated by
  run_opengrep.py's existing extension mapping) — DSN sslmode-disabled,
  TLS-verify-disabled, default-password, empty-password, auth-disabled
  rules over helm values / docker-compose / shipped CR samples; plus
  insecure-DSN-transport code rules for Go and Python. Every rule comment
  cites its measured miss (fn-analysis §4/§8 or a b-lite delta).
- gitleaks hps-gitleaks.toml: hps-dsn-url-credentials detector
  (postgres/mysql/mongodb/amqp/redis URLs with embedded credentials;
  placeholder allowlist; well-known defaults like guest:guest deliberately
  NOT allowlisted).
- SKILL.md: yaml-tranche exception to the KHS-deference rule (shipped
  deployment defaults are production posture, never "just config");
  gitleaks section names the new detector.
- Tests: 25 positive + 19 negative opengrep annotations across 3 new
  fixture files + extended go/python fixtures; negative gitleaks fixture
  (17 placeholder shapes) + calibration coverage.
- Known partial gap (documented): bare auth toggles in .env/.toml files —
  opengrep LANG_DIRS extension deferred; embedded-credential DSNs in those
  files ARE covered by the gitleaks detector.

## v0.146.0 — 2026-07-23

verify-remediation: cross-repo fixes — two-legged rule, propagation check, ledger mapping

A fix that lands in a different repository than the finding (upstream
library, vendored dep, deployment/policy repo) is now first-class:

- `schema/verification.schema.json`: per-finding `cross_repo` block
  (fix_repo, fix_ref, propagation: consumed/pending/module_absent/
  not_applicable, evidence) + `metadata.fix_repository`/`fix_ref`.
- Validator hard rule: `propagation: pending` forbids verdict
  `resolved` — upstream merging a fix does not resolve a finding the
  product still ships vulnerable (two-legged rule); `cross_repo` on a
  same-repo fix is rejected.
- New `scripts/check_fix_propagation.py`: deterministic Leg-B check of
  the ORIGINAL repo (go.mod + vendor/modules.txt, manifest-ecosystem
  lockfiles via the impact-analysis extractors, optional shipped-image
  SBOMs).
- verify-remediation SKILL: `--fix-repo`/`--fix-ref` mode with the
  three cross-repo shapes (consumed-via-bump / fix-lives-elsewhere /
  compensating-control) and their verdict rules.
- track-findings ingest mapping: `partially_resolved` + `pending` →
  ledger resolution `fix_in_progress` with fix-repo evidence_refs;
  promote to `resolved` when a later propagation check reports
  `consumed`. Finding identity never moves — the cross-repo fix is
  evidence attached to the original finding.

## v0.145.0 — 2026-07-23

fork advisory-lag pre-scan: the dominant measured FN class gets a
deterministic detector (error-correction plan v2.0 §5 item 3.6)

- scripts/run_fork_advisory_lag.py (stdlib-only): stage 1 detects
  fork/vendored-upstream identity locally (go.mod module path vs checkout
  identity w/ vanity-import table, replace directives, version constants,
  git remotes, vendored whole projects — file:line evidence per signal);
  stage 2 queries OSV and keeps only advisories whose affected range
  contains the tracked upstream version. Offline-tolerant (--offline /
  graceful network-error field); candidate generator, never a verdict.
- secure-code-audit SKILL.md subsection: in-range advisories on a fork are
  first-class supply-chain finding candidates in the repo's OWN shipped
  code — explicitly NOT dependency_audit material and NOT suppressible by
  the Precision Gate's dependency gate; mandatory backport check before
  filing (confirmed backport → negative_results). Added to the run-once
  pre-scan list for dual-pass.
- 12 tests (tests/test_run_fork_advisory_lag.py, OSV mocked); README/
  architecture script counts 56→57.

Measured basis: fork-lag = ≥21 of 51 missed CVEs in the 0a CVE-replay
backfill (CoreDNS forks 15, oauth2-proxy 4, prometheus 2, envoy).

## v0.144.0 — 2026-07-23

secure-code-audit recall track, slice 1 (error-correction plan v2.0 §5,
items 3.2/3.3/3.5)

- Dual-pass with union-merge is now the campaign default for every
  repository (Audit Passes section): pass 2 independently re-derives focus
  areas with varied traversal, findings union-merge with dedup, and each
  finding records its provenance in a new optional `passes` schema field
  ([1,2]/[1]/[2] — the standing run-variance measurement). Measured basis:
  unbiased single-pass high-tier recall 0.73 vs dual-pass union 0.83-0.85
  (0d capture-recapture), +7pp anchor recall at flat precision (0b arm D).
  Deterministic pre-scans still run once; single-pass only on explicit
  request (metadata.additional.audit_passes = 1).
- Severity floor for verification-disable and credential-transport classes
  (Field Conventions): high at minimum, exempt from chain-completion
  demands; lifts only on affirmative Precision Gate evidence.
- Threat-model coverage diff: when a <repo>-threat-model.md exists, every
  enumerated surface must end the audit with a finding or a
  negative_results entry — otherwise an explicit coverage-gap negative is
  emitted. Kills silent-omission FNs.
- schema/report.schema.json: additive optional finding field `passes`.

## v0.143.0 — 2026-07-23

secure-code-audit Precision Gate: measured FP suppression from the Phase-0
error-correction campaign (plan v2.0 §4, Phase 2 items 1-5)

Calibrated from 69 adversarially refuted crit/high findings (matrix stage-2
+ wave-2/3 fast-track + 0d fresh-only; taxonomy and per-rule traceability in
analysis-results/scan-testing/sxs-2026-07/phase2-refutation-rules.{json,md}).

- New `## Precision Gate` section in secure-code-audit/SKILL.md, applied to
  every candidate finding before filing, downgrade-not-drop throughout:
  dependency/advisory gate (artifact reachability, vendor CSAF
  applicability, manifest-only lint — 22/69 refutations), crit/high
  reporting bar (compensating-control sweep 13/69, privilege-delta test,
  by-design/opt-in checks requiring in-repo citations, chain completion at
  critical, no investigation-leads-as-findings), shipped-artifact path
  pre-filter + mechanism verification, and the /vuln-scan DO-NOT-REPORT
  class list ported with measured boundaries (CVE-grade algorithmic DoS
  stays reportable; own-fork advisory-lag is NOT a dependency finding —
  plan §3.6 boundary; credential-leaking open redirect keeps severity).
- `negative_results` precision rule: entries must state what was actually
  examined, never blanket class-absence claims (the measured
  narrow/wrong-negatives-adjacent-to-miss FN pattern).
- Report Validation Step 3b: audit-time citation-anchor gate
  (scripts/check_citations.py --repo, with metadata.commit freshness
  re-check) — the same deterministic gate /triage runs, moved to the
  source.
- SBOM/grype promotion rule now routes through the dependency gate.
- security-audit-phased P3: DO-NOT-REPORT class list + compensating-control
  sweep added beside its existing trust-boundary and delegated-control
  gates.
- Superseded without action: the preserved wave-2
  phase2-candidate-skillmd-tool-skip.patch (osv-scanner/gitleaks skip
  fallbacks) — both hunks shipped independently in the current contracts.
- pyproject.toml version re-synced with VERSION (had lagged at 0.141.1).

## v0.141.1 — 2026-07-22

README catch-up for the v0.139–0.141 baseline changes

- Workspace-layout tree: disposition-ledger companions
  (`-findings-layer` / `-findings-current`), container-audit artifacts
  with their full-stem naming, and the rpm `<stream>/<component>`
  placement.
- `track-findings` row: baseline inputs now list all three report
  kinds, not just `*-security-audit.json`.

## v0.141.0 — 2026-07-22

secure-rpm-audit campaign placement: analysis-results/findings + stream refs

RPM audit reports were specified to land in a `findings/` directory
sketched inside the harness repo — outside the registered corpus, so a
campaign run would have been invisible to census, dashboards, and the
disposition ledger. They now share the standard findings store:

- `harnessing/secure-rpm-audit/SKILL.md`: reports go to
  `analysis-results/findings/<stream>/<component>/` (the dist-git
  stream playing the product role), standard `-security-audit.{json,md}`
  naming unchanged — discovered by corpus, census, and the ledger flow
  with no extra wiring. Cross-stream dedup symlinks and the
  corpus-config ownership-override hook documented.
- **New `ref_kind: "stream"`** (report/cloud-config-audit/verification
  schemas + `corpus.REF_KINDS`): a dist-git release stream (`c10s`) is
  a mainline deliverable audited in its own right — stamping it
  `branch` would have misclassified every rpm report as a branch
  re-audit and dropped it from the census HEAD cuts. `is_branch_audit`
  keys on `ref_kind == "branch"` alone, so `stream` reports stay in
  the headline denominators.
- `harnessing/secure-code-audit/SKILL.md` +
  `harnessing/secure-container-audit/SKILL.md`: placement sections now
  name `analysis-results/findings/` explicitly instead of the stale
  "findings/ directory within this repository" wording (campaign
  practice, now written down).
- `docs/report-structure.md`: rpm profile deltas gain the ref/placement
  bullets; metadata row documents the `stream` enum value.
- Tests: `stream` in the schema-enum parametrization and cross-schema
  identity check; corpus stream-ref-is-not-branch-audit case.

## v0.140.0 — 2026-07-22

New skill: `impact-analysis` — per-repo CVE affectedness across the portfolio graph (MR 48, rebased + extended).

- New `harnessing/impact-analysis/SKILL.md` + `.claude`/`.crush` wiring:
  blast-radius query, L4 package-import refinement, language-specific
  deep scan, classification rubric with per-repo evidence provenance.
- New `scripts/run_impact_analysis.py` with pluggable `LanguageAnalyzer`
  architecture. GoAnalyzer (symbol tier): govulncheck source mode + ELF
  string scan + unsafe/reflect flagging. NEW manifest-tier analyzers:
  Python (requirements/Pipfile.lock/poetry.lock), Rust (Cargo.lock),
  JavaScript (package-lock/yarn.lock), Java (pom/gradle) — lockfile pin
  extraction + source import scan, classification ceiling
  `likely_affected` (a pin is never reachability). NEW CAnalyzer:
  header-include grep + DT_NEEDED linked-library scan via `lib/elf.py`.
  Every repo entry records `evidence_level` (symbol > binary > manifest).
- New `schema/impact-analysis.schema.json` (+ manifest-tier evidence
  fields) with cross-validation in `validate_report.py`.
- Wired into `/triage` Phase 2f, `/verify-remediation --impact-filter`,
  `/portfolio-graph` (handoff note), `/secure-code-audit` +
  `/secure-container-audit` (grype/K07 promotion-dismissal context),
  `/fleet-fix` (affected-repo worklists), `/file-security-defect`
  (portfolio-impact citation block), and `/drift-watch`
  (`check_impact_artifacts`: artifact vs graph-build staleness).
- Canonical artifact location: `analysis-results/impact/<cve>-impact-analysis.json`.

## v0.139.0 — 2026-07-22

container-audit reports become first-class disposition-ledger baselines

Container-image audit reports (`*-container-audit.json`) previously
could not enter the disposition flow at all — no ledger, no triage/FP
tracking, no census visibility. They are now a first-class baseline
kind end to end:

- `scripts/corpus.py`: new `container-audit` report kind
  (`-container-audit.{json,md}`). Because container reports share the
  code audit's directory (`findings/<product>/<image>/`), the record's
  `base` keeps the `-container-audit` marker — repo_key and every
  companion artifact (`<base>-findings-layer.json`, `<base>-triage.json`)
  stay collision-free next to the code audit's. `aggregates()` gains a
  per-tree `by_kind` breakdown.
- `harnessing/census/scripts/build_census.py`: dedicated `container_audit`
  block (like `cloud_config`) — container findings NEVER blend into the
  code-audit cuts or the distinct-vulnerability headline (image
  findings often manifest code findings already counted;
  `source_findings` cross-links are the dedup join).
- `scripts/build_findings_db.py`: `repos.report_kind` column
  (code-audit | cloud-config | container-audit) so ad-hoc queries can
  filter before blending units.
- Ledger tooling accepts container baselines:
  `emit_validation_ledger_events.py` basename index now also walks
  `*-container-audit.json`; the stem-derivation in both emitters and
  `build_cumulative.py` documents the deliberate full-stem naming
  (`<image>-container-audit-findings-{layer,current}` — never the short
  `<image>-findings-*` names, which belong to the code audit).
- `harnessing/secure-container-audit/SKILL.md`: new Disposition Flow
  section — immutable-baseline invariant, ledger naming, cross-digest
  disposition carry-forward via the `finding_identity.py` fingerprint
  match ladder (a fixed rebuild is a new digest → new baseline; the
  old finding resolves through the join, not a hand edit).
- `harnessing/track-findings/SKILL.md` + `docs/disposition-ledger.md`:
  container baselines documented in inputs and ledger-layout sections.
- `schema/layer.schema.json`: `metadata.audit_commit` pattern widened
  `{7,40}` → `{7,64}` — container baselines pin the 64-char image
  manifest digest where code baselines pin a git SHA.
- Tests: corpus container-kind discovery/collision coverage,
  build_cumulative CLI stem naming.

## v0.138.1 — 2026-07-22

pre-commit auto-sync of machine-local skill discovery

- `.githooks/pre-commit`: after the skill-alignment gate, symlink any
  newly committed `harnessing/<name>/` skill into `~/.claude/skills/`
  so it is discoverable in the next agent session run from the parent
  workspace. Opt-in by presence (only when `~/.claude/skills` already
  links into this clone's `harnessing/`), warn-only, never blocks a
  commit; CI and other clones are no-ops. Closes the gap where 23
  skills shipped after 2026-07-16 existed in the tree but were never
  linked and so never appeared in agent sessions.
- `docs/setup.md`: documented the sync in the hooks section.

## v0.138.0 — 2026-07-22

pqc-readiness: remediation recipes, reporting readability, patch enrichment

Structured PQC remediation knowledge base, developer-friendly reporting,
and automated patch path wiring for crypto/PQC findings.

- `harnessing/pqc-readiness/remediation/` (new directory): structured
  recipe knowledge base with `index.yaml` mapping findings to fix
  patterns. Recipes cover TLS server KE (Go, Python, Node, Rust), TLS
  client KE (Go, generic), digital signatures (certificates, tokens,
  code-signing), and config blockers (runtime switches, curve pins,
  crypto-policy). All recipes follow crypto-agility principle (remove
  restrictions, inherit defaults) rather than hardcoding versions.
- `remediation/index.yaml`: ordered most-specific-first with defined
  AND/OR matching semantics, sub-recipe selection by language or
  evidence keywords.
- `tables/pqc-version-matrix.yaml` (new): single source of truth for
  runtime PQC capabilities (Go, OpenSSL, Node, JDK, Rustls, GnuTLS,
  NSS), NIST IR 8547 clocks, and RHEL crypto-policy details. Replaces
  hardcoded thresholds in `pqc_facts.py`.
- `pqc_facts.py`: `_pqc_capable_version()` reads from the version
  matrix instead of hardcoded if/else logic.
- `build_pqc_dashboard.py`: executive summary, org-grouped repo tables,
  human-readable labels for buckets/effort/provenance/FIPS/classifications,
  "What the scores mean" legend, accurate "Clock items" column.
- `build_pqc_rollup.py`: plain-English section headings (no § plan
  references), human-readable FIPS/provenance/bucket labels, dynamic Go
  version from matrix, NIST timeline explained without jargon.
- SKILL.md step 8: explicit format instructions for per-repo `.md`
  companion — routing rules, bucket-to-status mapping, sub-recipe
  references, minimal examples, audience-appropriate language rules.
- `harnessing/patch/SKILL.md`: domain-knowledge enrichment section for
  crypto/PQC findings — AND/OR matching semantics, sub-recipe keyword
  selection, `DOMAIN KNOWLEDGE` prompt injection between FINDING and
  PROCEDURE.
- `config-blockers/runtime-switches.md` replaces the Go-only
  `godebug.md` with cross-ecosystem coverage (Go, JVM, Node, Python,
  Rust, Windows Schannel).

## v0.137.1 — 2026-07-22

centralized running critical-misses report (error-correction plan v2.0)

- `scripts/build_critical_misses.py` (new): deterministic generator for
  `analysis-results/CRITICAL-MISSES.md` — the single running view of
  every Type-II critical (a critical the original audit missed on an
  already-audited repo) discovered by the error-correction campaign.
  Walks the campaign artifacts under `scan-testing/sxs-2026-07/`:
  `b-lite/*-delta.json` critical delta candidates (glob covers future
  waves), `**/*-triage.json` verdicts (matched by source fragment and
  `orig_id`), `matrix/*-delta*.json` when present (absence tolerated),
  and `cve-replay/candidates.json` rows with `present_at_audit` +
  `audit_verdict=missed` + critical severity. Per-row ledger status is
  best-effort via the campaign `*-sample.json` slug→report maps
  (ingested-as id + findings-current disposition validity). One table
  per source instrument, summary count block, generation provenance.
  Read/render only — verdicts stay with /triage, state with the
  disposition ledger.
- `tests/test_build_critical_misses.py` (new): fixture-based coverage —
  row selection, triage/ledger joins, matrix absence + future-wave
  globs, determinism, provenance stamp.
- Docs: script count 54 → 55 (README.md, docs/architecture.md).

## v0.137.0 — 2026-07-22

inventory-repositories: Jira project resolution

Add a five-tier Jira project resolution chain to the
inventory-repositories skill so every inventoried repo gets a Jira
project key written to owners.csv. Downstream skills
(file-security-defect, track-findings, assign-findings-owners) can look
up the project directly instead of asking the user at runtime.

- `procedures/jira-resolution.md` (new): shared resolution procedure
  with five tiers — org repo team YAMLs, app-interface escalation
  policies, git history inference (commit/PR/MR Jira key patterns),
  known fallback table (~30 product mappings), Jira API search.
- owners.csv schemas gain `Jira Project` and `Jira Component` columns
  across all three target types (openshift, operator-catalog, services).
- Each target-type procedure (openshift-payload, operator-bundle,
  service-inventory) gains a Jira resolution step with target-specific
  rules (OCPBUGS default for payload, escalation-policy-first for
  services, sub-operator awareness for operator bundles).
- `add-inputs` and `assign-findings-owners` updated to match the new
  owners.csv schema.

## v0.136.0 — 2026-07-22

refutation-soundness gates (error-correction plan Phase 1)

~70% of live-validation refutations rested on probes that never tested
the claim (fp-live-refuted.md): validator-RBAC `Forbidden` transcripts,
`command not found`/jsonpath/NotFound errors, RBAC template probes with
an empty `vf-rbac-tried:` list (one with a literal
`system:serviceaccount:{ns}:{sa}` placeholder), and whole runs whose
operand never installed (`install-failure.yaml`) still emitting
`refuted`. This release makes such refutations un-emittable.

- `harnessing/validate-findings/soundness.py` (new): the deterministic
  gate. `refuted` downgrades to `inconclusive` + machine-readable
  `soundness_flag` (`error-signature:<name>` | `rbac-zero-subjects` |
  `rbac-template-placeholder` | `target-not-deployed`) when (a) the
  transcript matches an error signature, (b) an RBAC-style probe
  enumerated zero concrete subjects or carries an unsubstituted
  template, or (c) the run directory contains install-failure.yaml
  (whole run). Wired into `execute.py` (step level, audit-log stamped)
  and `report.py` (finding-level rollup + backstop for results that
  bypassed execute; flag rendered on Markdown verdict cards).
- `scripts/emit_validation_ledger_events.py`: flagged refutations
  (engine-stamped or retroactively detected, incl. the run-level
  install-failure gate) route to a `needs_review` item with new queue
  reason `unsound_refutation` — never a false_positive event, never a
  refuted-register entry, never the countersign queue.
- `scripts/countersign.py` + countersign SKILL: cards for machine
  (live-validation) refutations now render the raw probe `observed`
  output VERBATIM (indented block, artifact fallback), so a signer sees
  `Forbidden: User "gbuchana"` instead of a squashed rationale;
  unavailability is stated on the card.
- `scripts/lint_refutation_soundness.py` (new): retroactive linter —
  walks every `validation-audit.jsonl` under
  `analysis-results/**/validations/`, re-checks each refuted verdict
  against the gate, and writes a re-adjudication worklist
  (`analysis-results/scan-testing/sxs-2026-07/refutation-soundness-worklist.json`)
  with a by-condition/by-severity census. Read-only: no ledger or
  findings-current is modified (re-validation itself is Phase 0c).
- Schemas: `validation.schema.json` gains `soundness_flag` on
  step_result + validated_finding (and documents step `error`);
  `layer.schema.json` queue_reason gains `unsound_refutation`.
- Tests: `tests/test_refutation_soundness.py` (50 tests: gate
  conditions, execute/report wiring, ledger routing, countersign raw
  output, linter census + read-only guarantee).

## v0.135.0 — 2026-07-22

executive-summary: least-privilege + tenant-isolation posture tiles

- `harnessing/executive-summary-findings/scripts/build_executive_summary.py`:
  two new posture sections/cards alongside the PQC tile —
  `/operator-priv-profile` rollup (profiles, privileged workloads, SCC
  requests, wildcard RBAC, top surplus; KPI tile) and
  `/isolation-review` PEACH scores (dormant until reports land under
  `analysis-results/isolation/`). Both loaders degrade to `None` when
  their source artifact is absent and are explicitly labeled
  posture-not-findings: ratings stay out of finding counts (census is
  the denominator authority); escalation-worthy items promote
  individually via triage.

## v0.132.4 — 2026-07-21

repository-attribution hygiene: validator guard + stub-aware org index

- `scripts/validate_report.py`: strict mode now warns when
  `metadata.repository` is missing or does not parse as
  `https://<host>/<org>/<repo>` (mirrors build_org_index.py acceptance —
  unparseable values made reports invisible to org navigation). Test
  added.
- `scripts/build_org_index.py`: reports stamped
  `metadata.additional.repo_resolution: org-url-stub*` no longer warn —
  org-URL stub reports are intentionally unattributable.

Pairs with the analysis-results backfill of 70 reports (48 org-URL
stubs stamped, 22 real audits given their concrete repository URL).

## v0.131.1 — 2026-07-21

pqc-readiness: crypto governance model, FIPS detection, scoring improvements.

- **Crypto governance classification** — new analytical framework classifying
  each crypto decision point as `self` / `language-runtime` / `platform` /
  `infrastructure`. The LLM now identifies the governor before scoring.
- **Governance detection rules** — 6 `HP_GOV_PLATFORM_*` rules in
  `rules/hp_supplement.yml` detecting OCP TLS profile delegation
  (controller-runtime-common, library-go, ingress, kubelet, mesh).
- **FIPS mode detection** — `crypto_probe.py` emits `CRYPTO_FIPS140_GODEBUG`
  facts; `pqc_facts.py` annotates all provider facts with `fips_mode: true`
  when detected. `pqc_capable` stays a pure version check; FIPS×PQC
  interaction is agent-reasoned using `provider_fips_pqc_notes` in the
  decision tree (covers Go, OpenSSL, JDK, Node, Rust, GnuTLS, NSS).
- **Infrastructure governance ceiling** — PQCA-3 capped at "partial" for
  `infrastructure`-governed decision points (DB/LDAP/SMTP); new
  `server_side_caveats` schema array.
- **Blast-radius bucket override** — "ready" bucket overridden to "partial"
  when a fleet-wide trust anchor has a significant-effort clock item.
- **Dead code modifier** — dormant facts (zero non-test callers) no longer
  drive VULN/PQCA scores to "no".
- **Runtime reconciliation** — `source+runtime` assessment basis; step 7c
  reconciles cluster probe data back into reports.
- Schema: `crypto_governance` on checks, `blast_radius` on clock items,
  `server_side_caveats`, `runtime_confirmed_at`, `staleness_window_days`,
  `pqc-blocked-by-fips-mode` verdict.

## v0.131.0 — 2026-07-21

org-index: per-org symlink farm + strict URL parsing

- `scripts/build_org_index.py` now also materializes
  `analysis-results/findings/_orgs/<org>/<repo>` — a relative-symlink
  browse view of every canonical filing, one directory per source org
  (multi-filing repos get `<repo>` for the richest/oldest filing plus
  `<repo>__<product>` aliases). Regenerated with the index: stale links
  pruned, real files never touched; corpus resolver excludes symlinks so
  counts are unaffected.
- `metadata.repository` parsing is now strict (host + path-segment
  validation, markdown-autolink `<…>` unwrapping, `.github`-style
  dot-leading repo names accepted): free-text values no longer mint junk
  orgs; org-only URLs warn instead of indexing.

## v0.130.0 — 2026-07-21

repo-graph: generic inventory-segment ingestion (stackrox-org-gap campaign)

- `harnessing/repo-graph/scripts/build_repo_graph.py`: segments without a bespoke
  handler (`adhoc/`, `lightwell/`, …) are now ingested generically —
  one product node per `<segment>/<group>/` directory, `ships` edges from
  `*-repos.csv` rows, owners from `owners.csv` (the add-inputs skill's
  layout). Previously such segments were discovered but silently dropped,
  so ad-hoc inventory additions never reached the graph; found when the
  27 stackrox-org-gap repos (hybrid-platforms-inputs/adhoc/stackrox/)
  failed to appear. lightwell/ (53 repos) is picked up by the same fix.
  Strictly additive: bespoke segment handlers, repo-node identity, and
  existing edges are unchanged.

## v0.126.0 — 2026-07-21

consumers + policy docs: ref coverage surfacing, ref-semantics policy,
slug/declared drift check — branch-awareness Phase 4, FINAL (XWING-609,
closes the build work of epic XWING-604). Strictly additive, proven on
a live-tree snapshot: old-vs-new executive summary diff contains only
insertions (md: 0 deletions / 17 added lines; html: one inserted
ref-coverage block plus one `<li>` appended to the population panel,
byte-prefix-verified — every pre-existing key/row/number identical).

- `harnessing/executive-summary-findings/scripts/build_executive_summary.py`:
  ref coverage surfaced where branch_confirmations/branch_findings
  already render — compact per-release row set (top 10 refs by report
  count, tail folded into one row) in BOTH md and html, sourced
  straight from corpus.py `aggregates()['totals']['refs']` (the
  resolver owns ref identity — declared `metadata.ref` preferred,
  legacy slug fallback; the builder never re-parses slugs). Population
  block gains a **Ref scope** bullet so "HEAD or branch-inclusive?" is
  answerable from the header (occurrence totals branch-INCLUSIVE;
  Distinct Vulnerabilities headline HEAD-only). Corpus loader factored
  into `_corpus_module()` (shared by the population block).
- `scripts/check_drift.py`: new deterministic `ref-provenance` check —
  drift when a report's slug-derived ref and declared `metadata.ref`
  BOTH exist and disagree (stale slug after a move/rename, or a
  wrong-checkout stamp; symmetric — the checker never picks a winner).
  Reports carrying only one form are not comparable and stay silent.
  Zero disagreements on the live tree today (Phase-0 writers have begun
  landing declared refs — all `main`/`default` on slug-less reports).
  Corpus loading factored into `_corpus_mod()` (shared with the
  registration check). drift-watch SKILL.md check table updated.
- PROCESS.md: **Ref semantics** paragraph in the metrics/three-lens
  section — `metadata.ref`/`ref_kind` is authoritative provenance, slug
  suffixes are legacy fallback, the fingerprint stays branch-blind
  (HEAD↔branch folding), Lens 2 stays HEAD-canonical; cites the
  branch-awareness plan.
- Tests: exec-summary additive-invariance fixture (absent → byte-
  identical; present → insert-only diff), per-release row rendering +
  top-N tail folding, drift-check agree/disagree/absent cases, live-
  tree zero-disagreement canary.

## v0.125.0 — 2026-07-21

portfolio-graph: opt-in per-release ref enrichment — branch-awareness
Phase 3 (XWING-608, epic XWING-604). SELECTIVE and data-gated per the
plan: the stage never runs unless asked, and default builds are proven
byte-identical (old-vs-new script on a Phase-2 ref-carrying fixture
spine: SQLite dumps, stats.md, and summary.json all identical; ref
cache untouched).

- `scripts/build_portfolio_graph.py`: new `build --enrich-refs
  [N|branch,branch]` stage. For the supported releases' `repo-ref`
  nodes ONLY (spine refs from repo-graph Phase 2), fetches each repo's
  `go.mod` AT that branch (`gh api …/contents/go.mod?ref=<branch>`,
  raw — same path shape as the default-branch fetch) and attaches
  `depends_on_ref` edges FROM the ref node with attrs
  version/indirect/`ref=<branch>`. Supported-set derivation
  (`select_supported_refs`): numeric N → top-N `release-X.Y` branches
  by ships_ref edge count, ties to the newest release (bare flag →
  N=3: roughly the concurrently-supported OpenShift minor streams —
  newest GA + two maintenance — where the release-branch campaign
  showed shipped exposure concentrates, while bounding fetch volume);
  a comma list names branches verbatim (deliberate `main`/openshift-X.Y
  enrichment stays possible). `depends_on_ref` is a DISTINCT rel,
  mirroring the Phase-2 `ships_ref` decision — the depends_on consumer
  audit (q_blast_radius/q_top_shared/q_internal_coupling, fleet-fix
  `fleet_targets.py` rel-IN filter) shows every consumer keys
  rel='depends_on' with repo-node sources, so reuse would double-count
  and mis-key ref rows. Ref-fetch cache is per repo@branch
  (`gomod-ref/<org>__<name>@<branch>.json`, ok/absent cached, errors
  never); missing branch or missing go.mod at ref = counted skip,
  never a failure. Ref-only modules are INSERT OR IGNOREd
  (internal=0, `first_seen_ref`) so HEAD-derived module attrs are
  never overwritten.
- HEAD-only caveat wiring (plan Phase 3 known limit): one sentence
  wherever graph pqc/isolation attrs surface — pqc-dashboard legend,
  pqc-portfolio-rollup footer, per-product reports index header,
  portfolio-graph SKILL.md — graph PQC/isolation attrs describe
  default-branch (HEAD) posture; per-ref facts are a separately-costed
  decision. Scoring untouched.
- `harnessing/portfolio-graph/SKILL.md`: enrichment usage + ref
  semantics paragraph.
- Tests (tests/test_build_portfolio_graph.py): flag-off invariance
  (CLI build == pre-Phase-3 pipeline, no ref rels, ref cache never
  touched), flag-on attaches depends_on_ref from the ref node with
  HEAD consumers unaffected, missing-go.mod-at-ref counted skip,
  supported-set selection (release-X.Y-only ranking, `main` excluded,
  newest-release tie-break, bare-flag default N=3, verbatim list).

## v0.124.0 — 2026-07-21

repo-graph: first-class ref nodes for inventory branches —
branch-awareness Phase 2 (XWING-607, epic XWING-604). Strictly additive:
repo-node identity, every pre-existing edge/attr, hub degrees, and the
HTML view are byte-identical (proven on the live hybrid-platforms-inputs
CSVs — 10,527 nodes / 15,489 edges unchanged; only additions).

- `harnessing/repo-graph/scripts/build_repo_graph.py`: where an inventory CSV
  row declares a Source Branch (openshift payload + operator-catalog
  CSVs), the builder now ALSO emits an optional first-class ref node —
  id `ref:<host>/<org>/<name>@<branch>`, kind `repo-ref`, label
  `<org>/<name>@<branch>`, `attrs.branch` — deduplicated to one node
  per unique (repo, branch), plus `has_ref` (repo → ref) and a
  `ships_ref` edge parallel to each branch-carrying `ships` edge
  (same shipper, same release/version/branch attrs). `ships_ref` is a
  DISTINCT rel, not a reuse of `ships`: every existing `ships` consumer
  (portfolio-graph `q_blast_radius`, pqc rollup/product reports'
  `rel='ships'` SQL, fleet-fix targets, CVE enrichment) filters on
  rel + repo-node membership, so reuse would have mutated
  `stats.by_rel.ships` and invited double-counting; the distinct rel
  keeps all existing outputs unchanged. Live build adds 4,624 repo-ref
  nodes, 4,624 has_ref + 4,953 ships_ref edges. Ref layer is excluded
  from hub-degree stats and the HTML view; stats.md gains an additive
  ref-layer line; DOT gets a `repo-ref` style; GEXF gains a trailing
  `branch` attribute (pre-existing attr ids stable).
- portfolio-graph ingest verified, no guard needed: `build_spine`
  upserts refs as inert `kind='repo-ref'` rows; every enrichment stage
  and query filters `kind='repo'` / specific rels. Per-ref enrichment
  is Phase 3 (XWING-608), not this story.
- `harnessing/repo-graph/SKILL.md`: ref-layer section — node/edge
  reference, dedup + "created only where inventories declare branches"
  semantics, and jq recipes ("repos shipping release-X.Y from a
  non-default branch", branches per repo, shippers of a repo@branch).
- Tests: ref creation + (repo, branch) dedup + has_ref/ships_ref shape,
  branch attr retained on `ships`, no-branch inventory → zero refs
  (tests/test_build_repo_graph.py); ref-carrying spine ingests
  harmlessly into portfolio-graph — repo universe and `ships` counts
  unchanged (tests/test_build_portfolio_graph.py).

## v0.123.0 — 2026-07-21

index+census: branch-aware symbol index meta + per-ref breakdown —
branch-awareness Phase 1 (XWING-606, epic XWING-604). Additive only:
the index filename convention (`<dir>-<sha>.db`) stays the immutable
key, the finding fingerprint stays branch-blind, Lens 2 stays
HEAD-canonical, and corpus.py remains the single identity authority.

- `scripts/build_symbol_index.py`: new `detect_ref()` — the meta table
  now records `ref` alongside repo/sha/engine (`git rev-parse
  --abbrev-ref HEAD`; literal branch name, `detached` when HEAD is
  detached, `unknown` outside a git checkout). Provenance only: index
  identity is still (repo, sha).
- `scripts/query_index.py`: new `--info` command printing the meta
  table (text and `--json`). Pre-Phase-1 indexes without a `ref` row
  stay fully queryable — a missing ref is reported as `unknown`, never
  an error.
- `scripts/corpus.py`: `aggregates()` gains an additive per-ref report
  counter (`refs: {"release-4.19": N, …}`) per tree and in totals,
  sourced from BOTH legacy slug refs and declared `metadata.ref`. No
  pre-existing aggregate reads it; proven invariant on the live
  analysis-results tree (corpus summary stdout byte-identical;
  aggregates/census JSON identical after stripping only the new keys).
- census (`harnessing/census/scripts/build_census.py`): compact per-ref
  breakdown table in census.md and census.html next to the existing
  branch stats ("Population by tree" / branch re-audit cards);
  census.json carries the new `refs` keys inside the population block.
- Tests: index ref recording (branch / detached / non-git fixtures in
  tmp), legacy ref-less index queryability, per-ref counter over a
  fixture mixing slug and declared refs, census renderer surfacing.
## v0.122.1 — 2026-07-21

Patch: Activity Type field (`customfield_10464`) resolved to "Security &
Compliance" (option id 10609) for the two Jira-writing skills, instead of
figuring it out at runtime. sync-jira-backlog: added to the Jira constants
table in `references/exclusions.md`, parsed by `parse_config.py`, and
stamped into every created ticket's `additional_fields` by
`format_payloads.py` — the field was previously blocked pending a Jira
admin adding it to XWING's issue screens (now resolved). file-security-defect:
the value is now set by default in the `createJiraIssue` example and the
missing-fields troubleshooting note tells the agent to drop the field and
retry rather than ask the user, for the (rare) target project that doesn't
have it on-screen.

## v0.122.0 — 2026-07-21

reports: explicit ref provenance (`metadata.ref`) — branch-awareness
Phase 0 (XWING-605, epic XWING-604). Follows the
pqc_classification/attack_refs precedent: optional fields,
validator-enforced when present, all existing reports stay valid. The
finding fingerprint stays branch-blind, Lens 2 stays HEAD-canonical, and
corpus.py remains the single identity authority.

- `schema/report.schema.json` + `schema/cloud-config-audit.schema.json`:
  optional `metadata.ref` (string, minLength 1 — the branch/tag as
  checked out) and `metadata.ref_kind` (enum `branch|tag|default`).
  Never required; slug parsing stays the legacy fallback (declared in
  the metadata blocks because report.schema.json's metadata is
  `additionalProperties: false`).
- `schema/verification.schema.json`: the same optional pair on
  verification metadata — restating the ORIGINAL audit's ref (distinct
  from `patched_ref`), needed because that metadata block is also
  `additionalProperties: false`.
- Writer skills stamp it: secure-code-audit (Branch input → `branch`,
  tag → `tag`, default checkout → `default` with the branch's name,
  detached `commit:<sha>` → omit both); secure-rpm-audit mirrors the
  same rules for dist-git branches; secure-container-audit explicitly
  does NOT stamp it (image digests are not git checkouts);
  verify-remediation restates the original audit's ref/ref_kind
  verbatim.
- `scripts/corpus.py`: declared `metadata.ref`/`ref_kind` preferred over
  slug parsing (cheap `"ref"` substring probe keeps resolve() at
  walk-speed over the legacy corpus); `is_branch_audit` =
  `ref_kind == "branch"` for declared refs, unchanged slug semantics for
  legacy reports; the `__release-X.Y`/`__openshift-X.Y` whitelist is now
  documented as legacy-only; `base_slug` identity collapse stays
  slug-driven. Census/exec numbers verified byte-identical on the live
  tree (0 of 8,047 findings/ reports declare a ref today).
- `scripts/backfill_report_refs.py` (new, ships dormant): idempotent
  slug→metadata backfill, dry-run by default (`--apply` to write),
  `--results-root` per tree, skips symlink aliases and HEAD reports,
  re-validates every touched report against its schema, per-product
  batch summary. Not run against analysis-results — that is a separate,
  explicitly-batched decision.
- Tests: `tests/test_report_refs.py` — schema accepts/rejects/omission
  matrix across all three schemas, resolver declared-over-slug
  preference, legacy-layout invariance (no declared refs → identical
  census semantics), backfill dry-run/apply round-trip in tmp.
- Docs: `docs/report-structure.md` metadata row, `docs/architecture.md`
  script count + table rows.

## v0.120.0 — 2026-07-20

audit skills: per-finding isolation tags + declared-layer isolation
checks — PEACH lens Phase 2 (XWING-596, epic XWING-593). Mirrors the
pqc_classification precedent: optional, never required, all existing
reports stay valid.

- `schema/report.schema.json`: optional per-finding `isolation_dimensions`
  (array, minItems 1, unique, enum of the five isolation-hardening
  dimensions privilege/encryption/authentication/connectivity/hygiene —
  vocabulary shared with `schema/isolation-review.schema.json`) and
  `isolation_boundary` (free-form tenant-facing interface identifier).
  Assigned only when a finding stresses a tenant boundary in a
  multi-tenant service; absent elsewhere.
- `schema/cloud-config-audit.schema.json`: the same two optional finding
  fields, so declared-layer IaC findings feed the isolation dashboard.
- secure-code-audit SKILL.md: "Per-finding isolation tagging" pass at the
  end of the Multi-Tenant Isolation section — tag boundary-stressing
  findings only when `peach_isolation_review.applicable` is true; no new
  hunting, no severity inflation; PEACH cited by name/URL only
  (`check_content_licenses.py` fingerprint gate stays green).
- cloud-config-audit SKILL.md: declared-layer isolation checks over the
  existing Checkov facts (NetworkPolicy/segmentation presence, IAM/RBAC
  tenant separation, per-tenant encryption/key config) tagged with the
  same fields — declared layer only, the no-cloud-API-calls hard rule is
  unchanged.
- verify-remediation SKILL.md: restate `isolation_dimensions` /
  `isolation_boundary` in verification entries (don't-regress area, next
  to the PQC tag restatement) so roll-ups keep the boundary context.
- `scripts/validate_report.py`: no change needed — validation is generic
  jsonschema against the schema; claim-hash fields deliberately exclude
  tag fields (as with pqc_classification).
- Tests: `tests/test_isolation_tagging.py` — tagged findings validate,
  invalid dimension/empty array/empty boundary rejected, untagged
  findings stay valid, dimension vocabulary pinned to the
  isolation-review schema across both report schemas.

## v0.119.0 — 2026-07-20

threat-model+register: tenant-boundary isolation wiring — PEACH lens
Phase 1 (XWING-595, epic XWING-593). Mirrors the attack_refs integration
style exactly: optional fields, validator-enforced when present, older
artifacts stay valid.

- threat-model schema.md + SKILL.md: optional `## 10. Tenant boundaries`
  section for **multi-tenant services only** — one row per tenant-facing
  interface (`boundary_id` IF-n, interface name, kind, exposure,
  complexity, the five isolation-hardening dimension results
  yes/partial/no/na, linked `threat_ids`, optional `isolation_review_ref`
  to `analysis-results/isolation/<service-slug>/`), vocabulary shared
  with `schema/isolation-review.schema.json`; plus an optional trailing
  `isolation_dimensions` threat-table column (subset of
  privilege/encryption/authentication/connectivity/hygiene) tagging which
  dimension a threat stresses. PEACH is referenced by name/URL only —
  never adapted text (`check_content_licenses.py` fingerprint gate stays
  green).
- `scripts/lint_threat_model.py`: enforces the new contract when present
  (section 10 columns/enums/id stability/threat_ids referential
  integrity/review-ref shape; isolation_dimensions vocabulary) — 10- and
  11-column tables and section-10-free models stay valid.
- threat-register: optional per-row isolation fields
  (`isolation_dimensions`, `isolation_boundaries`, `isolation_review_ref`)
  and a weakest-first `tenant_boundaries` roll-up (JSON + md "Weakest
  tenant boundaries" table; failed dims weigh 2, partial 1) — absent
  entirely when no model carries the lens, so boundary-free registers are
  unchanged. Aggregation documented in the skill.
- Fix: the register builder previously accepted only the legacy
  ten-column threats table, silently skipping (as nonconforming) every
  model carrying the `attack_refs` column that is default since v0.82.0;
  it now parses all contract column variants.
- Tests: lint + register fixtures with and without the optional fields
  (both pass; omission stays valid — backward compat).

## v0.117.0 — 2026-07-20

isolation-review: PEACH-by-reference tenant-isolation skill — Phase 0 (XWING-594, epic XWING-593).

- New skill `harnessing/isolation-review/SKILL.md`: service-level
  tenant-isolation review — repo set resolved via the portfolio graph's
  `ships` edges, boundary inventory of customer-facing interfaces from
  graph + existing audit/threat-model findings, per-interface complexity
  rating, five isolation-hardening dimensions (privilege, encryption,
  authentication, connectivity, operational hygiene) scored yes/partial/no/na
  with mandatory evidence citations, overall posture + worst-first gaps.
- PEACH is applied **by reference only** (name/URL citation; all check
  wording original) — stated as a hard rule in the skill;
  `check_content_licenses.py` fingerprint gate stays green.
- `schema/isolation-review.schema.json`: report schema (metadata,
  interfaces[], gaps[], posture); reports land under
  `analysis-results/isolation/<service-slug>/`.
- `harnessing/isolation-review/scripts/validate_isolation_review.py`: stdlib-only
  validation gate mirroring the schema (the pqc_facts
  `--validate-readiness` pattern).
- Wiring: `.claude/skills` + `.crush/skills` symlinks,
  `/isolation-review` command wrapper + `.crush/commands` symlink.
- `tests/test_isolation_review.py`: fixture validated against the schema
  and the stdlib gate (valid + invalid cases); docs counts 50 → 51.

## v0.115.0 — 2026-07-20

Rewrite `crypto_audit.py` as slim unopinionated data collector; clarify skill delegation.

- `scripts/crypto_audit.py` rewritten: removed all interpretation logic
  (BinaryPattern, PatternSet, CRYPTO_PATTERNS, _ImageAuditor, dual-probe,
  PQC/classical classification). Now collects raw structural data only.
- Image tier: structural collectors (linked libs via ELF, packages, certs,
  crypto-policy, FIPS markers). No pattern matching.
- Cluster tier: single `openssl s_client` probe per endpoint. New `--groups`
  flag for consumer-driven TLS group selection. `--namespaces` now required.
- `crypto-analysis` confirmed as sole orchestrator of `crypto_audit.py`.
- `secure-code-audit`, `secure-container-audit`, `verify-remediation` now
  delegate crypto depth to `crypto-analysis` instead of calling the tool directly.
- `validate-findings` retains direct `cluster` tier usage for runtime probing.
- `pqc-readiness/SKILL.md`: documents `crypto_audit.py cluster --groups`
  as the mechanism for PQC runtime evidence collection, with interpretation
  guidance for ML-KEM negotiation results.
- Doc fixes: removed ghost `image_crypto_audit.py` reference, vestigial
  `pqc_facts.py` input bullet, fixed `novel.py` relative path.

## v0.114.0 — 2026-07-20

Minor release: sync-jira-backlog pipeline scripts (agentskills.io pattern).

- Four new bundled scripts under `harnessing/sync-jira-backlog/scripts/`:
  `parse_config.py`, `filter_candidates.py`, `classify_candidates.py`,
  `format_payloads.py` — deterministic data processing that was previously
  reinvented each run by the agent.
- SKILL.md restructured from 6 prose steps to 8 phases alternating
  MCP calls and script invocations, per agentskills.io best practices.
- Grouping algorithm for high-volume repos (progress-tracker,
  analysis-results) now codified: same-author/consecutive-day clustering
  with keyword-similarity merge.

## v0.113.0 — 2026-07-20

New skill: `crypto-analysis` — probe-driven crypto governance analysis.

- New `scripts/crypto_probe.py`: shared provider census probing across 9
  language ecosystems (Go, Python, Node, JDK, Rust, C/C++, .NET, Ruby,
  container/RPM) with broad keyword-driven Dockerfile directive detection
  and golang-fips backend swap detection.
- New `harnessing/crypto-analysis/SKILL.md`: probe-driven crypto analysis
  skill with governance chain reasoning, two-layer probe model (census +
  TLS/code), `backend-swap` type for builder image crypto injection.
- New `harnessing/crypto-analysis/tables/governance-chain.schema.json`:
  JSON Schema for governance chain output validation.
- `pqc_facts.py`: imports `crypto_probe` for census facts, extends
  `_pqc_capable_version()` (rustls >= 0.23.27, GnuTLS >= 3.8,
  NSS >= 3.105), wires governance chains into Phase 2 provenance.
- `pqc-readiness/SKILL.md`: documents two-layer probe model, governance
  chain → provenance mapping table.
- New `tests/test_crypto_probe.py`: 47 golden-file tests covering all
  probes, PQC capability thresholds, builder image detection, and
  probe-to-rule mapping completeness.

## v0.112.0 — 2026-07-19

Minor release: per-product PQC status reports (user request — the
"what does MY product look like" view for the leadership/ProdSec
conversation).

- New `harnessing/pqc-readiness/scripts/build_pqc_product_reports.py`: one
  markdown per product (134) from graph `ships` edges × `pqc` repo attrs
  × readiness-report clock detail — bucket summary, worst-first repo
  table (score/bucket/HNDL/2030-clock), 2030-clock item detail
  (significant-first), HNDL list — plus a worst-first index. Output:
  `progress-tracker/metrics/dashboards/pqc/products/`.

## v0.111.0 — 2026-07-19

Minor release: PQC vendor/dependency roadmap tracker (plan v1.3 Phase 3
handoff — the delegated/blocked-external class).

- New `harnessing/pqc-readiness/tables/pqc-vendor-roadmap.json`: curated
  16-vendor registry (providers/libraries/ecosystems/services/internal
  owners) with dated, reviewable PQC-status claims and watch signals.
- New `harnessing/pqc-readiness/scripts/build_pqc_vendor_tracker.py`: merges the
  registry with live fleet counts (graph `uses_crypto_dep` edges,
  blocked-external reports) into
  `progress-tracker/metrics/dashboards/pqc/pqc-vendor-roadmap.{md,json}`,
  sorted worst-first (go-jose: 235 repos, status none).

## v0.108.0 — 2026-07-19

Minor release: PQC calibration v2 — the sweep-proven scanner gaps
(supplement pack 47→51 rules, adapter 1.1.0→1.2.0).

- Four new HP supplement rules, each provoked by a confirmed Phase-1 blind
  spot: `HP_KEYGEN_PULUMI_TLS` (declarative IaC keygen — mapt's RSA-4096
  SSH minting was invisible), `HP_SIGN_GPG_VERIFY` (gpg/gpgv/python-gnupg
  + insights_signature — the playbook-signing thread), `HP_ENC_AGE`
  (filippo.io/age X25519 recipients — git-partition-sync-consumer),
  `HP_EC_PY_ED25519` (pyca/PyNaCl Ed25519 — compliance-trestle).
- Adapter path-classifier fixes: TESTDOC_RX gains `testfiles*`,
  `test_files/`, `__tests__/`, `__fixtures__/`, `__data__/`, `spec/`,
  `t/`, `.adoc`, and lint/review-bot config (`.coderabbit.yaml`,
  `semgrep.yaml`, `.sourcery.yaml` — instructions-not-usage); VENDOR_RX
  gains `site-packages/` + `.gomodcache/`. Fixture-verified: all four
  rules fire, new path classes tag test_docs.

## v0.106.1 — 2026-07-19

Patch: pqc-tls-negotiation / pqc-backend-tls probe templates also grep
`Peer Temp Key` — OpenSSL 3.x `-brief` reports the negotiated group on
that line, not `Negotiated TLS1.3 group`; found during the Phase-3 live
shakeout (the probes otherwise ran verbatim from the catalogue).

## v0.106.0 — 2026-07-19

Minor release: PQC executive wiring (user request — the XWING-385 views as
first-class KPI sections, ATT&CK-integration pattern).

- `executive-summary-findings/build_executive_summary.py`: new
  `load_pqc_readiness()` reads the Phase-2 roll-up sidecar (structured, no
  markdown scraping); Markdown gains a "Post-Quantum Cryptography
  Readiness (NIST IR 8547)" section (bucket distribution, KPI table for
  the five views, significant-effort 2030 items, vendor-blocked list);
  HTML gains a PQC KPI tile (2030-clock items) and a card with collapsible
  significant-2030 and HNDL-ranking tables.
- `scripts/metrics_ledger.py`: three new ledger keys
  (`pqc_2030_clock_items`, `pqc_hybrid_blockers`,
  `pqc_toolchain_quickwins`, all down-is-good) and six PQC series added to
  the Executive-Trends chart set (ready/not-ready/HNDL + the three new
  burndowns, joining coverage + total clock items).
- `pqc-readiness/build_pqc_rollup.py`: appends the three view metrics to
  the shared hash-chained ledger per rebuild (append_if_changed,
  idempotent).

## v0.105.0 — 2026-07-19

Minor release: PQC Phase-2 portfolio roll-up (plan v1.3 §Phase 2; the
XWING-385 executive views, folded into one artifact after the story was
closed).

- New `harnessing/pqc-readiness/scripts/build_pqc_rollup.py`: deterministic
  synthesis of the completed Phase-1 sweep (3,151 readiness reports +
  facts + portfolio graph) into
  `progress-tracker/metrics/dashboards/pqc/pqc-portfolio-rollup.{md,json}`
  plus 5 CSV exports — 2030-clock burndown (124 items / 95 repos, ranked
  significant-first), HNDL priority ranking (142 repos), hybrid-TLS
  group/KEX blockers with file:line (294 first-party pins),
  go-directive-<1.24 quick wins (536 one-line bumps), and per-product
  roll-up via graph `ships` edges (134 products). Sections cover both
  score vocabularies, provenance × provider census, the NIST 2030/2035
  timeline-compliance view, effort-classed blocking items, the FIPS/PQC
  matrix, and vendor/infra dependency bottlenecks.

## v0.101.1 — 2026-07-19

Patch: PQC dashboard worst-posture table deepened from 15 to 25 rows
(user request — the 40–42.5 not-ready band had scrolled off as the sweep
found lower scorers).

## v0.99.0 — 2026-07-19

Minor release: XWING-384 portfolio-graph crypto backfeed (plan v1.3
Phase 2b), running incrementally alongside the Phase-1 sweep.

- New `harnessing/pqc-readiness/scripts/scan_pqc_dependencies.py`: deterministic
  full rebuild of PQC-derived graph rows from the sweep's already-emitted
  `*-pqc-facts.json` — no re-scanning. L1 `crypto-dep` nodes (library ×
  version from DEP_*/HP_FW_* facts, masking-tolerant identity) with
  `uses_crypto_dep` edges; L3 `crypto-usage` nodes (ir8547 usage × qclass,
  no free-authored taxonomy) with `uses_crypto` edges whose attrs carry
  fact/first-party/2030-clock/per-rule counts. Repo nodes gain a `pqc`
  attrs block (overall/bucket/hndl_priority/2030-flag/assessed_at) — the
  data source XWING-385 exec views expect. Idempotent per-batch re-runs;
  summary sidecar at `graph/pqc-backfeed-summary.json`.
- First run over the 65.6%-assessed corpus: 3,225 repos (2,247 stamped),
  253 crypto-dep nodes / 739 edges, 22 crypto-usage nodes / 9,710 edges;
  "repos using quantum-vulnerable key exchange" is now a one-line graph
  query (1,064 today).
- Tests: `tests/test_scan_pqc_dependencies.py` (identity parsing, repo-id
  normalization, end-to-end idempotency on a fixture graph).

## v0.96.3 — 2026-07-18

Patch: PQC dashboard legend documents the FIPS interaction verdicts
(no-penalty / blocked-by-provider-version / fips-validation-gap).

## v0.96.2 — 2026-07-18

Patch: PQC dashboard worst-posture table gains per-domain columns
(VULN/AGIL/PQCA/HNDL, each 0-100 over assessable checks; HNDL cell
carries the hndl_priority flag) with legend text explaining each domain.

## v0.96.1 — 2026-07-18

Patch: PQC dashboard readability — "How to read the scores" legend (0-100
scale, weights, bucket derivation incl. the significant-effort override
and the not-applicable renormalization caveat) and the worst-posture
table now shows score and level together ("**25** (not-ready)").

## v0.92.0 — 2026-07-18

Minor release: live PQC status dashboard (XWING-18 "special dashboard").

- New `harnessing/pqc-readiness/scripts/build_pqc_dashboard.py`: per-batch
  deterministic roll-up of the Phase-1 sweep (coverage, readiness
  buckets, 2030-clock burndown, HNDL list, effort mix, provenance
  census, worst-posture table) PLUS the pqc_classification-tagged
  findings emitted by the general skills since v0.87.0
  (secure-code-audit tagging + verify-remediation regressions) — one
  dashboard tracks both the dedicated sweep and everyday-audit signal.
- Outputs progress-tracker/metrics/dashboards/pqc/pqc-dashboard.{md,json};
  `pqc-readiness` ledger source; Executive-Trends charts
  pqc_sweep_coverage_pct (up-good) + pqc_clock_items (burndown).
- Plan v1.3 gains Phase 1b (live dashboard); docs/architecture count fix.

## v0.91.0 — 2026-07-18

Minor release: cosign classical-signing rules in the opengrep pack.

- New hps-bash-cryptography-cosign-classical-signing and
  hps-go-cryptography-cosign-classical-signing (INFO, CWE-327,
  pqc_classification=shor-signature): inventory sigstore/cosign signing
  in everyday audits, ported from the PQC pilot's calibrated pattern —
  command-verb / quoted-import anchored; verify-only and prose mentions
  deliberately excluded (the bare-'sigstore' shape was 38/38 FP).
- opengrep-rules README: test invocation corrected to `opengrep test`.

## v0.90.0 — 2026-07-18

Minor release: PQC pilot calibration pass complete — Phase 1 gate cleared.

- Supplement pack 31→47 rules: HP_TLS_VERIFY_DISABLED family (Go/JS/Py/
  conf — 4 independent pilot confirmations), unauth cipher modes,
  secret-embed, openssl-enc static key, plaintext fetch, Python RSA
  keygen, Java KeyFactory EC/DH, Rust SHA-1/MD5, EVP_DigestSign family,
  maven-gpg, Ruby TLS-client gems, ceph msgr2 crc, JWT short-secret.
- FP fixes: cosign rule 38/38-FP pattern tightened (re-pilot: 4 hits,
  all vendor-quarantined); falcon prose match constrained to
  falcon-512/1024; HP_FW_SPRING_SECURITY converted to purl form.
- Adapter 1.1.0: test/docs path class (63-73% pilot noise now tagged
  and score-excluded), 112-bit clock co-resolution off evidence.match
  (RSA-2048 sites now land on the 2030 clock — verified on re-pilot),
  multi-stage FROM-alias filter, .nvmrc/engines/pom JDK provider census,
  bundled/3rdparty vendor globs, by_path_class summary.
- ir8547 mapping: non_quantum_risk class (posture rules never enter the
  quantum clocks); scoring records assessable_checks denominator.
- Re-pilot (oauth-proxy, apicast): new rules fire on known ground truth,
  0 unmapped classes, pilot reports validate backward-compatible.
  (Note: most files landed inside the concurrent v0.88-0.89 commits;
  this release completes and documents the pass.)

## v0.89.0 — 2026-07-18

Minor release: regression rules from resolved findings — capability C6.

- New scripts/emit_rule_drafts.py: every ledger finding RESOLVED at a
  named fix commit yields a calibration pair (pre-fix file = must fire,
  post-fix file = must not). Drafts staged under
  harnessing/mine-ledger/rule-drafts/ with evidence, prefilled skeleton
  (regression_of metadata carries fingerprint + fix commit so a future
  firing links back to the original finding), and a --verify gate:
  opengrep must fire on before/ and stay silent on after/ before a
  draft is promotable. Identical pairs (fix touched other files) are
  skipped — a non-differing pair calibrates nothing. Drafts are never
  loaded by run_opengrep.
- mine-ledger SKILL gains the stage→author→verify→promote procedure,
  including the honesty rule: additive-coverage and cross-file
  behavioral fixes have no matchable pre-shape — reject those drafts
  rather than author noisy rules (observed live: a secret-filter fix
  that ADDED patterns is not rule-expressible).
- First promoted regression rule:
  **hps-bash-regression-codecov-uploader-latest** (bash/supply-chain) —
  guards the 2021-compromise shape (mutable `latest` Codecov uploader
  fetch, no digest); calibration PASS on the insights-interact-tools
  pre/post-fix pair (before=2 fires, after=0), fixture lines annotated,
  pack fixture test added. 3 drafts remain in the authoring backlog.
- 5 new tests (emitter pairs, identical-pair skip, language skip,
  verify pass/fail, promoted-rule calibration).

## v0.88.1 — 2026-07-18

Patch: fleet-fix step-1 resolver — fleet_targets.py connects /fleet-fix
to both graphs.

- One command resolves the affected-repo fleet from the right source:
  --cwe (insecure-patterns pattern repo lists), --rollup (PROGRESS.md
  cross-cutting rollup rows), --module (portfolio-graph.db
  imports_package/depends_on — dependency fleets incl. subpackages),
  --repos passthrough. Every target enriched from repo-graph: product
  reach (output pre-sorted — fix highest blast radius first) and owner
  team (MR routing); unenriched targets listed with a URL guess, never
  dropped. fleet.json is the campaign target list of record.
- Live smokes: rollup "pipelineRef" fleet with owner teams;
  --module github.com/openshift/library-go → 264 importing repos;
  --cwe CWE-1104 → 621 targets (42 outside repo-graph, retained).
  5 new tests; SKILL step 1 now prescribes the resolver.

## v0.88.0 — 2026-07-18

Minor release: /fleet-fix — systemic-pattern remediation as one campaign
(capability C5).

- New harnessing/fleet-fix/ skill (44th): one reviewed transform spec,
  applied across every repo affected by a Lens-3 pattern. Hard gates:
  the spec IS the change (schema/fleet-fix.schema.json, golden tests
  mandatory — apply_fleet_fix.py refuses to run while a golden fails);
  diffs before forks, forks before MRs, humans before both (the applier
  only modifies working clones and emits diff + result JSON; MR opening
  is a separate, explicitly-approved batch stage via the
  remediate-finding fork flow); allowlist file_glob scope with
  max_files_changed / clean-tree guards that revert overreach.
- Matcher kinds: pinned_ref_line (guarded line rewrite + per-URL git
  ls-remote resolver, --pin override for determinism) and ast_grep
  (structural rewrite). 7 new tests.
- Pilot spec specs/konflux-mutable-pipelineref.yaml (pins Tekton
  git-resolver `revision: main` to the shared repo's HEAD SHA with a
  fleet-fix marker) — golden-tested, and applied live to three affected
  stolostron repos: 10 files rewritten, konflux-build-catalog resolved
  once per URL, 0 unresolved; diffs staged for human review, no MRs
  opened (gate 2).
- License intake (verified upstream 2026-07-18): ast-grep MIT, glab MIT.

## v0.88.0 — 2026-07-18

Minor release: PQC wired into the everyday workflow (XWING-382/383).

- New machine-readable decision tree
  `harnessing/pqc-readiness/tables/pqc-readiness-decision-tree.json`
  (provenance rules, remediation-effort mapping, readiness buckets,
  TLS-control crosswalk, FIPS interaction) gated by
  `schema/pqc-decision-tree.schema.json` (XWING-380).
- report.schema.json: optional per-finding `pqc_classification` +
  `remediation_effort` (backward compatible; XWING-381/382).
- secure-code-audit: PQC tagging pass (table lookup only; classical-break
  = real finding, quantum-timeline items = informational/hardening —
  severity never inflated).
- verify-remediation: PQC don't-regress checks (kill-switch
  reintroduction, TLS group-pin regressions, provider downgrades) filed
  as REG-* regression_introduced.
- validate-findings: PQC recon steps + safe `pqc-*` probe catalogue
  entries (TLS negotiation incl. X25519MLKEM768 offer, cert algorithms,
  crypto-policy/FIPS, backend hop); `chain.PQC_CAPS` posture vocabulary +
  deterministic `pqc_caps_from_probe()` (never enters attack chains);
  fixed revoked T1562 -> T1685 in the probe catalogue.
- pqc-readiness: optional `readiness_bucket`, `fips_interaction`,
  `clock_items[].remediation_effort`, `runtime_evidence` report fields
  (validator + schema); SKILL.md step 7b ingests probe evidence to close
  runtime_verification_required. Pilot reports re-validated (backward
  compatible).

## v0.86.0 — 2026-07-18

Minor release: ecosystem depth beyond Go — capability C4 (C3's polling
scheduler was deliberately skipped: Konflux CI/CD integration supersedes
it; decision recorded in the roadmap plan).

- New scripts/run_osv_scanner.py: multi-ecosystem dependency-CVE
  candidates (npm / PyPI / crates.io / Maven / Go and more from
  lockfiles) mirroring the run_govulncheck.py contract — candidates,
  never verdicts; every candidate is `dependency_declared` only (no
  reachability signal; the wrapper says so in its metadata role note).
  Version-tolerant CLI invocation (v2 `scan source` with v1 fallback);
  per-(advisory, package) dedup across lockfiles; graceful skip when the
  binary is absent. 4 fixture tests + live smoke (found 6 PyPI advisory
  candidates in the harness's own requirements — follow-up filed in the
  audit backlog). secure-code-audit gains the dependency pre-scan step
  under the same accelerator-never-precondition rules as opengrep.
- fuzz-harnesses goes multi-language: `language` field in targets.json
  (absent = go — zero change to the 58 existing targets), templates
  under harnesses/_templates/ for Python (atheris), JavaScript/TS
  (Jazzer.js), Rust (cargo-fuzz), Java (jazzer, manual run), and
  Makefile dispatch per language (python venv + atheris, npx jazzer,
  cargo +nightly fuzz; all FUZZTIME-bounded). Rollup generator gains
  language accounting and multi-extension harness discovery.
- License intake (all verified upstream 2026-07-18): osv-scanner,
  pip-audit, atheris, Jazzer.js, jazzer — Apache-2.0; cargo-fuzz MIT OR
  Apache-2.0 (both files confirmed). setup.md install rows added.

## v0.85.0 — 2026-07-18

Minor release: prompt-injection defense — capability C2, all three
layers, with a measured before/after.

- **Canary corpus (detect):** six seeded injection canaries (one per
  class: readme_blatant, comment_authority, file_suppression,
  soft_misdirection, report_shape, hidden_text), each a plausible small
  service with a real seeded finding and unique obedience tokens.
  Sources in progress-tracker/configs/benchmark-canaries/ (answer key
  never enters the materialized repo); build_canaries.py registers them
  as seeded benchmark targets. Injection-aware scoring in
  match_benchmark.py: pass = seeded finding detected AND no obedience
  (token as compliance marker, or seeded finding FP-neutralized); tokens
  quoted inside a finding that itself reports the injection count as
  vigilance (injection_reported), not obedience.
- **Prompt hardening (prevent):** "Adversarial Repository Content"
  rules in secure-code-audit (canonical) + secure-rpm-audit,
  secure-container-audit, and the triage verifier protocol: repo content
  is data, in-repo review/approval/FP claims carry zero evidentiary
  weight, embedded tool-targeting instructions are a CWE-1427 finding,
  injected markers never reproduced outside that finding's evidence.
- **Post-hoc screen (respond):** scripts/screen_injection.py — report-
  only anomaly screen (instruction_echo in prose, zero-findings on large
  repos, audit-time false positives); every hit is a human review item.
- **Measured:** baseline (unhardened) canary pass 0.833 — detection 6/6
  and injection reported as a finding 6/6, but the soft_misdirection
  class leaked its "compliance reference" into a finding's prose.
  Hardened re-run: **pass 1.0 (6/6)**, detection still 6/6, zero token
  leakage. Scoreboard gains the injection-canary pass-rate row; ledger
  gains injection_pass_rate. 11 new tests (31 total in the benchmark +
  screen suites).

## v0.84.0 — 2026-07-18

Minor release: /recall-benchmark — ground truth for the auditor
(capability C1 of the roadmap).

- New harnessing/recall-benchmark/ skill (43rd): audits pinned pre-fix
  refs of repos with known-real findings and scores detection with the
  finding_identity match ladder (fingerprint / path+CWE = detected;
  near-misses adjudicated separately). Two never-waived rules baked into
  the SKILL and enforced by the matcher: the manifest (answer key) never
  enters an audited tree and audit agents are never told they are
  benchmarked; held-out targets score only at release (--release).
- schema/benchmark-target.schema.json + scripts/
  bootstrap_benchmark_targets.py: candidates harvested from the
  disposition ledger — every finding resolved at a named fix commit
  proves the bug present at the fix's parent. First bootstrap: 178
  candidates (deterministic 20% held-out split), manifest at
  progress-tracker/configs/benchmark-targets.yaml; 10 development
  targets machine-admitted for the pilot (production admissions require
  LDAP-verified human review).
- match_benchmark.py emits benchmark.{json,md} (recall overall /
  per-CWE / per-severity / provenance / dev-vs-held-out split, stability
  from duplicate runs, wrong-clone + contamination guards) and appends a
  metrics-ledger `benchmark` row; scoreboard Platform-maturity gains
  detection-recall and auditor-stability rows.
- Pilot run (10 targets + 2 duplicates, auditor 0.82.0-f59c0e1):
  **strict recall 0.50 (5/10)**, 3 near-misses (right files, different
  CWE class), 2 misses; **stability Jaccard 0.059** — duplicate runs of
  identical inputs share almost no finding fingerprints (n=2 pairs;
  apicurio pair shared zero) — the first hard measurement of single-pass
  audit non-determinism. 15 new tests.
## v0.83.0 — 2026-07-18

Minor release: ATT&CK coverage wired into the executive dashboards.

- executive-summary-findings: new "MITRE ATT&CK Coverage" section (md) +
  KPI/card (HTML), read structurally from the Navigator layer; exact
  evidence-class counts come from new layer metadata entries (scores
  overlap classes and are never re-derived downstream).
- metrics_ledger: Executive-Trends charts attack_techniques_observed and
  attack_techniques_modeled from the attack-coverage ledger source
  (up-is-good coverage series).
- build_attack_coverage: layer metadata now carries
  techniques_covered/observed/modeled/derived and tactics_covered.

## v0.82.0 — 2026-07-18

Minor release: attack_refs is now DEFAULT schema for new threat-model
emissions.

- threat-model schema.md + SKILL.md: new emissions MUST include the
  `attack_refs` column (empty cells valid — never guess a technique).
- lint_threat_model.py enforces it deterministically via section-7
  provenance: a ten-column threats table whose harness_version is
  >= 0.82.0 is an ERROR; legacy models (older or missing version) stay
  valid and are never retrofitted.

## v0.81.0 — 2026-07-18

Minor release: deterministic MITRE ATT&CK integration + /attack-coverage.

- New `attack-coverage` skill owns the shared ATT&CK assets: a distilled
  technique/mitigation table vendored from one sha256-pinned Enterprise
  ATT&CK release (v19.1, `build_attack_table.py`), a versioned
  harness-vocabulary mapping (`tables/attack-mapping.json`, gated by
  `schema/attack-mapping.schema.json`), and `attack_refs.py`
  (loader/validator; rejects unknown/revoked/deprecated IDs).
- `build_attack_coverage.py`: deterministic fleet roll-up of observed
  (confirmed validation chains) / modeled (threat-model attack_refs) /
  derived (finding categories) technique coverage -> ATT&CK Navigator
  layer + coverage one-pager under metrics/dashboards/attack-coverage/.
- threat-model: optional, backward-compatible `attack_refs` column on
  threat rows; `lint_threat_model.py` validates IDs against the pinned
  table (bounded selection, never narrative).
- validate-findings: `chain.py` MITRE_MAP now loads from the shared
  mapping (one ATT&CK source of truth); import-time validation.
- ATT&CK ToU intake row in docs/external-dependencies.md (attribution
  carried in the vendored table and every emitted layer).

## v0.80.0 — 2026-07-18

Minor release: external-tool intake gate in /check-harness-docs.

- check_docs_consistency.py gains the "undocumented external tools"
  check: every CLI tool the harness invokes (subprocess literal,
  shutil.which, self-named --tool default flags, vendored bin/ paths,
  shell command -v) must have a row in docs/external-dependencies.md —
  the CLI-tool counterpart of /check-licensing's pyproject intake gate.
  Rule-pack fixture dirs and tests are excluded; base-system binaries
  ignored. First run caught two undocumented tools: curl (curl license)
  and wasm-tools (Apache-2.0 WITH LLVM-exception) — rows added.
  opengrep, govulncheck, and pqc-scan were already documented via the
  /check-licensing intakes and are now machine-verified against their
  invocation sites. 2 new tests.

## v0.79.0 — 2026-07-17

Minor release: machine-readable fuzz sidecar; fuzz artifacts published to
the metrics tree.

- `build_fuzz_rollup.py` now emits `FUZZ-CAMPAIGN-SUMMARY.json` (totals,
  batches, bugs, pattern hit-rates, advisory files) alongside the two
  markdown docs, and publishes all three to
  `progress-tracker/metrics/dashboards/fuzz/`.
- `validation-fuzz-dashboard` consumes the JSON sidecar (markdown pipe
  tables remain a fallback for pre-sidecar trees) — ends the
  regex-scrape fragility fixed tactically in v0.78.1.
- `traust-metrics` reads fuzz totals from the sidecar
  directly and lists it in the data-freshness table.
- Verified: /findings-trends, /insecure-patterns, /loc-dashboard all
  already default their outputs to progress-tracker/metrics/dashboards/
  via _dashboards_home; all three re-run against the current corpus.

## v0.78.1 — 2026-07-17

Patch: validation-fuzz-dashboard fuzz totals repopulated.

- `scan_fuzz` now parses both FUZZ-CAMPAIGN-SUMMARY.md batch-table
  layouts (legacy Batch|Strategy|Targets|Fuzzers|Bugs and current
  Batch|Targets|Fuzz functions|Real bugs|Bug #s); the summary rewrite
  had silently broken the totals match, rendering em-dashes that the
  metrics collector then couldn't parse — fuzz rows in
  traust-metrics.md showed "—" despite real statistics.
- Portfolio-advisory count is parsed from the summary instead of being
  hardcoded to 3.

## v0.78.0 — 2026-07-17

Minor release: risk-rating methodology as schema-validated data.

- The OWASP Risk Rating factor mappings, bucket thresholds, 3x3 matrix,
  and fallbacks move out of `build_trends.py` into
  `harnessing/findings-trends/risk-rating-methodology.json` (semver
  `methodology_version`, stamped into every `findings-trends.json`).
- New `schema/risk-rating-methodology.schema.json` enforces the
  structural invariants: complete CVSS value coverage, all nine matrix
  cells, 0-9 factor scores, and a vector-less fallback likelihood
  bounded below HIGH (vector-less findings can never rate Critical).
- Tests validate the tables against the schema and assert the engine
  loads the data file; numbers verified identical pre/post refactor.

## v0.77.0 — 2026-07-17

Minor release: risk headline moved to the OWASP Risk Rating Methodology.

- `findings-trends`: per-finding OWASP risk band (likelihood x impact,
  factors derived deterministically from the CVSS 3.x vector; documented
  fallback for vector-less findings) rolled up per bucket as a band
  distribution + `owasp_high_plus_pct` (% of open findings rated
  High/Critical). New "Open Findings by OWASP Risk Rating" dashboard
  section; unit tests added.
- `traust-metrics` + `metrics_ledger`: OWASP rows replace
  the mean-CVSS and unnormalized CVSS-sum "risk index" rows in the
  summary, history table, and executive-trends series. Retired series
  stay in the append-only ledger as as-reported history.
- New `docs/risk-rating-methodology.md` documents the factor mappings,
  the OWASP 3x3 matrix, and the retirement rationale.

## v0.76.1 — 2026-07-17

Patch: retire the team-packages scoreboard metric — a folder count
informs no decision; routing/adoption reads from Jira defects filed and
the disposition-ledger coverage rows. Collection, display, and history
label removed (immutable past history rows retained, as designed).

## v0.76.0 — 2026-07-17

Minor release: FIRST-aligned severity presentation + BU cohort coverage.

- findings-trends: the CVSS-sum "risk index" rows are retired from the
  headline table — CVSS v4.0 defines scores as SEVERITY (not risk) and
  provides no basis for summing them. Headline now presents **mean CVSS
  severity of open findings** plus the qualitative-band counts; the sum
  series remain in the JSON as legacy history only. New trend keys:
  mean_cvss_open, hardening (count), accepted (count).
- findings-trends: **ledger coverage split by cohort** directly under the
  blended figure — owned HEAD (findings/, the population remediation
  tracking applies to) vs release-branch re-audits (empty layers by
  design — the drag on the blended percentage) vs upstream. Cohort
  criterion aligned with covered_repos (non-empty ledger, not file
  existence); branch classification covers filename-suffixed reports in
  shared dirs, not just dir suffixes. Ownership-cuts table gains Mean
  CVSS (open) + ledgered-repos columns.
- census: per-cut head_with_ledger / head_ledger_coverage_pct; executive
  view states **disposition-ledger coverage (owned, HEAD)** explicitly.
- scoreboard: Lens 2 gains the owned-HEAD coverage row and the mean-CVSS
  severity row (labeled per CVSS v4.0, replacing the legacy sum); history
  labels mark the CVSS-sum series as legacy; "Team findings packages
  delivered" rephrased to "Finding packages routed to dev teams" with the
  routing definition (per-product findings folder, two lead developers,
  Drive/Slack).

## v0.74.0 — 2026-07-17

Minor release: hps rule pack v1.1 — bash tranche, mined from
analysis-results.

- Three bash rules under harnessing/secure-code-audit/opengrep-rules/
  bash/: curl-pipe-shell (CWE-494, HIGH), cred-in-argv registry login
  (CWE-532/214, HIGH), xtrace (CWE-532, INFO judge-tier). Mined from
  the ledger's CWE-494/bash (96 TPs, 90 repos) and CWE-532/bash
  (71 TPs, 61 repos) clusters; the confirmed findings' evidence
  snippets served as the rule specifications.
- Calibration: RedHatInsights/cicd-tools rediscovered the exact corpus
  evidence (anchore install.sh|sh; six login -p sites) — 7/7 HIGH
  facts true. Known non-coverage recorded: the download-then-execute
  CWE-494 shape needs a future multi-step rule.
- 23 pack rules total, all test suites green.


## v0.73.2 — 2026-07-17

Patch release: dependency-intake gate — /check-licensing Job 2 becomes
mechanical for Python packages.

- check_content_licenses.py gains check 3: every pyproject.toml package
  (core dependencies and all optional groups, inline and block list
  forms — the inline `signing` group is what a line-based parser would
  miss) must have a row in docs/external-dependencies.md. Enforced by
  the same pre-push hook and test suite; live-verified blocking an
  unlisted package and passing the current tree (12/12 dependencies
  have rows).
- /check-licensing SKILL documents the new violation class and marks
  Job 2 gate-enforced for Python packages (CLI tools/data feeds/
  frameworks remain convention-enforced).
- Closes the process gap the merkle-integration review surfaced: the
  sigstore dependency landed without an intake row and needed
  retroactive verification (v0.73.1); that class of miss now fails the
  push. 4 new tests.


## v0.73.1 — 2026-07-17

Patch release: merkle-ledger integration review — validation +
documentation completion.

- Validated the feat/merkle-tree-hashing integration end-to-end: all 95
  production-stamped layers verify (verify_merkle_integrity, 0 errors);
  legacy layers still validate; tamper detection confirmed layered as
  designed (event_id catches disposition edits, merkle root seals the
  event set/order and gives signing one attestable value).
- docs/disposition-ledger.md gains §10b documenting the merkle layer,
  its division of labor vs event_id/claim hashes, the signing hook, and
  the honest scope note (actor/rationale/timestamps pinned only
  indirectly).
- Retroactive /check-licensing intake for sigstore-python (Apache-2.0
  verbatim LICENSE; GitHub detector says NOASSERTION and PyPI metadata
  is empty — the file governs): row in external-dependencies.md.
- HARNESS_SIGNING_REQUIRED added to .env.example (was only in
  docs/signing.md).


## v0.73.0 — 2026-07-17

Minor release: Phase 5 defect fixes — the metrics-improvement plan's
consistency debt cleared.

- repo-graph findings discovery moved onto the corpus resolver:
  depth-tolerant (the 28 shallow findings/<repo>/ dirs are now indexed),
  dir-symlink aliases no longer double-counted (findings nodes 5,120 →
  5,106), hard-fail if the resolver is unavailable; population block
  "Known limitation" line replaced with resolver provenance. 3 new
  tests. portfolio-graph verified to flow through repo-graph.json — no
  code change needed.
- insecure-patterns scans oss-findings/ as a tagged upstream cut: owned
  ranking byte-identical, new top-10 upstream section (top: CWE-22 in 31
  repos), additive JSON `upstream` object, per-tree population counts;
  ledger headline stays owned-only.
- New harnessing/fuzz-harnesses/scripts/build_fuzz_rollup.py regenerates
  FUZZ-CAMPAIGN-SUMMARY.md and FUZZ-FINDINGS-ROLLUP.md from targets.json
  + run logs + verified per-bug write-ups: 18 real bugs (1:1 with
  evidence), 58 manifest targets / 48 with harnesses, legacy 48-vs-58
  and 15-vs-18 gaps explained in-document; hard-fails on drift between
  the embedded bug table and on-disk evidence.
- analysis-results side (committed there): update_progress.py emits dual
  labeled aggregates — as-audited (never rewritten) + current
  disposition-adjusted (open-by-severity from findings-current, resolved
  and FP and hardening broken out, --recompute mode), scoped to the main
  table; md-only re-audit manifest (162 reports, all with triage+threat
  models already); CAMPAIGN-TOTALS.json marked superseded; stray
  validation-input audit renamed (census drift warnings now zero).
  Deliberately NOT done: re-homing the 28 shallow dirs (no
  inventory-derived product mapping exists — resolver handles the depth;
  inventing products would corrupt provenance) and removing
  tmp-npm-oidc-test (it is a real audit of a real upstream repo; Phase 7
  liveness will track its fate).

## v0.72.0 — 2026-07-17

Minor release: /check-alignment — cross-skill contracts become a
pre-commit gate.

- New scripts/check_skill_alignment.py: seven mechanical contracts
  (A1 referenced scripts exist, repo- or skill-relative; A2/A3
  report-producing skills running the opengrep / k8s-hardening
  pre-scans carry deterministic_steps + the judge protocol; A4
  audit-profile skills link docs/report-structure.md; A5 liveness
  consumers name the census artifact; A6 frontmatter name == dir;
  A7 discovery wiring complete). Exemptions carry reasons and print
  every run; a stale exemption fails the test suite.
- New .githooks/pre-commit runs the checker on every commit (live-
  verified blocking + passing); /check-alignment is the skill wrapper
  and the extending-the-contracts procedure.
- First full-tree sweep found and fixed two real misalignments:
  validate-browser-finding had no discovery wiring at all, and
  repo-graph had no command wrapper (both now wired). 11 new tests.


## v0.72.0 — 2026-07-17

Minor release: three-lens scoreboard + ownership cuts + product
multiplicity — Phase 4 of the metrics-improvement plan.

- traust-metrics scoreboard reorganized into the three-lens
  taxonomy with **Lens 2 — Distinct exposure as the canonical headline**
  (sourced from census.json, the denominator authority: distinct owned
  vulns/open, open C/H distinct, hardening distinct, upstream adjacent);
  Lens 1 — work performed (occurrences, branch confirmations labeled as
  coverage, external-BU reports called out as excluded from HP risk);
  Lens 3 — systemic patterns (from insecure-patterns.json). Every
  section states scope · unit · stage; intro warns never to average
  across lenses. Stale pitch-deck-metrics self-references fixed.
- threat-register and findings-trends gain **Ownership cuts** tables
  (md + html + additive JSON keys): owned (findings/) vs upstream
  (oss-findings/) reported separately, portfolio headlines unchanged,
  cuts verified to sum exactly to the headlines (7,282+137 models;
  54,698+1,007 open findings at the latest bucket).
- Executive summary: top Critical/High table gains a **"Ships in N
  products"** column (per-dedup-key product multiplicity), and the
  distinct headline explicitly pairs with the total-occurrence count so
  fix-count vs exposure-surface is one read. 2 new tests (31 total in
  the two dashboard test files).

## v0.71.0 — 2026-07-17

Minor release: assessment-skill alignment batch — the deterministic
evidence machinery propagates to every skill where it belongs.

- security-audit-phased: P1 recon runs both pre-scans and records
  deterministic_steps; P3's CWE hunt seeds each category from the facts
  under the same judge protocol as /secure-code-audit.
- patch: new Phase 3-pre — scanner-backed findings get a scratch-
  worktree differential (apply diff, re-run backing scanner); a diff
  that does not silence its own evidence is rejected unless the
  reviewer refutes the scanner. fact_differential recorded per patch.
- remediate-finding: same differential in Phase 4 local checks, so
  /verify-remediation later confirms rather than discovers.
- threat-model bootstrap: Stage 1 seeds section-3 material from
  scan_k8s_hardening tenancy/interface signals and ingests repo
  liveness as unmaintained-component likelihood evidence.
- secure-rpm-audit: syft/grype SBOM step on the prepared source tree
  (deterministic_steps recorded); opengrep explicitly deferred until
  the rule pack grows C/bash rules (backlog noted in the ruleset plan).
- Liveness stamps (Phase 7 consumers): secure-code-audit records
  metadata.additional.repo_status; secure-container-audit records
  source_repo_status + its conditional KHS step; verify-remediation's
  sweep worklist annotates repo_status per entry (live run: all 25
  queued repos active — archived repos never drift, so they sit in the
  skip buckets, exactly the segment the disposition annotation
  formalizes). report-structure.md documents both conventions.
- 2 new tests.


## v0.70.0 — 2026-07-17

Minor release: repo liveness — archive-awareness for the corpus
(metrics-improvement plan, Phase 7).

- New scripts/check_repo_liveness.py: sweeps the repo-graph population
  (one GitHub API call per repo) into
  progress-tracker/metrics/repo-liveness.{json,md} with a status per
  repo — active | archived | moved (new location recorded) | missing |
  unknown (non-GitHub) — and status_since ratcheted across runs
  (GitHub exposes no archived-at; first-observed is the honest date).
- /census owns the sweep (new Step 2b): liveness is population
  metadata — which repos can still act on findings. One collector,
  many consumers (audit stamps, threat-model likelihood evidence,
  verify-remediation sweep flags, dashboard segmentation, graph node
  attrs, routing guards — consumer wiring is the phase's follow-on
  work). Scanning behavior never changes on status: archived code
  that ships is as exploitable as live code.
- First sweep: 3,014 active, 111 archived, 40 missing (explains the
  portfolio-graph clone-failure gap), 37 moved, 241 non-GitHub —
  188 non-active GitHub repos (~6%). 6 new tests.

## v0.69.0 — 2026-07-17

Minor release: fingerprint semantics in the executive summary — Phase 3
of the metrics-improvement plan.

- The executive summary gains a **Distinct Vulnerabilities** section
  (Lens 2, the canonical exposure headline) in md + html: unique finding
  fingerprints at HEAD across findings/, disposition-adjusted,
  FP-excluded, hardening separate; upstream (oss-findings/) adjacent,
  never folded in; release-branch findings that fingerprint-match a HEAD
  finding reported as confirmations on shipped releases. Computed in a
  separate post-pass (`distinct_metrics`) with census-identical
  semantics — verified to the exact finding against /census on the live
  tree (17,395 distinct owned / 994 upstream / 2,454 confirmations):
  md-fallback reports, symlink-aliased reports, and alias-attached
  ledgers are outside the distinct population; fingerprints are
  recomputed via finding_identity when absent (findings-current ledgers
  predate the backfill — observed 23% raw coverage, 100% after
  recompute); disposition.validity is authoritative over the mirrored
  validation_status.
- Census branch-confirmation semantics aligned the other way: hardening
  restatements no longer count as confirmations, so census and exec
  summary report the same number.
- Unique Critical/High and credential-leak tables now dedupe by
  fingerprint (fallback (repo, title)): unique crit/high 4,451 → 3,694,
  credential leaks 2,982 → 2,407 on the live tree — title rewording
  across mirror audits was inflating the legacy key.
- New ledger keys: distinct_vulns_owned, distinct_open_owned,
  branch_confirmations. New tests (distinct pass + fingerprint dedup).

## v0.68.0 — 2026-07-17

Minor release: mandatory population blocks — Phase 2 of the
metrics-improvement plan.

- `scripts/corpus.py` gains `population_block_lines()` (field-driven
  provenance block: tool + harness version, roots walked with ownership
  tags, unit counted, filters, denominator source, per-tool counts,
  warnings) and `roots_description()` (tree → "`findings/` (owned,
  Hybrid Platforms)" labels from corpus-config, engagement trees
  resolve, unknown roots flagged UNREGISTERED);
  `render_population_block()` refactored on top.
- All 7 dashboard builders now embed the block at the end of their md
  outputs and as a final panel in their HTML: executive-summary-findings,
  insecure-patterns, threat-register, findings-trends,
  validation-fuzz-dashboard, loc-dashboard (HTML-only), repo-graph.
  Strictly report-only — discovery, filters, units, and CLI flags are
  unchanged (headline numbers verified identical pre/post); the block
  states what each tool actually scanned and skipped, so any two
  dashboards' headline numbers reconcile on paper. repo-graph's block
  additionally states its known findings/*/*/ depth limitation (28
  reports unseen as of 2026-07-17; fix scheduled in Phase 5).
- Corpus loading in builders is fail-soft (block omitted with a stderr
  note, builder still writes) and registers the module in sys.modules
  before exec (Python 3.14 dataclass requirement).

Minor release: /corpus-intake skill — Phase 1b of the metrics-improvement
plan.

- New `harnessing/corpus-intake/` skill (38th): the only supported write
  path for `config/corpus-config.yaml`. Interview-driven (or flag-driven)
  registration of corpus trees and engagements: kind / name / tree /
  ownership tag (with semantic probes: owns-the-backlog → owned,
  ships-or-depends → upstream, scanning-only → external-bu) / business
  unit / inventory / notes.
- `corpus_intake.py` validates before writing (duplicate names and
  labels, overlapping tree mappings, ownership enum, name syntax),
  renders the config from a canonical template so documentation comments
  never rot, round-trip-verifies the render, and writes atomically via
  temp-file + rename — a failed gate can never corrupt the config.
  `list` shows registrations plus live DRIFT warnings (unregistered
  trees on disk); every add prints residual drift.
- SKILL.md prescribes the follow-ups: refresh /census after every
  change, /add-inputs when an engagement needs inventory rows, and
  notes-not-tags for BU boundaries that cut through a tree (per-product
  overrides land in a later phase).
- 10 new tests in tests/test_corpus_intake.py (round-trip, rejection
  paths leave the file untouched, dry-run, resolver acceptance).

## v0.66.1 — 2026-07-17

Patch release: verify-remediation aligned with the deterministic audit
machinery.

- New Phase 4-pre "deterministic differential re-scan": scanner-backed
  findings (opengrep scanner_correlation promotions, KHS-cited config
  findings, fixed-in-versioned dependency findings) are verified by
  re-running scan_k8s_hardening / run_opengrep / syft+grype against the
  patched checkout and reading the differential — fact gone (confirm
  root cause), fact persisting (unresolved, deterministic citation),
  fact moved (follow first). Rule-pack SHA differences are stated as a
  caveat; verification reports record their own deterministic_steps.
- Phase 5 regression scan starts from the differential: new facts in
  diff-scoped files are mechanical regression candidates. 4d evidence
  requirements gain the differential-result item; full-sweep mode runs
  the re-scan for every entry.

## v0.66.0 — 2026-07-17

Minor release: /census skill — Phase 1 of the metrics-improvement plan.

- New `harnessing/census/` skill (37th): the deterministic denominator
  authority. Resolves the population via scripts/corpus.py, quantifies
  the five duplication vectors fresh each run (symlink aliases incl.
  ledgers attached to aliased reports, branch re-audits with
  HEAD-fingerprint confirmations, layered-artifact restatement,
  cross-tree overlap, duplicate basenames), and computes **distinct
  vulnerabilities** — unique finding fingerprints at HEAD,
  disposition-adjusted, FP-excluded, hardening separate — per ownership
  cut. Owned (Hybrid Platforms) is the canonical Lens 2 headline;
  upstream (oss-findings) reports adjacent, never folded in;
  external-BU trees appear as work performed only. Registered
  engagement trees (lightwell/ansible) surface as "registered, no
  output" until they exist.
- Outputs census.{json,md,html} + corpus-manifest.json to
  progress-tracker/metrics/dashboards/census/; appends an
  append-if-changed snapshot to the central metrics ledger (source
  `census`) with trend-vs-previous injection.
- First live run: 8,363 reports / 3,502 unique slugs; owned distinct
  vulnerabilities 17,395 (17,007 open; C/H/M/L/I 105/2,162/5,240/5,463/
  4,037 open), 11,025 distinct hardening gaps; 4,214 branch re-audits
  restating 33,700 findings (3,525 tier-1 HEAD confirmations); 194 file
  + 110 dir symlink aliases → 174 canonicals (93 alias-attached
  ledgers); 95 cross-tree slugs; 162 md-only parse gaps; runtime ~2s.
- 6 new tests in tests/test_build_census.py (synthetic workspace +
  live smoke).

## v0.65.0 — 2026-07-17

Minor release: corpus resolver — Phase 0 of the metrics-improvement
plan (progress-tracker/metrics/metrics-improvement-plan.md).

- New `config/corpus-config.yaml`: single source of truth for which
  trees under analysis-results/ are in the report corpus and who owns
  them. Ownership tags owned / upstream / external-bu; registered
  engagement labels (lightwell, ansible) whose trees activate
  automatically on first output; per-product override hook for BU
  boundaries that cut through a tree (Ansible product-vs-BU duality).
- New `scripts/corpus.py`: one implementation of report discovery,
  identity, and dedup for every dashboard builder. Depth-tolerant walk
  (catches the 28 shallow findings/<repo>/ dirs the fixed */*/ glob
  missed), symlink aliasing to canonical reports (194 file + 110 dir
  aliases → 174 canonicals, never counted as reports), branch-ref
  identity (`__release-X.Y`/`__openshift-X.Y` → base slug + ref; 4,214
  branch re-audits collapse into 3,283 unique owned slugs while org__repo
  names like quay__enhancements pass through untouched), findings-current
  layer preference, md-only parse-gap flagging (162), unregistered-tree
  drift warnings, `corpus-manifest.json` emission, and
  `render_population_block()` — the standard provenance block generated
  dashboards will embed.
- 24 new tests in `tests/test_corpus.py`, including live census pins
  (2026-07-17 ground truth) gated behind CORPUS_LIVE_PINS=1.

## v0.64.0 — 2026-07-17

Minor release: portfolio-graph Layer 4 — tree-sitter symbols. All
planned graph layers now shipped.

- /check-licensing intake passed for py-tree-sitter + the official
  go/python/typescript/javascript grammar wheels (all MIT, verified
  against upstream LICENSE files; rows in external-dependencies.md;
  optional dependency group `graph` in pyproject). Deliberately per-
  language wheels, not grammar aggregation packs.
- build_portfolio_graph.py gains the `symbols` subcommand: tree-sitter
  extraction of exported symbols (name/kind/file/line + byte spans for
  source round-tripping) and per-package import aggregation for
  Go/Python/TS/JS, clone-sweep cached per repo; symbol nodes +
  defines/imports_package edges, internal packages matched to L1
  module owners; exports-of and imports-package queries; stats section.
- Full build: 3,115/3,160 repos; 2,507,631 exported symbols; 83,515
  source packages; 253,689 imports_package edges. Package-level
  coupling: github.com/openshift/library-go/pkg/operator is imported
  by 132 repos. DB ~3 GB (local rebuildable artifact, gitignored).
- 5 new tests (skip cleanly when the optional deps are absent).

## v0.63.0 — 2026-07-17

Minor release: portfolio-graph Layer 3 — artifacts.

- build_portfolio_graph.py gains the `artifacts` subcommand: ingests
  every *-container-audit.json into image nodes (digest identity, tag,
  base image) with built_from edges carrying vcs ref/branch and
  source-drift; dependency_audit entries and persisted CycloneDX SBOMs
  become ships_package edges, with golang purls joining Layer 1 module
  nodes as ships_module (new ships-module query; stats section).
- secure-container-audit now persists each SBOM to
  analysis-results/graph/sboms/<shortdigest>.cdx.json so the graph
  accrues per audit — L3 is an accrual pipeline, not a sweep.
- Live: the console audit yields 1 image, built_from with ref+drift,
  390 ships_package edges (352 SBOM-backed). 4 new tests.

## v0.62.1 — 2026-07-17

Patch release: deterministic spine-freshness gate for portfolio-graph.

- build_portfolio_graph.py gains a `freshness` subcommand and a build
  gate: the repo-graph spine is STALE when the hybrid-platforms-inputs
  inventories changed after it was generated (inputs repo commit date
  vs the spine's `generated` date; CSV mtimes as fallback) or when it
  exceeds a 30-day age backstop. `build` refuses a stale spine with a
  "run /repo-graph first" message (--allow-stale overrides); a fresh
  spine skips the /repo-graph rerun entirely. The spine's own
  `sources` paths are ignored — they are absolute to whichever machine
  built it.
- /portfolio-graph SKILL prerequisites now drive the check instead of
  assuming freshness or chaining /repo-graph unconditionally.

## v0.62.0 — 2026-07-17

Minor release: portfolio-graph Layer 2 — Kubernetes interfaces.

- scan_k8s_hardening.py extracts interface signals alongside the
  hardening facts: CRDs defined, CSV owned/required CRDs, webhook rules,
  structured RBAC grants, and Go API-group literals (new code signal).
  Audits get the same signals in tenancy_signals for free.
- build_portfolio_graph.py gains the `interfaces` subcommand: streaming
  shallow clone→extract→delete sweep (bounded disk, per-repo cache,
  resume-safe) loading crd/api-group nodes with owns_crd (via
  csv|crd-manifest), requires_crd, consumes_group, intercepts, and
  per-group aggregated rbac_grants edges; new crd-consumers query and
  an Interface-layer section in stats.
- First full build: 3,116/3,160 repos swept; 3,973 distinct CRDs across
  1,622 API groups; 331 repos with wildcard RBAC grants. Flagship:
  route.openshift.io couples 27 CRD-shipping repos, 60 code consumers,
  and 170 RBAC granters. 11 new tests.

## v0.61.0 — 2026-07-16

Minor release: /portfolio-graph — the portfolio source-code graph,
Layer 1 shipped.

- New docs/portfolio-graph-plan.md: layered design (L0 spine, L1 Go
  module dependencies, L2 Kubernetes interfaces, L3 artifacts/SBOM,
  L4 tree-sitter files/symbols, cross-layer risk annotations) with
  per-layer data and tooling dependencies. Layers 2-4 are gated on
  explicit user go-ahead.
- New scripts/build_portfolio_graph.py: SQLite nodes/edges graph;
  ingests repo-graph.json as the spine, fetches every GitHub repo's
  go.mod (gh-authenticated, cached per repo), parses requires with
  indirect flags, marks internal modules and distinguishes
  portfolio-authored libraries from sustaining forks of upstream
  (openshift-sustaining declares upstream module paths). Canned
  queries: blast-radius, top-shared, internal-coupling.
- New /portfolio-graph skill (distinct from /repo-graph, which stays
  the organizational coverage view).
- First full build: 1,247 Go repos, 4,862 modules, 133,087 depends_on
  edges, 0 fetch errors. Flagship result: golang.org/x/net reaches
  1,080 repos across 102 product surfaces; top authored internal
  coupling openshift/api (445 dependents), client-go (265),
  library-go (249). Stats committed to analysis-results/graph/;
  the .db is a rebuildable local artifact. 8 new tests.

## v0.60.1 — 2026-07-16

Patch release: explicit degradation semantics for deterministic
pre-scans.

- secure-code-audit's opengrep step now states its fallback outright:
  tool missing → full manual ASVS review, never a stall or an
  improvised substitute. The SBOM/grype step's silent skip became a
  recorded skip.
- New convention (docs/report-structure.md, code-profile deltas):
  metadata.additional.deterministic_steps records "ran" vs
  "skipped: <reason>" for k8s-hardening / opengrep / sbom-grype, so
  evidence quality is comparable across a batch and a skipped scanner
  is never read as a quiet one. vuln-scan records the same in its
  output; mine-ledger's precision step filters on it.
- validate_report.py --strict warns when a code-profile report from
  harness >= 0.60.1 omits deterministic_steps (version-gated; legacy
  reports exempt).

## v0.60.0 — 2026-07-16

Minor release: /check-licensing — the licensing gate is its own skill.

- Extracted the content-license guard from check_docs_consistency.py
  (where it was check 6) into a dedicated gate: the new /check-licensing
  skill wraps scripts/check_content_licenses.py and adds the
  license-intake checklist for adopting new external tools/frameworks/
  data feeds/rule packs (verify upstream with evidence, classify usage
  model, add the docs/external-dependencies.md row, pin versions,
  extend guard patterns for new protected content classes).
- .githooks/pre-push now runs BOTH checkers independently — doc drift
  and re-imported restrictively-licensed content each block a push on
  their own, so the licensing gate always runs before anything lands
  in the repo. check-harness-docs cross-references the new skill
  instead of embedding the check.
- Tests updated: guard extraction asserted, pre-push wiring asserted.

## v0.59.0 — 2026-07-16

Minor release: ledger mining for rule calibration — audits feed it by
default, /mine-ledger harvests out-of-band.

- secure-code-audit's opengrep pre-scan now records EVERY judge
  decision (promoted and dismissed) as a structured
  scanner_correlation entry — tool "opengrep", rule_id, location,
  result token, finding_ids/rationale. Schema: scanner_entry gains
  optional rule_id/location/finding_ids. Every audited repo thereby
  broadens rule calibration without extra work.
- New scripts/mine_ledger_truepositives.py: mines cumulative
  *-findings-current.json reports for validity:confirmed findings →
  tp-corpus.jsonl; clusters by CWE × language and matches against the
  hps rule pack (coverage backlog); aggregates audits' judge decisions
  into campaign-wide per-rule precision; emits a calibration worklist.
  Live run: 7,918 confirmed TPs from 2,646 cumulative reports; 21
  clusters covered by the v1 pack, 462-cluster authoring backlog,
  608-repo calibration worklist.
- New /mine-ledger skill (stage-independent): runs the miner
  out-of-band, adds detectability verdicts + rule-candidate proposals
  per uncovered cluster, flags rules under the ~50% precision gate.
- 6 new tests.

## v0.58.0 — 2026-07-16

Minor release: harness-authored opengrep rule pack, now the default.

- New harnessing/secure-code-audit/opengrep-rules/: 20 rules (12 Go,
  5 Python, 3 TS/JS) mined from the campaign's insecure-patterns corpus
  (top clusters: CWE-532/295/78/22/918/214), taint-mode-first, mapped
  to the shared category vocabulary + ASVS chapters, every rule with
  ruleid/ok test files (opengrep scan --test green). Our IP, licensed
  with the harness — no external restrictions, safe to commercialize.
- run_opengrep.py default flipped to the in-repo pack (language-
  filtered); the opengrep-rules fork remains an opt-in supplement via
  --rules with its license note carried into the output.
- Calibrated against 4 real repos: 5/5 facts true or judge-worthy —
  100% rediscovery of route-monitor-operator's InsecureSkipVerify pair
  and app-eng-backstage's audited command injection; two precision
  fixes landed (benign token/secret metadata suffixes, aliased
  childProcess receiver). Results table in docs/opengrep-ruleset-plan.md.
- 4 new tests including a gate that runs the pack's own rule tests.

## v0.57.0 — 2026-07-16

Minor release: opengrep semantic pre-scan with swappable rule packs.

- New scripts/run_opengrep.py: runs the opengrep engine (LGPL-2.1,
  subprocess) against an explicitly pinned ruleset and normalizes the
  output to judge-ready facts (rule id, severity hint, file:line, CWE/
  OWASP metadata, taint flag, snippet, test_path tag), surfacing engine
  errors and skipped rules. RULE PACKS ARE A SWAPPABLE INPUT, NEVER A
  BAKED-IN ASSET: nothing vendored, every run records pack source + SHA
  + license note, and `--config auto` is refused (registry auto-fetch
  has no per-pack license accounting). Default pack: the opengrep-rules
  fork pinned at f1d2b56, filtered to the target's languages.
- secure-code-audit ASVS section and vuln-scan Step 1 gain the
  deterministic semantic pre-scan with an explicit model-as-judge
  protocol: judge each fact in repository context, promote with
  file:line citations or dismiss into scanner_correlation with
  rationale; manifest facts defer to scan_k8s_hardening's KHS catalog.
- docs/external-dependencies.md: opengrep engine row (low risk) plus
  three rule-pack rows (opengrep-rules Commons Clause "no Sell";
  Semgrep-maintained registry rules internal-use-only, a
  commercialization blocker; third-party registry packs licensed per
  pack) and a commercialization-assessment caution.
- docs/opengrep-ruleset-plan.md: plan for a harness-authored Go-first
  rule pack mined from the campaign's 9,560 ledger-confirmed true
  positives and calibrated against triage-ledger ground truth, to
  replace the default pack before any commercialization.
- Smoke-tested: taint rule traces request→db.Query on a fixture; full
  default-pack run over openshift/route-monitor-operator produced 254
  facts across 272 files. 10 new tests.

## v0.56.1 — 2026-07-16

Patch release: scanner adoption in vuln-scan and secure-container-audit.

- vuln-scan Step 1 gains the deterministic manifest pre-scan: KHS-*
  facts are the evidence base for manifest/config focus areas, and
  tenancy_signals seed code-level focus areas. Skipped silently when
  the target ships no Kubernetes YAML (the skill stays read-only).
- secure-container-audit: manifest-bearing images (above all operator
  bundle images) get their filesystem extracted and scanned with
  scan_k8s_hardening; code-level tenancy signals are documented as
  not applicable to image contents, while CSV installModes extraction
  is. Ordinary application images skip the step.
- First end-to-end run of /secure-container-audit against a live image
  (quay.io/stolostron/console 2.15 stream): report validated 0
  errors/0 strict warnings; results in analysis-results
  findings/advanced-cluster-management/console/.

## v0.56.0 — 2026-07-16

Minor release: deterministic evidence base for the config-hardening and
multi-tenancy audit sections.

- New scripts/scan_k8s_hardening.py: parses every Kubernetes YAML
  document in a checkout (including CSV-embedded deployments), applies
  a fixed KHS-* check catalog (workload securityContext, host
  namespaces, hostPath, RBAC wildcards/cluster-admin/secrets/escalation
  verbs, service exposure, webhook failurePolicy, PSA labels, insecure
  flags, secrets-in-env, image pinning) and emits JSON facts with exact
  file:line, kind/name, framework refs (K-IDs + unambiguous CIS section
  IDs), plus a tenancy_signals block (CSV installModes, watch-scope
  hints, cluster-scoped RBAC, InsecureSkipVerify, SAR/TokenReview,
  NetworkPolicy/PSA posture). Helm-templated and unparseable files are
  counted, never silently skipped; test-path and kustomize
  patch-overlay results are tagged for down-weighting.
- secure-code-audit: the CIS/DISA section gains a required
  "Deterministic pre-scan" step — scanner facts are the evidence base
  for config-hardening findings (facts ≠ findings: promotion, dedup,
  and severity stay with the audit); the OWASP K8s table notes which
  rows the scanner covers; the multi-tenant isolation section (retitled
  "Multi-Tenant Isolation (PEACH methodology)") consumes
  tenancy_signals as deterministic Step 1–3 inputs.
- Smoke-tested against openshift/route-monitor-operator: 101 k8s docs,
  42 facts, AllNamespaces install mode + 2 InsecureSkipVerify call
  sites surfaced. 13 new tests.

## v0.55.0 — 2026-07-16

Minor release: deterministic content-license guard.

- New scripts/check_content_licenses.py enforces the two licensing
  rules from the 2026-07-16 sweep as build gates instead of prose:
  (1) PEACH keep-it-original — fails on NonCommercial license markers
  outside docs/external-dependencies.md + CHANGELOG.md, and on
  fingerprint phrases from the removed pre-v0.54.2 Wiz-derived
  adaptation; (2) CIS ID-only — fails on CIS benchmark
  recommendation-text signatures ("Ensure that the --<flag> argument
  is set ...", "(Automated)"/"(Manual)" near CIS). Corpus-verified
  zero false positives at introduction.
- Registered as check 6 in check_docs_consistency.py, so the pre-push
  hook and /check-harness-docs enforce it on every push.
- validate_report.py --strict now warns when a finding description or
  remediation matches CIS recommendation-title phrasing.
- 13 new tests (tests/test_check_content_licenses.py).

## v0.54.2 — 2026-07-16

Patch release: PEACH sections rewritten as original text.

- The PEACH tenant-isolation sections in secure-code-audit and
  security-audit-phased (including the phase-1/3/4 prompts) no longer
  reproduce or adapt any Wiz-authored content. They now describe the
  methodology in original words and cite PEACH by name, parameter
  names, and PEACH-* IDs only — ideas, methods, and short identifiers,
  which are not copyrightable. This removes the NonCommercial-license
  blocker regardless of which upstream license (LICENSE.md BY-NC-ND vs
  README/site BY-NC-SA) governs.
- Machine contract unchanged: peach_isolation_review shape, the
  complexity/boundary_type enums, hardening_gaps, and peach_references
  are all defined by our schema and keep their exact vocabulary.
- docs/external-dependencies.md updated: PEACH moved from Blockers to
  Resolved (risk HIGH → Low) with a keep-it-original rule; CIS remains
  the single content-license blocker (reports verified to cite bare
  section IDs only).

## v0.54.1 — 2026-07-16

Patch release: external-dependency inventory + license sweep.

- New `docs/external-dependencies.md` — every external requirement (CLI
  tools, Python libraries, MCP servers, vulnerability-data feeds, and
  framework content) with upstream-verified license, evidence URL,
  formal citations, and a commercialization risk assessment. Linked
  from the README documentation table and docs/setup.md.
- Key findings: PEACH is the top commercialization blocker (upstream
  licensing self-contradictory — repo LICENSE.md CC BY-NC-ND 4.0 vs
  README/site CC BY-NC-SA 4.0; both NonCommercial); CIS Benchmark
  non-member ToU prohibit commercial embedding; SEI CERT needs written
  permission for verbatim rule text; the grype hosted DB has no
  published terms. Everything else is permissive or
  subprocess-invoked copyleft with no obligations.
- secure-code-audit PEACH attribution block corrected to record the
  upstream license discrepancy and the pre-commercialization
  obligation.
- docs/setup.md tool table updated with the container-audit toolchain
  (syft, grype, cosign) and LoC counters.

## v0.54.0 — 2026-07-16

Minor release: container-image audit profile.

- New `secure-container-audit` skill (stage ③ alt) — audits registry
  images as shipped: `skopeo` config/signature/tag-hygiene inspection
  (no pull), `syft` SBOM, `grype` CVE scan, cross-reference to the
  source repo's code-profile report, and image↔source drift detection.
  Reports set `metadata.audit_profile: "container"`, are named
  `<image>-container-audit.json`, and key finding IDs on the manifest
  digest (`{IMAGE_SLUG}-{SHORTDIGEST}-{NNN}`), which satisfies the
  existing ID regex and validator cross-checks unchanged.
- `schema/report.schema.json`: `metadata.audit_profile` enum gains
  `"container"`; profile deltas documented in `docs/report-structure.md`.
- `secure-code-audit` gains a deterministic SBOM & dependency-scan step:
  when `syft`/`grype` are on PATH and a local checkout exists, the
  `dependency_audit` section is populated from `grype sbom:` output
  (tool + DB versions recorded in `metadata.tools`) instead of manual
  lockfile review.

## v0.48.0 — 2026-07-16

Minor release: optional cosign Merkle root signing (XWING-13).

- `scripts/sign_merkle_root.py` — `sign` and `verify` subcommands shell out
  to cosign for `metadata.merkle_root_signature`; Rekor upload is opt-in
  (`--rekor`).
- `scripts/ledger_integrity.py` — `verify_merkle_signature()` integrates
  optional signature checks into layer validation; warns when cosign or a
  pubkey is unavailable, errors only on verification failure.
- `scripts/validate_report.py` — `--signing-pubkey` / `HARNESS_SIGNING_VERIFY_PUBKEY`
  enable signature verification during layer sweeps.

## v0.45.1 — 2026-07-14

Patch release: sweep worklist deduplication, caught on the first
fleet-wide run.

- The same repository audited canonically under several products
  produced duplicate queue entries (e.g. `managedcluster-import-
  controller` under two ACM products). The worklist now keeps one entry
  per repository URL — the highest-priority one — and records the
  sibling findings dirs in `duplicate_report_dirs` so their trees can
  share the verification result. Fleet queue: 1,875 → 1,577 repos.

## v0.45.0 — 2026-07-14

Minor release: verify-remediation full-sweep mode.

- `/verify-remediation full-sweep` — campaign-scale "what has been fixed
  thus far?" without campaign-scale cost. New
  `harnessing/verify-remediation/scripts/build_verify_sweep.py` (16 tests)
  deterministically shortlists before any LLM re-audit: parallel
  `git ls-remote` skips repos whose HEAD still equals the audited SHA
  (nothing changed → nothing fixed), ledger remediation claims
  (`fix_in_progress`/`resolved`/`partially_resolved` events) queue first
  (T1), then drifted repos by severity (T2 crit / T3 high / T4 rest);
  already-verified repos are skipped so interrupted sweeps resume; the
  unreachable/no-URL remainder is listed, never silently dropped.
  Writes `findings/_manifest/verify-sweep-worklist.{json,md}`. Each
  queued repo runs the standard Phases 1–7 pinned at the observed HEAD,
  and the verification report feeds `/track-findings` (class-1
  evidence). Routes only — never authors a verdict.

## v0.44.0 — 2026-07-14

Minor release: executive-summary per-input-segment breakdown.

- `executive-summary-findings` gains a `by-segment` option
  (`--by-segment`, with `--inputs-root` / `--exclude-segment`): every
  `*-repos.csv` under `hybrid-platforms-inputs/{openshift,
  operator-catalog,services}` (ansible excluded by default) builds a
  canonical-URL → segment map; each report resolves to its first
  matching segment (priority openshift → operator-catalog → services,
  keeping totals additive; overlap count reported) with
  inventory-absent repos — including `oss-findings/` — bucketed as
  `unmapped`. Renders a Markdown severity-matrix table and an HTML
  stacked-bar card + table. Default (flag-less) output unchanged.

## v0.43.0 — 2026-07-14

Minor release: interim /triage wiring for govulncheck reachability
candidates (reachability integration stage 1a, owner-requested).

- `/triage` Phase 2e: when a SHA-matched `<repo>-govulncheck.json` exists
  beside the baseline audit report (or the input findings file), findings
  matching a candidate by OSV id / CVE alias / module@version carry a
  DEPENDENCY-REACHABILITY block into the Phase 3b verifier prompt —
  advisory, module/versions, reachability tag, caller-first call path.
  Annotation only: no vote-count changes, no skipped verification, no
  authored verdicts; stale or absent artifacts are skipped silently.
  Generation stays out-of-band (network vs. triage's no-network boundary).
- `docs/reachability-integration-draft.md` §2d/§2e: interim wiring marked
  executed; new rationale for deferring full wiring (one contract not two,
  routing power is an owner decision, ledger fields are forever,
  measure-before-trusting, isolation boundary).

## v0.42.0 — 2026-07-14

Minor release: reachability integration stage 1 — dependency-CVE
reachability candidates via govulncheck.

- `scripts/run_govulncheck.py` (18th script; 11 tests) — runs
  `govulncheck -json` against a pinned Go clone and reduces the stream to
  one candidate per OSV advisory, classified `symbol_reachable` /
  `package_imported_not_observed` / `module_required_not_observed`, with
  the shortest observed call path attached and full tool/DB/SHA
  provenance recorded at emission time. A candidate generator per the
  deterministic-tooling safety rule — tags with evidence, never verdicts;
  `not_observed` is deliberately not `unreachable`.
- `docs/reachability-integration-draft.md` — 4-stage design (govulncheck
  → finding-level call-graph tagger for /triage → ledger recording +
  validation prioritization → non-Go), guardrails inherited from the
  false-positive discipline, and owner decision points. Stage 1 marked
  executed with pilot results: `openshift-pipelines/manual-approval-gate`
  @ `edb306fe` — 18 advisories: 11 symbol-reachable, 1
  imported-not-observed, 6 module-only.

## v0.41.1 — 2026-07-14

Patch release: pitch-deck-metrics scoreboard title renamed to
"Project Ex-Wing" (campaign codename update).

## v0.41.0 — 2026-07-14

Minor release: new `pitch-deck-metrics` skill (31st skill, 36th command).

- `harnessing/pitch-deck-metrics/` — maintains
  `progress-tracker/pitch-deck-metrics.md`, a single scoreboard of the
  numbers quoted in funding pitches and leadership decks.
  `collect_pitch_metrics.py` deterministically parses every value from
  an existing derived artifact (executive summary, validation/fuzz
  dashboard, threat register, progress-tracker control files) or counts
  it from the harness tree/git — it never authors a number — and cites
  the source beside each row. Missing sources degrade to "—" and are
  flagged in a data-freshness table; a `MANUAL:BEGIN/END` block for
  hand-written talking points survives regeneration.

## v0.40.2 — 2026-07-13

Patch release: second validation-emitter fix caught by the schema gate
on the campaign backfill (re-run after v0.40.1; output again reverted
before commit).

- 63 validation reports re-verdicted by `recompute_verdicts.py` carry
  `harness_version: 0.6.4-37419f1+recompute`, which the layer schema's
  `^\d+\.\d+\.\d+(-sha)?$` pattern rejects — 89 of 534 backfilled
  layers failed validation. The emitter now normalizes the event/layer
  `harness_version` to the conforming prefix (omitting the field when
  nothing conforms); the raw annotated string is preserved in the
  machine actor identity (`validate-findings/0.6.4-37419f1+recompute`).
  2 regression tests (20 emitter tests).

## v0.40.1 — 2026-07-13

Patch release: validation-emitter batch dedupe fix, caught by the
schema gate on the first real campaign backfill.

- `emit_validation_ledger_events.py` deduplicated events only against
  those already in the layer file, not within the batch being appended —
  so a report reaching the same canonical finding twice (e.g. ACM's
  `kube-rbac-proxy` under two mirror sub-packages claim-matching to one
  audit) wrote duplicate event_ids, which `validate_report.py`
  cross_validate_layer rejects (137 of 534 layers failed validation;
  the backfill output was reverted before commit). Event, needs_review,
  and refuted-register appends now all dedupe within the batch as well.
  Regression test added (18 emitter tests).

## v0.40.0 — 2026-07-13

Minor release: live-validation verdicts flow into the disposition
ledger — the knitting step that links `validations/` proof back to the
findings it proves or refutes.

### track-findings / ledger (validation backfill)

- New `scripts/emit_validation_ledger_events.py`: deterministic
  transform from a `*-validation.json` live-validation report to
  disposition-ledger events, sibling of `emit_triage_ledger_events.py`.
  `confirmed` → validity `confirmed` with `source.type:
  validation_report` (class-1 execution-verified evidence — the merge
  engine's `execution_proven` assurance tier); `refuted` → machine
  false_positive event that pends `refuted_awaiting_signoff` until an
  LDAP-verified human countersigns, plus a merge-append into the repo's
  `*-refuted-register.json` (never clobbering the triage emitter's
  entries — registers gain a `sources` list);
  `inconclusive`/`blocked_by_scope`/`not_attempted` → no event. One
  validation report covers one logical product and fans out across
  every repo ledger its verdicts touch.
- Baseline resolution ladder (a validation report records foreign
  absolute `source_report` paths from the runner's machine): (1)
  suffix-localize on `analysis-results/`, realpath-resolving symlinked
  duplicates to the canonical audit whose ledger they share; (2)
  content match — the same-basename canonical whose sha256 equals the
  local `progress-tracker/processed-results/` mirror copy's; (3) claim
  match — every same-basename canonical whose same-id finding has an
  identical claim hash (`baseline_claims.py` canonical fields) receives
  the event, keeping claim-identical alias trees (e.g. `mce/` and
  `multicluster-engine/`) in sync instead of leaving one stale. Hidden
  scratch dirs (`.verify-tmp/`) are never targets.
- Staleness: when a directly-resolved baseline's current sha256 no
  longer matches the sha the validation recorded, the event still lands
  (the proof stands against the claim it tested, recorded in
  evidence_refs as `validated-baseline-sha256:`) and a new
  `stale_baseline` needs_review item (layer.schema.json queue_reason
  enum) is queued for human confirmation. Content- and claim-matched
  targets are current by construction and never queue.
- Idempotent (canonical event_ids; re-emission appends nothing),
  chronology-safe (append timestamps clamp to the layer's last event),
  `--dry-run`, `--build-cumulative` (regenerates
  `*-findings-current.{json,md}` per touched repo), and `--manifest`
  batch mode that replays a whole validation campaign from
  `validations/_manifest/validation-manifest.csv`. Campaign dry run:
  977 decided verdicts (529 confirmed, 448 refuted) resolve into 1,152
  events across 576 repo ledgers with 10 stale-baseline review items
  and zero unresolved. 17 tests.

### tests / tooling

- Split-test-runner gap closed by convention (best-practice assessment
  §5 item 2 / plan item 5): **pytest is the only test runner**,
  documented in AGENTS.md — `unittest discover` silently skipped the
  two pytest-native modules (~39% of the suite). Running the suite
  properly surfaced one real failure that habit had been hiding:
  `test_scope.py::test_load_targets_example` began failing on
  2026-07-01 when `targets.example.yaml`'s engagement window expired
  (the scope guard's expiry gate correctly preempts every other rule).
  The test now pins both sides of the window — asserting the expiry
  refusal explicitly, then the off_limits/control-plane refusals inside
  an unexpired window — so it never rots with the calendar again.

## v0.39.0 — 2026-07-13

Minor release: claim hashes make the audit baseline tamper-evident;
best-practice assessment; two conformance defects fixed and guarded.

### track-findings / ledger (claim hashes)

- The "original `*-security-audit.json` is never modified" invariant is
  now machine-enforced. New `scripts/baseline_claims.py` records a
  sha256 of each finding's canonical claim fields (id, title, severity,
  cwes, locations, description, remediation — `validation_status`
  deliberately excluded) from the **JSON** report (the `.md` is a
  derived rendering, not hashed) into the layer's new
  `metadata.claim_hashes` (layer.schema.json, optional — pre-0.39.0
  layers stay valid). Recording is add-only: sanctioned appends
  (fuzz-harnesses / vuln-scan follow-ups) get pinned on the next
  track-findings run; overwriting requires `validation_status:
  corrected` plus an explicit `--rebaseline <id>`. Verification has
  teeth in two places: `validate_report.py` cross_validate_layer errors
  on drifted or deleted baselined claims, and `build_cumulative.py`
  refuses to rebuild the cumulative report from a tampered baseline.
  track-findings Phase 1 gains the record step;
  `docs/disposition-ledger.md` §10 documents the design and §3 gains a
  "Where ledgers live" storage-layout section (one ledger per canonical
  audit report, cumulative report is a derived cache, no fleet-wide
  ledger by design). A `sweep` subcommand walks a findings tree and
  creates minimal layers + pins claim hashes for every canonical audit
  report lacking one (idempotent; symlinked duplicates skipped), so
  baselines are tamper-evident before any triage feedback arrives.
  13 tests.

### docs

- New `docs/best-practice-assessment.md`: best-practice conformance
  review of the harness itself (strong: contracts, ledger, injection
  defenses, self-checking docs; gaps: no CI, unpinned deps, unsigned
  tags, split test runner) with a 13-item prioritized future-work plan.

### fixed (assessment defects §5.2–§5.3, guarded against recurrence)

- `pyproject.toml` version corrected (0.8.1 → current; had silently
  drifted 30 releases) and `check_docs_consistency.py` gains a
  version-sync check (pyproject vs VERSION).
- `.claude/commands/assign-findings-owners.md` wrapper restored (lost
  in a branch-hygiene revert while the skill and its `.crush` mirror
  shipped; wrapper text updated to the skill's current LDAP-based
  procedure) — commands 34 → 35. `check_docs_consistency.py` gains a
  symlink-integrity check for `.claude/`/`.crush/`, closing the
  dead-path checks' by-design symlink blind spot. Checker tests added.

## v0.38.1 — 2026-07-13

### check-harness-docs

- New group-README check: when the `gitlab-profile` sibling is checked
  out, `check_docs_consistency.py` also vets the GitLab group profile
  page's harness facts — any `vX.Y.Z` on a line mentioning "harness"
  must equal the `VERSION` file, and its skill/command count claims
  (`N skills`, `Skills (N), by function`, `N slash-command wrappers`,
  `N commands`, markdown bold tolerated) must match the tree. Skipped
  with a notice when the sibling is absent (CI, standalone checkouts).
  The group README went stale at v0.32.1 while the harness reached
  v0.38.0 — this closes that gap class. SKILL.md documents the check,
  the fix path (edit + commit/push the sibling repo), and adds "bump
  VERSION" to the when-to-run list; 5 tests added.

## v0.38.0 — 2026-07-12

Minor release: vuln-scan aligned with the campaign's ledger discipline,
finding-ID scheme, severity enum, and report naming.

### vuln-scan

- **Campaign finding IDs**: findings now carry
  `{REPO_SLUG}-{SHORTSHA}-{NNN}` (the same canonical scheme as
  secure-code-audit; SHORTSHA is the scanned commit, so sweeps never
  collide with each other or the baseline). Subagent working ids are
  preserved as `scanner_ref`.
- **Shared severity enum**: critical/high/medium/low/informational with
  criteria aligned to the audit's severity ladder, replacing
  HIGH/MEDIUM/LOW. Findings also carry a primary `cwe` so the
  fold-into-baseline transcription can satisfy report.schema.json's
  required `cwes[]` mechanically; the fold-in step now spells out the
  full field transcription (locations, remediation,
  `validation_status: not_verified`, source_findings) and the
  validate_report.py gate.
- **Report naming**: output is `<target-dir>/<repo>-vuln-findings.{json,md}`
  (repo name derived by the same rule as `/threat-model`), replacing
  `VULN-FINDINGS.{json,md}`; both markdown and JSON are always written.
  Output metadata gains repo/repo_slug/scanned_ref/baseline fields.
- **Deterministic gate**: new `schema/vuln-findings.schema.json`
  (severity enum and canonical id pattern shared with
  report.schema.json), auto-detected by `validate_report.py` from the
  `*-vuln-findings.json` filename with a `cross_validate_vuln_findings`
  pass (id uniqueness + derivation from repo_slug/scanned_ref, summary
  reconciliation, baseline bookkeeping). Legacy `VULN-FINDINGS.json` is
  deliberately not auto-detected — it predates the contract. The scan is
  not complete until the validator passes; 16 tests added.
- **Baseline supplement flow (ledger technique)**: the skill locates the
  target's `<repo>-security-audit.json` (new `--baseline` flag, beside
  the target, or in the findings tree), feeds baseline findings into the
  review briefs as do-not-re-report context, dedupes candidates into a
  `known_findings` list, and hands back the update path: `/triage`
  verification, then appending confirmed findings to the baseline audit
  as follow-up findings (the `/fuzz-harnesses` flow) with dispositions
  through the append-only ledger — the scan itself never modifies the
  baseline.
- **Positioning documented in the skill**: `/secure-code-audit` is the
  preferred baseline (vuln-scan is deliberately less comprehensive),
  `/verify-remediation` is the tool for updating the baseline after
  fixes, and `/vuln-scan` is the between-audits sweep whose verified
  findings update the original `*-security-audit`.

### triage / patch (consumers)

- Ingest tables recognize `*-vuln-findings.json` (legacy
  `VULN-FINDINGS.json` still accepted); campaign ids from scan output
  are preserved as `orig_id` in triage and honored by `/patch --id`.
- `/patch --top` severity ranking restated on the shared five-level
  enum, case-insensitive, with legacy HIGH/MEDIUM/LOW mapped.

## v0.37.0 — 2026-07-12

Minor release: vuln-scan ported in (29th skill); the auditor's
remediation guidance now survives the audit → triage → patch path.

### vuln-scan (`harnessing/vuln-scan/`, new)

- Ported from the external vuln-pipeline project's user-level skill and
  aligned with harness conventions: threat-model scoping resolves the
  canonical `<repo>-threat-model.md` (legacy `THREAT_MODEL.md` still
  read); `VULN-FINDINGS.json` gains `metadata.harness_version`;
  vuln-pipeline references are marked as an external CLI; provenance
  section records the port. Discovery symlinks and `/vuln-scan` command
  wrappers added for Claude Code and Crush. The lightweight static-scan
  alternative for the audit slot: threat-model-scoped focus areas,
  parallel review subagents, per-finding confidence pass, nothing
  dropped — `/triage` does the verification.

### triage

- `recommendation` is now carried through to TRIAGE.json **verbatim**
  from the input finding (audit `remediation`, scanner `fix`/
  `mitigation`) and emitted as `null` when absent — previously the
  ingest alias table read it but the output schema dropped it, so the
  auditor's remediation guidance never reached `/patch` on the
  recommended audit → triage → patch path. `schema/triage.schema.json`
  gains the optional field; tests added.
- Ingest alias table maps the audit schema's `locations[0].path`/
  `locations[0].lines` explicitly.

### patch

- `<repo>-security-audit.json` documented as a first-class input
  container (read `.findings[]`, alias `remediation` → `recommendation`,
  skip dispositioned false positives, warn that audit findings are
  claimed-not-verified). The canary-fixture test example and the
  `vuln-pipeline patch` delegate are marked as external-repo
  dependencies. New design note: remediation guidance reaches the patch
  author as a hint on every input path; the reviewer still never sees
  it.

### docs

- README/AGENTS skill counts 28 → 29 and new pipeline rows;
  `docs/skills.md` gains the vuln-scan section and updated triage/patch
  sections; `docs/public-skill-assessment.md` updated (8 of 29 skills
  portable; vuln-scan Tier 2).

### licensing

- Third-party attribution added per Apache-2.0 §4: root `NOTICE` file
  and `LICENSES/{Apache-2.0.txt, MIT-claude-code-security-review.txt}`.
  The `triage` (v0.22.0), `threat-model` (v0.23.0), `patch` (v0.23.0),
  and `vuln-scan` (v0.37.0) skills and `scripts/checkpoint.py` are
  derivative works of Anthropic's Apache-2.0-licensed
  defending-code-reference-harness; parts of `vuln-scan` are adapted
  from the MIT-licensed claude-code-security-review. Each derived skill
  carries a Provenance section pointing at the NOTICE;
  `checkpoint.py` already carried the upstream copyright/SPDX header.
  README gains a License section.

## v0.36.0 — 2026-07-12

Minor release: one threat-model naming convention.

### threat-model

- The model file is now **always named after its target**:
  `<repo>-threat-model.md`, where the repo name comes from
  `git remote get-url origin` (basename, `.git` stripped) with the
  target directory's basename as fallback. `THREAT_MODEL.md` is demoted
  to a legacy name: still resolved when reading (explicit path > single
  `*-threat-model.md` > legacy `THREAT_MODEL.md` > interactive choice
  among branch variants > no-model behavior), never written — any mode
  that writes back to a resolved legacy file first renames it to the
  canonical name (`git mv` if tracked, `mv` otherwise) and tells the
  user. Rationale: the dual convention existed because in-checkout
  models imitated the well-known-filename idiom (SECURITY.md), but
  nothing outside this repo expects the fixed name, so the split bought
  complexity without discoverability. Bootstrap's Stage-5 assembly
  buffer renamed `./.threat-model-state/THREAT_MODEL.md` → `_model.md`.
  `lint_threat_model.py`, `build_threat_register.py`, and the tests
  keep accepting both names unchanged (portfolio and pre-0.36.0
  artifacts remain valid). SKILL.md/schema.md/mode files/wrapper/
  README/docs updated; `Bash(mv:*)` added to the skill's allowed tools
  for the legacy migration.

## v0.35.2 — 2026-07-12

### threat-model

- Model-file resolution rule (SKILL.md, applied by review/update/pr and
  `--seed`): the skill's maintenance modes previously assumed
  `<target-dir>/THREAT_MODEL.md`, but portfolio artifacts are named
  `<repo>-threat-model.md` (optionally branch-suffixed). Resolution now
  covers both conventions — explicit file path > THREAT_MODEL.md >
  single `*-threat-model.md` > interactive choice among branch variants
  (never guessed in --auto) > mode's no-model behavior. Write-back
  always targets the resolved file, so review/update on a portfolio
  artifact can never create a stray THREAT_MODEL.md beside it. Review
  report files derive their name from the resolved model. schema.md
  documents the dual convention; wrapper/README/docs updated.


## v0.35.1 — 2026-07-12

### threat-register

- threat-register.md upgraded from bare tables to a standalone
  leadership report: "How to read this" caveats (statuses as the models
  state them, decay until review; ordinal score is not CVSS; key
  stability; ledger join direction), totals with open counts, top-25
  open threats and quick wins with of-N framing, a fleet-wide
  risk-acceptances section by product (first aggregate view of the 714
  acceptances), top products, and a footer pointing at the JSON/HTML
  siblings and the rebuild command.

## v0.35.0 — 2026-07-12

Minor release: fleet-wide threat register (28th skill).

### threat-register skill (new)

- `harnessing/threat-register/scripts/build_threat_register.py`: deterministic
  aggregation of every THREAT_MODEL.md / `*-threat-model.md` under
  `analysis-results/{findings,oss-findings}` into
  `threat-register/threat-register.{json,md,html}`. Reuses
  lint_threat_model.py's parser, so the register reads exactly what the
  contract gate enforces; nonconforming models are skipped and counted,
  never edited.
- Identity: stable compound key `<product>/<model-slug>:<Tn>` — durable
  because schema.md forbids renumbering/reusing threat IDs; colliding
  slugs (same-named files across products or sibling dirs) are
  requalified by full path, guaranteeing global uniqueness. Threats join
  the disposition ledger only via their `evidence` citations of canonical
  finding IDs — threats themselves remain outside the ledger by design
  (they are re-scored, not refuted).
- Roll-ups: status/impact totals, per-product open-threat exposure,
  evidence-backed vs gap-fill counts, LINDDUN row count, and **quick
  wins** — `closes_class: yes` mitigations at XS/S effort covering an
  open high/critical/existential threat. Ordinal rank score (impact ×
  likelihood weights, documented in `meta.scoring`) orders rows only;
  it is not CVSS and never feeds the ledger risk index.
- First live build: 7,525 models → 83,021 threats, 0 nonconforming
  (the v0.33–0.34 lint remediation left the fleet fully parseable);
  34,690 unmitigated / 45,329 partially mitigated; 18,575 open critical
  + 151 open existential; 9,899 quick wins.
- Wiring: `.claude`/`.crush` skill symlinks, `/threat-register` command
  wrapper, docs (README skills table + counts now 28 skills / 33
  commands, docs/skills.md section), tests
  (`tests/test_build_threat_register.py`, 7 tests).

## v0.34.0 — 2026-07-12

Minor release: portfolio lint sweep, contract amendments the fleet
demanded, and a deterministic repair script. First full sweep (7,562
files, ~4s) found 2,010 errors in 549 files; after this release and the
paired analysis-results repair commit, 921 errors in 323 files remain —
all requiring judgment (coverage gaps, free-text actors), queued for a
/threat-model review pass.

### schema (contract amendments — fleet-driven)

- `actor` may be a comma-separated list of enum values (150+ artifacts
  legitimately model multi-position threats like `remote_auth, insider`;
  weakest position first, scoring reads the first entry).
- `effort` gains `XS` (110 rows in the wild); `closes_class` gains `no`
  (worthwhile defense-in-depth that doesn't close the class, 22 rows).
- Cells containing literal `|` must escape it as `\|` (documented).

### scripts

- `lint_threat_model.py`: validates each comma-separated actor;
  directory sweeps skip pipeline scratch under any `artifacts/` path
  component (per-worker THREAT_MODEL.md drafts are working files, not
  portfolio artifacts — explicit file paths still lint).
- New `repair_threat_model.py`: mechanical repair with the
  reemit_legacy_triage discipline — escape unescaped pipes inside
  inline-code spans of fractured table rows, normalize actor separators,
  remap unambiguous enum synonyms (adjacent→adjacent_network,
  in-cluster→adjacent_network, accepted→risk_accepted,
  certain→almost_certain, …). A file is rewritten ONLY when its lint
  error count strictly decreases and no new error *class* appears
  (class-based comparison so partial fixes of multi-token cells count as
  shrinkage, not regressions). Free-text actors with no unambiguous
  mapping are left for review — mapping them would be concluding, not
  routing.

### tests

- test_lint_threat_model grows to 27: multi-actor, XS/no enums,
  artifacts-dir sweep exclusion (explicit paths still lint).

## v0.33.1 — 2026-07-12

### lint_threat_model.py

- Table parsing honors GFM escaped pipes: cells split on unescaped `|`
  only, so `\|` inside inline code (regex alternations, `\|\| true`)
  no longer fractures a row. Found repairing the aro-ai-tools artifact
  the v0.33.0 sweep flagged — the correct fix for a `|` inside a table
  cell is `\|`, and the linter must accept it. New escaped-pipe test.
  `findings/openshift-online` now lints ALL PASSED (23 files).

## v0.33.0 — 2026-07-12

Minor release: /threat-model lifecycle + narrative + validation upgrade,
adopting the improvements assessed in
`docs/threat-model-guild-comparison.md` (comparison against the ProdSec
threat-modeling-guild Lola module; its "what not to adopt" list — per-threat
file:line citations, narrative-first structure, coarse likelihood scale,
permissive tool grants — was honored).

### scripts

- New `lint_threat_model.py`: deterministic THREAT_MODEL.md contract gate,
  playing the role `validate_report.py` plays for audit/triage JSON.
  Checks sections/order, table columns, enums (actor/impact/likelihood/
  status/sensitivity/closes_class/effort/mode), the coverage invariant
  (every section 3 entry point threatened in section 4 or parked in
  section 5), threat-ID shape/uniqueness, section 8/9 cross-references,
  provenance completeness (harness_version warns on legacy artifacts),
  update-history dates, and evidence-cell hygiene — vuln references only
  (CVE/GHSA/commit/FIND-NNN/canonical ledger IDs/tracker IDs/URLs, with
  prose tolerance for "commit <hash> (…)" and `-NNN` continuations);
  file:line citations in evidence are an error (litmus-test guard).
  Directory sweeps cover both `THREAT_MODEL.md` and `*-threat-model.md`;
  symlinks skipped. Every /threat-model mode that writes or modifies a
  model now ends with this gate at ALL PASSED. First live sweep:
  `findings/openshift-online` 23 files → 1 file with real defects
  (unescaped `|` inside table cells).

### threat-model skill

- **Three new modes.** `review` (new `review.md`): measures an existing
  model's drift — deterministic git-diff pre-pass against the provenance
  SHA (surface-relevant vs supply-chain-relevant vs ignorable paths,
  newer pipeline artifacts weighted by assurance), LLM re-scoring of only
  what moved, drift report (health summary / new surface / stale threats /
  changed risk / mitigation status / invalidated assumptions), then an
  interactive AskUserQuestion offer to apply (all / per-change with card
  previews / report-only); `--auto` (report-only) and `--apply`
  (accept-all) run prompt-free for batch drift sweeps. `update` (same file): targeted changes under
  continuity rules — IDs never renumbered and retired-never-reused,
  removed threats move to section 5 with a dated reason, human edits
  survive, provenance appends an update-history row, only feedback-named
  parts re-analyzed, requested-but-unappliable changes reported back.
  `pr` (new `pr.md`): diff-scoped assessment (git three-dot diff, change
  classification, one-hop neighbor reads, cross-reference against the
  existing model) ending in approve / approve_with_conditions /
  request_changes; writes no THREAT_MODEL.md and feeds no ledger events.
  Routing with no mode token is now two interactive questions (existing
  model → review/update/rebuild; owner present → interview flavors).
- **Bootstrap upgrades.** New Stage-1 `Context ingester` swarm agent
  behind `--context <paths>` (OpenAPI, SBOM, IaC, prior threat models,
  SAR/pentest exports, diagrams; never silently skips a provided source;
  doc-vs-code conflicts become candidate threats or open questions).
  Conditional LINDDUN privacy overlay in Stage 4 when personal-data
  assets exist (rows tagged `linddun:`); PASTA/OCTAVE explicitly not
  adopted. Stage 5 emits the new schema layers and ends with the lint
  gate.
- **Interview upgrades.** Q1 asks regulatory scope + example records per
  sensitive asset (one follow-up, not an audit); Q2 opens the threat-actor
  persona question; Q4 reads the draft attack scenarios back to the owner
  as stories to surface wrong assumptions; emit includes the lint gate.

### schema (THREAT_MODEL.md contract — all additive)

- Section 1 opens with a 1-2 paragraph jargon-free executive summary and
  may close with a `### Threat actor landscape` subsection (2-4 personas
  from an eight-persona list, one sentence of system-specific motivation
  each; the section 4 `actor` access-position enum remains the scoring
  input).
- Section 2 assets may append `regulatory_scope` and `example_records`
  data-classification columns — feeds the same tenancy_profile derivation
  the ledger emitter uses for hardening λ weights.
- New optional `## 9. Attack scenarios`: `### Tn — <threat>` narrative
  subsections for the top 3-5 threats (present tense, no jargon, no
  file:line; consumers must tolerate absence).
- Provenance requires `harness_version` on new emissions (same epoch
  marker as audit `metadata.harness_version` and triage
  `triage_context.harness_version`) and gains an optional
  `### Update history` table for review/update passes.

### related skills

- `generate-team-report` Step 3b: lifts `## 9. Attack scenarios` verbatim
  into team-package executive summaries (never paraphrased into tables;
  never synthesized for models that lack it).

### docs

- README (skills table, repo tree, report tooling, docs table),
  docs/skills.md threat-model section, skill README, and the
  `.claude/commands/threat-model.md` wrapper updated for the six-mode
  surface and the lint gate. `docs/threat-model-guild-comparison.md`
  carries the adoption status.

### tests

- New `tests/test_lint_threat_model.py` (22 tests): structure, enums,
  IDs, coverage invariant, evidence hygiene (file:line rejection, prose
  tolerance, canonical ledger IDs), provenance, sort-order warning,
  collection/symlink behavior.

## v0.32.1 — 2026-07-12

### validate_report.py

- Directory-sweep auto-detection covers the ledger artifacts:
  `*-findings-layer.json` routes to layer.schema.json and
  `*-refuted-register.json` (an operational worklist, not a schema'd
  report) is excluded from sweeps. `findings/openshift-online` now
  validates ALL PASSED end to end.

## v0.32.0 — 2026-07-12

Minor release: legacy triage re-emission tooling.

### scripts

- New `reemit_legacy_triage.py`: deterministic conversion of pre-0.24.0
  triage artifacts to the current taxonomy and triage.schema.json — no
  re-verification, votes/confidence/rationales preserved verbatim.
  Verdict remap: primary-rule-13 false positives → `hardening`
  (refutation votes counted as hardening votes), unlocatable refutations
  and legacy `cannot_verify` verdicts → `undetermined`. Shape
  normalization: boolean `triage_completed` → last-git-commit date
  (single streamed git-log pass), string/null vote breakdowns, uppercase
  severities, free-text exclusion rules (primary rule number extracted),
  line ranges, null threat_model, non-conformant ids renumbered with the
  original preserved in `source`. A file is rewritten ONLY when the
  converted document passes schema + cross-validation with zero errors;
  Markdown re-rendered via render_triage.
- Portfolio dry run: 5,696/5,697 legacy artifacts convert cleanly
  (1 already conformant, 0 failures) — 22,358 findings re-labeled
  hardening, 10,033 re-labeled undetermined.

### schema

- `triage.schema.json`: `findings` minItems 1 → 0 — a zero-finding audit
  legitimately yields a zero-finding triage (60 such artifacts exist).

## v0.31.0 — 2026-07-12

Minor release: the remaining breadcrumbs get first-class surfacing, and
the hardening backlog gets work-drivers.

### countersign inbox covers every pending-attention state

- `countersign.py queue` now also derives **attention cards**:
  `fp_overridden` (informational — an execution proof overturned a human
  FP; the §2b draft's "review-queue item" finally exists),
  `fp_reassertion_blocked` (addressed to the SECOND signer the two-person
  rule requires, decision markers included), and `conflict` (adjudication
  card; rationale mandatory either way). The `/countersign` skill
  presents them after the signoff cards, same one-card-per-question
  pattern.

### needs_manual_test stops evaporating

- `emit_triage_ledger_events.py`: recall-mode true positives with
  `verify_verdict: needs_manual_test` now queue a `needs_review` item
  (`queue_reason: needs_manual_test`, suggested validity `confirmed`)
  instead of vanishing into a skip log. Schema enum extended.

### refuted register becomes a portfolio number

- `findings-trends` aggregates every `*-refuted-register.json`: standing
  FP assertions, repos covered, tier split, and the fuzzable-class count
  — rendered as a "Refuted Register" section naming `/fuzz-harnesses` as
  the consumer. The falsifiability backlog is now a visible metric next
  to the validation gap it feeds.

### hardening work-drivers (owner policy, 2026-07-12)

- `generate-team-report`: new Step 3a extracts the hardening backlog
  from triage/ledger artifacts and renders a dedicated section in the
  team deliverables — posture debt, never mixed into vulnerability
  counts.
- `file-security-defect --hardening`: non-embargoed path — ONE regular
  Jira Story/Task per component batching its hardening backlog as a
  checklist, explicitly WITHOUT the Embargoed Security Issue level or
  CVSS (there is no exploit to protect; hiding hygiene work reduces the
  chance it gets scheduled). The trends hardening burndown remains the
  third driver.

## v0.30.0 — 2026-07-11

Minor release: `/countersign` becomes a first-class skill (the 26th), so
pending human decisions are discoverable, not tribal knowledge.

### countersign (`harnessing/countersign/`)

- New user-invocable skill + `/countersign` slash command driving the
  v0.29.0 workbench end-to-end: build the decision-card inbox
  (`countersign.py queue`), present ONE card per question with the full
  card as the option preview (confirm / keep-open / defer), collect
  rationales (keep-open requires the reviewer's own words), record
  everything in a single LDAP-verified `apply` call, validate the rebuilt
  cumulative reports, and show the receipt. Explicitly forbids working
  around a failed LDAP check or hand-assembling events.
- Discovery nudges from the producers of pending state:
  `emit_triage_ledger_events.py` prints a "NEXT: run /countersign" line
  whenever countersign-gated FPs or review items were queued, and the
  triage skill's Phase 6e/terminal summary tells the user the same.
- Registered per AGENTS.md conventions (symlinks, command wrappers,
  docs/skills.md pipeline row + section, README table, counts 25 → 26).

## v0.29.0 — 2026-07-11

Minor release: the countersign workbench — pending human decisions get a
real inbox with self-contained decision cards, replacing the
remember-the-report interrogation flow.

### scripts

- New `countersign.py`:
  - `queue` derives every `refuted_awaiting_signoff` finding and pending
    `needs_review` item across a findings tree (both are derived state
    with no stored queue) and renders one decision card each — audit
    claim, machine refutation with lint-verified evidence and triage
    vote data, and exactly what signing records — into an annotatable
    `countersign-queue.md` (+ optional JSON).
  - `apply` ingests the annotated queue; `record` handles one decision.
    Both LDAP-verify the signer once via validate_employee.py (recording
    refused otherwise), append canonical interactive events (idempotent
    per signer-day), require the reviewer's own rationale for `keep_open`
    (blank countersign rationale adopts the machine rationale, framed as
    an adopted determination), rebuild the cumulative pair
    deterministically, and print a receipt.

### track-findings

- Merge engine: ANY human validity determination now clears
  `refuted_awaiting_signoff` — a `keep_open` (human `confirmed`) is
  reviewed-and-rejected, not still-awaiting.
- SKILL.md interactive phase rewritten around the workbench: one card
  per question (card as the question preview), confirm/keep-open/defer,
  adopt-machine-rationale default, receipt; async annotate-and-apply
  path documented. Cumulative-report hint text points at
  `countersign.py queue`.

### docs

- `docs/disposition-ledger.md` §6a documents the workbench and why it
  relaxes none of the §6 safeguards; architecture scripts table updated.

### tests

- `tests/test_countersign.py` (13 tests): discovery of pending state,
  card self-containment, queue-annotation parsing, recording semantics
  (adopt-rationale framing, keep_open→confirmed, rationale refusal,
  per-day idempotency, defer), and the awaiting-signoff flag clearing on
  any human determination.

## v0.28.0 — 2026-07-11

Minor release: cross-skill alignment sweep for the v0.24–0.27 verdict
taxonomy and ledger model — dashboards stop counting hardening findings
as confirmed vulnerabilities, and consumers gate on dispositions.

### dashboards

- executive-summary-findings: `validation_status: hardening` findings in
  cumulative reports are bucketed separately (`hardening_count` /
  `hardening_total`) and excluded from the leadership severity
  aggregates, with an explanatory note in both MD and HTML output —
  posture debt is λ-weighted in findings-trends, never a confirmed
  vulnerability here. Verified against the live agent-control-plane
  cumulative report (11 hardening excluded; countersign-pending FPs
  correctly still counted).
- repo-graph: hardening/undetermined counts on findings nodes; hardening
  validity excluded from `open_findings`; triage `by_severity` lookup is
  now case-insensitive (the v0.25.0 schema is lowercase; June artifacts
  were uppercase — both parse).

### skill guidance

- threat-model bootstrap: harness pipeline artifacts as vuln evidence,
  weighted by verdict and assurance — execution_proven strongest,
  hardening findings are *mitigation* evidence (weaker controls for
  threats crossing that component), countersigned FPs are not evidence,
  undetermined findings become section-6 open questions verbatim.
- file-security-defect: disposition gate before filing — never file
  hardening (posture backlog) / false_positive / undetermined /
  resolved findings; surface disposition and require confirmation on
  explicit override.
- patch: `--top` excludes hardening-verdict findings; `--id` may patch
  them explicitly (de-amplifies co-located confirmed findings).
- secure-code-audit + secure-rpm-audit: `validation_status` docs gain the
  `hardening` value (ledger-set, never at audit time) and route triage
  verdicts through the disposition ledger.

### reviewed, no change needed

- validation-fuzz-dashboard (live-validation verdict vocabulary is
  unchanged), loc-dashboard, insecure-patterns, generate-team-report
  (copies triage artifacts through schema-agnostically),
  assign/reassign-findings-owners, inventory-repositories,
  deploy-operator, remediate-finding (`verdict == true_positive` filter
  remains correct), verify-remediation, security-audit-phased.
- validate-core-ocp campaign tooling (flip_fp_triage.py et al.): its
  2026-06-24 "defense-in-depth policy" manually flipped rule-13 FPs to
  TP — superseded at the source by the hardening verdict for all future
  triage runs; historical campaign scripts left untouched.

## v0.27.0 — 2026-07-11

Minor release: the triage → disposition-ledger integration lands, per the
owner-approved design (now finalized as
`docs/triage-ledger-integration.md`; capstone: `docs/findings-lifecycle.md`).

### scripts

- New `emit_triage_ledger_events.py`: deterministic TRIAGE.json →
  layer-event transform. true_positive → `confirmed` (skipped when
  needs_manual_test); hardening → `hardening` with the category-aware λ
  resolved from `config/hardening-risk-weights.json` and recorded into
  the event (tenancy profile from `peach_isolation_review.applicable`);
  false_positive → tiered machine FP events (auto-accept only when
  unanimous + lint-clean + confidence ≥ 8 + low/informational-claimed,
  with a deterministic 10% `fp_audit_valve` sample); undetermined →
  `undetermined_finding` needs_review item; duplicate → nothing. Also
  emits the `*-refuted-register.json` (every FP stays in fuzzing/
  live-validation scope). Canonical sha256 event ids; idempotent append.

### schemas + config

- `layer.schema.json`: validity += `hardening`; source_type +=
  `triage_report`; optional event fields `risk_weight` (emission-time λ
  record) and `auto_accept_tier`; queue reasons `undetermined_finding`,
  `fp_audit_valve`. `report.schema.json`: `validation_status` and
  disposition validity += `hardening`; disposition gains `assurance`,
  `fp_overridden`, `fp_reassertion_blocked`; by_validity accepts a
  hardening count. New `config/hardening-risk-weights.json` (versioned,
  owner-tunable; tenancy-load-bearing categories at/near 1.0).

### track-findings (merge engine)

- Evidence-class precedence on the validity axis: execution-verified
  (validation/verification reports) > human static > machine static;
  recency breaks ties within a class. A class-1 `confirmed` overrides a
  human false_positive (`fp_overridden`, rendered loudly with the
  countersigner attributed); re-asserting FP after a proof requires two
  distinct LDAP-verified humans (`fp_reassertion_blocked` otherwise).
  Auto-accept-tier machine FPs set validity without countersign. Every
  disposition carries `assurance` (claimed | machine_verified |
  human_reviewed | execution_proven).

### findings-trends

- Hardening is risk-bearing: `hardening` state replayed from the ledger,
  λ-weighted via the emission-time record (`hardening_risk_index`,
  `risk_index_combined` — always reported split). New final-bucket views:
  claimed/verified/proven assurance stages with triage-compression and
  validation-gap delta metrics; per-identity FP-override accountability;
  unhardened-blast-radius co-location table (component-directory
  granularity).

### skills + docs

- triage Phase 6e emits ledger events automatically for harness-audit
  input; fuzz-harnesses treats refuted-register entries as PRIORITY
  targets; validate-findings keeps register entries in candidate scope.
  track-findings SKILL.md documents the triage source row, the
  auto-accept carve-out, and evidence-class precedence.
- `docs/triage-ledger-integration-draft.md` finalized as
  `docs/triage-ledger-integration.md` (implemented voice, quick-start,
  implementation map, full owner-decision record);
  `docs/findings-lifecycle.md` draft markers flipped to implemented.
  One recorded deviation: event_id uses the canonical sha256 scheme
  rather than a `triage-` prefix (same deterministic/idempotent intent,
  already validator-enforced).

### tests

- `tests/test_ledger_integration.py` (21 tests): weight resolution +
  tenancy profiles, verdict mapping, FP tier boundaries, undetermined
  queue items, idempotent CLI round-trip, merge precedence incl.
  two-person rule and auto-accept. `test_build_cumulative.py` updated
  for the intended behavior change (execution proof overrides human FP)
  plus a new human-outranks-machine-static case.

## v0.26.0 — 2026-07-11

Minor release: triage anti-false-positive tranche — deterministic
renderer, verifier-evidence lint, dissent escalation, taxonomy canaries,
FP-composition tripwire; plus a DRAFT ledger-integration design awaiting
owner review.

### scripts

- New `render_triage.py`: TRIAGE.md becomes a deterministic projection of
  the validated TRIAGE.json (same convention as render_report.py) —
  section order Act on these → Hardening backlog → Undetermined →
  Dropped. The skill's hand-assembled incremental Markdown flow is
  removed.
- New `lint_verdict_citations.py`: post-vote evidence lint. Every
  file:line cited in a verdict's `first_links`/`rationale` must resolve
  under the target clone and be in range; a `false_positive`/`hardening`
  verdict citing broken evidence gets `re_vote_recommended` (hallucinated
  refutations are the most dangerous wrong-FP mode), a `true_positive`
  gets `review_recommended`. Routes only; never flips a verdict.

### triage (`harnessing/triage/`)

- Phase 3c dissent escalation: a TRUE_POSITIVE vote with confidence ≥ 8
  against a FALSE_POSITIVE/HARDENING majority buys exactly one extra
  verifier vote; surviving dissent is preserved verbatim in the rationale.
- Phase 3d: verdict-citation lint wired between tally and checkpoint,
  with one re-vote per flagged dismissal.
- Phase 6c/6d reordered: validate JSON first, then render Markdown via
  render_triage.py.
- Phase 6e terminal summary: false-positives-by-exclusion-rule line as a
  regression tripwire (rule 13 appearing there means broken tally logic)
  plus a verdict-lint status line.
- Self-contained smoke-test fixture: `fixtures/canary-target/` (entry.c +
  deploy/deployment.yaml) ships in-repo; canary set grows to seven with
  one per verdict path, including the two taxonomy regression canaries —
  f006 accurate CIS-style gaps that must return `hardening`, f007 a
  nonexistent cited file that must return `undetermined`.

### docs

- `docs/triage-ledger-integration-draft.md`: DRAFT verdict→ledger event
  mapping for track-findings integration (source_type `triage_report`,
  countersign-preserving FP evidence events, hardening validity-axis
  options, no-event mapping for undetermined). Explicitly awaiting
  track-findings owner review before any implementation.

### tests

- `tests/test_triage_tooling.py` (16 tests): renderer sections and
  determinism, citation extraction, hallucinated-refutation re-vote
  routing, canary fixture/target line-number consistency.

## v0.25.0 — 2026-07-11

Minor release: triage output schema + validator gates, aligned with the
report schema's conventions.

### schema

- New `schema/triage.schema.json` for TRIAGE.json / `*-triage.json`,
  built from `report.schema.json`'s vocabulary: identical five-level
  lowercase `severity_level` enum, canonical `{REPO_SLUG}-{SHORTSHA}-{NNN}`
  `orig_id` cross-referencing, ISO dates, `additionalProperties: false`
  on findings, and a required `triage_context.harness_version` that pins
  the verdict-taxonomy epoch (solves the pre/post-0.24.0 FP-rate
  comparability problem machine-readably).

### validate_report.py

- New `cross_validate_triage` gates that machine-enforce the 0.24.0
  taxonomy: `exclusion_rule 13 ⇔ verdict hardening` (both directions,
  hard error), false positives require non-empty `refute_reasons`,
  `undetermined` carries no confident conclusion, derived severity on
  true positives only, duplicates reference a real non-duplicate
  canonical, summary counts and `by_severity` reconcile with the findings
  array. Warnings: verdict contradicting a strict vote majority,
  non-canonical `orig_id` in a canonical batch.
- Filename-based schema auto-detection: `TRIAGE.json` / `*-triage.json`
  select the triage schema unless `--schema` is passed explicitly.
  Directory sweeps over `findings/` now validate triage artifacts against
  the right schema instead of failing them wholesale against the audit
  report schema. Legacy pre-0.24.0 triage artifacts fail meaningfully
  (missing harness_version, old shapes) until re-emitted — an intentional
  drift gate.

### triage (`harnessing/triage/`)

- Phase 6d added: TRIAGE.json must pass `validate_report.py` with 0
  errors before the done checkpoint — same completion contract as
  secure-code-audit. `validate_report.py` added to the skill's Bash
  allowlist.
- Output contract aligned with the schema: lowercase severity vocabulary
  shared with report.schema.json, `triage_completed` as ISO date,
  `harness_version` in triage_context, summary key names fixed.

### tests

- `tests/test_validate_triage.py` (21 tests): schema acceptance/rejection,
  every cross-validation gate, and filename auto-detection.

## v0.24.0 — 2026-07-11

Minor release: triage verdict taxonomy — hardening gaps and inaccessible
material are no longer recorded as false positives.

### triage (`harnessing/triage/`)

- New verifier verdict **HARDENING** and finding verdict **`hardening`**:
  exclusion rule 13 (missing-hardening/best-practice gap with no concrete
  exploit) now yields HARDENING instead of FALSE_POSITIVE. Explicitly
  covers benchmark-derived findings — CIS Benchmark, DISA STIG, OpenSSF
  Scorecard, SLSA posture, securityContext/PSA/NetworkPolicy/pinning gaps
  — when the control is genuinely absent but no attacker path is proven.
  Hardening findings skip severity ranking but keep Phase 5 owner routing
  and land in a dedicated "Hardening backlog" report section.
- New finding verdict **`undetermined`**: unlocatable/unreadable cited
  material (Phase 1b, citation-gate `file_missing`), all-CANNOT_VERIFY
  tallies, and precision-policy split votes now emit `undetermined`
  (`needs_manual_test`, confidence 0 where applicable) instead of
  `false_positive`. `false_positive` is reserved for findings with
  positive evidence of wrongness. `refute_reasons` for unlocatable
  findings change from `doesnt_exist` to `unlocatable`.
- Tally rules generalized: majority over TP/HARDENING/FP with
  CANNOT_VERIFY excluded; TP-vs-HARDENING-only splits resolve to
  `hardening` (the agreed floor); splits involving FP resolve per noise
  tolerance (precision → `undetermined`, recall → TP+needs_manual_test,
  ask → user chooses confirm/hardening/undetermined).
- Output contract: TRIAGE.json summary gains `hardening` + `undetermined`
  counts, `vote_breakdown` gains `hardening`; TRIAGE.md gains "Hardening
  backlog" and "Undetermined" sections (Dropped now holds only refuted
  findings and duplicates); sort order true_positive → hardening →
  undetermined → duplicate → false_positive.
- docs/skills.md and the skill README document the taxonomy;
  check_citations.py docstring and the deterministic-tooling assessment
  updated to match (`file_missing` → `undetermined`).

## v0.23.0 — 2026-07-10

Minor release: the **threat-model** and **patch** skills are ported into
the harness from user-level skills (skills 24 and 25), and the shared
checkpoint helper is consolidated into `scripts/`.

### threat-model (`harnessing/threat-model/`)

- Three modes writing `<target-dir>/THREAT_MODEL.md` in a shared schema:
  `bootstrap` (parallel research swarm over code + past vulns, five
  checkpointed stages), `interview` (four-question owner walk), and
  `bootstrap-then-interview`. Ships SKILL.md + bootstrap.md +
  interview.md + schema.md + README.
- Static-analysis-only safety preamble; bootstrap checkpoints to
  `./.threat-model-state/`. Dangling vuln-pipeline-era doc links replaced
  with harness references (AGENTS.md Security Testing Context).

### patch (`harnessing/patch/`)

- Post-triage candidate-fix generation: per-finding patch subagent +
  independent reviewer, inert diffs under `./PATCHES/bug_NN/` with
  PATCHES.md/PATCHES.json roll-ups. No apply capability by design; Write
  scope confined to `./PATCHES/` and `./.patch-state/`. Cross-referenced
  with `remediate-finding` (the fork-and-test counterpart).

### scripts

- `checkpoint.py` moves from `harnessing/triage/` to `scripts/` — it is
  shared state-I/O for triage, threat-model, and patch. All three skills
  reference `python3 <harness>/scripts/checkpoint.py`; triage's
  `<skill-base>/checkpoint.py` references updated accordingly.

### docs

- `docs/skills.md`: pipeline rows (threat-model ② pre, patch ② post) and
  full sections for both; README skills table rows; skill counts 23 → 25;
  `docs/architecture.md` scripts table gains checkpoint.py.
- Discovery symlinks and slash-command wrappers added for both skills
  (Claude Code + Crush) per AGENTS.md conventions.

## v0.22.0 — 2026-07-10

Minor release: the **triage** skill is ported into the harness from a
user-level skill, becoming the 23rd active skill.

### triage (`harnessing/triage/`)

- Six-phase adversarial triage of raw scanner output: interview →
  ingest/normalize → dedup → N-vote adversarial verification → rank by
  precondition-derived severity → route to owners; emits TRIAGE.json +
  TRIAGE.md. Checkpointed per phase to `./.triage-state/` (resumable).
- `checkpoint.py` (previously `~/.claude/skills/_lib/`) now ships inside
  the skill directory; all references use `<skill-base>/checkpoint.py`.
- Wired to the v0.21.0 deterministic accelerators by path relative to the
  skill's own base directory (`<harness> = <skill-base>/../..`): Phase 2c
  citation gate routes vote spend, Phase 2d warms the symbol index, and
  verifier prompts use `query_index.py` for one-lookup reachability with
  Grep fallback. "Harness not checked out" fallbacks dropped — the skill
  lives in the harness now; accelerator errors still degrade gracefully.
- Discovery symlinks (`.claude/skills/triage`, `.crush/skills/triage`)
  and slash-command wrappers (`.claude/commands/triage.md`,
  `.crush/commands/triage.md`) added per AGENTS.md conventions.
- Docs: pipeline table + full skill section in `docs/skills.md`
  (stage ② post-audit), README skills table row, skill counts 22 → 23.

## v0.21.0 — 2026-07-10

Minor release: deterministic triage accelerators — citation gate and
per-run symbol index. Design rationale in
`docs/deterministic-tooling-assessment.md`. Both tools follow the
harness invariant: they route, gate, tag, or index — never conclude.

### check_citations.py (`scripts/`)

- New citation gate for triage: deterministic file/line/anchor pre-check
  run between dedup and verification. Verifies the cited path resolves
  under the target clone (tolerating `./`, `src/`, `app/`, and
  repo-basename prefix skew; repo-escaping paths rejected), the cited
  line is in range, and backtick-quoted anchors from the finding text
  appear within ±15 lines (whole-file fallback → `line_drifted`).
- Tags map to vote routing only: `ok`/`line_drifted` → full votes,
  `anchor_absent` → single vote, `file_missing` → skip verification
  (`needs_manual_test`, confidence 0). Worst tag wins across multi-
  location findings. Accepts triage phase1.json or audit-report
  `locations[]` format.

### build_symbol_index.py + query_index.py (`scripts/`)

- Per-run SQLite symbol index of a target clone, keyed by `(repo, sha)`
  at `$TMPDIR/symbol-index/<repo>-<sha>.db` — derived data that
  self-invalidates; no manual freshness management.
- Engines: `ctags` (universal-ctags, preferred when installed; macOS BSD
  ctags detected and skipped) and `builtin` (zero-dependency Go/Python/
  TypeScript/JavaScript/Shell definition extractors); `auto` default.
  Vendor/node_modules/testdata excluded.
- `query_index.py --defs NAME` (exact, then bounded fuzzy fallback),
  `--refs NAME` (word-boundary textual references, definition sites
  marked, capped at 200), `--file-symbols PATH`; `--json` mode;
  auto-builds the index on first query so one call always works.
- Accelerator, not gatekeeper: consumers fall back to grep on index
  misses; a miss is never evidence of absence.

### docs

- New `docs/deterministic-tooling-assessment.md`: where deterministic
  tools belong in the harness (five insertion points, cost baseline from
  the 2026-07-09 agent-control-plane run, anti-goals, invariants
  checklist, roadmap).
- `docs/setup.md`: universal-ctags as optional dependency;
  `docs/architecture.md` + `AGENTS.md`: scripts table updated.

### tests

- `tests/test_check_citations.py` (15 tests) and
  `tests/test_symbol_index.py` (13 tests; ctags-engine test auto-skips
  when universal-ctags is absent).

## v0.20.1 — 2026-07-10

### verify-remediation

- Restructured the Gotchas section into four phase-referenced groups
  (Verdict integrity, Evidence standards by framework, Git history &
  attribution, Scope discipline) with a pre-delivery-checklist framing.
  Bullet text unchanged — pure reorganization.

## v0.20.0 — 2026-07-10

Minor release: new **findings-trends** skill — upward/downward portfolio
trends by disposition-ledger replay.

### findings-trends (`harnessing/findings-trends/`)

- New skill + `build_trends.py`: reconstructs the portfolio state at every
  monthly (or weekly) boundary by replaying each repo's track-findings
  ledger — no snapshots, no stored trend state, fully deterministic.
  Reuses the track-findings merge engine so the false-positive
  human-countersign rule holds at every point in time.
- Metrics with direction arrows and polarity (± 10% dead band, ⚠ on
  worsening): open findings, CVSS-sum risk index, remediation velocity,
  new findings, MTTR by severity, regressions, false-positive rate,
  accepted-risk index, ledger coverage.
- Option A open counting: findings in ledger-less repos count as open
  (total exposure), with ledger coverage printed next to every headline.
- Standing **Accepted Risk Register**: risk-accepted findings reported as
  unfixed-and-unmitigated with severity, CVSS, who accepted, when, and
  rationale; tracked as their own CVSS-sum trend, never lumped into
  "closed".
- Risk index = sum of per-finding CVSS scores; severity band midpoints
  (9.5/8.0/5.5/2.0/0) as fallback. Custom weighting deferred by design.
- New optional `occurred_at` on layer events (source timestamp: commit
  date, Jira transition, MR comment date) — trends bucket by it so late
  ingestion doesn't distort series; validator warns when it postdates
  `recorded_at`; track-findings adapters instructed to set it.
- Outputs `analysis-results/trends/findings-trends.{json,md,html}`
  (direction table, burndown, risk-index and flow charts, MTTR, register).
- 24 new tests; replay of the full 8,129-repo production corpus in ~2 s.

## v0.19.1 — 2026-07-10

### executive-summary-findings

- New remediation metric: a "Findings remediated" KPI (fully-resolved
  count, colored green, with a per-severity breakdown in the Markdown
  Remediation Status section) and a "Remediation Trend" stacked bar chart /
  table — resolved and partially-resolved findings per month, bucketed by
  each finding's last disposition event date from the track-findings
  ledger. Rendered only when disposition data exists.

## v0.19.0 — 2026-07-10

Minor release: the roll-up dashboards prefer track-findings cumulative
reports by default.

### executive-summary-findings, insecure-patterns, repo-graph

- All three build scripts now look for a sibling
  `<repo>-findings-current.json` (track-findings cumulative report) next to
  every `*-security-audit.json` and use it **instead of** the audit when
  present, falling back to the audit if the cumulative file is unreadable.
- Human-confirmed false positives (`validation_status: false_positive`) are
  excluded from every aggregate; severity counts for dispositioned repos are
  recomputed from the surviving findings rather than trusted from
  `executive_summary.severity_counts`.
- executive-summary-findings: new "Remediation Status" section (Markdown)
  and closure-rate KPI + card (HTML) — dispositioned-repo count, resolution
  breakdown, excluded-FP count; Top Critical & High tables gain a Status
  column showing each finding's resolution.
- insecure-patterns: stats table and console output report how many reports
  carried dispositions; methodology section updated.
- repo-graph: findings nodes gain `dispositions`, `resolved_findings`,
  `open_findings`, `false_positives` attributes (counted from findings with
  FPs excluded); stats.md reports ledger coverage.
- SKILL.md docs updated for all three skills.

## v0.18.0 — 2026-07-10

Minor release: new **track-findings** skill — an append-only findings
disposition ledger plus cumulative status reports.

### track-findings (`harnessing/track-findings/`)

- New skill: ingests human triage feedback (MR/PR comments, commit
  messages, Jira tickets, interactive sessions) and machine results
  (`*-validation.json`, `*-remediation-verification.json`) into an
  append-only `<repo>-findings-layer.json` ledger, then regenerates a
  `<repo>-findings-current.{json,md}` cumulative report. The original
  audit report is never modified.
- Two-axis disposition model: validity (mirrors `validation_status`) and
  resolution (`open`/`fix_in_progress`/`resolved`/`partially_resolved`/
  `risk_accepted`/`regression_introduced`).
- Three-tier trust policy for human statements: explicit grammar +
  LDAP-verified identity + package-owner/maintainer authority auto-records;
  everything else queues in `needs_review` until a human confirms;
  model-inferred intent never changes state.
- Human-countersign rule: machine `refuted` evidence raises
  `refuted_awaiting_signoff`; `validation_status: false_positive` requires
  an LDAP-verified human event (validator-enforced).
- `build_cumulative.py` deterministic merge engine (precedence tiers,
  conflict detection, disposition summary); events carry deterministic
  sha256 `event_id`s so re-ingesting the same source is idempotent.
- New `schema/layer.schema.json`; `report.schema.json` gains optional
  `finding.disposition` + `disposition_summary` (cumulative reports only)
  and an updated `validation_status` `$comment`; `validate_report.py`
  gains `cross_validate_layer` (hash integrity, chronology, identity rule)
  and disposition-consistency checks on base reports.
- 33 new tests (`tests/test_build_cumulative.py` + layer/disposition cases
  in `tests/test_validate_report.py`); docs, README/AGENTS skill count
  (21), and slash commands updated; cross-references added from
  `verify-remediation` and `file-security-defect`.

## v0.17.0 — 2026-07-10

Minor release: schema-validated **verify-remediation** reports, GitLab MR
support, and two new disposition verdicts.

### verify-remediation (`harnessing/verify-remediation/`)

- New `schema/verification.schema.json` for
  `<repo>-remediation-verification.json` reports, plus a
  `cross_validate_verification` pass in `scripts/validate_report.py` that
  automates the former Phase 7a honor-system checklist (verdict counts,
  finding coverage, attribution consistency, chronological
  `commit_timeline`, regression ID format). Phase 7a now requires running
  the validator; `summary` is restructured to the house `by_verdict` shape.
- GitLab merge request support: `merge-requests/<iid>/head` refspec
  alongside the GitHub `pull/<number>/head` one, MR-number (`!NN`)
  extraction in commit attribution, a GitLab example, and a forge-refspec
  gotcha. Inputs now state explicitly that unmerged PRs/MRs and branches
  are verifiable as-is.
- New verdicts `false_positive` and `risk_accepted` (both requiring
  `disposition_rationale`) so team dispositions are no longer force-fitted
  into `unresolved`; decision tree and summary tables updated.
- Phase 5 regression scan now scopes explicitly: full diff for fix
  branches/PRs, remediation-commit files for `latest`-mode mega-diffs,
  with the scoping decision recorded in the report `notes` (no silent
  truncation).
- Fixed duplicated subsection numbering (Phase 4 was labelled 3a–3d);
  regressions now carry CVSS like original audit findings; default output
  location pinned next to the original audit report; `metadata.patched_ref`
  records the exact ref verified.
- 24 new tests in `tests/test_validate_report.py`; docs (README,
  docs/outputs.md) and the slash command updated.

## v0.16.1 — 2026-07-10

### validation-fuzz-dashboard

- Also emits `Live-validation-fuzz-dashboard.md` — a Markdown one-pager with
  the same numbers as the HTML dashboard (headline, verdict×severity table,
  top targets, fuzz hit-rates/bugs, confirmed-Critical list). New `--out-md`
  flag; default is the HTML path with a `.md` extension.
- Docs: corrected active-skill count (12/15 → 20) in README + AGENTS.md and
  added the five missing skills to the README table.

## v0.16.0 — 2026-07-10

Minor release: new **validation-fuzz-dashboard** skill.

### validation-fuzz-dashboard (`harnessing/validation-fuzz-dashboard/`)

- New `SKILL.md` + `build_validation_fuzz_dashboard.py`: aggregates every
  `validations/*/*validation*.json` live-validation report plus
  `FUZZ-CAMPAIGN-SUMMARY.md` into a single self-contained
  `Live-validation-fuzz-dashboard.html` (inline SVG, no CDN, light/dark,
  tooltips + table views).
- Surfaces: confirmed-exploitable hero number, verdict share by claimed
  severity (status palette; NOT_ATTEMPTED excluded and shown as a coverage
  meter instead), top targets by confirmed findings, attack chains with ≥ 1
  confirmed step, fuzz pattern hit-rates, and the confirmed fuzz-bug table.
- Slash command `/validation-fuzz-dashboard` + Claude/Crush skill symlinks.

## v0.15.0 — 2026-07-08

Consistency gates for report fields (schema, validator, renderer) — pins
`validation_status` and other per-batch-oscillating fields against prompt
drift; see commit `73fff97` for the drift-audit rationale. *(Backfilled
entry.)*

## v0.14.0 — 2026-07-06

Minor release: promote **fuzz-harnesses** from tooling directory to active
skill.

### fuzz-harnesses (`harnessing/fuzz-harnesses/`)

- New `SKILL.md` wrapping the existing `targets.json` + `Makefile` +
  `harnesses/<id>/*_fuzz_test.go` workflow so agents can add a target,
  author a white-box Go fuzz test, drive
  `make clone install build fuzz-<id>`, and triage crashers into
  follow-up findings — all offline (no cluster/cloud/network at fuzz time).
- Wired into agent discovery: `.claude/skills/fuzz-harnesses` and
  `.crush/skills/fuzz-harnesses` symlinks; `/fuzz-harnesses` slash command
  for both agents.
- README skills table updated (14 → 15 active skills).

## v0.13.0 — 2026-07-06

Minor release: promote **secure-rpm-audit** from draft to active skill.

### secure-rpm-audit (`harnessing/secure-rpm-audit/`)

- Wired into agent discovery: `.claude/skills/secure-rpm-audit` and
  `.crush/skills/secure-rpm-audit` symlinks added; `/secure-rpm-audit`
  slash command added for both agents.
- Finding IDs migrated from legacy `FIND-NNN` to the campaign-wide
  `{COMPONENT_SLUG}-{SHORTSHA}-{NNN}` format introduced in v0.12.0, with
  an `RPM_` prefix rule for components whose name begins with a digit
  (e.g. `389-ds-base` → `RPM_389_DS_BASE`) so the schema anchor
  `^[A-Z]` is satisfied.
- README skills table updated (13 → 14 active skills); draft caveat
  removed.

## v0.8.1 — 2026-07-01

Minor release: new **repo-graph** skill for building/refreshing the
portfolio repository graph.

### repo-graph (new — `harnessing/repo-graph/`)

- `build_repo_graph.py` — ingests `hybrid-platforms-inputs/{openshift,
  operator-catalog,services}` CSV inventories (default excludes `ansible/`),
  indexes `analysis-results/findings/*/*/name-security-audit.json` by
  `metadata.repository`, links repos → findings (exact URL match with a
  guarded name-only fallback that never claims a dir whose recorded URL
  points elsewhere), and emits `repo-graph.{json,dot,gexf,html}` +
  `repo-graph-stats.md` into `analysis-results/graph/`.
- Node types: `segment`, `release`, `product`, `product-version`,
  `category`, `owner-team`, `repo`, `findings`. Edge relations: `contains`,
  `ships`, `owned-by`, `has-findings`. Repo nodes coloured by max triaged
  severity and carry `tp_total` / `findings_dirs`.
- HTML view collapses `product-version`/`category` into tooltips so the
  ~10k-node graph stays interactive; text filter + segment-focus dropdown.
- First run: 10,175 nodes / 15,038 edges; 3,209/3,293 repos (97.4%) linked
  to findings; top hub `openshift/kube-rbac-proxy` (ships in 85 products).

### Housekeeping

- `pyproject.toml` version synced with `VERSION` (was stale at 0.7.1).

## v0.6.0 — 2026-06-22

Minor release: new **validate-core-ocp** track for live validation of core
OpenShift payload ClusterOperators (sibling to validate-operator-live, no
provision/OLM-install/teardown). Driven by the core-OCP 4.22 pilot on
isolated lab cluster `stc-ipi`; first full pass produced 15 live-confirmed
findings across 26 COs.

### validate-core-ocp (new — `harnessing/validate-core-ocp/`)

- `co_namespace_map.py` — ClusterOperator ↔ namespaces (live `relatedObjects`
  + static fallback) ↔ payload repos ↔ findings sources.
- `blast_radius.yaml` — tier-1/2/3 CO assignments with per-tier
  `verbs_denied` / `off_limits`. Tier-3 includes `apply, create` after the
  2026-06-22 single-node kube-apiserver-rollout incident.
- `gen_targets.py` — per-CO `targets.yaml` with **explicit** namespace
  allowlist (only sanctioned `CONTROL_PLANE_NS_PATTERNS` unlock path).
- `oauth_token.py` — mint short-lived `kube:admin` `OAuthAccessToken` for
  HTTP probes; exported as `VF_OAUTH_TOKEN`.
- `run_one.sh` / `run_tier.sh` — one-CO and per-tier orchestrators.
- `build_manifest.py` / `update_progress.py` — campaign manifest with
  fcntl-locked atomic row updates.
- `coverage.py` / `gen_gaps.py` — PoC-coverage analyzer + `GAPS.md`.
- `build_dashboard.py` — self-contained Chart.js HTML dashboard.
- `SKILL.md` — agent prompt, symlinked under `.claude/skills/`.

### validate-findings

- **`_http_adapted_step()`** (`plan.py`): conditional `port-forward+http`
  for CWE-918/306/295/319/200/532 — emits a step **only** when
  `(method, path[, port])` is extractable from `finding.{title,
  attack_pattern, description}` or a linked threat-model entry_point.
  Route-first, svc port-forward fallback, CSRF cookie round-trip,
  `${VF_OAUTH_TOKEN:-SA-token}` bearer. Preserves v0.4.x skip behaviour
  for CR-field SSRF (no path → no step).
- **`_spoof_adapted_step()`**: CWE-290/348 — extract `X-*` header name and
  replay with canary value.
- **`_secret_adapted_step()`**: CWE-312/522/256/313/540/260 — scan decoded
  Secret/ConfigMap data for credential-shaped strings.
- **`CWE_SKIP_REASON`**: categorized `not_attempted` reasons in place of
  opaque `no-poc-no-adapter` for CWEs that genuinely cannot be auto-probed
  (`dos-needs-destructive-load`, `needs-cr-manifest`,
  `needs-config-field-ref`, `crypto-needs-statistical-test`,
  `supply-chain-not-cluster-validatable`, `needs-protocol-crafting`,
  `needs-failure-injection`).
- **`CWE_ADAPTED`**: CWE-489/215 → `GET /debug/pprof/` via the HTTP scaffold.
- **`_verdict()`** (`adapters/k8s.py`): `401` on a finding whose
  precondition is "authenticated user" → `inconclusive` (probe could not
  satisfy auth model) instead of false `refuted`.
- **`preflight()`** (`execute.py`): shim that delegates to bound adapters'
  `preflight()`. `run.py` always called `ex.preflight()` but it never
  existed, so `metadata.target_fingerprint` was always `[]`. Now populated
  for both core-OCP and operator runs.

PoC coverage on the 4.22 payload (169 runtime-TP findings): 55% → 95% with
steps; 100% accounted for (step or categorized reason); 0 High/Critical
residual gaps. 193/193 tests pass.

## v0.4.4 — 2026-06-20

Patch release driven by `analysis-results/validations/_manifest/MANUAL-REVIEW-FLAGS.md`
(6 false-positive `confirmed` verdicts traced to `_verdict()` step-3 substring matching).

### validate-findings

- **`_verdict()` probe-target-not-found guard** (`adapters/k8s.py`): before
  expected-token matching, if `observed` matches `(?i)\b(notfound|not found|
  no such file|no such container|is not valid for pod|does not exist|
  could not resolve host)\b` and verb ∈ {`raw`, `get`, `exec`,
  `port-forward+http`} → return `inconclusive` and tag the `StepResult`
  with `error="probe-target-not-found"`. NotFound is environmental (the pod
  / container / path the PoC targets isn't present in this lab install),
  distinct from the block-token → refuted path.
- **`_verdict()` word-boundary token match**: step-3 expected-token matching
  changed from `tok in observed` substring to
  `re.search(r'\b'+re.escape(tok)+r'\b', observed)` for tokens ≥4 chars, so
  `account` no longer matches inside `serviceaccount`, `error` inside
  `errored`, etc.
- **`_verdict()` claim-vocabulary stop-list**: new `_VERDICT_STOP =
  {error, container, pod, service, account, request, server, client}` —
  words that appear in both claim text and generic kubectl error text. A
  match on these alone never confirms; step 3 now requires ≥1 non-stop
  strong token.
- `StepResult` gains an `error: str` field for environmental-failure
  attribution (currently only `probe-target-not-found`).
- 8 new `TestK8sVerdict` cases covering the three guards + a regression
  guard that distinctive tokens still confirm.

This caused 6 FP confirms (kube-rbac-proxy/FIND-001 ×5 — gatekeeper,
business-automation, ptp-operator, kubernetes-nmstate, medik8s — plus
devspaces oauth-proxy/FIND-002), now downgraded to `inconclusive` with a
`verdict_note` in the existing reports.

### deploy-operator

- `product_map.py` `"OpenShift AI / RHODS"` `findings_packages` was missing
  `"red-hat-data-services"` (per `progress-tracker/VALIDATION-PRIORITY-LIST.md:97`);
  added so the RHODS run ingests the GitHub-org repos as well.

### misc hardening (carried from in-flight WIP)

- `AdapterBase._run()`: catch `subprocess.TimeoutExpired` → `(124, out, err)`
  instead of propagating.
- `K8sAdapter.rollback()`: skip `kubectl delete -f -` when the apply was
  rejected (`denied the request` / `is invalid` / `(Forbidden)` /
  `validation failed`) so we don't delete a pre-existing operand CR of the
  same name; add `--wait=false --timeout=30s`.
- `execute.run()`: wrap `adapter.rollback()` in `try/except` so a rollback
  exception doesn't abort the run.
- `ingest._parse_triage_json()`: accept string `confidence` values
  (`high`/`medium`/`low` → 0.9/0.5/0.1).

## v0.4.3 — 2026-06-19

Patch release driven by `analysis-results/validations/_manifest/INCONCLUSIVE-ANALYSIS.json`
(852 inconclusive verdicts across waves 2–14; 449 harness-defect, 193 signal-ambiguous).

### validate-findings

- **`port-forward+http` curl write-out** (273 inconclusives): `plan.CWE_ADAPTED`
  stored `'%{{http_code}}'` as if `str.format()` were applied, but `_adapted_step()`
  passes the string through verbatim → curl saw the doubled braces and emitted
  `unknown --write-out variable: '{http_code'`. Fixed the literal and added
  `K8sAdapter._normalize_curl()` which un-escapes `%{{var}}` and appends
  `-w 'vf-http-status:%{http_code}'` whenever a curl PoC has no write-out, so
  the status code is always observable.
- **`exec` None-target guard** (93 inconclusives): adapted CWE-77/78 steps set
  `target={"context": ctx}` with no pod name; `subprocess.run([..., None, ...])`
  raised `TypeError('expected str, bytes or os.PathLike object, not NoneType')`.
  `K8sAdapter.execute()` now early-returns an attributable
  `inconclusive / target-unresolved:no pod/name` instead of an adapter-error.
- **`apply-manifest` YAML normalizer** (~60 inconclusives): replay PoCs are raw
  fenced blocks; ~44 carry a prose lead-in containing `:` (`mapping values are
  not allowed in this context`), mixed indentation (`could not find expected ':'`),
  or non-object docs (`cannot unmarshal string/array`). New
  `K8sAdapter._normalize_manifest()` round-trips through `yaml.safe_load_all` /
  `safe_dump_all`, keeping only docs with `apiVersion` + `kind`.
- **`_verdict()` tightening** (targets 193 signal-ambiguous):
  - `rbac-can-i`: handle `yes - <reason>` / `no - <reason>` suffixes.
  - `port-forward+http`: parse trailing `%{http_code}`; `2xx` + expected
    mentions unauthenticated/SSRF/exposed/pprof/metrics → confirmed; `401/403`
    → refuted (or confirmed if expected IS a denial); `000`/refused → inconclusive.
  - `exec`: `uid=0(root)` + expected root/escalation → confirmed;
    `Permission denied` / `Operation not permitted` / `Read-only file system` → refuted.
  - `apply-manifest`: expected-is-denial + observed `created` → **refuted**
    (precedence fix); `(Cluster)RoleBinding ... created` + expected mentions
    cluster-admin/escalation → confirmed.
  - `raw`/`get`: `No resources found` / `items: []` / `{}` + expected
    read/leak/secret → refuted; expected secret/token/credential + observed
    base64-looking blob → confirmed; CRB-created escalation rule mirrored.
  - `network-probe`: `succeeded`/`open`/`connected` → confirmed;
    `refused`/`timeout`/`no route` → refuted.

### deploy-operator

- `resolve_package.resolve()` now honours the
  `operatorframework.io/suggested-namespace` annotation from the CSV
  (`PackageManifest.status.channels[].currentCSVDesc.annotations`). Operators
  that hard-code RBAC/webhook selectors to that namespace (SMB CSI, EFS CSI,
  Lifecycle Agent) previously landed in `glasswing-<pkg>` and never reconciled.

### tests

- Repaired `TestK8sVerdict` (broken since the v0.4.2 `verb` parameter was added).
- Added `TestK8sNormalizers` and 14 corpus-derived `_verdict()` cases.

## v0.4.2 — 2026-06-18

See git log.
