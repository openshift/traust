# Setup reference

> New to the harness? The tiered requirements overview is
> [requirements.md](requirements.md) and the first-audit walkthrough is
> [getting-started.md](getting-started.md); this page is the complete
> reference for installation, configuration, storage, toolchain, and the
> contributor gates, in install order.

## 1. Start here: `install_traust`

```bash
scripts/install_traust            # choose TRAUST_CONFIG_HOME, copy templates,
                                  # persist the variable, optionally install the toolchain
scripts/install_traust --doctor   # verify variable, files, parsing, resolver, toolchain
```

The harness will not run without `TRAUST_CONFIG_HOME` pointing at a directory
holding the operational config files: corpus registry, product map, budget
policy, safe-exec profiles, rule-pack allowlist, hardening weights, dist-git
watch list, internal vocabulary, ledger signing public key. None of them is in
this repository; `config/` ships templates only. `install_traust` creates the
directory from those templates (default `~/.traust/config`; a deployment's
orchestrator points the variable at its private config checkout), you edit each
file (every one opens with a comment block describing its fields) and generate
your ledger signing key ([signing.md](signing.md)). A missing file fails closed.

`--doctor` is the troubleshooting entry point: it reports every missing or
unparseable file, any file still carrying its template banner, whether the
resolver actually reads from your directory, and which scanner binaries are
absent. Flags for CI: `--yes --config-home DIR --toolchain PROFILE`
(`--no-toolchain`, `--no-profile-write`, `--force` also available). The full
contract: [config/README.md](../config/README.md).

## 2. Prerequisites

- Python 3.11+ and [`uv`](https://github.com/astral-sh/uv) (or pip with the
  hash-pinned lockfile, below)
- Git access to this repository and, for the multi-repository pipeline, the
  sibling data repositories (§3)
- Network access to the forge holding the repositories you audit
- A ledger identity for anyone who countersigns: `ledger auth login`
  against your OIDC provider, or `ledger auth local` where there is none
  (local tokens countersign only with `HARNESS_COUNTERSIGN_ALLOW_LOCAL=1`
  — see the countersign skill). Optionally an employee-directory command
  (`LEDGER_DIRECTORY_COMMAND`) the ledger runs to confirm a signer is a
  current member of your organisation.

Scanner tools are per capability, not global: nothing beyond the baseline is
needed until a skill calls for it. What each capability needs is the table in
[requirements.md](requirements.md); the pinned versions are the manifest
`config/external-tools.yaml`; licenses and citations are in
[external-dependencies.md](external-dependencies.md). Installing them is §4.

## 3. Clone the workspace and install

Standalone use needs only this repository. The multi-repository pipeline
expects a **workspace**: a parent directory holding the harness beside the
data repositories, which hold content, not code, and are referenced by
relative path ([storage.md](storage.md) for what goes where):

```bash
# FORGE is your git host and namespace, e.g. git@gitlab.example.com:my-team
FORGE=<your-forge-and-namespace>

mkdir harness-workspace && cd harness-workspace
git clone "$FORGE/traust.git"
git clone "$FORGE/analysis-results.git"        # findings store (name is the deployment's)
git clone "$FORGE/<inputs-inventory>.git"      # scope declarations, repo rosters
git clone "$FORGE/progress-tracker.git"        # metrics tree (name is the deployment's)

cd traust && uv sync
```

No `uv`? `pip install --require-hashes -r requirements.lock`.

`uv sync` pulls the code dependencies from release tags — `traust-engine`
(scanner adapters, corpus, metrics, reporting, the gateway to the ledger) and
`traust-contracts` (schemas, enums, shared models) — and, through
traust-engine, `traust-ledger` (finding identity, Merkle integrity, signing).
Clone those only to change them. What each owns, which one to change for a
given fix, how the pins work and how they fail (`uv lock` "conflicting URLs"):
[components.md](components.md). `/check-drift` reports an installed package
that does not match its pin; `uv sync` fixes it.

## 4. Scanner toolchain

The harness ships an opinionated, version-pinned toolchain. You name a
**profile** and it handles install, database population and provenance
stamping. Profiles are the `consumers` values in `config/external-tools.yaml`
(one per skill that needs external tools, plus `ledger-signing`); the CLI lists
them when given an unknown name.

```bash
./scripts/install-toolchain.sh secure-code-audit          # binaries + DBs for one profile
./scripts/install-toolchain.sh --all                      # every profile
python3 -m traust.cli admin toolchain setup --profile secure-code-audit   # same, via the CLI
python3 -m traust.cli admin toolchain doctor --profile secure-code-audit  # verify
```

Binaries download straight from each project's own upstream release at the
version pinned in the manifest — the same pins the toolchain container image
consumes, so workstation and job image match — and are verified against the
upstream checksum where the project publishes one. No third-party package
manager or index sits in between. Binaries land in `~/.local/bin` (override
with `HARNESS_BIN_DIR`); `--dry-run` previews. macOS and Linux. `doctor` exits
0 when every tool for the profile is installed at the pinned version with its
databases populated, 1 with a per-tool diagnostic otherwise; `/drift-watch`
runs the same comparison continuously.

Step by step, if you need to install by hand:

| Tool | Upstream release | Checksum verified |
|------|------------------|-------------------|
| `opengrep` | github.com/opengrep/opengrep | no (upstream publishes none) |
| `gitleaks` | github.com/gitleaks/gitleaks | yes |
| `syft` | github.com/anchore/syft | yes |
| `grype` | github.com/anchore/grype | yes |
| `osv-scanner` | github.com/google/osv-scanner | no (upstream publishes none) |
| `cosign` | github.com/sigstore/cosign | yes |
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@<pin>` (needs a Go toolchain) | Go module checksum DB |

Take the pin from the manifest and fetch that tag's asset for your OS/arch.
Tools with no standalone upstream binary come from a package manager:

| Tool | Install method |
|------|---------------|
| `joern` | `brew install joern` or the [joern release](https://github.com/joernio/joern/releases) (Java 11+) |
| `skopeo` | `brew install skopeo` (macOS), `dnf install skopeo` (Fedora/RHEL) |
| `yara` | `brew install yara`, or build from the [yara release](https://github.com/VirusTotal/yara/releases) |
| `pip-audit` | `pipx install pip-audit` |
| `checkov` | `pipx install checkov==<pin>` — the pin is `PINNED_CHECKOV_VERSION` in `harnessing/3-audit/cloud-config-audit/scripts/run_checkov.py`, which hard-fails on a mismatch |

Vulnerability databases (grype, osv-scanner, govulncheck) are populated by
`setup`; to refresh them, or to bundle them for an air-gapped host:

```bash
python3 -m traust.cli admin toolchain fetch-dbs --profile secure-container-audit
python3 -m traust.cli admin toolchain fetch-dbs --profile secure-container-audit --offline-bundle dbs.tar.gz
```

### Container image (CI, platform worker, air gap)

For CI pipelines, platform worker pods, or air-gapped environments, use the
toolchain image instead of the install script. It ships every pinned scanner
on `PATH` with databases pre-populated:

```bash
./scripts/build-toolchain-image.sh                       # pins come from the manifest
./scripts/build-toolchain-image.sh --tag <registry>/harness-toolchain:<tag>

podman run --rm -v "$PWD":/workspace:Z harness-toolchain:latest \
  python3 -m traust.cli admin toolchain doctor --profile secure-code-audit
```

This is the **runtime base** a platform worker extends or mounts from; it is
separate from the data-only `Containerfile`, which ships skills and templates
as a mountable OCI artifact. Deployment configuration is mounted at
`TRAUST_CONFIG_HOME` (the image sets `/harness/deploy-config`), never baked in.

## 5. Storage locations

Where each kind of data lives is in [storage.md](storage.md). Runtime paths
resolve from `$TRAUST_CONFIG_HOME/locations.yaml` — copy
`config/locations.example.yaml` into your config home and fill in the fields
you use. There are no environment overrides for workspace, analysis-results,
progress-tracker, or feeds-cache.

Example for a mono-checkout:

```yaml
# $TRAUST_CONFIG_HOME/locations.yaml
workspace: /path/to/workspace
inputs: /path/to/workspace/inputs            # repository inventories (CSV)
analysis_results: /path/to/workspace/analysis-results
progress_tracker: /path/to/workspace/progress-tracker
feeds_cache: /path/to/workspace/progress-tracker/feeds
```

### Bring your own inventory

`locations.inputs` points at the **repository inventory**: the list of
repositories the harness audits, graphs, and reports on. The harness ships no
inventory and no discovery for one — how you enumerate your repositories
(a forge API, a release manifest, a CMDB export) is yours. It only requires a
directory layout and a CSV shape, both deliberately small:

```
<inputs>/
  <segment>/                 # any name — a business unit, a product line, "adhoc"
    <group>/                 # one directory per org, team or engagement
      <anything>-repos.csv   # one row per repository
      owners.csv             # optional: who owns each repository
```

`*-repos.csv` needs one column the graph can read a repository URL from,
`URL` (or `GitHub URL`); the rest is optional context the dashboards carry
through:

```
Repository,URL,Host,Organization/Group,Repo Name,App/Sub-Service,Resource Type
example-org/api-server,https://github.com/example-org/api-server,GitHub,example-org,api-server,platform,service
```

`owners.csv` maps repositories to owning teams; `Repository` and `Owner Team`
are the columns the graph uses (`Manager` is carried through when present).
That layout is the `groups` kind, and it is what every segment is unless
an **inventory descriptor** at `<inputs>/inventory.yaml` says otherwise. The
descriptor declares what each segment *is*, so nothing in the harness keys on
a segment's name:

```yaml
segments:
  platform:  {kind: release-payload, label: Platform}   # <segment>-<version>-payload-repos.csv per release
  operators: {kind: catalog,         label: Operators}  # <segment>/<product>/<version>/*-payload-repos.csv
  services:  {kind: services,        label: Services}   # groups layout; rows may carry App/Sub-Service
```

Kinds are `groups` (default), `release-payload`, `catalog` and `services`;
their layouts are documented in the `traust.inventory` module docstring.
Declaration order is the segment priority the executive summary uses when a
repo ships in more than one segment. Start with one `groups` segment and one
group and add the descriptor only when you have a release payload or an
operator catalog to inventory (`/inventory-repositories` writes those).

Three ways to populate it:

- **`/add-inputs`** appends a repository or a whole GitHub/GitLab org to a
  segment and derives `owners.csv` rows from `OWNERS` / `approvers` files in
  the repos. Point it at your inventory with `--inventory` or let it use
  `locations.inputs`.
- **Export from your own source of truth** into the CSV shape above; a
  spreadsheet export is enough.
- **Keep the inventory in its own repository**, as this project does, so that
  ownership changes are reviewed and the graphs can detect when it moves
  (`/drift-watch` compares the inventory's HEAD with each graph's build stamp).

Then register the *output* tree the audits write to with `/corpus-intake`,
and build the graph with `/repo-graph`. Unset, `locations.inputs` defaults to
`<workspace>/inputs`.

### Remote results and graph

Findings and the portfolio graph do not have to be local. Set
`locations.yaml` → `analysis_results` (and optionally `portfolio_graph`) to a
bare path, a `file://` URI, or an object-store URI, which is how a scheduled
orchestrator run reaches them.

| Variable / field | Purpose |
|---|---|
| `locations.yaml` → `analysis_results` | findings-side artifacts (SBOMs, extracted images, graphs) |
| `locations.yaml` → `portfolio_graph` | the graph; defaults to `<analysis_results>/graph/portfolio-graph.db` when unset |
| `HARNESS_REMOTE_CACHE` | where remote artifacts materialise (default `~/.cache/traust-engine/remote`) |

A bare path or `file://` imports no backend and copies no file, so a
workstation acquires no dependency for a deployment feature. Remote needs an
extra:

```bash
pip install 'traust-engine[s3]'     # or [gcs], or [remote] + your driver
# in locations.yaml:
# analysis_results: s3://<bucket>/results
```

Remote artifacts are **fetched once per job, not streamed**: the graph is a
large SQLite file and one query issues thousands of small indexed reads, which
object stores cannot serve, so it is materialised to the cache and queried
locally. The cache keys on the store's ETag; an unchanged artifact costs one
metadata call.

**S3-compatible stores** (MinIO, Ceph RGW, OpenShift Data Foundation) speak the
S3 API at a private endpoint. Without an override, `s3://` resolves to AWS and
the failure looks like bad credentials rather than a wrong endpoint:

```bash
export HARNESS_S3_ENDPOINT_URL=https://minio.apps.example.com:9000
export HARNESS_S3_PATH_STYLE=true        # no wildcard DNS for virtual-host style
export HARNESS_S3_CA_BUNDLE=/etc/pki/tls/certs/cluster-ca.crt   # private CA
export HARNESS_S3_REGION=us-east-1       # some stores require any non-empty region
```

There is deliberately **no TLS-verification-off switch** — supply a CA bundle.
`HARNESS_STORAGE_OPTIONS` takes a JSON object merged over the derived options
for any backend kwarg not covered above.

### Security-feed cache

Cached vulnerability data (EPSS, CISA KEV, vendor CVE and VEX feeds) is a
mirror of third-party licensed data: a different provenance class from the
findings you author, with opposite retention and redistribution properties, so
it lives outside the findings tree and is never committed. Set
`locations.yaml` → `feeds_cache` — there is **no default**; unset, feed fetch
fails closed. The metrics tree is the conventional place:

```yaml
# locations.yaml
feeds_cache: /path/to/progress-tracker/feeds
```

```bash
python3 -m traust.cli feeds fetch --feed all
```

## 6. Environment variables

```bash
cp .env.example .env
```

Only the variables for the skills you run are required. [`.env.example`](../.env.example)
lists them all with descriptions. Model routing is policy data, not an
environment variable: before batch work, read [model-routing.md](model-routing.md)
for how roles resolve to models (never hardcode IDs — gate A12) and how a batch
declares its spend.

## 7. Run the tests

```bash
.venv/bin/python -m pytest tests/
```

pytest is the only runner (a unittest discover run silently skips the
pytest-native share of the suite). When the environment has no operational
config, the suite points `TRAUST_CONFIG_HOME` at a checked-in template copy
and skips the live smokes. A clean run shows zero errors.

## 8. Validate and render a report

```bash
python3 -m traust.cli reporting validate path/to/report.json            # schema auto-detected from the filename
python3 -m traust.cli reporting validate path/to/report.json --schema schemas/v1/validation.schema.json
python3 -m traust.cli reporting validate path/to/report.json --strict   # additional warnings
python3 -m traust.cli reporting render   path/to/report.json            # writes report.md alongside
```

The path may be a directory of `.json` reports. Without `--schema`, the schema
is detected from the filename (`*-triage.json`, `*-vuln-findings.json`, and so
on); anything unrecognised validates against the security-audit schema.

## 9. Contributor gates

The repository ships its hooks; enable them once per clone:

```bash
git config core.hooksPath .githooks
```

| Hook | Runs | Blocks |
|---|---|---|
| pre-commit | python3 -m traust.cli check skill-alignment and python3 -m traust.cli check skill-security --quiet | a cross-skill contract or security-posture regression; a missing python3 or a deleted checker also blocks (fail closed) |
| pre-push | python3 -m traust.cli check docs-consistency and python3 -m traust.cli check content-licenses | docs that drifted from the tree (counts, dead paths, stale generated pages) or re-imported restrictively licensed content |

Bypass once, in an emergency, with `--no-verify`. The same gates run
server-side in CI against merge requests, from pinned target-branch copies a
merge request cannot edit away. The pre-commit hook also prints a read-only
hint when a newly committed skill is not linked from `~/.claude/skills/`
(`bin/link_skills.sh`); it never writes into `$HOME`.
