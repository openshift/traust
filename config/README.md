# `config/` — harness configuration: what ships, what does not

The harness reads two kinds of configuration and keeps them apart on purpose.

## Ships with the harness (this directory)

| File | Why it is safe to publish |
|---|---|
| `external-tools.yaml` | Pinned versions of the open-source scanner binaries the harness runs |
| `feeds.yaml` | Public vulnerability-feed endpoints (OSV, NVD, vendor CSAF/VEX) and their fetch policy |
| `model-registry.yaml` | Model tier classes and routing roles; no estate data. `install_traust` also copies it into `TRAUST_CONFIG_HOME`, so a deployment is complete in one directory even where only traust-engine is installed; the copy there wins (`--doctor` warns when it differs from the shipped one, `--force` refreshes it) |

## Deployment configuration (NOT in this repository)

Everything that describes *one estate* — which corpus trees exist and who owns
them, how findings packages map to products, spend limits, the dist-git watch
list, the ledger signing key, the safe-exec allowlists, the vocabulary the
internal-reference scanner hunts for — lives in a **deployment config
directory** that each adopter keeps in a private repository. This directory
ships a template for each such file:

| Template here | Deployment file | Read by |
|---|---|---|
| `corpus-config.example.yaml` | `corpus-config.yaml` | `traust_engine.corpus.resolver`, `/census`, every dashboard |
| `remediation.example.yaml` | `remediation.yaml` | `/remediate-finding` (private mirror org, naming prefix) — no shipped default for the org |
| `campaign.example.yaml` | `campaign.yaml` | dashboards that cite a tracking reference (`/validation-fuzz-dashboard`, `/generate-team-report`) |
| `product-definitions-map.example.yaml` | `product-definitions-map.yaml` | `traust_engine.registry.products`, `/assign-findings-owners`, `/sla-view` |
| `budget-policy.example.yaml` | `budget-policy.yaml` | `traust_engine.metrics.spend`, rescan worklist, drain tranche |
| `rpm-distgit-watch.example.yaml` | `rpm-distgit-watch.yaml` | `build_release_events.py` (threat-model event feeder) |
| `rule-pack-allowlist.example.yaml` | `rule-pack-allowlist.yaml` | `traust_engine.adapters.opengrep`, `/mine-ledger` |
| `safe-exec-profiles.example.yaml` | `safe-exec-profiles.yaml` | `traust_engine._util.safe_exec` |
| `hardening-risk-weights.example.json` | `hardening-risk-weights.json` | `emit_triage_ledger_events` |
| `export.example.yaml` | `export.yaml` | `traust.migrations.export_public_tree` — the one-shot public export (public forge URL, private URLs to rewrite, build plumbing to strip, CHANGELOG cut) |
| `internal-vocabulary.example.yaml` | `internal-vocabulary.yaml` | `scan_internal_refs` |
| `ledger-signing-key.example.pub` | `ledger-signing-key.pub` | `traust_engine.reporting.validate`, `/drift-watch` signature check |

### How the harness finds the deployment directory

One environment variable: **`TRAUST_CONFIG_HOME`**. Default `~/.traust/config`
when that directory exists. Nothing else is consulted.

Every consumer resolves a file with `config_path("<name>")`
(`traust_engine.config`, re-exported by `traust.paths`). A file
missing from `$TRAUST_CONFIG_HOME` **fails closed** with
`DeploymentConfigMissing`, naming the template to copy. The harness never runs
on a template: dashboards computed over placeholder corpus or product data
would report numbers about nobody's estate. The one exception is
`model-registry.yaml`, which ships here and is read from here unless you place
a copy in `$TRAUST_CONFIG_HOME`, in which case yours wins.

### Setting up a new deployment — start here

```bash
scripts/install_traust            # interactive: choose the location, copy templates,
                                  # record TRAUST_CONFIG_HOME in your shell profile,
                                  # optionally run scripts/install-toolchain.sh
scripts/install_traust --doctor   # verify: variable, files, parse, resolver, toolchain
```

Non-interactive (CI, images):

```bash
scripts/install_traust --yes --config-home /srv/traust/config --toolchain secure-code-audit
```

Then edit each file in `$TRAUST_CONFIG_HOME`. Every file documents its fields
in a header comment. Run `scripts/install_traust --doctor` to see unset estate
fields (empty corpus trees, location paths, …). Generate your own ledger signing
key pair as described in `ledger-signing-key.example.pub`.

An organization's real operational files belong in a private repository of
its own; its orchestrator sets `TRAUST_CONFIG_HOME` to that checkout.

### Hygiene gate

`python3 -m traust.cli.check_docs_consistency` fails when this
directory contains anything other than the three shipped files, the templates,
and this README — or when any file here carries estate-specific markers.
