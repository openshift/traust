# Getting Started

From zero to your first audit report. This walkthrough covers standalone
use — running individual skills against a codebase of your choosing. For
the full multi-repository pipeline, finish this page first, then continue
with [PROCESS.md](../PROCESS.md). Every detail behind these steps is in the
[setup reference](setup.md).

## 1. Check the requirements

See [requirements.md](requirements.md). For a first standalone audit you
need only the baseline: macOS/Linux, Python 3.11+, git, and an AI coding
agent (Claude Code or Crush) running a strong model — the audit skills are
rated mythos-class. No cluster, VPN, or extra CLI tools required yet.

## 2. Clone, install, configure

Standalone use needs just this repository:

```bash
git clone <your-forge>/traust.git
cd traust
uv sync
```

No `uv`? Use the hash-pinned lockfile instead:
`pip install --require-hashes -r requirements.lock`.

Then create your operational configuration. The harness does not run
without it: nine files (corpus registry, product map, budget policy,
safe-exec profiles, and so on) live in a directory named by
`TRAUST_CONFIG_HOME`, and `install_traust` creates that directory from the
templates in `config/`, records the variable in your shell profile, and
offers to install the scanner toolchain:

```bash
scripts/install_traust            # accept the default ~/.traust/config
scripts/install_traust --doctor   # confirms the install end to end
```

Edit the copied files when you are ready (each opens with a comment block
explaining its fields); the defaults are enough for a first standalone audit.
Details: [config/README.md](../config/README.md).

(For the multi-repository pipeline, the sibling data repositories are laid out
in the [setup reference](setup.md).)

## 3. Point your agent at the harness

Start your agent **from the harness root** (or, for campaign layouts, from
the parent workspace directory). Skills are discovered automatically:

- **Claude Code** finds them via the `.claude/skills/` symlink tree and the
  `.claude/commands/` slash-command wrappers.
- **Crush** finds the same skills via `.crush/skills/` (symlinks into
  `harnessing/`, the single source of truth) and `.crush/commands/`
  (symlinks to the `.claude/commands/` wrappers).

Type `/` in the agent to see the available commands. Every skill is also
invocable by asking in plain language ("run a security audit of <repo>").

## 4. Run your first audit

A good first sequence on any repository you are authorized to assess:

```
/threat-model <path-or-url>        # writes <repo>-threat-model.md
/secure-code-audit <path-or-url>   # writes <repo>-security-audit.{json,md}
```

The threat model is optional but sharpens the audit — the audit skill reads
it when present. The audit clones the target if you give it a URL, applies
the multi-framework methodology (OWASP ASVS, Kubernetes Top 10, CIS, DISA
STIG, SLSA, Scorecard), and emits a schema-validated JSON report plus a
human-readable Markdown companion.

Prefer a lighter first pass? `/vuln-scan <dir>` is the faster,
focus-area-driven sweep. For other target types, see the skill tables in
the [README](../README.md): container images (`secure-container-audit`),
RPM dist-git (`secure-rpm-audit`), IaC (`cloud-config-audit`).

## 5. Check the output

```bash
# validate the report against its schema
python3 -m traust.cli reporting validate <repo>-security-audit.json

# regenerate the Markdown rendering
python3 -m traust.cli reporting render <repo>-security-audit.json
```

Reports embed the harness version and commit (`metadata.harness_version`)
so results are traceable to an exact harness revision. What the fields mean
is documented in [report-structure.md](report-structure.md) and the schemas;
[artifacts.md](artifacts.md) maps each artifact to its producers and consumers.

## 6. Optional: sharpen the audits with deterministic pre-scanners

The audit skills work with no extra tools, but if these are on `PATH` the
skills use them automatically and cite their machine-verified facts instead
of free-reading:

| Tool | What it adds |
|---|---|
| `opengrep` | semantic pre-scan with the harness-authored rule pack |
| `gitleaks` | secret detection incl. git history |
| `osv-scanner`, `govulncheck` | known-vulnerability dependency scans |
| `tokei` (or `cloc`/`scc`) | lines-of-code accounting |

Install hints are in [setup.md](setup.md). The Kubernetes manifest
hardening scanner (python3 -m traust.cli adapters checkov) is built in and needs
nothing extra.

## 7. Where to go next

| Goal | Read |
|---|---|
| Triage and verify what the audit found | `/triage` — adversarial verification of raw findings; then [artifacts.md](artifacts.md) for how a finding moves from audit to dashboard |
| Understand every skill and its options | [skills.md](skills.md) |
| Track findings over time (disposition ledger) | [disposition-ledger.md](disposition-ledger.md) |
| Generate candidate fixes | `/patch` (inert diffs) or `/remediate-finding` (on your own fork) |
| Run the full pipeline across many repositories | [PROCESS.md](../PROCESS.md); register targets with `/add-inputs` and `/corpus-intake` |
| Keep audits fresh (when to rescan what) | [continuous-operations.md](continuous-operations.md) — the router decides re-audit frequency from live change data; never schedule rescans by hand |
| Every setup detail (env vars, storage locations, toolchain, contributor hooks and tests) | [setup.md](setup.md) |

## Ground rules

Only assess targets you are explicitly authorized to test. Audit skills are
read-only against the target by default, with two narrow, documented
exceptions: the sanitizer-probe lane (`probe_sanitizers.py --run`, an
opt-in step granted in secure-code-audit's allowed-tools) executes
repository code to test sanitizer behavior, and reachability/build steps
(govulncheck, repo test suites in remediation checks) execute the
target's build machinery — always routed through the `safe_exec` sandbox
(gate rule S10) or a rootless container, never bare. Live validation
happens only on disposable clusters within an authorized scope. The full
constraints are in [AGENTS.md](../AGENTS.md).
