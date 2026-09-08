# Components — the repositories this harness is built from

The harness is **not one repository**. It is a stack of five independently
versioned components plus three data repositories. This page is the
authoritative map: what each component owns, which way the dependencies point,
how versions are pinned, and — the question that actually comes up — **which
repo do I change to fix this?**

If you only want to install and run, [setup.md](setup.md) is enough.
Read this before changing a schema, an enum, the fingerprint recipe, or
anything under `traust_engine` / `traust_ledger`.

---

## 1. The stack

```
                    traust-sdk (Go)  ─────┐
                                               │  both import the contracts;
  traust   skills, slash commands │  neither imports the other
        │               agent-facing CLIs      │
        ▼                                      │
  traust-engine        scanners, corpus,      │
        │               metrics, reporting,    │
        │               ledger gateway         │
        ▼                                      │
  traust-ledger           identity, integrity,   │
        │               signing, ledger service│
        ▼                                      ▼
  traust-contracts schemas · enums · shared models    (leaf — depends on nothing internal)
```

Dependencies point **one way, downward**. `traust-contracts` is the leaf and
imports nothing from the others. The harness declares two direct dependencies,
`traust-engine` and `traust-contracts`; `traust-ledger` is traust-engine's
dependency, and harness code reaches it only through the engine's ledger gateway
(`traust_engine.ledger`), never by importing `traust_ledger` itself. There are no
cycles, and adding one would be a design defect — the whole point of the split is
that the vocabulary can be released without releasing the skills.

| Component | Lang | Owns | Why it is its own repo |
|---|---|---|---|
| `traust` | Python | Skills (`harnessing/`), slash commands, agent-facing CLIs (`src/traust/`), docs, gates | The agent-facing surface. Changes constantly; must not force a release of the vocabulary underneath it |
| `traust-engine` | Python | `adapters` (scanner wrappers), `corpus`, `portfolio`, `metrics`, `reporting` (incl. SARIF), `validation`, `compliance`, `impact`, `registry`, `sweep`, `toolchain`, `data`, `ledger` (the gateway — the one place the engine touches traust-ledger), `_util` (safe_exec, escaping, redaction) | Deterministic machinery with no prompt content — testable and reusable without an agent |
| `traust-ledger` | Python | The ledger kernel and its service: `_internal/` (the fingerprint recipe `identity.py`, `writer.py`, `events`, `integrity/` — RFC 9162 Merkle, stamping, signing — `reports`), and three OIDC-gated entry points over shared `handlers` — `client.py` (in-process SDK), `cli`, and `service/` (REST app, auth, identity providers) with pluggable `backends` | The trust root. Isolated so its blast radius is small and its test surface is exhaustive |
| `traust-contracts` | Python | `schemas/v1/*.json`, `enums/v1/*.json` with the matching `StrEnum`s in `enums.py`, `models.py`, `paths.py` | The shared vocabulary. Every producer and consumer — including non-Python ones — must agree on it |
| `traust-sdk` | Go | Typed SDK for invoking harness skills with pluggable execution backends (`go/v1/`: `skills`, `types`, `enums`, `ingest`, `query`, `validate`) | Lets non-Python consumers (a platform service, for example) drive the harness and read its artifacts without reimplementing the contracts |

**`traust-sdk` is not a dependency of the harness.** It is a *sibling
consumer* — it depends on the contracts and calls the harness, not the reverse.
Nothing in this repository imports it. It is listed here because it is part of
the stack and because a contracts change can break it.

### Data repositories (not components)

`setup.md` also uses the word "sibling" for these, in a different sense — its
clone list is four entries because it counts `traust` itself. They
hold content, not code, are not pip dependencies, and are referenced by relative
path, not imported:

| Repo | Holds |
|---|---|
| `analysis-results` | Audit reports, disposition ledgers, triage, threat models — the corpus |
| `<inputs-inventory>` (name is the deployment's) | Scope declarations, repo rosters, service inventories |
| `progress-tracker` | Plans, dashboards, metrics, gap assessments |

---

## 2. Which repo do I change?

The most common mistake is editing the wrong layer — usually adding a schema
field to the harness, where it has no effect, because the validator loads
schemas from the **installed contracts package** (`traust_contracts`),
not from this repo.

| I want to… | Repo | Note |
|---|---|---|
| Add or edit a skill, prompt, or slash command | `traust` | No release chain needed |
| Add a field to a report/layer schema | `traust-contracts` | Then release up the chain (§4) |
| Add an enum value | `traust-contracts` | **Three surfaces**: `schemas/v1/*.json`, `enums/v1/<name>.json`, and the `StrEnum` in `enums.py`. Missing one silently half-lands the value |
| Change the finding fingerprint | `traust-ledger` (`_internal/identity.py`) | **One implementation only.** Move `ALGO_VERSION` and update the fixtures in `traust-ledger/tests/fixtures/` — §5 |
| Change Merkle/stamping/signing behaviour | `traust-ledger` (`integrity/`) | See [signing.md](signing.md) |
| Add or fix a scanner adapter | `traust-engine` (`adapters/`) | Return shape is gated by `schemas/v1/adapter-result.schema.json` |
| Change dashboards, SARIF export, corpus resolution | `traust-engine` | `metrics/`, `reporting/`, `corpus/` |
| Change what a Go consumer sees | `traust-sdk` | And the contracts, if the vocabulary itself changed |

---

## 3. Version pinning

Each component carries its own `VERSION` + `pyproject.toml` version and its own
git tags. Consumers pin **by git tag** in `[tool.uv.sources]`, with a matching
floor in `dependencies`. The harness pins its two direct dependencies (shape
only — the live values are in `pyproject.toml`, which is the only place they
belong):

```toml
dependencies = [
    "traust-engine>=X.Y.Z",
    "traust-contracts>=A.B.C,<A+1",
]

[tool.uv.sources]
traust-engine        = { git = "<forge>/traust-engine.git",        tag = "vX.Y.Z" }
traust-contracts = { git = "<forge>/traust-contracts.git", tag = "vA.B.C" }
```

`traust-engine` in turn pins `traust-ledger` and the contracts the same way, and
`traust-ledger` pins the contracts.

### The failure mode to know

`uv` resolves each git dependency to exactly one URL-plus-tag. If the harness
pins one contracts tag while the `traust-engine` tag it depends on pins
an older one, `uv lock` fails with **"conflicting URLs"** — not a version
conflict message, a URL one, which is why it reads as a tooling bug the first
time you hit it. The fix is always the same: make the transitive pins agree,
which in practice means releasing the intermediate component so its pin catches
up. Both `traust-engine` and `traust-ledger` pin the contracts themselves, so a
contracts bump is a three-repo operation, not a one-line edit here; a
`traust-ledger` bump is a two-repo operation (traust-ledger, then traust-engine)
and reaches the harness when it re-pins the engine.

**Installed-vs-pinned drift** is caught by the `dependency-pins:*` items in
`/check-drift` — an absent or wrong-version sibling package is reported as
drift, fixed with `uv sync`. That check exists because CI cannot cover this
class: CI builds its own venv, while skills run on the operator's workstation
against whatever is installed there.

### Reading the current pins

This page carries no version table — it would be stale within a week. Ask the
tree:

```bash
grep -E 'tag = ' pyproject.toml                 # what the harness pins
grep -E 'tag = ' ../traust-engine/pyproject.toml   # what the engine pins (incl. traust-ledger)
for r in traust-engine traust-ledger traust-contracts; do
  printf '%-24s %s\n' "$r" "$(git -C ../$r tag --sort=-v:refname | head -1)"
done                                            # latest tag that exists in each checkout
```

---

## 4. Release order

Downward dependencies mean releases go **bottom-up**, and a change to the
vocabulary is the expensive case: it touches four repos. A traust-ledger change
stops at traust-engine unless the harness needs the new engine.

```
contracts ──▶ traust-ledger ──▶ traust-engine ──▶ harness
                                              └▶ traust-sdk (if the vocabulary changed)
```

The three Python packages share release mechanics — each has a `Makefile` and a
`release.py`:

```bash
make test                      # gates + suite
make check-release             # ci/gates.py mr, against origin/main
make bump patch|minor|major    # writes VERSION + pyproject.toml
git push --follow-tags
```

Then in each **consumer**, bump both the `dependencies` floor and the
`[tool.uv.sources]` tag, run `uv lock && uv sync`, and release that repo in
turn. Skipping the floor while bumping the tag is the usual slip: it installs
correctly but stops expressing the real minimum.

Two components differ:

- **`traust`** has no `Makefile` and no `release.py`. Edit `VERSION`
  by hand per the bump rules in [AGENTS.md](../AGENTS.md), then
  `git tag v$(cat VERSION)`. Nothing depends on it, so it is always last.
- **`traust-sdk`** is versioned **per language**, not per repo: `go/VERSION`
  with tags prefixed from `ci/languages.json` — `go/v0.5.2`, not `v0.5.2`. Adding
  a second language adds its own VERSION and tag series.

> The per-repo `release.py` docstring points at a `tools/release.py` "in the
> mono-checkout" for workspace-wide stack releases. **No such tool exists in
> this workspace** — release each repo individually.

---

## 5. What crosses the boundary

Two things are shared contracts in the strong sense: change them and every
consumer, in any language, is affected.

| Contract | Defined in | Consumed by |
|---|---|---|
| **Report / layer / adapter schemas** | `schemas/v1/` (contracts) | validated in `traust_engine` via `config.SCHEMA_DIR`; typed in `traust-sdk` `go/v1/types` + `validate` |
| **Enums** (16) | `enums/v1/*.json` + `src/traust_contracts/enums.py` | everything, incl. `traust-sdk` `go/v1/enums` |

Adding an enum value means touching **three surfaces** — the JSON Schema that
constrains the field, `enums/v1/<name>.json`, and the `StrEnum` in `enums.py`.
Land two of the three and the value half-exists: accepted in one path,
rejected in another.

### Finding identity is deliberately *not* a cross-boundary contract

**Only the harness computes identity.** No consumer and no non-harness producer
implements the fingerprint; a producer that mints findings routes through the
harness or submits unstamped. The recipe lives in exactly one place —
`traust_ledger/_internal/identity.py`, contract in
`traust-ledger/docs/finding-identity.md` — and its regression net sits beside it
in `traust-ledger/tests/fixtures/` (`identity-recipe-vectors.json`,
`finding-identity-vectors.json`). Those are **fixtures, not a contract**: they
exist so the one implementation cannot change by accident, especially across an
`ALGO_VERSION` bump. Changing the recipe intentionally means moving
`ALGO_VERSION` and letting the fixtures' recorded values make the move visible
rather than a silent re-baseline.

Do not reintroduce a fingerprint implementation outside `traust-ledger` — not in
the Go SDK, not in a producer. A divergent fingerprint means two systems disagree
about whether two findings are the same finding, and that compounds through
every dedupe, alias and metric downstream.

---

## See also

- [setup.md](setup.md) — cloning the workspace and `uv sync`
- [architecture.md](architecture.md) — code internals within a component
- [disposition-ledger.md](disposition-ledger.md) — what `traust-ledger` is protecting
- [signing.md](signing.md) — ledger signing
