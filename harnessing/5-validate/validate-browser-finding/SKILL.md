---
name: validate-browser-finding
description: >-
  Run browser-based security validations (CSRF, XSS, clickjacking) against
  containerized labs using Playwright. Separate from validate-findings which
  targets K8s operators/containers.
metadata:
  harness.tier: "primary"
---

# validate-browser-finding

Browser-native validation using an onion-layer methodology: prove the exploit at the innermost layer (app with simple auth), then progressively add real-world defenses (OAuth, proxy, ingress) to confirm each layer's contribution.

## Validation Layers (Onion Model)

| Layer | What's Running | Proves |
|-------|---------------|--------|
| **1 — Bare app** | Target + attacker + Playwright. Simple/no auth. | Exploit works when last line of defense is absent |
| **2 — App + auth** | Add real login (form, basic, token). | Exploit survives authenticated sessions |
| **3 — App + auth + middleware** | Add oauth-proxy, CSRF tokens, SameSite policy. | Which middleware layer actually blocks the attack |
| **4 — Full stack** | Add IdP (Keycloak/Dex), TLS, ingress. | Real-world exploitability with production auth flow |

Start at Layer 1. If confirmed, move outward — each layer either blocks the attack (refuted at that layer) or passes it through (confirmed, move to next layer).

### Escalation Policy

| Finding Severity | Required Validation | Infrastructure |
|-----------------|--------------------|----|
| **Critical / High** | Layer 1-2 (local) + Layer 3-4 (OCP cluster) | docker-compose → deploy to ephemeral OCP in AWS |
| **Medium / Low** | Layer 1-2 only | docker-compose (Playwright + containers) |

- High/Critical confirmed at Layer 1 → **must** escalate to OCP to prove real-world exploitability
- Medium/Low confirmed at Layer 1 → sufficient evidence, no cluster needed
- Any severity refuted at Layer 1 → close the finding

### Layer 3-4 on OCP (High/Critical only)

For high/critical findings that confirm at Layer 1-2, deploy the target to OCP:
- Same attack plan, different `targets.yaml` (origins point to cluster Routes)
- OCP provides real oauth-proxy, TLS, ingress, cross-site hostnames
- Use `security-testing-clusters` for ephemeral provisioning
- No mocking needed — the platform IS the middleware stack

### Why Layers Matter

- Layer 1 confirmation + Layer 3 refutation = "the app is vulnerable but middleware saves it" — still worth hardening the app
- Layer 1 confirmation + Layer 4 confirmation = "exploitable in production" — critical
- Layer 1 refutation = "app handles it natively" — close the finding

## When to Use

- Web vulnerability requires browser automation (CSRF, XSS, session fixation, clickjacking, CORS)
- Target runs in a container (docker-compose lab)
- Evidence requires screenshots, HAR captures, cookie inspection
- `validate-findings` or `validate-core-ocp` reported inconclusive/refuted on HTTP-surface findings due to missing cookie/session round-trip

## When NOT to Use

- K8s operator or container-only finding → use `validate-findings`
- Static analysis sufficient → no live validation needed
- Finding is purely API-level (no browser behavior involved) → use `validate-findings` with `port-forward+http`

## Current Scope (Layer 1–2)

Auth strategies supported today:
- Form-fill login (username/password fields + submit)
- No-auth targets (public endpoints)

Not yet supported (Layer 3–4 follow-up):
- OAuth/OIDC redirect flows (app → oauth-proxy → IdP → redirect chain)
- Double-submit CSRF token extraction + header replay
- Multi-hop TLS with ingress/route termination

## Invocation

```bash
cd traust/harnessing/5-validate/validate-browser-finding
python run.py <validation-dir> [--destructive] [--out <dir>]
```

**Target attestation (fail-closed — P2).** Before invoking `run.py`,
attest that the lab/target actually answers:

```bash
python3 -m traust.cli admin attest-target \
    --out <validation-dir>/target-attestation.json --url <target-base-url>
```

`attested: false` (target unreachable, TLS broken, 5xx) voids every
verdict the run would produce — the ledger emitter routes the run to
`environment_invalid`/needs_review instead of the FP queue. A dead lab
must never read as "refuted".

**Severity validation (P9).** Confirmed browser findings record
demonstrated components (auth state actually needed, interaction
required, scope of what was read/written) in `severity_validation`;
material deltas propose via the countersign severity decision.

**Differential route pairs (P3).** "Role R cannot reach route X"
refutations pair the probe with a route the role IS authorized to
reach, in the same session (`differential` block). Two identical
responses (e.g. both land on the same error page) mean the oracle can't
discriminate — quarantined as non-discriminating.

**Positive controls (P1).** Browser authz refutations pair a
session-validity control: the same authenticated session must reach a
page the role legitimately owns (`must_succeed`) before "role cannot
reach X" may be recorded — a broken/expired session otherwise reads as
a refutation. Record in the step's `controls[]`; failed/missing
controls quarantine per the soundness gate.

## Prerequisites

1. Lab running: `podman compose up -d` in the validation directory
2. Python deps from repo root: `pip install -r requirements.txt` (includes `playwright` + `pyyaml`)
3. Playwright browser: `playwright install chromium` (or use remote container)

## Validation Directory Layout

```
validations/<name>/
├── *-attack-plan.yaml      # Steps to execute
├── *-security-audit.json   # Source finding (optional)
├── targets.yaml            # Scope: origins, credentials, allowed verbs
├── docker-compose.yaml     # Lab: app + attacker + playwright
├── exploit-page/           # HTML PoCs
└── artifacts/              # Output: screenshots, HARs, logs
```

## Output

- `<name>-validation.json` — structured report (same schema as validate-findings)
- `validation-audit.jsonl` — append-only execution log
- `artifacts/` — screenshots, HAR files, response captures

## Adding a New Validation

1. Create `validations/<jira-slug>/` with docker-compose, targets, attack plan
2. Write exploit HTML in `exploit-page/`
3. Run: `podman compose up -d && python run.py validations/<jira-slug>/`
4. Review artifacts and validation JSON
5. If confirmed at Layer 1, duplicate docker-compose with middleware additions for Layer 2+

## Integrations

`*-validation.json` reports and `validation-audit.jsonl` trails are
ingested by `/track-findings` as machine validation events (evidence
class 1 on confirmed steps) and appear in `/validation-fuzz-dashboard`;
confirmed results also override refuted-register FP assertions via
evidence-class precedence.
