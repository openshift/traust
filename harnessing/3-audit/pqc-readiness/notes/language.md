# Plain language rules

Primary surface must be readable without crypto expertise.
Jargon lives only under `details` / `evidence`.

## Glossary

| Field | Meaning | Values |
|---|---|---|
| `status` | Are we ready? | `ready` / `needs_work` / `blocked` / `not_applicable` |
| `who_sets_tls` | Who picks TLS crypto? | `this_app` / `language_defaults` / `platform` / `mesh_or_ingress` / `external_server` / `unknown` |
| `quantum_ready` | Can TLS use post-quantum key exchange today? | `yes_by_default` / `yes_if_configured` / `no` / `only_with_fips_curves` / `unknown` |
| `why_not` | Short reason codes | `old_version` / `feature_turned_off` / `curves_pinned` / `platform_profile_missing_pq` / `peer_not_checked` / … |
| `do_next` | What to do + who + how + where | `{ "who", "do", "how?", "locations?" }` — `how` is self-contained prose; `locations` are repo `file:line` anchors |
| `kind` | What a capability note describes | `language` / `library` / `os_policy` |

## Length caps

| Field | Cap |
|---|---|
| `in_plain_english` | ≤2 sentences, ≤300 chars |
| report `summary` | ≤20 words |
| `do_next.do` | ≤25 words, imperative |
| `do_next.how` | 1–3 sentences; no harness paths (`remediation/`, `notes/`, `harnessing/`) |

## Banned on primary surface

Do not put these in `summary`, `title`, `do_next`, or `remediations`:

- Fact ids (`F0008`) — machine citations only on `scores.*.checks[]` /
  `clock_items[]` and the sibling facts file; owners use `locations`
- Internal scoring IDs or domain codes (`VULN-1`, …)
- Provenance labels
- Standards body acronyms or reference numbers
- Internal field names from the scorecard
- Harness-local paths (remediation/, notes/, harnessing/ subtrees) — distill playbooks into `how`; `/patch` loads the full recipe separately

These belong under scorecard evidence / the facts file only (except
harness paths, which never go in the report). The primary surface should
make sense to someone who has never seen the scoring system or the
harness checkout.
