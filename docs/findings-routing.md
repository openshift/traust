# Findings routing — how a finding gets into the ledger

A **router** takes a producer's own report and turns its findings into ledger
events. Routers do more than move findings — they mint campaign ids, pin claim
hashes, enforce idempotence, write provenance back to the producer's report, and
stamp and sign the layer they touch. This page covers all of it. Routers exist because nothing audit-grade may live only inside a
producer's report: an unrouted finding has no owner, no SLA clock, no
disposition history, and no dashboard presence — it is invisible risk.

This page is the canonical reference for **findings routing** — getting a
producer's findings into the ledger. If another document disagrees, this one is
authoritative for that; [disposition-ledger.md](disposition-ledger.md) owns the
ledger's design and [artifacts.md](artifacts.md) maps the whole chain.

### It is *not* the only kind of routing here

"Routing" is overloaded in this harness. Four distinct things carry the name, and
only the first is in scope for this page:

| Kind | What it routes | Where it lives | Documented in |
|---|---|---|---|
| **Findings routing** | a producer's findings → ledger events | `route_regressions.py`, `route_impact_findings.py` | **this page** |
| **Work routing** (the *rescan router*) | repos → one of 12 scan lanes (`full-audit`, `impact-lane`, `diff-scan`, `deps-lane`, `threat-model-review`, …) | `build_rescan_worklist.py` | [continuous-operations.md](continuous-operations.md) |
| **Owner routing** | findings packages → teams and named maintainers | `/assign-findings-owners` (internal extension), `/reassign-findings-owners` | those skills |
| **Defect routing** | findings → Jira issues | `/file-security-defect` (internal extension) | those skills |

The rescan router and the findings routers are easy to confuse and do opposite
jobs: the **rescan router decides what work to do** and never authors a finding,
verdict, or audit; the **findings routers record work already done** and never
decide what to scan. They meet at one point only — the rescan router's authority
over *when a new baseline is cut* is precisely what a producer appending to a
baseline used to bypass (§1).

---

## 1. The one rule everything else follows

**Only `/secure-code-audit`, `/secure-rpm-audit` and `/secure-container-audit`
may write an audit baseline (`*-{security,rpm,container}-audit.json`). Every
other producer writes a LEDGER LAYER.**

Enforced by gate **A15** in `check_skill_alignment.py`, not by convention.
Mutating a baseline changes the claim set with *no event recording it*, which
breaks the ledger's core tenet — events, not state
([§2.2](disposition-ledger.md)) — and bypasses the rescan router's authority
over *when* a new baseline is cut.

The failure this rule prevents is concrete: a producer appending straight into a
baseline records findings against a commit they were not found at, with no event
recording the change, and it stays invisible while code and docs each describe
the write differently. Gate A15 checks the claim mechanically.

### How a finding with no baseline id gets recorded

A finding discovered *between* audits has no baseline id for `finding_ref` to
join to. Its claim therefore travels **on the event**, in an `event.finding`
block (contracts ≥ v0.4.4, `$defs/event_finding`), and `build_cumulative`
unions those with the baseline's findings at replay. Required keys are exactly
the canonical claim fields `metadata.claim_hashes` pins, so an event-carried
claim is tamper-evident on the same terms as a baselined one.

**Precedence: the baseline wins.** If a later re-audit baselines the same id, the
baseline's claim is authoritative and the event-carried copy is a stale
duplicate. That is what lets a supplement be absorbed at re-audit with no
migration — the event stays in history, the baseline takes over.

---

## 2. Every writer that touches a layer

| Writer | Invoked by | What it records | Stamps + signs |
|---|---|---|---|
| `emit_triage_ledger_events.py` | `/triage` | triage verdicts → validity events | ✅ `:362` |
| `emit_validation_ledger_events.py` | `/validate-findings` | live-validation verdicts (class-1 evidence) | ✅ `:555` |
| `countersign.py` | `/countersign` | human decisions, overrides, severity changes | ✅ `:910` |
| `build_cumulative.py` | `/track-findings` | rebuilds `*-findings-current.{json,md}`; re-stamps | ✅ `:689` |
| `route_regressions.py` | `/verify-remediation`, `/track-findings` | `regressions[]` → findings-carrying events | ✅ `:338` |
| `route_impact_findings.py` | `/dependency-watch`, `/impact-analysis` | reachable dependency CVEs → findings-carrying events | ✅ |
| `rebaseline()` (traust-engine `_util/finding_identity.py`) | re-audit | re-points the layer at a new baseline | — re-points only; does not stamp |

Every writer calls `stamp_and_sign(layer)` immediately before serialising —
stamp the Merkle root, then sign it if a key is configured. Signing a stale root
is impossible by construction. `rebaseline()` is the one writer that does not
stamp: it re-points the layer's `audit_report` and leaves the root to the next
recording write.

---

## 3. The two findings-carrying routers

### `route_regressions.py` — verification regressions

**Input:** `*-remediation-verification.json`. A verification report carries two
arrays and only one of them is routed here:

| Array | What it is | Where it goes |
|---|---|---|
| `verified_findings[]` | per-original-finding verdicts (resolved / partially_resolved / unresolved) | **plain disposition events** on the existing `finding_ref` |
| `regressions[]` | audit-grade **new** findings found in the patched code, native ids `{SLUG}-{sha7}-REG-{NNN}` | **findings-carrying events** — this router |

**Mechanics.** Mints a campaign id at the **patched** sha
(`{SLUG}-{PATCHED_SHA7}-{NNN}`); transcribes the regression into the
report-finding shape with `validation_status: not_verified` and
`origin: verify-remediation`; pins the claim hash (add-only); appends one birth
event with `source.type: verification_report`, machine actor
`verify-remediation`, `disposition: {resolution: "open"}`; writes `routed_id`
back onto the regression entry (provenance both ways).

**The returning-vulnerability link.** A regression whose **fingerprint** matches
an existing baseline finding stays a *new* finding at the patched sha — the id
records when it came back and against which commit — but the original finding's
id is appended to `source_findings`, so the connection is explicit rather than
merely inferable. Fingerprint equality
(`sha256(repo | sorted locations | primary CWE)`) is the deterministic test.
Resolution state is deliberately not consulted: a fingerprint match is the same
vulnerability either way, and the ledger already records whether the original was
resolved.

### `route_impact_findings.py` — dependency CVEs

**Input:** `<cve>-impact-analysis.json` from `/impact-analysis`, plus
`--severity` from the advisory. **This tool never invents a severity.**

**Mechanics.** Resolves each `affected` repo's baseline + layer from
`findings.db`; mints a campaign id at the **baseline's** pinned sha; builds a
dependency finding with `origin: impact-analysis`, `category: supply-chain`, the
reachability evidence transcribed into the description, and the dependency
manifest as the location; pins the claim hash; appends one birth event with
`source.type: impact_report`, actor `impact-analysis`,
`disposition: {resolution: "open"}`.

`--include-likely` extends routing to `likely_affected`; without it only
`affected` is routed.

---

## 4. Idempotence — why re-runs are no-ops

Both routers run on a cadence (`/dependency-watch` daily), so re-filing would be
a correctness bug, not just noise. Three mechanisms, and **all three had to be
taught about event-carried findings** when the baseline appends were removed —
each would otherwise have failed silently:

| Mechanism | Router | What it scans |
|---|---|---|
| `already_filed(audit, cve, module, layer)` | impact | baseline findings **and** event-carried findings, for a CVE+module already claimed |
| `already_routed` / `routed_id` back-reference | regressions | `source_findings` on baseline **and** event-carried findings for the `REG-*` id |
| deterministic `event_id` | both | `sha256(source.ref \| finding_ref \| validity \| resolution)` — an identical event cannot be appended twice |

### Id minting

`next_sequence(audit, slug, sha7, layer)` returns the first free `NNN` at
`(slug, sha7)`, scanning the baseline **and** the layer's event-carried ids.
Shared by both routers.

Two failure modes this closes, both discovered by test rather than by reading:

- **Across runs:** ids minted by a router live only on events now, so scanning
  the baseline alone would re-issue the same `NNN` on the next run.
- **Within one run:** the birth event is appended to `layer["events"]`
  **in-loop**, not after, because `next_sequence` reads ids off the layer — two
  regressions in one report would otherwise both be minted `-001`. The baseline
  append used to provide that accumulation for free.

---

## 5. What a routed finding looks like on arrival

An arrival is **not a determination**. It records
`disposition: {"resolution": "open"}` — resolution is the lifecycle axis,
validity the truth axis ([§4](disposition-ledger.md)) — so a new finding is
*open with validity unstated*. Nothing at routing time sets `confirmed`; that
takes execution evidence or a human, and those verdicts flow through the ledger.

`not_verified` is a **report-level** `validation_status`, never an event
`validity`; the event vocabulary is `confirmed | false_positive | corrected |
hardening`.

Evidence class is 3 (machine static) for `impact_report`, `triage_report` and
`vuln_scan_report`; `verification_report` and `validation_report` are class 1
(execution-verified) and outrank human static determinations. Class decides
precedence in `build_cumulative`, not recency or actor authority.

---

## 6. Invocation

```bash
# dependency CVEs — severity comes from the advisory, never invented
python3 -m traust.cli route impact-findings \
    analysis-results/impact/<cve>-impact-analysis.json \
    --severity high [--include-likely] [--limit N] [--no-rebuild] [--dry-run]

# verification regressions
python3 -m traust.cli route regressions \
    <path>/<repo>-remediation-verification.json \
    [--audit <audit.json>] [--layer <layer.json>] [--no-rebuild] [--dry-run]
```

`--dry-run` reports what would be routed and writes nothing. `--no-rebuild`
skips the `*-findings-current` rebuild; the layer is still stamped and signed.

---
