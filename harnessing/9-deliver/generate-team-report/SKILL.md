---
name: generate-team-report
description: Use when the user asks to generate a shareable findings folder, executive summary, or team-specific security audit report for one or more products from the findings directory.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# Generate Team Security Report

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Creates the executive-summary rollup (HTML dashboard + Markdown one-pager) for
a given set of products, and — **only when the user explicitly asks for a
self-contained/shareable folder** — a bundled copy of the component-level
findings to go with it. The default output is the rollup pair alone:
findings reports and evidence stay in their source of record
(`analysis-results/`), and the summaries link to them.

## When to Use

- User asks to "generate a report for [product/team]"
- User asks to "create a shareable folder of findings for [product]"
- User asks for an "executive summary" of findings for specific products
- User asks to "package findings" for coordination with a team

## Inputs

`$ARGUMENTS` is one or more **product names**, **team names**, or **operator names**.

The findings live in the **analysis-results** sibling repo at:
`../analysis-results/findings/<product>/<component>/<component>-security-audit.md`

Map user-provided names to directory names under `findings/`. Common mappings:

| User says | Directories to scan |
|-----------|-------------------|
| RHACM, ACM, Advanced Cluster Management | `rhacm/`, `advanced-cluster-management/` |
| MCE, Multicluster Engine | `multicluster-engine/`, `mce/`, `klusterlet-product/`, `placement-operator/` |
| Gatekeeper | `gatekeeper/`, `gatekeeper-operator-product/` |
| GlobalHub | `globalhub/`, `multicluster-global-hub-operator-rh/` |
| VolSync | `volsync/`, `volsync-product/` |
| OpenShift GitOps, ArgoCD | `openshift-gitops-operator/` |
| OpenShift Pipelines, Tekton | `openshift-pipelines-operator-rh/` |
| OpenShift AI, RHODS | `rhods-operator/` |
| Service Mesh v2 | `servicemeshoperator/` |
| Service Mesh v3 | `servicemeshoperator3/` |
| Kiali OSSM | `kiali-ossm/` |
| MCP Gateway | `mcp-gateway/` |

If the user names a product not in this table, search the `findings/` directory
for matching folder names (case-insensitive, partial match).

When a product has mirror directories (e.g. `rhacm/` ↔ `advanced-cluster-management/`),
do **not** assume they are identical — mirror trees drift as different pipeline
stages (verify-remediation, validation backfill, branch re-audits) land on one
side only. Pick the canonical tree by git recency
(`git log -1 --format=%ad -- <dir>`), preferring the side that carries
remediation-verification artifacts, then supplement it with files from the other
tree whose **basename** does not exist in the canonical copy (this is how
release-branch re-audits like `<comp>__release-5.1-*` usually arrive). For
same-basename files that differ in content, the canonical (fresher) copy wins.
Deduplicate by `(product_group, component_basename)` key.

## Procedure

### Step 1 — Locate the Analysis Results Repository

The findings data lives in the sibling repository. Determine its path:

```bash
RESULTS_DIR="$(cd "$(dirname "$0")/../analysis-results" 2>/dev/null && pwd)" \
  || RESULTS_DIR="$(find .. -maxdepth 1 -name 'analysis-results' -type d | head -1)"
```

If running from the `analysis-results` repo directly, `RESULTS_DIR` is the
current repo root.

### Step 2 — Identify Source Directories

1. Search `$RESULTS_DIR/findings/` for all directories matching the requested products.
2. List all report artefacts recursively under those directories — every file
   matching one of these suffixes:
   `-security-audit.md`, `-security-audit.json`, `-triage.json`, `-triage.md`,
   `-threat-model.md`. The `.md` audit report drives the executive summary; the
   JSON/triage/threat-model siblings are copied through so downstream tooling
   (notably the `validate-findings` skill) can ingest structured data.
3. **EXCLUDE** top-level flat `.md` files directly under `findings/` — these are
   legacy experimental reports scheduled for cleanup.

### Step 3 — Extract Severity Data

Severity counts must be **disposition-aware** wherever the artifacts allow it —
raw audit reports overstate because they still contain findings later refuted or
resolved. Per component, use the best available source, in this precedence:

1. **`<component>-findings-current.json`** (disposition ledger view, harness
   ≥ 0.27.0). This is the trusted source: its dispositions come from
   live-validation events, `/verify-remediation` reports, and countersigned
   human decisions. Per finding: skip `disposition.validity ==
   "false_positive"`; route `validation_status == "hardening"` to the Step 3a
   backlog; count `disposition.resolution == "resolved"` separately
   (remediation progress, not open exposure); count the rest by the `severity`
   field. `disposition.validity == "confirmed"` findings are execution-proven —
   badge them in the outputs.
2. **`<component>-security-audit.{json,md}`** raw audit counts, labeled
   **"unverified"** in the outputs. Even when a `<component>-triage.json`
   exists, do **not** count from its verdicts: the early `/triage` runs
   over-marked false positives (unreachable repos, hardening issues misfiled as
   FP), and counting "true positives only" silently trusts exactly those bad FP
   verdicts — a wrong FP hides a real vulnerability. Triage `verdict:
   "hardening"` entries are still trustworthy affirmative classifications and
   still feed the Step 3a backlog; when a raw-audit finding can be matched to a
   triage hardening verdict (by source finding id, else file+title), move it
   out of the vulnerability counts into the backlog.

Only count from unconfirmed triage TP/FP verdicts if the user explicitly asks;
label those components "unconfirmed triage" wherever their numbers appear.
⚠️ Triage schema trap if you do: `severity` holds the label
(`critical`/`high`/…) while `severity_label` holds the CVSS **vector string**
with the score in parentheses, e.g. `CVSS:3.1/AV:N/... (8.2)` — parse the score
with `re.search(r'\((\d+\.\d+)\)', severity_label)`, never feed
`severity_label` to the severity bucketer.

Report the excluded false-positive and resolved totals in the KPI tiles and
the Markdown one-pager
so readers see which counts are validated and which are raw audit output.

**Branch variants:** artifacts whose slug contains `__` (e.g.
`console__release-2.14`, `search-v2-api__release-5.1-*`) are release-branch
re-audits of the same code. Copy them into the package and list them as a
coverage note, but **exclude them from severity counts** — otherwise one
component is counted once per audited branch.

The audit-md fallback can use the extraction script at
harnessing/9-deliver/generate-team-report/scripts/extract_findings.py relative to this skill's directory:

```bash
python3 <skill_dir>/scripts/extract_findings.py \
  "$RESULTS_DIR/findings/dir1" "$RESULTS_DIR/findings/dir2" \
  --product-map "dir1=ProductName1,dir2=ProductName2" \
  > /tmp/findings_data.json
```

If the script is unavailable, extract inline. For each audit file, scan for lines
containing `CVSS` and parse score + severity:

```python
# Remove 'v3.1' etc to avoid matching as score
cleaned = re.sub(r"v3\.\d+", "vXX", line)
scores = [float(s) for s in re.findall(r"(?<![/v])(\d+\.\d+)", cleaned) if 1.0 <= float(s) <= 10.0]
score = max(scores)
# Extract severity keyword from same line
sev = re.search(r"\b(Critical|High|Medium|Low|Informational)\b", line, re.IGNORECASE)
```

Also extract the finding ID and title from the preceding `### FIND-NNN — Title`
header. Finding IDs may also use `FND-NNN`, `KC-NN`, or `SVC-NN` prefixes in
some legacy reports.

### Step 3a — Extract the Hardening Backlog

When a component carries triage or ledger artifacts, split hardening
findings out of the vulnerability counts (harness ≥ 0.27.0 taxonomy —
see `docs/disposition-ledger.md` §7):

- From `<component>-triage.json`: findings with `verdict: "hardening"`.
- From `<component>-findings-current.json`: findings with
  `validation_status: "hardening"` (this wins when both exist).

Collect per component: count, categories, titles + locations, and the
owner hint. These are **accurate defense-in-depth/benchmark gaps with no
demonstrated exploit path** — engineering hygiene and compliance work,
never presented as vulnerabilities, but never omitted: absent hardening
degrades posture and amplifies co-located vulnerabilities. In the
executive-summary HTML and Markdown one-pager (Steps 5-6), render a dedicated
**"Hardening Backlog"** section AFTER the severity tables: per-component
counts with category breakdown and a one-line framing ("posture debt —
λ-weighted in the portfolio risk index; file as regular engineering work
via `/file-security-defect --hardening`, not as security defects").

### Step 3b — Lift Attack Scenarios from Threat Models

When a component's `<component>-threat-model.md` contains a
`## 9. Attack scenarios` section (harness ≥ 0.33.0 emissions), lift it
**verbatim** into both executive-summary formats (HTML and Markdown) under an
"Attack scenarios" heading, attributed to the source threat model. These
narratives are written to the schema's bar — present tense, jargon-free,
readable by a non-technical VP — and are the single most effective
persuasion artifact in a team package; never paraphrase them into table
rows. Older threat models without section 9 get no such section (do not
synthesize one from the threat table).

### Step 4 — Create Output Folder

**Two output modes. Default is rollup-only.**

**Rollup-only (default).** Create
`progress-tracker/metrics/team-reports/<product-slug>-findings/` containing
ONLY the executive-summary pair from Steps 5–6:

```
progress-tracker/metrics/team-reports/<slug>-findings/
├── Executive-Summary-<Product>.html
└── Executive-Summary-<Product>.md
```

The progress-tracker repo carries rollups, dashboards, and summaries — never
copies of findings reports or evidence artifacts (owner directive,
2026-07-21: duplicating findings there widens access to embargoed material
and bloats the metrics repo). Both summary files must link to the
`analysis-results/` source paths for the detailed reports (e.g.
`analysis-results/findings/<product>/<component>/` or the engagement tree
such as `analysis-results/<engagement>-findings/<repo>/`), including
`fuzz-corpus/` evidence where present.

**Bundled (opt-in only).** Only when the user has explicitly asked for a
self-contained/shareable folder (e.g. "package the findings", "folder I can
email/drive-share"), additionally copy the component directories per the
layouts below — and **ask the user where the bundle should live before
writing it**. Never place bundles in progress-tracker (rollups only) and
never in the analysis-results repo (the aggregation dashboards scan its
trees — bundled copies double-count every component). A scratch export
directory or a drive-synced folder outside both repos is typical.
⚠️ Bundles contain EMBARGOED per-team findings — share them only with
Product Security + the affected teams.

Bundle layout for **single-product** reports:
```
progress-tracker/metrics/team-reports/<slug>-findings/
├── Executive-Summary-<Product>.html
├── Executive-Summary-<Product>.md
├── <ComponentA>/
│   ├── <ComponentA>-security-audit.md
│   ├── <ComponentA>-security-audit.json
│   ├── <ComponentA>-triage.json
│   ├── <ComponentA>-triage.md
│   └── <ComponentA>-threat-model.md      # if present
└── <ComponentB>/
    └── … (same set)
```

Bundle layout for **multi-product** reports, grouped by product:
```
progress-tracker/metrics/team-reports/<slug>-findings/
├── Executive-Summary-<Products>.html
├── Executive-Summary-<Products>.md
├── ProductA/
│   ├── componentX/
│   └── componentY/
└── ProductB/
    └── componentZ/
```

In bundled mode, **copy** the component directories (not symlink) so the
folder is fully self-contained and shareable. Use `cp -RL` so any
symlinked artifacts are dereferenced into real files. After copying, delete
pipeline scratch state from the package — it is internal checkpoint data, not
part of the deliverable:

```bash
find <slug>-findings -type d \( -name '.triage-state' -o -name '.threat-model-state' \) -exec rm -rf {} +
find <slug>-findings -name '.DS_Store' -delete
```

### Step 5 — Generate Executive Summary HTML

**Escaping is mandatory (CWE-79; assessment 2026-07-31 F12).** Every
value that originates in a finding — titles, impact text, action
descriptions, component names, theme labels — is attacker-influencable
(a hostile repo controls what its audit findings quote) and lands in an
HTML file opened from Drive/file:// beside embargoed content. Before
placing ANY finding-derived text into the HTML:

1. HTML-escape it (`&`, `<`, `>`, `"`, `'`). No exceptions — a finding
   title is never trusted markup.
2. The `<head>` MUST carry the CSP meta tag (in the reference
   template): `default-src 'none'; style-src 'unsafe-inline'` — the
   dashboard is fully self-contained, so any network fetch or script
   execution is hostile.
3. No remote subresources of any kind (no CDN scripts, no fonts, no
   images) and no `<script>` elements at all — the dashboard renders
   with inline CSS only.

The HTML dashboard must follow this exact structure and styling. Use the
reference template at `references/executive-summary-template.html` relative to
this skill's directory for the complete CSS. The key elements are:

#### 1. Document Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{Product} — Security Audit Executive Summary</title>
<style>/* see CSS section below */</style>
</head>
<body>
  <div class="banner">...</div>
  <header>...</header>
  <div class="grid">
    <!-- KPI tiles -->
    <!-- Severity bar -->
    <!-- Themes -->
    <!-- Component/product bar chart -->
    <!-- Top findings table -->
    <!-- Actions -->
  </div>
  <footer>...</footer>
</body>
</html>
```

#### 2. CSS Variables (required)

```css
:root {
  --crit: #cc0000; --high: #ec7a08; --med: #f0ab00;
  --low: #3f9c35; --info: #73bcf7;
  --rh-red: #ee0000; --ink: #151515; --muted: #6a6e73;
  --bg: #f5f5f5; --card: #ffffff;
}
```

#### 3. Required Sections

| Section | Grid span | Key class | Content |
|---------|-----------|-----------|---------|
| **Banner** | full width | `.banner` | `RED HAT INTERNAL — EMBARGOED.` warning |
| **Header** | full width | `header` | Product name(s), component count, frameworks, date, the tracking reference from `campaign.yaml` (`tracking_reference`, omitted when unset) |
| **KPI tiles** | 4 × `span-3` | `.kpi` + `.crit` or `.high` | Critical count, High count, Total findings, Repos audited |
| **Severity bar** | `span-12` | `.sevbar` | Proportional colored bar with `.c`/`.h`/`.m`/`.l`/`.i` segments + `.legend` |
| **Themes** | `span-7` | `.themes` | Grouped vulnerability themes with Critical/High `.pill` counts |
| **Component chart** | `span-5` | `.hbar` | Horizontal stacked bars per component/product, C+H count |
| **Top findings table** | `span-8` | `table` | Columns: Component, Finding, Impact, CVSS. Sort by CVSS desc. Show all Critical + top High. |
| **Actions** | `span-4` | `.actions` | Ordered list with `.tag.now` (≤7d), `.tag.d30` (≤30d), `.tag.d90` (≤90d) time-horizon tags |
| **Footer** | full width | `footer` | Source files, methodology note |

#### 4. Key CSS Classes

| Class | Purpose |
|-------|---------|
| `.grid` | 12-column CSS grid, 16px gap |
| `.card` | White card with border-radius 6px, shadow |
| `.kpi .num` | 40px bold number |
| `.sevbar > div` | Flex segments with severity background colors |
| `.hbar .row.tight` | Grid: 220px label, 1fr track, 50px value |
| `.hbar .fill .c` / `.h` | Stacked bar segments (critical red, high orange) |
| `.pill.c` / `.pill.h` | Inline pill badges for theme counts |
| `.tag.now` / `.d30` / `.d90` | Priority time-horizon labels |
| `td.cvss` | Bold red CVSS score |
| `td.comp` | Bold component name |
| `td.imp` | Muted impact description |

For multi-product reports, add a `td.prod` column (font-size 11px, muted) before
the Component column.

#### 5. Theme Identification

Group Critical + High findings into recurring themes. Common themes observed:

- Multi-cluster trust collapse (hub↔spoke CSR/impersonate escalation)
- Over-privileged operator RBAC (secrets/rbac/exec cluster-wide)
- Confused-deputy SSRF → credential exfiltration
- Arbitrary container-image override → privileged execution
- Supply-chain integrity (unpinned refs, mutable tags, curl|sh)
- Auth bypass / hardcoded credentials / secret leakage
- Unauthenticated admin APIs / dashboards
- Code / config injection → RCE
- Approval-gate bypass (mutable thresholds)
- Multi-tenant boundary bypass (cross-namespace, cross-project)

Only include themes that have ≥1 Critical or High finding in the current data.

#### 6. Action Priorities

- **≤7d (`tag.now`)**: Critical findings — unauth RCE/admin, credential
  exfiltration, CSR bypass, system:authenticated over-grants
- **≤30d (`tag.d30`)**: High findings requiring code changes — RBAC reduction,
  confused-deputy fixes, auth hardening, approval-gate immutability
- **≤90d (`tag.d90`)**: Systemic hardening — supply-chain pinning, cipher
  upgrades, defense-in-depth, container hardening

### Step 6 — Generate the Markdown One-Pager

Name it as the HTML dashboard's pair — same basename, different extension:
`Executive-Summary-<Product>.md` (never a generic `README.md`; the Markdown
is the same executive summary in a paste-into-Slack/doc format, and the pair
must sort and share together).

Include:
- `RED HAT INTERNAL — EMBARGOED` classification
- Date and the tracking reference from `$TRAUST_CONFIG_HOME/campaign.yaml` (omit the line when unset)
- Summary table: Component × Severity (Critical/High/Medium/Low/Info/Total)
- Folder structure tree (abbreviated)
- Top Critical findings with one-line impact descriptions
- Source directory references

### Step 7 — Redact Secrets in Output

> **Canonical patterns:** python3 -m traust.cli util redact is now the single
> source for these patterns (plus Luhn-gated payment cards, SSNs, and
> URL credentials it added — VVAH plan P2). Prefer
> `python3 -c "from lib.redact import redact_text; ..."` over
> re-implementing the table below; the table remains as the
> human-readable contract.

Applies to both modes (summaries can quote finding evidence; bundles copy
whole reports). Scan every file in the output folder for secrets and partially redact them
in-place. The original files in `analysis-results/` are never modified.

For each match, keep the **first 5 characters** and replace the remainder
with `...REDACTED` (e.g., `AKIAI...REDACTED`, `xoxb-...REDACTED`).

#### Patterns to detect

| Category | Regex | Notes |
|----------|-------|-------|
| AWS access keys | `AKIA[0-9A-Z]{12,}` | |
| GitHub tokens | `gh[posru]_[a-zA-Z0-9]{30,}` | ghp_, gho_, ghs_, ghr_, ghu_ |
| GitHub fine-grained PATs | `github_pat_[a-zA-Z0-9_]{20,}` | |
| GitLab tokens | `glpat-[a-zA-Z0-9\-_]{20,}` | |
| Slack tokens | `xox[bpsa]-[a-zA-Z0-9\-]{10,}` | xoxb-, xoxp-, xoxs-, xapp- |
| OpenAI / LLM API keys | `sk-[a-zA-Z0-9]{20,}` | |
| Google API keys | `AIza[0-9A-Za-z_\-]{35}` | |
| Bearer tokens | `Bearer\s+[a-zA-Z0-9._\-]{20,}` | |
| JWT tokens | `eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}` | |
| PEM private key blocks | `-----BEGIN .*PRIVATE KEY-----` through `-----END .*PRIVATE KEY-----` | See special handling below |
| Password assignments | `(password\|passwd)\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |
| Secret assignments | `secret\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |
| Token assignments | `token\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |
| API key assignments | `api[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]` | Redact the quoted value only |

#### PEM private key handling

Keep the `-----BEGIN` / `-----END` markers. Replace all lines between them
with a single line:

```
-----BEGIN PRIVATE KEY-----
[REDACTED — PEM key material removed]
-----END PRIVATE KEY-----
```

This applies to all PEM private key variants (`PRIVATE KEY`,
`RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, etc.).

#### Exclusions — do NOT redact

- **Git commit SHAs** — 40-character hex strings that appear after `commit`,
  `@`, `sha/`, `ref`, or inside a git/GitHub URL. These are not secrets.
- **CVSS scores** and version numbers.
- **Strings shorter than 8 characters** — too short to be a meaningful secret.
- **Pattern names used as examples** — lines that describe patterns rather than
  contain live values (e.g., `No AKIA…`, `scan for ghp_`). Use judgment: if
  the match is inside prose describing what to look for rather than a real
  credential, skip it.

#### Procedure

1. Use `grep -rn -P` with each pattern above against the output folder to
   identify matches.
2. For each match, apply the partial redaction using `sed -i` or the Edit
   tool.
3. After all redactions, report a summary: number of redactions, which files
   were modified, and a sample of redacted stubs.

### Step 7a — Snapshot the Package Metrics (trends)

Append the package's headline numbers to the central hash-chained metrics
ledger, source `team-report:<product-slug>`:

```bash
echo '{"findings_total": <open>, "sev_critical": <C>, "sev_high": <H>,
      "hardening_backlog": <N>, "resolved_findings": <N>}' | \
python3 -m traust.cli metrics history append \
    --source team-report:<product-slug> --metrics-json - \
    --note "<counting-policy context if it changed>"
```

When `metrics_history.py latest --source team-report:<product-slug>` returns a
prior snapshot, render a "Trend vs previous package (<date>)" line in the
executive summary (HTML header + Markdown one-pager) using the deltas — e.g.
"Open findings ↓ 96 (improving) · Resolved ↑ 21". Prior rows are immutable;
never edit the ledger by hand.

### Step 8 — Verify

- Confirm file counts match expectations
- Report total size with `du -sh`
- Summarize output to user

## Output Format

Always present a final summary to the user with:
1. Output folder path and total size
2. Component × Severity table
3. Key critical/high findings highlighted

## Notes

- Report files follow an 8-section structure: Executive Summary, OWASP ASVS,
  K8s Top 10, CIS/STIG, Supply Chain, Detailed Analysis, Severity Summary,
  Remediation Roadmap.
- Finding IDs are sequential within each report (`FIND-001`, `FIND-002`, …).
- When mirror directories exist (same component shipped by multiple products),
  the reports often diverge — pick the canonical copy by git recency (see
  Inputs) and supplement with unique-basename files from the mirror.
- Some components have 0 CVSS-scored findings (stub reports from failed audits
  or org-URL manifest entries). These should still be included in the folder for
  completeness but will show 0 in the severity table.

## Integrations

**Consumes:** per-repo reports and cumulative findings from
`analysis-results/findings/<product>/` (audit + triage +
findings-current), threat-model attack scenarios (lifted verbatim into
packages).

**Emits:** self-contained findings packages under
`progress-tracker/processed-results/` (reports + executive-summary
HTML) — consumed by `/assign-findings-owners` (stage ⑨) and the Drive
sharing flow (delivery). Terminal for machine consumers by design: the
audience is the owning engineering team.
