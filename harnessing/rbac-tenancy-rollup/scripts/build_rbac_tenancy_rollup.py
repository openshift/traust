#!/usr/bin/env python3
"""Deterministic RBAC + multi-tenancy findings rollup.

Walks the report population via traust.cli.groups.corpus (never a hand-rolled
walker), selects findings in the RBAC / multi-tenancy classes through a
three-tier documented predicate, applies disposition-aware counting
(findings-current preferred; false positives excluded; resolved and
hardening bucketed separately), clusters the selected findings into named
misconfiguration patterns, and writes:

  progress-tracker/metrics/dashboards/rbac-tenancy/
    rbac-tenancy.json          machine-readable rollup
    rbac-tenancy-rollup.md     executive one-pager
    rbac-tenancy-detailed.md   top misconfigurations, per-pattern findings
    rbac-tenancy.html          self-contained dashboard

Selection tiers (a finding is selected at its lowest matching tier):
  T1 structured  category in {authorization, tenant-isolation} OR
                 peach_references / isolation_dimensions / isolation_boundary set
  T2 framework   primary-CWE in the RBAC/authz set OR K02/K08 or KHS-R* cited
  T3 lexical     RBAC/tenancy token regex over title+description (heuristic —
                 reported separately, never silently blended)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from traust_engine import locations
from traust_engine.assets import harness_version
from traust_engine.corpus import report_store
from traust_engine.corpus import resolver as corpus
from traust_engine.corpus.resolver import *  # noqa: F403  # noqa: E402
from traust_engine.escaping import esc_html

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_engine,
)
from traust.paths import HARNESS_ROOT

AUTHZ_CWES = {
    "CWE-862",
    "CWE-863",
    "CWE-269",
    "CWE-284",
    "CWE-266",
    "CWE-250",
    "CWE-648",
    "CWE-283",
    "CWE-639",
    "CWE-668",
}

RBAC_RX = re.compile(
    r"\brbac\b|clusterrole|cluster-admin|rolebinding|role binding|"
    r"\bimpersonat|escalate\b|\bbind\b.{0,40}verb|verb.{0,40}\bbind\b|"
    r"wildcard.{0,30}(verb|resource)|(verb|resource)s?.{0,30}wildcard|"
    r"service ?account|automount|selfsubject|aggregated (cluster)?role|"
    r"secrets?.{0,50}(get|list|watch).{0,40}cluster|kubeconfig|"
    r"least.privilege|over.?privileg|overly.{0,15}permissive",
    re.I,
)
TENANCY_RX = re.compile(
    r"multi.?tenan|tenant|cross.namespace|namespace isolation|"
    r"allnamespaces|hostedcluster|blast radius|isolation boundary|"
    r"cross.customer|noisy neighbor",
    re.I,
)
K_REF_RX = re.compile(r"\bK0[28]\b|KHS-R\d+")

LEGEND_MD = "\n## Legend\n\n- **Tier (selection confidence)** \u2014 how the finding qualified for this rollup: **T1** structured fields (`category` = authorization/tenant-isolation, PEACH/isolation tags) and **T2** framework signals (authorization CWEs, OWASP-K8s K02/K08, `KHS-R*` scanner refs) are quotable as-is; **T3** is a keyword-heuristic match \u2014 open the underlying finding before quoting it individually (aggregates are directionally sound).\n- **\u2713conf / Confirmed** \u2014 `validation_status: confirmed`: execution evidence (fuzz crash, PoC, live validation) or a human triage determination. Everything else is static-analysis judgment (`not_verified`).\n- **Severity** \u2014 the audit's judgment. CVSS bands for reference: critical 9.0\u201310, high 7.0\u20138.9, medium 4.0\u20136.9, low 0.1\u20133.9. A severity below the CVSS band is a documented contextual downgrade (rationale stated in the finding text); undocumented gaps are surfaced in the Data quality section.\n- **ATT&CK candidates** \u2014 techniques an adversary would use to exploit that weakness class (weakness-derived, NEVER observed behavior), validated against the pinned ATT&CK table. Source order: `cited` (the finding names the technique) > `pattern` (bucket-derived) > `category` (shared category map).\n- **`other`** \u2014 no recurring pattern; individual findings grouped by weakness category purely for navigation.\n- **Hardening** \u2014 accurate defense-in-depth gaps with no demonstrated exploit path; posture debt, always excluded from vulnerability counts.\n"

# Misconfiguration pattern buckets — first match wins (order matters).
PATTERNS = [
    (
        "confused-deputy-controller-sa",
        re.compile(
            r"confused.deputy|spoke.controlled|(tenant|user|cr).?(driven|supplied|controlled)"
            r".{0,60}(manifest|image|serviceaccount)|escalat.{0,50}(operator|controller)"
            r".{0,15}(sa\b|service ?account)|(operator|controller).{0,15}(sa\b|service ?account)"
            r".{0,50}(escalat|privileg)",
            re.I,
        ),
    ),
    (
        "cross-tenant-access",
        re.compile(
            r"cross.tenant|another tenant|other tenants?['s]?\s+(data|secret|credential|cluster|namespace)",
            re.I,
        ),
    ),
    ("cluster-admin-binding", re.compile(r"cluster-admin", re.I)),
    (
        "wildcard-verbs-or-resources",
        re.compile(
            r"wildcard.{0,40}(verb|resource)|(verb|resource)s?\s*[:=]?\s*\[?['\"]?\*|\*.{0,20}(verb|resource)",
            re.I,
        ),
    ),
    (
        "secrets-read-cluster-wide",
        re.compile(
            r"secrets?.{0,60}(get|list|watch|read).{0,60}(cluster|all namespaces)|"
            r"(cluster.wide|all namespaces).{0,60}secrets?",
            re.I,
        ),
    ),
    (
        "escalate-bind-impersonate",
        re.compile(
            r"\bimpersonat|escalate|\bbind\b.{0,40}verb|verb.{0,40}\bbind\b|csr|certificatesigningrequest",
            re.I,
        ),
    ),
    (
        "rbac-write-self-escalation",
        re.compile(r"(create|update|patch).{0,50}(clusterrole|rolebinding|role\b)|rbac self", re.I),
    ),
    (
        "cross-namespace-or-allnamespaces",
        re.compile(
            r"cross.namespace|allnamespaces|all namespaces|watch(es)? every namespace|fleet.wide (read|watch)",
            re.I,
        ),
    ),
    (
        "missing-tenant-scoping",
        re.compile(
            r"tenant.{0,50}(scop|filter|check|validat)|missing.{0,30}tenant|without.{0,30}tenant",
            re.I,
        ),
    ),
    ("sa-token-automount-or-default-sa", re.compile(r"automount|default service ?account", re.I)),
    (
        "missing-network-segmentation",
        re.compile(r"networkpolicy|network policy|default.deny|egress", re.I),
    ),
    ("webhook-or-aggregated-api-exposure", re.compile(r"webhook|aggregated api|admission", re.I)),
    (
        "github-actions-workflow-privilege",
        re.compile(
            r"pull_request_target|issue_comment|dangerous.workflow|workflow|"
            r"github.{0,10}(token|actions)|actions.{0,30}permission",
            re.I,
        ),
    ),
    (
        "unauthenticated-endpoint",
        re.compile(
            r"unauthenticated|no authentication|without auth(entication|orization)|"
            r"auth(entication|orization) (is )?(disabled|missing|absent)|"
            r"missing auth(entication|orization)|lacks? auth|anonymous access|"
            r"0\.0\.0\.0/0|world.(readable|accessible)",
            re.I,
        ),
    ),
    (
        "role-overgrant-app-level",
        re.compile(
            r"grant(s|ed)?.{0,60}(all (authenticated )?users|administer|run_scripts|"
            r"cluster.wide (update|write|edit))|overall/administer",
            re.I,
        ),
    ),
    (
        "injection-to-privilege",
        re.compile(
            r"(command|sql|template|parameter|predicate|drop.in|header) injection|"
            r"injection via|child_process|os command",
            re.I,
        ),
    ),
    (
        "untrusted-input-in-build-or-automerge",
        re.compile(
            r"auto.merge|gradlew|wrapper.{0,30}inherit|trusts? pr\b|"
            r"user.supplied.{0,30}(wrapper|build)",
            re.I,
        ),
    ),
    (
        "tls-verification-gaps",
        re.compile(
            r"self.signed|cipher suite|insecureskipverify|skip.{0,12}(tls|cert)|"
            r"certificate (validation|verification)|hostname verif",
            re.I,
        ),
    ),
    (
        "client-supplied-identity-trust",
        re.compile(
            r"(client|caller|user|attacker).{0,3}(controlled|supplied|asserted)"
            r".{0,40}(id\b|identity|header|token|tenant|subscription|role)|self.asserted",
            re.I,
        ),
    ),
    (
        "hardcoded-or-leaked-credentials",
        re.compile(
            r"hard.?coded|committed.{0,25}(secret|token|credential|password)|"
            r"(bearer token|credential|password).{0,30}(in (public )?source|leak)",
            re.I,
        ),
    ),
    (
        "privileged-workload-config",
        re.compile(
            r"privileged|runasany|\bscc\b|allowprivilegeescalation|"
            r"host(path|network|pid|ipc)|run(s|ning)? as root",
            re.I,
        ),
    ),
    (
        "cloud-iam-overbreadth",
        re.compile(r"\biam\b|irsa|cloud credential|role assumption|\bsts\b", re.I),
    ),
    (
        "shared-identity-across-tenants",
        re.compile(r"shared (service ?account|credential|key|identity|token)", re.I),
    ),
    # --- LLM-clustering tranche 2026-07-21 (proposals independently
    # checked against the tail with rbac_bucket_proposal_check.py;
    # appended last so they only carve from 'other') ---
    (
        "auth-proxy-path-exclusion-bypass",
        re.compile("(--ignore-paths|--allow-paths|\\bignore-paths\\b|\\ballow-paths\\b)", re.I),
    ),
    (
        "vulnerable-or-eol-dependency",
        re.compile(
            "(GO-20\\d{2}-\\d+|CVE-\\d{4}-\\d+|govulncheck|known[- ](CVEs?|advisories|vulnerabilit)|known-vulnerable|end-of-life|\\bEOL\\b|outdated|unmaintained|abandoned|deprecated|vulnerable\\s+(dependen|component|transitive|to)|last (commit|release) 20\\d\\d|ReDoS advisories)",
            re.I,
        ),
    ),
    (
        "secret-exposure-in-logs-argv-diagnostics",
        re.compile(
            "(logg?ed\\b|\\blogs?\\b\\s.*(token|secret|credential|password|payload|bod(y|ies)|header)|written to\\s+(std(out|err)|logs?/?|build log|debug)|prints?\\s.*(std(out|err)|log\\b)|printed to|echoed to|dump(s|ed)?\\s.*(std(out|err)|log|archive|artifact|environment)|(writes?|dumps?) all namespace secrets|--v=\\d+|verbosity|xtrace|set -x|\\bdebug\\s+(log|mode|task|transport|middleware|logger|http|wire)|trace log|to (container |pod )?stdout|leak\\S*\\s.*(log\\b|logs\\b|stdout)|collected|redact|(passed|supplied|exposed|token|secret|password|credential|passphrase)\\s+(on|via)\\s+.{0,40}(command[- ]line|argv)|command[- ]line via|-p (flag|cli|argument)|docker login -p|argv|positional flag|copied to clipboard)",
            re.I,
        ),
    ),
    (
        "attacker-directed-outbound-request",
        re.compile(
            "(ssrf|open[- ]proxy|arbitrary\\s+(scheme/host|protocol/address)|exfiltrat|outbound\\s+(url|fetch|GET|HTTP)|(tenant|user|caller|client|policy|config)[- ](controlled|supplied|configurable|chosen)\\s.{0,40}(url\\b|endpoint|nameserver|scrape target)|to tenant-controlled|no\\s+(scheme/host|destination)\\s+allow|sdk endpoint without host validation|forwarded to (policy|user|tenant))",
            re.I,
        ),
    ),
    (
        "missing-limits-resource-exhaustion-dos",
        re.compile(
            "(unbounded|slowloris|readheadertimeout|decompression|no timeout|without\\s+(a\\s+)?timeout|lacks timeout|memory[- ]exhaust|resource[- ]exhaust|disk exhaustion|cardinality|no rate-limiting|without\\s+(a\\s+)?size limit|no size limit|size limit\\b|\\bdos\\b|denial of service|goroutine-per|never evicted|grows without bound|no\\s+(GraphQL query-complexity|resource (requests?/limits|limits))|no (CPU/memory|concurrency) limit|resource requests or limits|empty resources block|without bounds|cost limit|redos)",
            re.I,
        ),
    ),
    (
        "inert-or-fail-open-security-control",
        re.compile(
            "(fail[s\\-]?\\s?open|copy-paste|missing\\s+`?return`?|does not\\s+(abort|return)|no-op|nonehandler|allow[- ]?all\\b|allowall|never\\s+(enforced|invoked|applied|exercised|triggers)|declared but never|dead\\s+(security|rbac|bootstrap)|silently\\s+(discarded|yields|disregard)|silent fallback|ineffective|is never|renders empty|bypass(es)? auth entirely|not aggregated to admin|enforced only for|dead code path|acts as (a )?wildcard|inverted|neutralises|(auth|authorization|rbac)\\S*\\s.{0,20}disabled (entirely|by default)|SETTINGS__DISABLE_RBAC|AUTHDISABLE)",
            re.I,
        ),
    ),
    (
        "cleartext-transport",
        re.compile(
            "(insecure-listen-address|\\bh2c\\b|plain(text)?\\s?http|plaintext\\s+(traffic|metrics|deks)|over\\s+(plaintext|cleartext|plain\\s?http)|cleartext http|db-disable-tls|use_ssl|s3_use_ssl|edge\\s+(tls\\s+)?terminat|insecureedgeterminationpolicy|podtopodtls|without\\s+(tls|auth or tls)|no tls|never enables tls|sslmode|prefer crc|plaintext downgrade|insecure gRPC channels)",
            re.I,
        ),
    ),
    (
        "unpinned-or-unverified-artifact",
        re.compile(
            "(mutable\\s+(tag|branch|ref|revision|git|upstream|labels)|:latest|:snapshot|floating|unpinned|not pinned by|pinned by (mutable )?tag|by tag,? not digest|without\\s+(checksum|integrity|signature)|no\\s+(integrity|checksum|catalog)|integrity\\s+(check|verification)|curl\\s*\\||pipes?\\s+remote|insecureacceptanything|gpgcheck=0|unsigned|unattested|unverified|signature policy|sources? (remote|unverified)|untagged|@latest|@main|tag-pinned)",
            re.I,
        ),
    ),
    (
        "cr-spec-privileged-passthrough",
        re.compile(
            "(secret-name template|spec\\.\\w+\\s+(permits|allows|enables)|via spec\\.|CR[- ]supplied|CR spec values|CR-controllable|user-controll?able\\s+(image|imageversion)|image\\s?override|installerimageoverride|overridevalues|podoverrides|override\\.env|podconfig\\.env|kubernetesexecutorconfig|caller-controlled|user-influenced|corev1 passthrough|env passthrough|init.?container.?commands|via CR annotation|permits guest-kernel|CR creator can target)",
            re.I,
        ),
    ),
    (
        "missing-repo-security-governance",
        re.compile(
            "(security\\.md|codeowners|owners (file|mirrors upstream)|no sast|sast\\s*(0|/|:|not|integrated)|no fuzz|fuzzing wired|fuzz testing$|scorecard|dependency[- ]update automation|dependabot|vulnerability[- ](disclosure|scanning)|0 approvals|snyk policy|renovate go-module updates disabled|no in-repo(sitory)? dependency)",
            re.I,
        ),
    ),
    (
        "hub-spoke-fleet-trust",
        re.compile(
            "(\\bspokes?\\b|managed hubs?\\b|manifestworks?\\b|klusterlet|hosting-cluster-name|spoke-asserted|spoke-writable|hub (trusts|sa|token|secret|proxy-server)|to every (spoke|managed|openshift spoke)|all managed hubs|managedcluster\\.status|bootstrap-cert holder|federation discovery|member cluster can)",
            re.I,
        ),
    ),
    (
        "broken-object-level-authorization",
        re.compile(
            "(broken object-level|\\bbola\\b|\\bidor\\b|insecure direct object|object-level author|without\\s+owner(ship)?\\s+check|no per-resource|per-resource (author|tenant|isolation)|any\\s+(authenticated\\s+)?user can|cross-user|cross-account|cross-session|does not bind\\s+(caller|approval)|lacks\\s+(caller|tenant|per-user)\\s+(author|org)|another user's|takeover|organization-scope bypass|granularity is namespace-level|no per-cluster authorization|lacks tenant authorization|clientid ignored|erasing another)",
            re.I,
        ),
    ),
]


# ---------------------------------------------------------------------------
# MITRE ATT&CK inference — CANDIDATE techniques (weakness-derived, never
# observed behavior; same semantics as /attack-coverage's category_map).
# Three sources, strongest first: cited (explicit Txxxx in finding text) >
# pattern (bucket-derived) > category (attack-mapping.json category_map).
# Every ID is validated against the pinned vendored table; unknown,
# deprecated, or revoked IDs are dropped and counted as warnings.
# ---------------------------------------------------------------------------
ATTACK_TABLE = HARNESS_ROOT / "harnessing/attack-coverage/tables" / "attack-techniques.json"
ATTACK_MAPPING = HARNESS_ROOT / "harnessing/attack-coverage/tables" / "attack-mapping.json"
TECH_RX = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

BUCKET_TECHNIQUES = {
    "cluster-admin-binding": ["T1078.004", "T1098"],
    "wildcard-verbs-or-resources": ["T1098", "T1548"],
    "secrets-read-cluster-wide": ["T1552.007", "T1528"],
    "escalate-bind-impersonate": ["T1548", "T1550.001"],
    "rbac-write-self-escalation": ["T1098", "T1548"],
    "cross-namespace-or-allnamespaces": ["T1613", "T1552.007"],
    "missing-tenant-scoping": ["T1613", "T1078"],
    "sa-token-automount-or-default-sa": ["T1528", "T1550.001"],
    "missing-network-segmentation": ["T1046", "T1210"],
    "webhook-or-aggregated-api-exposure": ["T1190"],
    "github-actions-workflow-privilege": ["T1195.002", "T1552"],
    "unauthenticated-endpoint": ["T1190"],
    "client-supplied-identity-trust": ["T1548", "T1190"],
    "hardcoded-or-leaked-credentials": ["T1552.001", "T1078"],
    "privileged-workload-config": ["T1611", "T1610"],
    "cloud-iam-overbreadth": ["T1078.004", "T1098.003"],
    "shared-identity-across-tenants": ["T1078.004", "T1550.001"],
    "confused-deputy-controller-sa": ["T1548", "T1609"],
    "cross-tenant-access": ["T1078.004", "T1530"],
    "injection-to-privilege": ["T1059", "T1190"],
    "role-overgrant-app-level": ["T1078", "T1098"],
    "untrusted-input-in-build-or-automerge": ["T1195.002"],
    "tls-verification-gaps": ["T1557"],
    "auth-proxy-path-exclusion-bypass": ["T1190", "T1550.001"],
    "vulnerable-or-eol-dependency": ["T1190", "T1210"],
    "secret-exposure-in-logs-argv-diagnostics": ["T1552"],
    "attacker-directed-outbound-request": ["T1190", "T1567"],
    "missing-limits-resource-exhaustion-dos": ["T1499"],
    "inert-or-fail-open-security-control": ["T1685"],
    "cleartext-transport": ["T1040", "T1557"],
    "unpinned-or-unverified-artifact": ["T1195.001", "T1195.002"],
    "cr-spec-privileged-passthrough": ["T1609", "T1610"],
    "missing-repo-security-governance": ["T1195.002"],
    "hub-spoke-fleet-trust": ["T1199", "T1550.001"],
    "broken-object-level-authorization": ["T1078", "T1213"],
}


def load_attack():
    table = json.loads(ATTACK_TABLE.read_text(encoding="utf-8"))
    mapping = json.loads(ATTACK_MAPPING.read_text(encoding="utf-8"))
    techs = table.get("techniques", {})
    cat_map = {k: v for k, v in mapping.get("category_map", {}).items() if not k.startswith("_")}
    return techs, cat_map, table.get("attack_version"), table.get("attribution")


def dropped_id_hint(tid: str, techs: dict) -> str:
    meta = techs.get(tid)
    if meta is None:
        return "not in the pinned table"
    if meta.get("revoked") and meta.get("revoked_by"):
        succ = meta["revoked_by"]
        sname = (techs.get(succ) or {}).get("name", "?")
        return f"REVOKED — remap to {succ} ({sname})"
    if meta.get("revoked"):
        return "REVOKED (no successor recorded)"
    return "DEPRECATED"


def infer_techniques(
    f: dict, text: str, pattern: str, techs: dict, cat_map: dict, dropped: Counter
) -> list[dict]:
    out = {}

    def add(tid: str, source: str):
        meta = techs.get(tid)
        if not meta or meta.get("deprecated") or meta.get("revoked"):
            dropped[tid] += 1
            return
        if tid not in out:
            out[tid] = {
                "id": tid,
                "name": meta["name"],
                "tactics": meta.get("tactics", []),
                "source": source,
            }

    for tid in TECH_RX.findall(text + " " + (f.get("attack_pattern") or "")):
        add(tid, "cited")
    for tid in BUCKET_TECHNIQUES.get(pattern, []):
        add(tid, "pattern")
    for tid in cat_map.get(f.get("category") or "", []):
        add(tid, "category")
    return list(out.values())


_SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
_DOWNGRADE_RX = re.compile(
    r"deployment context|contextual|downgrad|base score|CVSS base|"
    r"advisory (score|CVSS)|rated (low|medium|informational)|"
    r"not attacker.reachable|reachab|DATA REPAIR|SEVERITY RATIONALE|"
    r"accepted.risk|accepted deviation|documented (pattern|behaviou?r|posture)|"
    r"not a production|hardening (gap|note|observation)|"
    r"recorded (as|for|here)|noted (as|for|only)|informational because|"
    r"raised (as )?informational|for (inventory )?completeness|test fixture|"
    r"sample data|quickstart|intentional|by design|blast radius is small|"
    r"flagged information|upstream.documented|expected and documented|"
    r"functionally required|risk.acceptance",
    re.I,
)


def _cvss_band(score: float) -> str:
    return (
        "critical"
        if score >= 9.0
        else "high"
        if score >= 7.0
        else "medium"
        if score >= 4.0
        else "low"
    )


def severity_cvss_mismatch(f: dict) -> str | None:
    """'undocumented' | 'documented' | None — severity >=2 bands below the
    CVSS band (or informational-with-CVSS), with/without stated rationale."""
    score = (f.get("cvss") or {}).get("score")
    sev = f.get("severity")
    # 0.0 = a no-impact vector: internally consistent with informational/low,
    # never a mismatch (129-item triage 2026-07-21 proved this class is noise)
    if score is None or float(score) == 0.0 or sev not in _SEV_ORDER:
        return None
    gap = _SEV_ORDER.index(_cvss_band(float(score))) - _SEV_ORDER.index(sev)
    # informational with a sub-medium score (<4.0) is a minor style issue
    # (validator nudges it); only medium-band-or-higher scores are mismatches
    if (sev == "informational" and float(score) >= 4.0) or gap >= 2:
        return "documented" if _DOWNGRADE_RX.search(f.get("description", "")) else "undocumented"
    return None


def classify_axis(f: dict, text: str) -> set[str]:
    axes = set()
    if (
        f.get("category") == "authorization"
        or (set(f.get("cwes") or []) & AUTHZ_CWES)
        or RBAC_RX.search(text)
        or "K02" in text
    ):
        axes.add("rbac")
    if (
        f.get("category") == "tenant-isolation"
        or f.get("peach_references")
        or f.get("isolation_dimensions")
        or f.get("isolation_boundary")
        or TENANCY_RX.search(text)
        or "K08" in text
    ):
        axes.add("tenancy")
    return axes


def select_tier(f: dict, text: str) -> int | None:
    if (
        f.get("category") in ("authorization", "tenant-isolation")
        or f.get("peach_references")
        or f.get("isolation_dimensions")
        or f.get("isolation_boundary")
    ):
        return 1
    if (set(f.get("cwes") or []) & AUTHZ_CWES) or K_REF_RX.search(text):
        return 2
    if RBAC_RX.search(text) or TENANCY_RX.search(text):
        return 3
    return None


def bucket(text: str) -> str:
    for name, rx in PATTERNS:
        if rx.search(text):
            return name
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument("--analysis-results", type=Path, default=None)
    ap.add_argument(
        "--trees",
        nargs="*",
        default=["findings"],
        help="corpus trees to roll up (default: findings — the owned tree)",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="output dir (default progress-tracker/metrics/dashboards/rbac-tenancy)",
    )
    ap.add_argument(
        "--include",
        action="append",
        default=None,
        metavar="PRODUCT_GLOB[:REPO_GLOB]",
        help="scope to matching product dirs (fnmatch), optionally "
        "narrowed by repo glob — repeatable; default: everything",
    )
    ap.add_argument(
        "--axis",
        choices=["rbac", "tenancy", "both"],
        default="both",
        help="restrict to one selection axis (default both)",
    )
    args = ap.parse_args()

    engine = load_engine(args.config_home)
    ar = Path(args.analysis_results) if args.analysis_results else analysis_results_dir(engine)
    res = engine.corpus.load_resolution(trees=args.trees)
    store = report_store.ReportStore(report_store.LocalBackend(ar))
    pt = locations.require(
        locations.progress_tracker_dir(engine.ctx.locations),
        "progress_tracker",
    )
    out = Path(args.out) if args.out else pt / "metrics" / "dashboards" / "rbac-tenancy"
    out.mkdir(parents=True, exist_ok=True)

    techs, cat_map, attack_version, attack_attribution = load_attack()
    dropped_techs = Counter()
    sel = []
    stats = Counter()
    parse_errors = []
    import fnmatch

    def _in_scope(rec) -> bool:
        if not args.include:
            return True
        prod = rec.product or ""
        for pat in args.include:
            pglob, _, rglob = pat.partition(":")
            if fnmatch.fnmatch(prod, pglob) and (not rglob or fnmatch.fnmatch(rec.repo_dir, rglob)):
                return True
        return False

    for rec in res.records:
        if rec.is_branch_audit or rec.is_md_only:
            stats["skipped_branch_or_mdonly"] += 1
            continue
        if not _in_scope(rec):
            stats["skipped_out_of_scope"] += 1
            continue
        src = rec.findings_current or rec.audit_json
        disposition_aware = rec.findings_current is not None
        try:
            doc = store.get_json(report_store.to_ref(src, ar))
        except Exception as e:
            parse_errors.append(f"{src}: {e}")
            continue
        stats["reports_scanned"] += 1
        for f in doc.get("findings", []):
            text = f"{f.get('title', '')} {f.get('description', '')}"
            tier = select_tier(f, text)
            if tier is None:
                continue
            if args.axis != "both" and args.axis not in classify_axis(f, text):
                continue
            disp = f.get("disposition") or {}
            validity = disp.get("validity") or f.get("validation_status")
            if validity == "false_positive":
                stats["fp_excluded"] += 1
                continue
            pat = bucket(text)
            entry = {
                "repo": rec.repo_dir,
                "product": rec.product,
                "tree": rec.tree,
                "id": f.get("id"),
                "title": (f.get("title") or "")[:160],
                "severity": f.get("severity"),
                "cvss": (f.get("cvss") or {}).get("score"),
                "category": f.get("category"),
                "cwes": f.get("cwes") or [],
                "tier": tier,
                "axes": sorted(classify_axis(f, text)),
                "pattern": pat,
                "attack_techniques": infer_techniques(f, text, pat, techs, cat_map, dropped_techs),
                "peach": f.get("peach_references") or [],
                "isolation_dimensions": f.get("isolation_dimensions") or [],
                "confirmed": validity == "confirmed",
                "resolved": disp.get("resolution") == "resolved",
                "hardening": (
                    f.get("validation_status") == "hardening" or disp.get("validity") == "hardening"
                ),
                "disposition_aware": disposition_aware,
                "severity_cvss_mismatch": severity_cvss_mismatch(f),
                "locations": [loc.get("path") for loc in (f.get("locations") or [])][:3],
            }
            sel.append(entry)

    open_f = [e for e in sel if not e["resolved"] and not e["hardening"]]
    resolved = [e for e in sel if e["resolved"]]
    hardening = [e for e in sel if e["hardening"] and not e["resolved"]]

    def sev_counts(rows):
        c = Counter(e["severity"] for e in rows)
        return {s: c.get(s, 0) for s in ("critical", "high", "medium", "low", "informational")}

    def axis(rows, a):
        return [e for e in rows if a in e["axes"]]

    pattern_rank = Counter(e["pattern"] for e in open_f).most_common()
    # Worst offenders: per (repo, product) stats, then dedupe mirror-product
    # copies of the same repo by taking the MAX of each metric (mirror trees
    # carry identical reports); rank by critical, then high, then total open.
    per_path: dict[tuple, dict] = defaultdict(
        lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "total": 0,
            "confirmed": 0,
            "patterns": Counter(),
        }
    )
    for e in open_f:
        s = per_path[(e["repo"], e["product"] or "")]
        if e["severity"] in ("critical", "high", "medium"):
            s[e["severity"]] += 1
        s["total"] += 1
        if e["confirmed"]:
            s["confirmed"] += 1
        s["patterns"][e["pattern"]] += 1
    by_slug: dict[str, dict] = {}
    repo_products = defaultdict(set)
    for (repo, product), s in per_path.items():
        repo_products[repo].add(product)
        cur = by_slug.setdefault(
            repo,
            {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "total": 0,
                "confirmed": 0,
                "patterns": Counter(),
            },
        )
        for k in ("critical", "high", "medium", "total", "confirmed"):
            cur[k] = max(cur[k], s[k])
        if sum(s["patterns"].values()) > sum(cur["patterns"].values()):
            cur["patterns"] = s["patterns"]
    worst = []
    for repo, s in by_slug.items():
        prods = sorted(p for p in repo_products[repo] if p)
        top_pat = s["patterns"].most_common(1)
        worst.append(
            {
                "repo": repo,
                "products": prods,
                "critical": s["critical"],
                "high": s["high"],
                "medium": s["medium"],
                "open_total": s["total"],
                "confirmed": s["confirmed"],
                "dominant_pattern": top_pat[0][0] if top_pat else None,
            }
        )
    worst.sort(key=lambda w: (-w["critical"], -w["high"], -w["open_total"]))
    worst = worst[:25]
    per_repo = Counter(
        {  # kept for the HTML chart
            f"{w['repo']}" + (f"  ({', '.join(w['products'])})" if w["products"] else ""): w[
                "critical"
            ]
            + w["high"]
            for w in worst
            if w["critical"] + w["high"]
        }
    )
    peach_dims = Counter(d for e in open_f for d in e["isolation_dimensions"])
    tiers = Counter(e["tier"] for e in open_f)

    # ATT&CK heat: per-technique open-finding counts + tactic distribution
    tech_heat = Counter()
    tech_meta = {}
    tech_cited = Counter()
    tactic_heat = Counter()
    for e in open_f:
        for t in e["attack_techniques"]:
            tech_heat[t["id"]] += 1
            tech_meta[t["id"]] = t
            if t["source"] == "cited":
                tech_cited[t["id"]] += 1
            for ta in t["tactics"]:
                tactic_heat[ta] += 1
    attack_rollup = {
        "attack_version": attack_version,
        "attribution": attack_attribution,
        "semantics": (
            "weakness-derived CANDIDATE techniques (what an adversary "
            "would use to exploit the weakness class) — never observed "
            "behavior; 'cited' counts findings whose text names the "
            "technique explicitly"
        ),
        "techniques": [
            {
                "id": tid,
                "name": tech_meta[tid]["name"],
                "tactics": tech_meta[tid]["tactics"],
                "open_findings": n,
                "cited_in": tech_cited.get(tid, 0),
            }
            for tid, n in tech_heat.most_common()
        ],
        "tactics": dict(tactic_heat.most_common()),
        "dropped_unknown_or_deprecated": dict(dropped_techs),
    }

    pop = corpus.render_population_block(
        res,
        tool="build_rbac_tenancy_rollup.py",
        unit="RBAC/tenancy findings (open, per finding)",
        filters=(
            "branch re-audits and md-only reports excluded; findings selected by "
            "3-tier RBAC/tenancy predicate (see SKILL.md); disposition-aware where "
            "findings-current exists: false_positive excluded, resolved and hardening "
            "bucketed separately"
            + (f"; PRODUCT SCOPE: {', '.join(args.include)}" if args.include else "")
            + (f"; AXIS: {args.axis} only" if args.axis != "both" else "")
        ),
        denominator="corpus.resolve() over the configured trees (census is the authority)",
    )

    rollup = {
        "generated_by": f"rbac-tenancy-rollup @ {harness_version()}",
        "trees": args.trees,
        "stats": dict(stats),
        "parse_errors": parse_errors,
        "totals": {
            "selected": len(sel),
            "open": len(open_f),
            "resolved": len(resolved),
            "hardening": len(hardening),
            "fp_excluded": stats["fp_excluded"],
            "open_severity": sev_counts(open_f),
            "open_rbac": len(axis(open_f, "rbac")),
            "open_tenancy": len(axis(open_f, "tenancy")),
            "confirmed": sum(1 for e in open_f if e["confirmed"]),
            "tiers": {f"T{k}": v for k, v in sorted(tiers.items())},
        },
        "patterns": [{"pattern": p, "open": n} for p, n in pattern_rank],
        "attack": attack_rollup,
        "peach_dimensions": dict(peach_dims.most_common()),
        "worst_offenders": worst,
        "data_quality": {
            "severity_cvss_mismatches": {
                "undocumented": [
                    {
                        "repo": e["repo"],
                        "id": e["id"],
                        "severity": e["severity"],
                        "cvss": e["cvss"],
                        "title": e["title"],
                    }
                    for e in open_f
                    if e["severity_cvss_mismatch"] == "undocumented"
                ],
                "documented_downgrades": sum(
                    1 for e in open_f if e["severity_cvss_mismatch"] == "documented"
                ),
            },
        },
        "top_repos_crit_high": per_repo.most_common(25),
        "findings_open": sorted(open_f, key=lambda e: -(e["cvss"] or 0)),
        "population_block": pop,
    }
    if dropped_techs:
        print("\n" + "!" * 72, file=sys.stderr)
        print("!! ATT&CK MAPPING DRIFT — candidate techniques silently dropped:", file=sys.stderr)
        for tid, n in dropped_techs.most_common():
            print(f"!!   {tid} dropped {n}x — {dropped_id_hint(tid, techs)}", file=sys.stderr)
        print("!! Fix BUCKET_TECHNIQUES (or the category map) — until then the", file=sys.stderr)
        print("!! affected buckets have NO ATT&CK candidates in the outputs.", file=sys.stderr)
        print("!" * 72 + "\n", file=sys.stderr)

    (out / "rbac-tenancy.json").write_text(json.dumps(rollup, indent=1) + "\n", encoding="utf-8")

    # ---- executive one-pager -------------------------------------------
    t = rollup["totals"]
    sv = t["open_severity"]
    ex = []
    ex.append("# RBAC & Multi-Tenancy Findings — Executive Rollup\n")
    ex.append(pop + "\n")
    ex.append(LEGEND_MD)
    ex.append(
        f"## Headline: {t['open']} open RBAC/tenancy findings — "
        f"{sv['critical']} critical / {sv['high']} high / {sv['medium']} medium / "
        f"{sv['low']} low / {sv['informational']} informational\n"
    )
    ex.append(
        f"- **RBAC axis:** {t['open_rbac']} open · **Tenancy axis:** "
        f"{t['open_tenancy']} open (findings can carry both axes)"
    )
    ex.append(
        f"- **Execution/human-confirmed:** {t['confirmed']} · "
        f"**Resolved (excluded from open):** {t['resolved']} · "
        f"**Hardening backlog (posture, not vulnerabilities):** {t['hardening']} · "
        f"**False positives excluded:** {t['fp_excluded']}"
    )
    ex.append(
        f"- **Selection confidence:** structured T1 {t['tiers'].get('T1', 0)} · "
        f"framework T2 {t['tiers'].get('T2', 0)} · lexical-heuristic T3 "
        f"{t['tiers'].get('T3', 0)} (T3 rows are keyword matches — spot-check "
        f"before quoting individually; aggregates are directionally sound)\n"
    )
    ex.append("## Top misconfiguration patterns (open findings)\n")
    ex.append("| # | Pattern | Open |")
    ex.append("|---|---|---:|")
    for i, row in enumerate(rollup["patterns"][:12], 1):
        ex.append(f"| {i} | {row['pattern']} | {row['open']} |")
    dq = rollup["data_quality"]["severity_cvss_mismatches"]
    ex.append("\n## Data quality: severity vs CVSS\n")
    ex.append(
        f"- Documented contextual downgrades (advisory score > judged severity, rationale stated): {dq['documented_downgrades']}"
    )
    ex.append(
        f"- **Undocumented mismatches: {len(dq['undocumented'])}** — severity >=2 bands below the CVSS band with no stated rationale; the validator now flags these at emission (2026-07-21). Fix in the source report, not here."
    )
    for m in dq["undocumented"][:8]:
        ex.append(
            f"  - {m['severity']} @ CVSS {m['cvss']} — {m['repo']} {m['id']}: {m['title'][:80]}"
        )
    ex.append(f"\n## MITRE ATT&CK candidate-technique heat (ATT&CK {attack_version})\n")
    ex.append(
        "_Weakness-derived candidates (what an adversary would use to exploit each "
        "class) — not observed behavior. 'Cited' = findings whose own text names "
        "the technique._\n"
    )
    ex.append("| Technique | Name | Tactics | Open findings | Cited |")
    ex.append("|---|---|---|---:|---:|")
    for row in attack_rollup["techniques"][:12]:
        ex.append(
            f"| {row['id']} | {row['name']} | {', '.join(row['tactics'])} | "
            f"{row['open_findings']} | {row['cited_in'] or ''} |"
        )
    ex.append(
        "\n**Tactic distribution:** "
        + " · ".join(f"{k} {v}" for k, v in list(attack_rollup["tactics"].items())[:8])
    )
    if dropped_techs:
        ex.append(
            "\n> ⚠ **ATT&CK mapping drift:** "
            + ", ".join(
                f"{tid} (dropped {n}×: {dropped_id_hint(tid, techs)})"
                for tid, n in dropped_techs.most_common()
            )
            + " — affected buckets are missing candidates until the map is fixed."
        )
    ex.append(f"\n_{attack_attribution}_\n")
    ex.append("\n## Top 25 worst offenders (repositories)\n")
    ex.append(
        "_Ranked by open critical, then high, then total open RBAC/tenancy "
        "findings; mirror-product copies deduplicated (max per metric)._\n"
    )
    ex.append("| # | Repository | Products | C | H | M | Open | Confirmed | Dominant pattern |")
    ex.append("|---|---|---|---:|---:|---:|---:|---:|---|")
    for i, w in enumerate(rollup["worst_offenders"], 1):
        prods = ", ".join(w["products"][:3]) + ("…" if len(w["products"]) > 3 else "")
        ex.append(
            f"| {i} | {w['repo']} | {prods} | {w['critical']} | {w['high']} | "
            f"{w['medium']} | {w['open_total']} | {w['confirmed']} | "
            f"{w['dominant_pattern'] or '—'} |"
        )
    if peach_dims:
        ex.append("\n## PEACH isolation dimensions (tagged findings)\n")
        ex.append(" · ".join(f"**{k}** {v}" for k, v in peach_dims.most_common()))
    ex.append(
        "\nDetailed misconfigurations: `rbac-tenancy-detailed.md` · "
        "machine-readable: `rbac-tenancy.json`\n"
    )
    (out / "rbac-tenancy-rollup.md").write_text("\n".join(ex), encoding="utf-8")

    # ---- detailed report ------------------------------------------------
    dt = []
    dt.append("# RBAC & Multi-Tenancy — Top Misconfigurations (detailed)\n")
    dt.append(pop + "\n")
    dt.append(LEGEND_MD)
    by_pattern = defaultdict(list)
    for e in open_f:
        by_pattern[e["pattern"]].append(e)
    for p, n in pattern_rank:
        rows = sorted(by_pattern[p], key=lambda e: -(e["cvss"] or 0))
        ch = sum(1 for e in rows if e["severity"] in ("critical", "high"))
        dt.append(f"\n## {p} — {n} open ({ch} critical/high)\n")
        bt = BUCKET_TECHNIQUES.get(p)
        if bt:
            names = [f"{tid} ({techs[tid]['name']})" for tid in bt if tid in techs]
            dt.append(f"_ATT&CK candidates: {', '.join(names)}_\n")
        if p == "other":
            # heterogeneous tail: sub-group by weakness category for
            # navigation (honest structure — no pattern claim implied)
            dt.append(
                "_No recurring pattern — grouped by finding category for "
                "navigation; each entry is an individual finding._\n"
            )
            _VOCAB = [
                "tenant-isolation",
                "authorization",
                "authentication",
                "secrets-management",
                "supply-chain",
                "insecure-workload-config",
                "network-exposure",
                "cryptography",
                "input-validation",
                "path-traversal",
                "cross-site-scripting",
                "ssrf",
                "resource-management",
                "logging-monitoring",
                "data-exposure",
                "injection",
            ]

            def _norm_cat(c, _vocab=_VOCAB):
                if not c:
                    return "uncategorized (legacy report)"
                lc = re.sub(r"[\s_]+", "-", str(c).strip().lower())
                if lc in _vocab:
                    return lc
                # legacy free-form labels: map by recognizable token
                for v in _vocab:
                    if v in lc or v.replace("-", " ") in str(c).lower():
                        return v
                low = str(c).lower()
                for token, v in (
                    ("access control", "authorization"),
                    ("auth", "authentication"),
                    ("secret", "secrets-management"),
                    ("crypto", "cryptography"),
                    ("inject", "injection"),
                    ("supply", "supply-chain"),
                    ("workload", "insecure-workload-config"),
                    ("network", "network-exposure"),
                    ("logging", "logging-monitoring"),
                ):
                    if token in low:
                        return v
                return "nonstandard category label"

            by_cat = defaultdict(list)
            for e in rows:
                by_cat[_norm_cat(e["category"])].append(e)
            for cat, crows in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
                cch = sum(1 for e in crows if e["severity"] in ("critical", "high"))
                dt.append(f"\n### other / {cat} — {len(crows)} open ({cch} critical/high)\n")
                dt.append("| Sev | CVSS | Repository | Finding | Tier |")
                dt.append("|---|---|---|---|---|")
                for e in crows[:15]:
                    repo = f"{e['product'] or ''}/{e['repo']}".lstrip("/")
                    conf = " ✓conf" if e["confirmed"] else ""
                    dt.append(
                        f"| {e['severity']} | {e['cvss'] or '—'} | {repo} | "
                        f"{e['title']} (`{e['id']}`){conf} | T{e['tier']} |"
                    )
                if len(crows) > 15:
                    dt.append(f"\n_…and {len(crows) - 15} more (see rbac-tenancy.json)._")
            continue
        dt.append("| Sev | CVSS | Repository | Finding | Tier |")
        dt.append("|---|---|---|---|---|")
        for e in rows[:15]:
            repo = f"{e['product'] or ''}/{e['repo']}".lstrip("/")
            conf = " ✓conf" if e["confirmed"] else ""
            dt.append(
                f"| {e['severity']} | {e['cvss'] or '—'} | {repo} | "
                f"{e['title']} (`{e['id']}`){conf} | T{e['tier']} |"
            )
        if len(rows) > 15:
            dt.append(f"\n_…and {len(rows) - 15} more (see rbac-tenancy.json)._")
    if hardening:
        hc = Counter(e["pattern"] for e in hardening)
        dt.append("\n## Hardening backlog (posture debt — not vulnerabilities)\n")
        dt.append(" · ".join(f"{k} {v}" for k, v in hc.most_common()))
    (out / "rbac-tenancy-detailed.md").write_text("\n".join(dt), encoding="utf-8")

    # ---- compact self-contained html ------------------------------------
    def bar(v, mx):
        return f'<div style="background:#ec7a08;height:12px;width:{max(int(v / mx * 420), 3)}px"></div>'

    mx = max((n for _, n in pattern_rank[:12]), default=1)
    rows_html = "".join(
        f"<tr><td>{esc_html(p)}</td><td>{bar(n, mx)}</td><td style='text-align:right'>{n}</td></tr>"
        for p, n in pattern_rank[:12]
    )
    top_html = "".join(
        f"<tr><td>{esc_html(r)}</td><td style='text-align:right'>{n}</td></tr>"
        for r, n in rollup["top_repos_crit_high"][:15]
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>RBAC & Multi-Tenancy Rollup</title><style>
body{{font-family:-apple-system,'Red Hat Text',sans-serif;background:#f5f5f5;color:#151515;margin:24px}}
.card{{background:#fff;border-radius:6px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.08)}}
h1{{font-size:20px}}h2{{font-size:15px;color:#6a6e73;text-transform:uppercase;letter-spacing:.04em}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{padding:4px 8px;border-bottom:1px solid #eee;text-align:left}}
.kpi{{display:inline-block;margin-right:32px}}.kpi b{{font-size:34px}}.kpi span{{color:#6a6e73;font-size:12px;display:block}}
.banner{{background:#151515;color:#fff;padding:6px 12px;font-size:12px;border-radius:4px;margin-bottom:16px}}
</style></head><body>
<div class="banner">RED HAT INTERNAL — EMBARGOED</div>
<h1>RBAC &amp; Multi-Tenancy Findings Rollup <span style="color:#6a6e73;font-size:13px">· {harness_version()} · trees: {", ".join(args.trees)}</span></h1>
<div class="card"><span class="kpi"><b>{t["open"]}</b><span>open findings</span></span>
<span class="kpi"><b style="color:#cc0000">{sv["critical"]}</b><span>critical</span></span>
<span class="kpi"><b style="color:#ec7a08">{sv["high"]}</b><span>high</span></span>
<span class="kpi"><b>{t["open_rbac"]}</b><span>RBAC axis</span></span>
<span class="kpi"><b>{t["open_tenancy"]}</b><span>tenancy axis</span></span>
<span class="kpi"><b>{t["confirmed"]}</b><span>confirmed</span></span>
<span class="kpi"><b>{t["resolved"]}</b><span>resolved (excluded)</span></span></div>
<div class="card"><h2>Top misconfiguration patterns</h2><table>{rows_html}</table></div>
<div class="card"><h2>Top repositories (open critical+high)</h2><table>{top_html}</table></div>
<div class="card"><h2>Legend</h2><ul style="font-size:12px;color:#444;margin:4px 0 0 16px;padding:0">
<li><b>T1/T2/T3</b> — selection confidence: T1 structured category/PEACH fields, T2 framework signals (authz CWEs, K02/K08), T3 keyword heuristic (verify individual rows before quoting).</li>
<li><b>Confirmed</b> — execution evidence (fuzz/PoC/live validation) or human triage; all else is static-analysis judgment.</li>
<li><b>ATT&amp;CK candidates</b> — weakness-derived techniques an adversary would use; never observed behavior. Validated against the pinned ATT&amp;CK table.</li>
<li><b>other</b> — no recurring pattern; individual findings grouped by category for navigation.</li>
<li><b>Severity bands</b> — C 9.0–10 · H 7.0–8.9 · M 4.0–6.9 · L 0.1–3.9; sub-band severities carry a stated contextual-downgrade rationale.</li>
</ul></div>
<div class="card" style="font-size:12px;color:#6a6e73"><pre style="white-space:pre-wrap">{pop}</pre></div>
</body></html>"""
    (out / "rbac-tenancy.html").write_text(html, encoding="utf-8")

    print(
        f"rbac-tenancy rollup: {t['open']} open "
        f"({sv['critical']}C/{sv['high']}H/{sv['medium']}M) from "
        f"{stats['reports_scanned']} reports; resolved {t['resolved']}, "
        f"hardening {t['hardening']}, FP excluded {t['fp_excluded']}, "
        f"parse errors {len(parse_errors)}"
    )
    print(
        f"  wrote {out}/rbac-tenancy{{.json,.html}}, "
        f"rbac-tenancy-rollup.md, rbac-tenancy-detailed.md"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
