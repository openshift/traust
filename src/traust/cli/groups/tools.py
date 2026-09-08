"""``traust tools …`` — deprecated aliases for migrated command groups."""

from __future__ import annotations

from traust.cli.groups.admin import ADMIN
from traust.cli.groups.build import BUILD
from traust.cli.groups.check import CHECK
from traust.cli.groups.dashboard import DASHBOARD
from traust.cli.groups.feeds import FEEDS
from traust.cli.groups.impact import IMPACT_OPS
from traust.cli.groups.ledger import LEDGER
from traust.cli.groups.route import ROUTE

TOOLS: dict[str, object] = {
    "attest-target": ADMIN["attest-target"],
    "build-cumulative": BUILD["cumulative"],
    "build-rescan-worklist": BUILD["rescan-worklist"],
    "build-skills-reference": BUILD["skills-reference"],
    "build-symbol-index": BUILD["symbol-index"],
    "calibrate-rule-pack": IMPACT_OPS["calibrate-rule-pack"],
    "check-citations": CHECK["citations"],
    "check-content-licenses": CHECK["content-licenses"],
    "check-docs-consistency": CHECK["docs-consistency"],
    "check-drift": CHECK["drift"],
    "check-fix-propagation": CHECK["fix-propagation"],
    "check-location-paths": CHECK["location-paths"],
    "check-reference-integrity": CHECK["reference-integrity"],
    "check-skill-alignment": CHECK["skill-alignment"],
    "check-skill-security": CHECK["skill-security"],
    "checkpoint": ADMIN["checkpoint"],
    "cluster-state-diff": IMPACT_OPS["cluster-state-diff"],
    "countersign": ADMIN["countersign"],
    "emit-doc-variance": LEDGER["doc-variance"],
    "emit-triage-ledger-events": LEDGER["emit-triage"],
    "emit-validation-ledger-events": LEDGER["emit-validation"],
    "emit-verification-ledger-events": LEDGER["emit-verification"],
    "fetch-feeds": FEEDS["fetch"],
    "query-index": ADMIN["query-index"],
    "reconcile-cve-provenance": FEEDS["reconcile-cve-provenance"],
    "refresh-dashboards": DASHBOARD["refresh"],
    "resolve-advisory-symbols": IMPACT_OPS["resolve-advisory-symbols"],
    "route-impact-findings": ROUTE["impact-findings"],
    "route-regressions": ROUTE["regressions"],
    "run-impact-sweep": IMPACT_OPS["sweep"],
    "scan-internal-refs": ADMIN["scan-internal-refs"],
    "toolchain": ADMIN["toolchain"],
    "verify-report-digests": CHECK["report-digests"],
}
