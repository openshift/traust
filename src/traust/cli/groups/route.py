"""``traust route …`` — findings corpus routing."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    (
        "impact-findings",
        "route_impact_findings",
        "Route /impact-analysis `affected` classifications into the findings corpus.",
    ),
    (
        "regressions",
        "route_regressions",
        "Route verify-remediation Phase-5 regressions into the findings corpus.",
    ),
)

ROUTE: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
