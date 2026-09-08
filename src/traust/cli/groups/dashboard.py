"""``traust dashboard …`` — deterministic dashboard rebuild."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REFRESH = passthrough_op(
    "refresh_dashboards",
    "Rebuild every deterministic dashboard in dependency order.",
)

DASHBOARD: dict[str, object] = {"refresh": REFRESH}
