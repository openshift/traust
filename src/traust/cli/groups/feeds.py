"""``traust feeds …`` — external reference feed cache."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("fetch", "fetch_feeds", "Pull-through cache for external reference feeds."),
    (
        "reconcile-cve-provenance",
        "reconcile_cve_provenance",
        "Reconcile audit findings against published Red Hat CVEs.",
    ),
)

FEEDS: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
