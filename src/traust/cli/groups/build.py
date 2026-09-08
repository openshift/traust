"""``traust build …`` — deterministic builders and indexes."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("cumulative", "build_cumulative", "Deterministic merge engine for the track-findings skill."),
    (
        "rescan-worklist",
        "build_rescan_worklist",
        "Build the continuous-operations rescan worklist — the daily router.",
    ),
    (
        "skills-reference",
        "build_skills_reference",
        "Generate docs/skills.md from the skill tree — never hand-edit that file.",
    ),
    ("symbol-index", "build_symbol_index", "Build a per-run symbol index for a target repo clone."),
)

BUILD: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
