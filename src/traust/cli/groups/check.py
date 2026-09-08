"""``traust check …`` — deterministic gates and consistency guards."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    (
        "citations",
        "check_citations",
        "Citation gate: deterministic pre-verification check for triage reports.",
    ),
    (
        "content-licenses",
        "check_content_licenses",
        "Content-license guard — deterministic enforcement of the two license tables.",
    ),
    (
        "docs-consistency",
        "check_docs_consistency",
        "Doc-consistency checker — catch documentation drift before it ships.",
    ),
    (
        "drift",
        "check_drift",
        "Staleness & drift checker across derived artifacts and paired reports.",
    ),
    (
        "fix-propagation",
        "check_fix_propagation",
        "Deterministic fix-propagation check for cross-repo remediation chains.",
    ),
    (
        "location-paths",
        "check_location_paths",
        "Gate: `locations[].path` must identify an artifact, not the repo root.",
    ),
    (
        "reference-integrity",
        "check_reference_integrity",
        "Reference-integrity gate (C8.4 placement-rule companion).",
    ),
    (
        "skill-alignment",
        "check_skill_alignment",
        "Cross-skill alignment guard — catch a skill drifting from the corpus.",
    ),
    (
        "skill-security",
        "check_skill_security",
        "Skill security-posture guard — catch a new or edited skill dropping controls.",
    ),
    (
        "report-digests",
        "verify_report_digests",
        "Verify every report against the digest its layer signed.",
    ),
)

CHECK: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
