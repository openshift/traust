#!/usr/bin/env python3
"""
Refutation-soundness gate for the validate-findings engine.

Phase 1 of the scanning-skill error-correction plan
(progress-tracker/plans/scanning-skill-error-correction-plan.md v2.0):
~70% of historical live-validation refutations rested on probes that
never actually tested the claim (fp-live-refuted.md, 2026-07-22) — the
probe errored out (validator RBAC Forbidden, tool-not-found, jsonpath
failures, target NotFound), or an RBAC template probe enumerated zero
concrete subjects (empty ``vf-rbac-tried:`` list, or a literal
un-substituted ``system:serviceaccount:{ns}:{sa}`` template), or the
operand never installed (``install-failure.yaml`` in the run directory)
yet the run still emitted ``refuted`` verdicts that became ledgered
false-positive events.

This module makes ``refuted`` deterministically UN-EMITTABLE under any
of those conditions. Gated verdicts downgrade to ``inconclusive`` and
carry a machine-readable ``soundness_flag``:

  error-signature:<name>     probe transcript matches an error signature
  rbac-zero-subjects         RBAC-style probe enumerated zero concrete
                             subjects (empty ``vf-rbac-tried:`` list)
  rbac-template-placeholder  RBAC-style probe carries an un-substituted
                             template placeholder (``{ns}``/``{sa}``)
  target-not-deployed        the run directory contains
                             install-failure.yaml — the operand never
                             installed, so nothing in the run can refute

Downstream contract: a finding carrying a soundness_flag routes to
``needs_review`` (emit_validation_ledger_events.py), never to the
false-positive/countersign path.

Shared by: execute.py (step-level gate at dispatch time),
report.py (finding-level rollup), emit_validation_ledger_events.py
(retroactive gate on ungated legacy reports), and
traust.ops.lint_refutation_soundness (retroactive corpus linter).
"""

from __future__ import annotations

import re
from pathlib import Path

#: A run containing this file never reached a deployed target; no verdict
#: in it may claim ``refuted`` (deploy-operator writes it on OLM/operand
#: install failure).
INSTALL_FAILURE_FILENAME = "install-failure.yaml"

FLAG_TARGET_NOT_DEPLOYED = "target-not-deployed"
FLAG_RBAC_ZERO_SUBJECTS = "rbac-zero-subjects"
FLAG_RBAC_TEMPLATE = "rbac-template-placeholder"
FLAG_MISSING_CONTROL = "missing-positive-control"
FLAG_FAILED_CONTROL = "failed-positive-control"
FLAG_NON_DISCRIMINATING = "non-discriminating-oracle"
FLAG_MISSING_DIFFERENTIAL = "missing-differential-probe"

#: Probe-transcript error signatures (fp-live-refuted.md §4.1.1). Any of
#: these in ``observed`` means the probe errored before testing the
#: claim — the transcript records the VALIDATOR's failure, not the
#: target's control. Order matters only for which name gets reported.
ERROR_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    # kubectl/oc RBAC denial of the probe's own user
    # (`Error from server (Forbidden): ... User "<user>" cannot list ...`)
    (
        "forbidden",
        re.compile(
            r"Error from server \(Forbidden\)"
            r"|\bforbidden: User\b"
            r"|\bForbidden\b[^\n]{0,160}\bcannot (?:get|list|watch|create"
            r"|update|patch|delete|impersonate|use)\b"
            r"|\bUser \"[^\"]+\" cannot (?:get|list|watch|create|update"
            r"|patch|delete|impersonate|use)\b",
            re.IGNORECASE,
        ),
    ),
    # host tooling missing (`bash: openssl: command not found`)
    (
        "command-not-found",
        re.compile(
            r"command not found|executable file not found"
            r"|not found in \$?PATH",
            re.IGNORECASE,
        ),
    ),
    # kubectl jsonpath template errors
    (
        "jsonpath-error",
        re.compile(
            r"error executing jsonpath|error parsing jsonpath"
            r"|unrecognized identifier",
            re.IGNORECASE,
        ),
    ),
    # probe target absent from the API server
    (
        "not-found",
        re.compile(
            r"Error from server \(NotFound\)"
            r"|the server doesn'?t have a resource type",
            re.IGNORECASE,
        ),
    ),
    # generic absence errors (`... does not exist`)
    ("does-not-exist", re.compile(r"\bdoes not exist\b", re.IGNORECASE)),
    # connectivity failures — the probe never reached the target
    (
        "could-not-connect",
        re.compile(
            r"Could not connect|Unable to connect to the server"
            r"|could not resolve host|no route to host",
            re.IGNORECASE,
        ),
    ),
    # a literal un-substituted template anywhere in the transcript
    (
        "unsubstituted-template",
        re.compile(
            r"system:serviceaccount:\{[^}]*\}"
            r"|\{ns\}:\{sa\}|--as=[^\s\"']*\{[a-z_]+\}"
        ),
    ),
)

#: Marker emitted by the plan.py RBAC probe: ``vf-rbac-tried:<subjects>``.
#: Empty subject list == nothing was ever probed.
_RBAC_TRIED_EMPTY_RE = re.compile(r"^vf-rbac-tried:\s*$", re.MULTILINE)
_RBAC_MARKER_RE = re.compile(r"vf-rbac-")
_RBAC_TEMPLATE_RE = re.compile(r"system:serviceaccount:\{[^}]*\}|\{ns\}:\{sa\}")


def is_rbac_probe(verb: str, observed: str) -> bool:
    """An RBAC-style probe: the ``rbac-can-i`` verb or any transcript
    carrying the harness's ``vf-rbac-*`` markers."""
    return verb == "rbac-can-i" or bool(_RBAC_MARKER_RE.search(observed or ""))


def match_error_signature(observed: str) -> str | None:
    """Name of the first matching error signature in the transcript."""
    text = observed or ""
    for name, pat in ERROR_SIGNATURES:
        if pat.search(text):
            return name
    return None


def soundness_flag(verb: str, observed: str, *, install_failure: bool = False) -> str | None:
    """The soundness flag a ``refuted`` verdict would carry, or None
    when the refutation is emittable. Deterministic; text-only."""
    if install_failure:
        return FLAG_TARGET_NOT_DEPLOYED
    text = observed or ""
    sig = match_error_signature(text)
    if sig:
        return f"error-signature:{sig}"
    if is_rbac_probe(verb, text):
        if _RBAC_TEMPLATE_RE.search(text):
            return FLAG_RBAC_TEMPLATE
        if _RBAC_TRIED_EMPTY_RE.search(text):
            return FLAG_RBAC_ZERO_SUBJECTS
    return None


def gate_verdict(
    verdict: str, verb: str, observed: str, *, install_failure: bool = False
) -> tuple[str, str | None]:
    """Apply the soundness gate to a step verdict.

    Only ``refuted`` is gated (downgrade-not-drop: a gated refutation
    becomes ``inconclusive`` + flag; confirmations and other verdicts
    pass through untouched).
    """
    if verdict != "refuted":
        return verdict, None
    flag = soundness_flag(verb, observed, install_failure=install_failure)
    if flag:
        return "inconclusive", flag
    return verdict, None


def run_install_failed(run_dir: Path | str) -> bool:
    """True when the run directory records an operand install failure."""
    return (Path(run_dir) / INSTALL_FAILURE_FILENAME).is_file()


def controls_flag(vf: dict, *, required: bool = False) -> str | None:
    """P1 assay-validity gate: a refuted verdict must rest on at least
    one PASSING positive control on its refuted steps (reports at/after
    CONTROLS_SINCE in the emitter set required=True). A failed control
    invalidates the refutation regardless of report age — the assay
    itself demonstrably didn't work."""
    if vf.get("verdict") != "refuted":
        return None
    controls = []
    for step in vf.get("steps") or []:
        if step.get("verdict") == "refuted":
            controls.extend(step.get("controls") or [])
    if any(c.get("ok") is False for c in controls):
        return FLAG_FAILED_CONTROL
    if required and not any(c.get("ok") for c in controls):
        return FLAG_MISSING_CONTROL
    return None


def differential_flag(vf: dict, *, required: bool = False) -> str | None:
    """P3 differential gate for authz refutations: when a step carries a
    differential probe whose outcomes did NOT differ, the oracle cannot
    discriminate allowed from denied — the refutation is unsound at any
    report age. When `required` (reports at/after DIFFERENTIAL_SINCE in
    the emitter), RBAC/authz-class refuted steps must carry a
    discriminating differential."""
    if vf.get("verdict") != "refuted":
        return None
    saw_authz_step = False
    saw_discriminating = False
    for step in vf.get("steps") or []:
        if step.get("verdict") != "refuted":
            continue
        diff = step.get("differential")
        if diff is not None:
            if diff.get("discriminated") is False:
                return FLAG_NON_DISCRIMINATING
            if diff.get("discriminated"):
                saw_discriminating = True
        if is_rbac_probe(str(step.get("verb") or ""), str(step.get("observed") or "")):
            saw_authz_step = True
    if required and saw_authz_step and not saw_discriminating:
        return FLAG_MISSING_DIFFERENTIAL
    return None


def flag_validated_finding(
    vf: dict,
    *,
    install_failure: bool = False,
    controls_required: bool = False,
    differential_required: bool = False,
) -> str | None:
    """Retroactive gate over a ``validated_findings[]`` entry from an
    existing (possibly pre-gate) validation report.

    Returns the soundness flag the finding's ``refuted`` verdict falls
    under, or None. An explicit ``soundness_flag`` stamped by the engine
    always wins; otherwise the finding's refuted steps and its
    ``observed_impact`` are re-examined with the same rules the live
    gate applies.
    """
    explicit = vf.get("soundness_flag")
    if explicit:
        return str(explicit)
    if install_failure and vf.get("verdict") == "refuted":
        return FLAG_TARGET_NOT_DEPLOYED
    if vf.get("verdict") != "refuted":
        return None
    cflag = controls_flag(vf, required=controls_required)
    if cflag:
        return cflag
    dflag = differential_flag(vf, required=differential_required)
    if dflag:
        return dflag
    probes = []
    for step in vf.get("steps") or []:
        if step.get("verdict") == "refuted":
            probes.append((str(step.get("verb") or ""), str(step.get("observed") or "")))
    if not probes and vf.get("observed_impact"):
        probes.append(("", str(vf["observed_impact"])))
    flags = [soundness_flag(verb, obs) for verb, obs in probes]
    flags = [fl for fl in flags if fl]
    if not flags:
        return None
    # Every refuted probe must be sound for the refutation to stand.
    if len(flags) == len(probes):
        return flags[0]
    # Mixed: at least one probe soundly refuted — the refutation stands.
    return None
