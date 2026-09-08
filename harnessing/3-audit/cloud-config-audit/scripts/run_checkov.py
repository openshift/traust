#!/usr/bin/env python3
"""Offline, pinned Checkov runner → deterministic IaC-config facts.

Layer 1 of the /cloud-config-audit skill. Invokes the open-source
Checkov policy engine (Apache-2.0, subprocess only — never imported,
never vendored) against a LOCAL IaC checkout. Declared-layer only, by
user decision: no cloud API calls, ever. The scan surface is files on
disk (Terraform, CloudFormation, Kubernetes/Helm, ARM/Bicep,
Dockerfiles); nothing here can observe — let alone touch — a live
environment.

Offline guarantee (structural, not disciplinary):
- `--skip-download` is always passed: no policy downloads, no doc-link
  fetches, no Prisma Cloud platform calls.
- No `--bc-api-key` path exists in this runner; the argv may never
  grow one (platform integration is the commercial SaaS — out of
  scope by design).
- The `secrets` framework is always skipped: gitleaks is the one
  secret scanner in scope (docs/external-dependencies.md); a second
  detector would fork the disposition trail.

Determinism contract (mirrors the other pinned scanners):
- The Checkov version is PINNED; a mismatch is a hard failure. The
  pin advances only as a deliberate config change, never mid-run.
- JSON output is normalized into sorted, canonicalized facts and the
  body is stamped with its own sha256 (`snapshot_id`).
- Degradation is loud, never silent: a scan with zero evaluated
  checks or with parsing errors becomes a `gaps[]` entry — a target
  with a gap is NOT ASSESSED, never clean.
- OSS Checkov emits no severities (a platform feature). Facts carry
  `scanner_severity: "unrated"`; Layer 2 assigns severity from the
  SKILL.md rubric and the report gate requires a rationale for every
  severity assigned over an unrated fact.

Usage:
    python3 run_checkov.py --target-dir <checkout> [--out <facts.json>]
        [--framework terraform,cloudformation,...]
    python3 run_checkov.py --validate-report <report.json>
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from traust_contracts.paths import schema_path

# Where the sibling skills live: `harnessing/` today, and the ③ Audit stage
# directory after the skill-usability move (plan 1.2). Resolved relative to
# this skill rather than down from the harness root, so it stays correct
# either way — `HARNESS_ROOT / "harnessing"` resolved to
# `harnessing/harnessing/` and had never found compliance_assert.py.
SIBLING_SKILLS = Path(__file__).resolve().parents[2]

# Bump ONLY as a deliberate config change: verify the license row in
# docs/external-dependencies.md still holds, then re-baseline one known
# IaC tree before trusting a sweep (check IDs and policy logic can
# change between releases).
PINNED_CHECKOV_VERSION = "3.3.6"

CHECKOV_TIMEOUT = 1800
SCHEMA = schema_path("cloud-config-audit")

SEVERITIES = {"critical", "high", "medium", "low", "informational"}

# check-id prefix → provider bucket (report roll-up axis)
_PROVIDER_PREFIXES = (
    ("CKV_AWS", "aws"),
    ("CKV2_AWS", "aws"),
    ("CKV_AZURE", "azure"),
    ("CKV2_AZURE", "azure"),
    ("CKV_GCP", "gcp"),
    ("CKV2_GCP", "gcp"),
    ("CKV_K8S", "kubernetes"),
    ("CKV2_K8S", "kubernetes"),
    ("CKV_DOCKER", "docker"),
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _utcnow() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_pin() -> tuple[str | None, str | None]:
    """Return (version, error). Hard-fail on any mismatch with the pin."""
    try:
        proc = subprocess.run(["checkov", "--version"], capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return None, f"checkov not on PATH (pip install checkov=={PINNED_CHECKOV_VERSION})"
    except subprocess.TimeoutExpired:
        return None, "checkov --version timed out"
    out = (proc.stdout + proc.stderr).strip()
    if PINNED_CHECKOV_VERSION not in out:
        return None, (
            f"checkov version mismatch: pinned {PINNED_CHECKOV_VERSION}, found: {out[:120]}"
        )
    return PINNED_CHECKOV_VERSION, None


def _provider(check_id: str) -> str:
    for prefix, provider in _PROVIDER_PREFIXES:
        if check_id.startswith(prefix):
            return provider
    return "other"


# directories whose contents are not first-party IaC for this target
_SKIP_DIR_NAMES = {"vendor", "node_modules", "third_party"}


def _walkable_dir(entry: Path, name: str) -> bool:
    return (
        entry.is_dir()
        and not entry.is_symlink()
        and not name.startswith(".")
        and name not in _SKIP_DIR_NAMES
    )


def find_containerfiles(root: Path) -> list[Path]:
    """Relative paths of first-party `Containerfile` / `Containerfile.*`
    files. checkov 3.3.6's dockerfile framework matches only files
    literally named Dockerfile/Dockerfile.* — the Red Hat Containerfile
    convention is silently skipped (observed: rhoim-bootc-images
    vllm-bootc/Containerfile unassessed, Phase-0 sweep 2026-07)."""
    found: list[Path] = []

    def walk(d: Path) -> None:
        for entry in sorted(d.iterdir()):
            name = entry.name
            if _walkable_dir(entry, name):
                walk(entry)
            elif entry.is_file() and (name == "Containerfile" or name.startswith("Containerfile.")):
                found.append(entry.relative_to(root))

    walk(root)
    return found


def materialize_scan_tree(
    resolved: Path,
    tmp_root: Path,
    containerfiles: list[Path],
) -> tuple[Path, dict[str, str], list[str]]:
    """Build the temp scan tree with Dockerfile-named aliases.

    Mirrors EVERY real directory as a real directory and symlinks only
    files (and symlinked dirs, preserved as symlinks — no loop risk).
    Checkov's file discovery does not descend through directory
    symlinks, so a partial mirror silently drops every framework whose
    files live off the Containerfile paths (live re-baseline
    2026-07-29: rhoim-bootc-images lost all 32 kubernetes+terraform
    facts under a dirs-as-symlinks tree). File symlinks ARE followed —
    same read-only-toward-the-target guarantee as the hidden-path
    workaround, and the temp root is non-hidden so it covers that case
    too. Each Containerfile gets a sibling alias symlink named
    Dockerfile[.suffix] so checkov's dockerfile framework assesses it.
    Returns (scan_dir, {alias_rel_path: real_rel_path} for mapping
    fact paths back, [rel paths skipped because the alias name already
    exists])."""
    scan_dir = tmp_root / (resolved.name.lstrip(".") or "target")
    scan_dir.mkdir()

    def mirror(src: Path, dst: Path) -> None:
        for entry in sorted(src.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                (dst / entry.name).mkdir()
                mirror(entry, dst / entry.name)
            else:
                (dst / entry.name).symlink_to(entry)

    mirror(resolved, scan_dir)
    aliases: dict[str, str] = {}
    skipped: list[str] = []
    for rel in containerfiles:
        alias_name = "Dockerfile" + rel.name[len("Containerfile") :]
        alias_path = scan_dir / rel.parent / alias_name
        if alias_path.exists() or alias_path.is_symlink():
            skipped.append(rel.as_posix())  # real Dockerfile twin exists
            continue
        alias_path.symlink_to(resolved / rel)
        prefix = "" if str(rel.parent) == "." else "/" + rel.parent.as_posix()
        aliases[f"{prefix}/{alias_name}"] = f"{prefix}/{rel.name}"
    return scan_dir, aliases, skipped


_KIND_TEMPLATE = re.compile(r'^\s*kind:\s*["\']?Template["\']?\s*$', re.MULTILINE)
_KIND_PIPELINERUN = re.compile(r'^\s*kind:\s*["\']?PipelineRun["\']?\s*$', re.MULTILINE)
_YAML_READ_CAP = 1_000_000  # bytes; kind: sits near the top in practice


def detect_coverage_gaps(root: Path, evaluated_frameworks, target: str) -> list[str]:
    """Mechanical provider/framework coverage-gap detection (Phase-0
    sweep register, 2026-07): IaC files present whose framework
    evaluated ZERO checks become explicit gaps[] entries — the agent
    never has to remember to look. Detected classes:

    - *.tf present, terraform framework evaluated nothing → checkov
      ships no policies for the provider (observed: rhoas, Cloudflare,
      IBM Cloud providers).
    - *.bicep present, bicep framework evaluated nothing → weak Bicep
      parsing (observed: 82/188 files failed to parse on ARO-HCP).
    - OpenShift Template files (yaml with kind: Template) → objects
      inside templates are assessed by NO framework (no template
      unwrapping in this pass — deliberate).
    - .tekton/ PipelineRun files → assessed by NO framework.
    """
    n_tf = n_bicep = n_template = n_tekton = 0

    def _text(p: Path) -> str:
        try:
            with Path(p).open(encoding="utf-8", errors="replace") as fh:
                return fh.read(_YAML_READ_CAP)
        except OSError:
            return ""

    def walk(d: Path, in_tekton: bool) -> None:
        nonlocal n_tf, n_bicep, n_template, n_tekton
        for entry in sorted(d.iterdir()):
            name = entry.name
            if entry.is_dir() and not entry.is_symlink() and name == ".tekton":
                walk(entry, True)
            elif _walkable_dir(entry, name):
                walk(entry, in_tekton)
            elif entry.is_file():
                if name.endswith(".tf"):
                    n_tf += 1
                elif name.endswith(".bicep"):
                    n_bicep += 1
                elif name.endswith((".yaml", ".yml")):
                    text = _text(entry)
                    if in_tekton and _KIND_PIPELINERUN.search(text):
                        n_tekton += 1
                    elif _KIND_TEMPLATE.search(text):
                        n_template += 1

    walk(root, False)
    evaluated = set(evaluated_frameworks or ())
    gaps = []
    if n_tf and "terraform" not in evaluated:
        gaps.append(
            f"{target}: {n_tf} Terraform file(s) (*.tf) present but the "
            "terraform framework evaluated zero checks — likely cause: "
            "no Checkov policies for the provider(s) in use (observed "
            "classes: rhoas, Cloudflare, IBM Cloud); these files are "
            "NOT ASSESSED, never clean"
        )
    if n_bicep and "bicep" not in evaluated:
        gaps.append(
            f"{target}: {n_bicep} Bicep file(s) present but the bicep "
            "framework evaluated zero checks — likely cause: weak "
            "Bicep parsing in checkov 3.3.6 (see SKILL.md known "
            "limitations); these files are NOT ASSESSED, never clean"
        )
    if n_template:
        gaps.append(
            f"{target}: {n_template} OpenShift Template file(s) (yaml "
            "kind: Template) present — objects inside templates are "
            "not assessed by any Checkov framework (template "
            "unwrapping deliberately not attempted); NOT ASSESSED, "
            "never clean"
        )
    if n_tekton:
        gaps.append(
            f"{target}: {n_tekton} .tekton/ PipelineRun file(s) "
            "present — not assessed by any Checkov framework; "
            "NOT ASSESSED, never clean"
        )
    return gaps


def normalize_checkov(
    raw, target: str, target_root: str | None = None, path_aliases: dict[str, str] | None = None
) -> tuple[list[dict], dict]:
    """Checkov JSON (one object per framework, or a list of them) →
    facts (failed checks only) + counts.

    target_root, when given, is stripped from file paths BEFORE the
    fact_id hash — checkov sometimes reports absolute paths, and a
    fact_id that depends on where the repo was cloned breaks
    cross-run burndown joins. Accepts a str or a tuple of candidate
    prefixes (the caller passes both the as-given and the resolved
    path: on macOS /tmp is a symlink to /private/tmp, so the two can
    legitimately differ).

    path_aliases maps scan-tree alias paths back to real repo paths
    (Containerfile workaround) AFTER root stripping and BEFORE the
    fact_id hash — facts must cite real paths, and the fact_id must be
    stable whether or not the alias mechanism was needed."""
    roots = (target_root,) if isinstance(target_root, str) else tuple(target_root or ())
    blocks = raw if isinstance(raw, list) else [raw]
    facts = []
    counts = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "frameworks": []}
    for block in blocks:
        if not isinstance(block, dict):
            continue
        framework = str(block.get("check_type") or "unknown")
        results = block.get("results") or {}
        summary = block.get("summary") or {}
        counts["passed"] += int(summary.get("passed") or 0)
        counts["failed"] += int(summary.get("failed") or 0)
        counts["skipped"] += int(summary.get("skipped") or 0)
        counts["parsing_errors"] += int(summary.get("parsing_errors") or 0)
        if summary.get("passed") or summary.get("failed"):
            counts["frameworks"].append(framework)
        for c in results.get("failed_checks") or []:
            check_id = str(c.get("check_id") or "unknown-check")
            file_path = str(c.get("repo_file_path") or c.get("file_path") or "")
            for root in roots:
                if root and file_path.startswith(root):
                    file_path = "/" + file_path[len(root) :].lstrip("/")
                    break
            resource = str(c.get("resource") or "")
            if path_aliases:
                file_path = path_aliases.get(file_path, file_path)
                for alias, real in path_aliases.items():
                    # dockerfile resources embed the file path
                    # (e.g. "/x/Dockerfile.FROM") — cite real paths
                    if resource.startswith(alias):
                        resource = real + resource[len(alias) :]
                        break
            raw_sev = str(c.get("severity") or "").strip().lower()
            fact_id = (
                "cca-"
                + hashlib.sha256(
                    f"{framework}|{check_id}|{file_path}|{resource}".encode()
                ).hexdigest()[:12]
            )
            facts.append(
                {
                    "fact_id": fact_id,
                    "target": target,
                    "framework": framework,
                    "provider": _provider(check_id),
                    "check_id": check_id,
                    "title": c.get("check_name"),
                    "scanner_severity": (raw_sev if raw_sev in SEVERITIES else "unrated"),
                    "file_path": file_path,
                    "file_line_range": c.get("file_line_range"),
                    "resource": resource or None,
                    "guideline": c.get("guideline"),
                }
            )
    counts["frameworks"] = sorted(set(counts["frameworks"]))
    # one row per fact identity: framework|check|file|resource IS the
    # fact_id — repeated hits (a module instantiated N times in
    # transpiled ARM, two ADDs in one Dockerfile) collapse to the first
    # occurrence; counts keep the raw failed total
    seen: set[str] = set()
    facts = [f for f in facts if not (f["fact_id"] in seen or seen.add(f["fact_id"]))]
    return facts, counts


PINNED_BICEP_VERSION = "0.45.15"
PINNED_BICEP_SHA256 = {
    # sha256 of the release binary actually vetted per platform;
    # intake row: docs/external-dependencies.md (MIT, Azure/bicep,
    # verified upstream 2026-07-29)
    "bicep-osx-arm64": "59072cc82da704ab45d6bb11133da15b169795e42ef585dedc73d98e19fcf1be",
}
BICEP_BUILD_TIMEOUT = 60  # per file


def _find_bicep() -> str | None:
    """Pinned bicep CLI, if present. Resolution: $CCA_BICEP override →
    PATH → the per-user pinned install dir (docs/setup.md). Version is
    verified against the pin by the caller — a different bicep is
    treated as absent, mirroring check_pin()'s posture for checkov."""
    for cand in (
        os.environ.get("CCA_BICEP"),
        shutil.which("bicep"),
        str(Path.home() / ".cache" / "cca-tools" / f"bicep-{PINNED_BICEP_VERSION}" / "bicep"),
    ):
        if cand and Path(cand).is_file():
            try:
                proc = subprocess.run(
                    [cand, "--version"], capture_output=True, text=True, timeout=30
                )
            except (subprocess.SubprocessError, OSError):
                continue
            if PINNED_BICEP_VERSION in (proc.stdout or ""):
                return cand
    return None


def _bicep_parse_failures(parsed: list | dict, strip_roots: tuple[str, ...]) -> list[str]:
    """Rel paths (leading /) of .bicep files checkov failed to parse."""
    blocks = parsed if isinstance(parsed, list) else [parsed]
    rels = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for p in (block.get("results") or {}).get("parsing_errors") or []:
            p = str(p)
            if not p.endswith(".bicep"):
                continue
            for root in strip_roots:
                if root and p.startswith(root):
                    p = "/" + p[len(root) :].lstrip("/")
                    break
            rels.append(p)
    return sorted(set(rels))


def _bicep_fallback(
    resolved: Path,
    parsed: list | dict,
    strip_roots: tuple[str, ...],
) -> tuple[list, tuple[str, ...], dict[str, str], dict[str, str], list[str], list[str]]:
    """BICEP-TRANSPILE FALLBACK: checkov 3.3.6's bicep parser fails on
    a large share of real-world Bicep (82/188 on ARO-HCP). Parse-failed
    .bicep files are transpiled to ARM JSON with the pinned bicep CLI
    (`bicep build --no-restore` — OFFLINE: external registry modules
    are never fetched; a file needing them stays a gap) and re-scanned
    through the arm framework. Fact paths are aliased back to the
    source .bicep; LINE RANGES refer to the generated ARM template,
    not the .bicep source (recorded in the note).

    Returns (extra arm blocks, extra strip roots, extra aliases,
    notes, transpiled_ok rels, transpile_failed rels)."""
    failures = _bicep_parse_failures(parsed, strip_roots)
    if not failures:
        return [], (), {}, {}, [], []
    bicep = _find_bicep()
    if bicep is None:
        return (
            [],
            (),
            {},
            {
                "bicep_transpile_fallback": f"{len(failures)} .bicep file(s) failed checkov's "
                f"parser and the pinned bicep CLI "
                f"(v{PINNED_BICEP_VERSION}) is not installed — "
                f"transpile fallback unavailable, files stay "
                f"NOT ASSESSED (docs/setup.md has the install)"
            },
            [],
            failures,
        )
    tmp = tempfile.mkdtemp(prefix="cca-bicep-")
    ok, failed, aliases = [], [], {}
    try:
        for rel in failures:
            src = resolved / rel.lstrip("/")
            if not src.is_file():
                failed.append(rel)
                continue
            dst = Path(tmp) / (rel.lstrip("/") + ".arm.json")
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                proc = subprocess.run(
                    [bicep, "build", str(src), "--no-restore", "--outfile", str(dst)],
                    capture_output=True,
                    text=True,
                    timeout=BICEP_BUILD_TIMEOUT,
                )
            except (subprocess.SubprocessError, OSError):
                failed.append(rel)
                continue
            if proc.returncode != 0 or not dst.is_file():
                failed.append(rel)
                continue
            ok.append(rel)
            aliases["/" + rel.lstrip("/") + ".arm.json"] = rel
        if not ok:
            shutil.rmtree(tmp, ignore_errors=True)
            return (
                [],
                (),
                {},
                {
                    "bicep_transpile_fallback": f"0/{len(failures)} parse-failed .bicep file(s) "
                    f"transpiled (bicep v{PINNED_BICEP_VERSION} "
                    f"--no-restore; likely external registry modules "
                    f"— fetched by design never); files stay "
                    f"NOT ASSESSED"
                },
                [],
                failed,
            )
        cmd = [
            "checkov",
            "--directory",
            tmp,
            "--output",
            "json",
            "--skip-download",
            "--compact",
            "--framework",
            "arm",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CHECKOV_TIMEOUT)
            arm = json.loads(proc.stdout) if proc.stdout.strip() else []
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
            arm = []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    blocks = arm if isinstance(arm, list) else [arm]
    note = (
        f"{len(ok)}/{len(failures)} parse-failed .bicep file(s) "
        f"transpiled with the pinned bicep CLI "
        f"v{PINNED_BICEP_VERSION} (--no-restore, offline) and "
        f"re-scanned via the arm framework; fact paths cite the "
        f"source .bicep but LINE RANGES refer to the generated "
        f"ARM template"
        + (f"; still unparsed (stay NOT ASSESSED): {', '.join(failed)}" if failed else "")
    )
    return (blocks, (tmp,), aliases, {"bicep_transpile_fallback": note}, ok, failed)


def run_checkov(
    target_dir: Path,
    frameworks: str | None,
) -> tuple[list, str | None, tuple[str, ...], dict[str, str], dict[str, str]]:
    """One offline checkov invocation (plus the bicep-transpile
    fallback re-scan when needed) →
    (parsed JSON, error, extra path roots to strip,
    {metadata key: workaround note}, {alias path: real path}).

    OFFLINE GUARANTEE: --skip-download always; no API-key flag exists
    here and may never be added. `--skip-framework secrets` always:
    gitleaks is the one secret scanner in scope.

    Two engine workarounds share ONE temp-scan-tree mechanism; each is
    recorded as a note in the facts metadata when applied:

    HIDDEN-PATH WORKAROUND: checkov 3.3.6's kubernetes framework
    silently evaluates zero checks when any component of the scan path
    is dot-prefixed (e.g. a checkout under `.cache-clones/`) — no
    error, no gap signal, first observed 2026-07-21 on
    acs-fleet-manager-config. When the resolved target contains a
    hidden component, scan through a temporary non-hidden path.

    CONTAINERFILE-ALIAS WORKAROUND: checkov 3.3.6's dockerfile
    framework only matches files literally named Dockerfile or
    Dockerfile.* — Red Hat-convention Containerfiles are silently
    skipped. When first-party Containerfiles exist, the temp scan tree
    carries a Dockerfile-named alias symlink for each; the returned
    alias map lets the normalizer cite the REAL Containerfile paths in
    the emitted facts.
    """
    resolved = target_dir.resolve()
    hidden = any(part.startswith(".") for part in resolved.parts[1:])
    containerfiles = find_containerfiles(resolved)
    scan_dir, tmp = resolved, None
    notes: dict[str, str] = {}
    aliases: dict[str, str] = {}
    if hidden or containerfiles:
        tmp = tempfile.mkdtemp(prefix="cca-scan-")
        if containerfiles:
            scan_dir, aliases, skipped = materialize_scan_tree(resolved, Path(tmp), containerfiles)
            notes["containerfile_alias_workaround"] = (
                f"{len(aliases)} Containerfile(s) aliased to "
                f"Dockerfile-named symlinks in temp scan tree "
                f"{scan_dir} (checkov {PINNED_CHECKOV_VERSION}'s "
                f"dockerfile framework skips Containerfile names); "
                f"fact paths are mapped back to the real "
                f"Containerfile paths"
                + (
                    f"; not aliased (Dockerfile-name twin already exists): {', '.join(skipped)}"
                    if skipped
                    else ""
                )
            )
        else:
            scan_dir = Path(tmp) / (resolved.name.lstrip(".") or "target")
            scan_dir.symlink_to(resolved)
        if hidden:
            notes["hidden_path_workaround"] = (
                f"hidden path component in {resolved} suppresses "
                f"checkov's kubernetes framework; scanned via "
                f"non-hidden temp path {scan_dir}"
            )
    extra_roots = (str(scan_dir),) if tmp else ()
    cmd = [
        "checkov",
        "--directory",
        str(scan_dir),
        "--output",
        "json",
        "--skip-download",
        "--compact",
        "--skip-framework",
        "secrets",
    ]
    if frameworks:
        cmd += ["--framework", *frameworks.split(",")]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CHECKOV_TIMEOUT)
    except FileNotFoundError:
        return [], "checkov not on PATH", extra_roots, notes, aliases
    except subprocess.TimeoutExpired:
        return ([], f"timeout after {CHECKOV_TIMEOUT}s", extra_roots, notes, aliases)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    if not proc.stdout.strip():
        err = (
            proc.stderr.strip().splitlines()[-1][:200]
            if proc.stderr.strip()
            else f"exit {proc.returncode}, no output"
        )
        return [], err, extra_roots, notes, aliases
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ([], "unparseable checkov JSON output", extra_roots, notes, aliases)
    # bicep-transpile fallback (respects an explicit --framework filter
    # that excludes bicep/arm)
    if frameworks is None or any(f in ("bicep", "arm") for f in frameworks.split(",")):
        strip = (*extra_roots, str(resolved), str(target_dir))
        arm_blocks, arm_roots, arm_aliases, arm_notes, _ok, _failed = _bicep_fallback(
            resolved, parsed, strip
        )
        if arm_blocks:
            parsed = (parsed if isinstance(parsed, list) else [parsed]) + arm_blocks
            extra_roots += arm_roots
        aliases.update(arm_aliases)
        notes.update(arm_notes)
    return parsed, None, extra_roots, notes, aliases


def _git_head(target_dir: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(target_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return proc.stdout.strip() or None if proc.returncode == 0 else None
    except (subprocess.SubprocessError, OSError):
        return None


def validate_report(path: Path) -> int:
    """Schema + citation gate for the Layer-2 report. Prints error count."""
    try:
        import jsonschema
    except ImportError:
        print("jsonschema not installed", file=sys.stderr)
        return 2
    doc = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = [
        f"schema: {e.message} at {'/'.join(str(p) for p in e.absolute_path)}"
        for e in jsonschema.Draft7Validator(schema).iter_errors(doc)
    ]
    # citation gate: every disposition cites fact IDs; suppressions and
    # needs_review need written rationale; and because OSS Checkov emits
    # no severities, EVERY severity assigned over an unrated fact needs
    # a rationale naming the rubric row (anti-severity-flattening).
    for i, f in enumerate(doc.get("findings", [])):
        where = f"findings[{i}] ({f.get('id', '?')})"
        rationale = (f.get("rationale") or "").strip()
        if not f.get("fact_ids"):
            errors.append(f"{where}: no fact_ids citation")
        if f.get("status") in ("suppressed", "needs_review") and not rationale:
            errors.append(f"{where}: status '{f.get('status')}' without rationale")
        scanner_sev = f.get("scanner_severity") or "unrated"
        if scanner_sev == "unrated" and not rationale:
            errors.append(
                f"{where}: severity assigned over an unrated "
                f"fact without rationale (cite the SKILL.md "
                f"rubric row)"
            )
        elif scanner_sev != "unrated" and scanner_sev != f.get("severity") and not rationale:
            errors.append(f"{where}: severity changed from scanner's without rationale")
    for e in errors:
        print(f"ERROR {e}")
    print(f"{len(errors)} errors")
    return 1 if errors else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target-dir", type=Path, help="local IaC checkout to scan (read-only)")
    ap.add_argument(
        "--framework",
        default=None,
        help="comma-separated checkov framework filter (default: all except secrets)",
    )
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--validate-report",
        type=Path,
        default=None,
        help="validate a Layer-2 report instead of scanning",
    )
    args = ap.parse_args(argv)

    if args.validate_report:
        return validate_report(args.validate_report)
    if not args.target_dir:
        ap.error("--target-dir is required for a scan")
    if not args.target_dir.is_dir():
        print(f"target dir not found: {args.target_dir}", file=sys.stderr)
        return 1

    version, err = check_pin()
    if err:
        print(f"pin check failed: {err}", file=sys.stderr)
        return 1

    ca = _load(
        "compliance_assert",
        SIBLING_SKILLS / "compliance-check" / "scripts" / "compliance_assert.py",
    )
    target = args.target_dir.resolve().name
    out = args.out or Path.cwd() / f"{target}-cloud-facts.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    raw, err, extra_roots, workaround_notes, path_aliases = run_checkov(
        args.target_dir, args.framework
    )
    gaps = []
    if err:
        gaps.append(f"{target}: {err}")
        facts, counts = (
            [],
            {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "frameworks": []},
        )
    else:
        facts, counts = normalize_checkov(
            raw,
            target,
            target_root=(str(args.target_dir), str(args.target_dir.resolve()), *extra_roots),
            path_aliases=path_aliases,
        )
        if counts["passed"] + counts["failed"] == 0:
            gaps.append(
                f"{target}: scan evaluated zero checks — no "
                "IaC frameworks detected or scan failed; "
                "treating as not assessed, not clean"
            )
        if counts["parsing_errors"]:
            recovered = ""
            m = re.match(
                r"(\d+)/(\d+) parse-failed", workaround_notes.get("bicep_transpile_fallback", "")
            )
            if m and int(m.group(1)):
                recovered = (
                    f" ({m.group(1)} .bicep of them "
                    f"transpile-recovered via the arm "
                    f"framework — see metadata."
                    f"bicep_transpile_fallback)"
                )
            gaps.append(
                f"{target}: {counts['parsing_errors']} file(s) "
                "failed to parse — those files are not "
                f"assessed{recovered}"
            )
        # mechanical coverage-gap register: IaC present that no
        # framework evaluated is a loud gap, never agent-remembered
        gaps.extend(detect_coverage_gaps(args.target_dir.resolve(), counts["frameworks"], target))

    body = {
        "facts": sorted(facts, key=lambda f: f["fact_id"]),
        "counts": counts,
        "gaps": sorted(gaps),
    }
    snapshot_id = ca.evidence_id(body)
    doc = {
        "metadata": {
            "artifact": "cloud-config-facts",
            "role": (
                "deterministic Checkov facts for the "
                "/cloud-config-audit skill; DECLARED configuration "
                "only (IaC at rest — this run observed no live "
                "environment); agents never add, remove, or "
                "reword facts; targets with gaps are not "
                "assessed, never clean"
            ),
            "collector": "run_checkov.py",
            "checkov_version": version,
            "checkov_pinned": PINNED_CHECKOV_VERSION,
            "target": target,
            "target_dir": str(args.target_dir.resolve()),
            "target_head": _git_head(args.target_dir),
            "snapshot_id": snapshot_id,
            "generated_at": _utcnow(),
            **workaround_notes,
        },
        **body,
    }
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    for note in workaround_notes.values():
        print(f"  ! {note}")
    print(
        f"  snapshot_id {snapshot_id[:16]}… | "
        f"{counts['failed']} failed / {counts['passed']} passed "
        f"({', '.join(counts['frameworks']) or 'no frameworks'}) | "
        f"{len(gaps)} gap(s)"
    )
    for g in gaps[:8]:
        print(f"  ! {g}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
