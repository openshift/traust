"""The app's single composition root for traust-engine.

Every entry point resolves the engine here, once, and threads it (or the one ops
namespace it needs) into its workers. Nothing else in the app calls
HarnessEngine.load(); nothing reaches into traust_engine.* config internals.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from traust_contracts import DeploymentConfigMissing
from traust_contracts.config import deployment_config_dir
from traust_engine import HarnessEngine, locations

# ---------------------------------------------------------------------------
# Sanctioned environment overrides — read ONLY in this module, never in consumers.
#
# ``locations.yaml`` owns estate/campaign paths. These three env vars are
# deliberate escape hatches for layouts that must not live in checked-in config.
# ---------------------------------------------------------------------------
#
# AUDIT_RESULTS_ROOT
#   Point a one-off run or CI matrix job at an analysis-results tree without
#   editing ``locations.yaml``. Used when the job checks out results elsewhere
#   or shares a prebuilt tree across steps. Consumed by :func:`resolve_results_root`
#   (after an explicit ``--results-root`` CLI flag).
#
# FEEDS_CACHE_DIR
#   Pin the EPSS/KEV/product-definitions pull-through cache to a shared volume,
#   temp dir, or orchestrator-managed path. Feed mirrors are third-party licensed
#   data — intentionally kept out of ``analysis-results/`` (different provenance
#   and retention). Consumed by :func:`feeds_cache_dir`.
#


def _audit_results_root_from_env() -> Path | None:
    raw = os.environ.get("AUDIT_RESULTS_ROOT")
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw).strip()).expanduser().resolve()


def _feeds_cache_dir_from_env() -> Path | None:
    raw = os.environ.get("FEEDS_CACHE_DIR")
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw).strip()).expanduser().resolve()


def load_engine(config_home: Path | None = None) -> HarnessEngine:
    """Resolve the engine, or exit 2 with a one-line message (no traceback).

    Pass config_home for tests / explicit overrides; production leaves it None
    (contracts resolves $TRAUST_CONFIG_HOME).
    """
    try:
        return HarnessEngine.load(config_home=config_home)
    except DeploymentConfigMissing as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def add_config_home_arg(parser) -> None:
    """Standard --config-home flag so every CLI resolves config the same way."""
    parser.add_argument(
        "--config-home",
        type=Path,
        default=None,
        help="TRAUST config home (default: $TRAUST_CONFIG_HOME)",
    )


def analysis_results_dir(engine: HarnessEngine) -> Path:
    """Configured local analysis-results root (fail-loud when unset)."""
    return locations.require(
        locations.analysis_results_dir(engine.ctx.locations), "analysis_results"
    )


def workspace_dir(engine: HarnessEngine) -> Path:
    """Configured workspace root (fail-loud when unset)."""
    return locations.workspace_dir(engine.ctx.locations)


def inputs_dir(engine: HarnessEngine) -> Path:
    """The repository-inventory tree, from ``locations.inputs``.

    Falls back to ``<workspace>/inputs``. The inventory's directory name is
    deployment config, not a harness constant — until 2026-09-07 this returned
    a hardcoded sibling directory named after one organisation's repository.
    Relative values resolve against the config home like every other location.
    """
    loc = engine.ctx.locations
    val = getattr(loc, "inputs", None) if loc is not None else None
    if val:
        p = locations.local_path(val)
        if p is not None:
            if not p.is_absolute():
                home = deployment_config_dir()
                p = (home / p).resolve() if home else p.resolve()
            return p
    return workspace_dir(engine) / "inputs"


def _optional_config(name: str) -> dict:
    """``$TRAUST_CONFIG_HOME/<name>`` as a dict, or {} when the file is absent.

    For the small per-flow settings files (``remediation.yaml``,
    ``campaign.yaml``) that ship as ``config/*.example.yaml`` templates. Read
    directly rather than through the contracts manifest, which lists the
    schema-gated files; a schema for these is a contracts follow-up.
    """
    home = deployment_config_dir()
    if home is None:
        return {}
    path = home / name
    if not path.is_file():
        return {}
    import yaml  # local import: only these two settings files need it here

    data = yaml.safe_load(path.read_text()) or {}
    return data if isinstance(data, dict) else {}


def _normalise_host(value: str) -> str:
    """``https://gitlab.example.com/group/`` → ``gitlab.example.com``."""
    h = str(value).strip().lower()
    h = h.split("://", 1)[-1]
    h = h.split("/", 1)[0]
    return h.strip(". ")


def _private_forge_hosts(cfg: dict) -> tuple[str, ...]:
    raw = os.environ.get("HARNESS_PRIVATE_FORGE_HOSTS")
    if raw and raw.strip():
        values: list = raw.split(",")
    else:
        values = cfg.get("private_forge_hosts") or []
        if isinstance(values, str):
            values = values.split(",")
        elif not isinstance(values, list):
            values = []
    return tuple(dict.fromkeys(h for h in (_normalise_host(v) for v in values) if h))


def remediation_settings() -> dict:
    """remediate-finding's deployment settings — ``fork_org``,
    ``naming_prefix`` and ``private_forge_hosts`` — from ``remediation.yaml``
    in the config home, each overridable by ``HARNESS_FORK_ORG`` /
    ``REMEDIATION_PREFIX`` / ``HARNESS_PRIVATE_FORGE_HOSTS`` in the
    environment. ``fork_org`` has no shipped default: the private mirror
    organisation is the adopter's (decision D5, 2026-09-07); callers fail loud
    when it is unset. ``naming_prefix`` defaults to ``traust``.
    ``private_forge_hosts`` defaults to empty — naming an organisation's
    internal forge is deployment config, never a shipped constant.
    """
    cfg = _optional_config("remediation.yaml")
    fork_org = os.environ.get("HARNESS_FORK_ORG") or str(cfg.get("fork_org") or "").strip()
    prefix = (
        os.environ.get("REMEDIATION_PREFIX") or str(cfg.get("naming_prefix") or "traust").strip()
    )
    if fork_org in ("", "example-org"):
        fork_org = ""
    return {
        "fork_org": fork_org,
        "naming_prefix": prefix,
        "private_forge_hosts": _private_forge_hosts(cfg),
    }


def private_forge_hosts() -> tuple[str, ...]:
    """Hosts of self-hosted forges whose repositories ARE their own downstream
    fork — remediation lands in place rather than in a mirror. Empty unless the
    deployment lists them in ``remediation.yaml``; see
    ``config/remediation.example.yaml``.
    """
    return remediation_settings()["private_forge_hosts"]


def require_fork_org() -> str:
    org = remediation_settings()["fork_org"]
    if not org:
        raise SystemExit(
            "remediate-finding: no private mirror organisation configured — set "
            "fork_org in $TRAUST_CONFIG_HOME/remediation.yaml (template: "
            "config/remediation.example.yaml) or HARNESS_FORK_ORG in the environment"
        )
    return org


def campaign_settings() -> dict:
    """``campaign.yaml`` in the config home: ``tracking_reference`` (the
    issue-tracker key dashboards cite) and ``display_name``. Both optional;
    dashboards omit the line when unset."""
    cfg = _optional_config("campaign.yaml")
    return {
        "tracking_reference": str(cfg.get("tracking_reference") or "").strip(),
        "display_name": str(cfg.get("display_name") or "").strip(),
    }


def findings_db(engine: HarnessEngine) -> Path:
    """``<analysis-results>/graph/findings.db`` (fail-loud when unset)."""
    return locations.require(locations.findings_db(engine.ctx.locations), "analysis_results")


def progress_tracker_dir(engine: HarnessEngine) -> Path:
    """Configured progress-tracker root (fail-loud when unset)."""
    return locations.require(
        locations.progress_tracker_dir(engine.ctx.locations), "progress_tracker"
    )


def rule_drafts_dir(engine: HarnessEngine) -> Path:
    """Configured rule-drafts root (fail-loud when unset)."""
    return locations.require(locations.rule_drafts_dir(engine.ctx.locations), "rule_drafts")


def feeds_cache_dir(engine: HarnessEngine) -> Path:
    """Feeds pull-through cache: ``FEEDS_CACHE_DIR`` > config > ``progress_tracker/feeds``."""
    override = _feeds_cache_dir_from_env()
    if override is not None:
        return override
    cache = locations.feeds_cache_dir(engine.ctx.locations)
    if cache is not None:
        return cache
    return progress_tracker_dir(engine) / "feeds"


def findings_tree_dir(engine: HarnessEngine) -> Path:
    """``<analysis-results>/findings`` (fail-loud when analysis_results unset)."""
    return analysis_results_dir(engine) / "findings"


def default_findings_roots(
    engine: HarnessEngine,
    audit_path: Path,
) -> list[Path]:
    """Path-confinement roots for ledger/triage writes under configured findings."""
    findings = findings_tree_dir(engine)
    parent = audit_path.resolve().parent
    try:
        parent.relative_to(findings)
        return [parent, findings]
    except ValueError:
        return [findings]


def resolve_results_root(args=None, *, config_home: Path | None = None) -> Path:
    """``--results-root`` > ``$AUDIT_RESULTS_ROOT`` > ``locations.analysis_results``.

    Raises ``SystemExit(2)`` via :func:`load_engine` when config is required
    but missing. Pass ``args`` from argparse after :func:`add_config_home_arg`.
    """
    if args is not None and getattr(args, "results_root", None):
        return Path(args.results_root).expanduser().resolve()
    if args is not None and config_home is None and getattr(args, "config_home", None):
        config_home = args.config_home
    override = _audit_results_root_from_env()
    if override is not None:
        return override
    return analysis_results_dir(load_engine(config_home)).resolve()
