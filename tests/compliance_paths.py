"""Compliance test paths — via the config loader (same as production)."""

from __future__ import annotations

import os
from pathlib import Path

from traust_contracts.config import load_section

from traust.context import load_engine, progress_tracker_dir

REGISTRY = "compliance-mapping.yaml"


def compliance_configs_dir() -> Path:
    """``<configured progress_tracker>/configs/compliance`` for the test suite."""
    return progress_tracker_dir(load_engine()) / "configs" / "compliance"


def compliance_configs_available() -> bool:
    return (compliance_configs_dir() / REGISTRY).is_file()


def _operator_config_home() -> Path | None:
    raw = os.environ.get("TRAUST_OPERATOR_CONFIG_HOME")
    return Path(raw) if raw else None


def compliance_skip_reason() -> str:
    """Explain why compliance tests are skipped (operator config, not test home)."""
    home = _operator_config_home()
    if home is None:
        return "no traust config home (~/.traust/config) — run scripts/install_traust"
    loc_file = home / "locations.yaml"
    if not loc_file.is_file():
        return f"{loc_file} missing"
    locs = load_section("locations.yaml", config_home=home, required=False)
    if locs is None or not locs.progress_tracker:
        return "set progress_tracker in ~/.traust/config/locations.yaml"
    pt = Path(locs.progress_tracker)
    reg = pt / "configs" / "compliance" / REGISTRY
    if not reg.is_file():
        return f"compliance registry missing under configured progress_tracker ({pt})"
    return "progress-tracker compliance configs unavailable"
