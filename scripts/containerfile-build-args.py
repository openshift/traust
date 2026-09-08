#!/usr/bin/env python3
"""Emit --build-arg flags for Containerfile.toolchain from external-tools.yaml.

Usage (the canonical build command):
    podman build -f Containerfile.toolchain \
      $(python3 scripts/containerfile-build-args.py) \
      -t harness-toolchain:latest .

Also usable as a library to generate version.args for Konflux:
    python3 scripts/containerfile-build-args.py --env > version.args
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required — pip install pyyaml", file=sys.stderr)
    sys.exit(1)

MANIFEST = Path(__file__).resolve().parents[1] / "config" / "external-tools.yaml"

NAME_TO_ARG = {
    "opengrep": "OPENGREP_VERSION",
    "gitleaks": "GITLEAKS_VERSION",
    "syft": "SYFT_VERSION",
    "grype": "GRYPE_VERSION",
    "osv-scanner": "OSV_SCANNER_VERSION",
    "cosign": "COSIGN_VERSION",
    "govulncheck": "GOVULNCHECK_VERSION",
    "skopeo": "SKOPEO_VERSION",
    "yara": "YARA_VERSION",
    "pip-audit": "PIP_AUDIT_VERSION",
}


def load_pins(manifest: Path = MANIFEST) -> dict[str, str]:
    tools = yaml.safe_load(manifest.read_text())["tools"]
    pins = {}
    for spec in tools:
        arg = NAME_TO_ARG.get(spec["name"])
        if arg:
            pins[arg] = spec["expected"]
    return pins


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--env",
        action="store_true",
        help="emit KEY=VALUE lines (for Konflux version.args / .env files)",
    )
    args = ap.parse_args()

    pins = load_pins()
    if args.env:
        for k, v in pins.items():
            print(f"{k}={v}")
    else:
        parts = [f"--build-arg {k}={v}" for k, v in pins.items()]
        print(" ".join(parts))


if __name__ == "__main__":
    main()
