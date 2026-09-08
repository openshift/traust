#!/usr/bin/env bash
# Build the toolchain container image with pins from external-tools.yaml.
#
# Usage:
#   ./scripts/build-toolchain-image.sh
#   ./scripts/build-toolchain-image.sh --tag myregistry/harness-toolchain:v0.331
#   ./scripts/build-toolchain-image.sh --no-db    # skip DB population (faster builds)
#
# This is the canonical build command. Pins always come from
# config/external-tools.yaml — never edit Containerfile.toolchain ARGs directly.
# Python wheels are built from sibling repos into _build/wheels/ before the
# container build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE="$(cd "$REPO_ROOT/.." && pwd)"

TAG="harness-toolchain:latest"
EXTRA_ARGS=""

for arg in "$@"; do
  case "$arg" in
    --tag=*) TAG="${arg#--tag=}" ;;
    --tag)   shift; TAG="$1" ;;
    --no-db) EXTRA_ARGS="$EXTRA_ARGS --build-arg SKIP_DB=1" ;;
  esac
done

BUILD_ARGS=$(python3 "$SCRIPT_DIR/containerfile-build-args.py")

# --- Pre-build Python wheels from sibling repos ---
WHEEL_DIR="$REPO_ROOT/_build/wheels"
rm -rf "$WHEEL_DIR"
mkdir -p "$WHEEL_DIR"

echo "Building Python wheels into _build/wheels/ ..."
for pkg in traust-contracts traust-ledger traust-engine; do
  pkg_dir="$WORKSPACE/$pkg"
  if [ -d "$pkg_dir" ]; then
    python3 -m pip wheel --no-deps --wheel-dir "$WHEEL_DIR" "$pkg_dir" 2>&1 | tail -1
  else
    echo "  WARN: $pkg_dir not found — skipping (install from git tags at runtime)" >&2
  fi
done
python3 -m pip wheel --no-deps --wheel-dir "$WHEEL_DIR" "$REPO_ROOT" 2>&1 | tail -1
echo ""

echo "Building $TAG from external-tools.yaml pins..."
echo "  $BUILD_ARGS"
echo ""

# shellcheck disable=SC2086
podman build -f "$REPO_ROOT/Containerfile.toolchain" \
  $BUILD_ARGS \
  $EXTRA_ARGS \
  -t "$TAG" \
  "$REPO_ROOT"

# Clean up build artifacts
rm -rf "$REPO_ROOT/_build"

echo ""
echo "Built: $TAG"
echo "Verify: podman run --rm $TAG doctor --profile secure-code-audit"
