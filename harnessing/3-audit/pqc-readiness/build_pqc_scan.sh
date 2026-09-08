#!/usr/bin/env bash
# Build the pinned pqc-scan binary into harnessing/3-audit/pqc-readiness/bin/.
# Supply-chain posture: pinned commit, --locked build, sha256 recorded.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PIN="be5c760adb7d1d4d99e39d35d87d2956079db76e"
# per-user build dir — a fixed /tmp source dir allows TOCTOU between
# checkout and cargo build by any local user (audit E9, plan P2.15)
SRC="${PQC_SCAN_SRC:-${XDG_CACHE_HOME:-$HOME/.cache}/pqc-scan-src}"
export GIT_ALLOW_PROTOCOL=https

if [ ! -d "$SRC/.git" ]; then
  git clone --quiet https://github.com/wakaken/pqc-scan "$SRC"
fi
git -C "$SRC" fetch --quiet origin "$PIN" 2>/dev/null || true
git -C "$SRC" checkout --quiet "$PIN"
ACTUAL="$(git -C "$SRC" rev-parse HEAD)"
[ "$ACTUAL" = "$PIN" ] || { echo "pin mismatch: $ACTUAL != $PIN" >&2; exit 1; }

( cd "$SRC" && cargo build --release --locked )
mkdir -p "$HERE/bin"
cp "$SRC/target/release/pqc-scan" "$HERE/bin/pqc-scan"
shasum -a 256 "$HERE/bin/pqc-scan" | tee "$HERE/bin/pqc-scan.sha256"
echo "pqc-scan built at $HERE/bin/pqc-scan (commit $PIN)"
