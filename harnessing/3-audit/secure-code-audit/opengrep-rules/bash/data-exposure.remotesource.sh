#!/bin/bash
# Fixture for the remote-source co-occurrence branch (2026-07-29): no
# sensitive-value lexicon terms appear in this file, but tracing is
# inherited by a remotely fetched build script (the RedHatInsights
# frontend-build confirmed-TP class), so the fact is still emitted.

export COMPONENT="sandbox"
COMMON_BUILDER=https://raw.example.com/builder-common/master

# ruleid: traust-bash-data-exposure-xtrace
set -exv
source <(curl -sSL $COMMON_BUILDER/src/frontend-build.sh)
