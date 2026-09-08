#!/bin/bash
# Negative fixture for the xtrace rule's file-level co-occurrence
# constraint (2026-07-29 recalibration): this script enables tracing but
# never mentions sensitive-value lexicon terms, so no fact is emitted —
# the pre-fix rule fired here, producing the 0.07-precision dismissal
# mass. (NOTE: the lexicon scan covers the whole file, comments included,
# so this comment must not name the lexicon words either.)

# ok: traust-bash-data-exposure-xtrace
set -ex

# ok: traust-bash-data-exposure-xtrace
set -o xtrace

make build
cp artifact.tar.gz /output/
