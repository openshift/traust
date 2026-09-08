# Build stage: assemble the harness content
# This is a data-only OCI artifact — its layers are mounted as a volume by
# agent runtimes and nothing from a base OS is ever executed. We therefore
# build FROM scratch: no base image, no shell, no package surface to patch,
# and no digest to keep refreshing. The image contains only the COPY'd
# harness payload under /harness.
FROM scratch AS harness

# Harness semver, fed from version.args (generated from VERSION) via the
# Konflux build-args-file param; the release pipeline's {{ oci_version }}
# tag template reads org.opencontainers.image.version, so each released
# image is also tagged with this value.
ARG VERSION=0.0.0

# OCI artifact labels.
# vendor / url / release / distribution-scope are REQUIRED by the Konflux
# Enterprise Contract (labels.required_labels). They used to arrive for free
# as inherited ubi9-micro base labels; FROM scratch has no base, so a
# base-less image must declare them itself. Do not drop them.
LABEL name="traust" \
      org.opencontainers.image.version="${VERSION}" \
      summary="Traust — skills, scripts, and schemas for automated security assessments" \
      description="A data-only OCI artifact containing AI agent skills, prompt engineering, \
Python scripts, JSON schemas, and configuration for automated multi-framework security \
audits of Red Hat Hybrid Platforms source code. Mounted as a volume by agent runtimes." \
      version="${VERSION:-0.0.0}" \
      io.k8s.display-name="Traust" \
      io.k8s.description="AI agent harness for automated security assessments" \
      io.openshift.tags="ai,security,harness,skills,agents" \
      com.redhat.component="traust" \
      maintainer="Traust maintainers <traust@redhat.com>" \
      vendor="Red Hat, Inc." \
      url="https://catalog.redhat.com/en/search?searchType=containers" \
      release="1" \
      distribution-scope="public"

# Data-only artifact — no entrypoint, no pip install in-image.
# Consumers mount this tree (typically at /harness) and run Python from
# a separately installed stack: traust + traust-engine +
# traust-contracts + traust-ledger (pip/uv from pyproject.toml git tags).
#
# What lives where after the scripts/ → packages refactor:
#   harnessing/          skills, per-skill scripts, rule-pack copies — YES (payload)
#   config/              shipped estate-neutral config + *.example.* templates — YES
#                        (deployment config is NOT here: mount it and set
#                        TRAUST_CONFIG_HOME — see config/README.md)
#   docs/                agent/human reference — YES
#   schema/              RETIRED — schemas ship in traust-contracts wheel
#   scripts/             RETIRED — CLIs in src/ + traust-engine; do not COPY
#   src/                 NOT in image — install the wheel on the host/CI runner
#
# Deployment-specific config (corpus-config, product map, budget policy,
# safe-exec profiles, rule-pack allowlist, hardening weights, dist-git watch,
# signing pubkey, internal vocabulary) never ships in this image. Every
# consumer resolves it through traust_contracts.config_path(), which
# reads $TRAUST_CONFIG_HOME and fails closed when the file is absent.

WORKDIR /harness

# Core skill definitions (the primary payload)
COPY harnessing/ ./harnessing/

# Shipped config (external-tools, feeds, model-registry) + templates only
COPY config/ ./config/
# Deployment config: mount at runtime, e.g. -v /path/to/deploy/config:/harness/deploy-config:ro
ENV TRAUST_CONFIG_HOME=/harness/deploy-config

# Documentation
COPY docs/ ./docs/

# Optional explicit skill-link helper (agents discover via harnessing/ + link_skills.sh)
COPY bin/ ./bin/

# Project metadata
COPY VERSION pyproject.toml requirements.txt ./
COPY LICENSE NOTICE ./
COPY LICENSES/ ./LICENSES/

# Certification tooling (ecosystem-cert-preflight-checks HasLicense) looks for
# license text at the absolute path /licenses, not under WORKDIR.
COPY LICENSES/ /licenses/

USER 1001

# No entrypoint — mount and pair with pip-installed sibling packages on the host
