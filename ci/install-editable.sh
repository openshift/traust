#!/usr/bin/env bash
# CI-only: uv pip install -e . with git-tag sibling deps from pyproject.toml.
#
# Runner checkout (helper container) trusts gitlab.cee.redhat.com; the UBI job
# container does not. uv's in-job git fetch needs the runner CA — see
# gates:pinned and GitLab docs on CI_SERVER_TLS_CA_FILE.
set -euo pipefail

root="${CI_PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

git config --global \
  url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.cee.redhat.com/".insteadOf \
  "ssh://git@gitlab.cee.redhat.com/"

ca=""
for candidate in "${CI_SERVER_TLS_CA_FILE:-}" /etc/gitlab-runner/certs/ca.crt; do
  [[ -n "$candidate" && -f "$candidate" ]] || continue
  ca="$candidate"
  break
done
[[ -n "$ca" ]] || {
  echo "GitLab CA unavailable (CI_SERVER_TLS_CA_FILE or /etc/gitlab-runner/certs/ca.crt)" >&2
  exit 1
}

export GIT_SSL_CAINFO="$ca"
git config --global http.sslCAInfo "$ca"
# Do not set SSL_CERT_FILE — that replaces the system trust store and breaks
# PyPI (uv fetches jsonschema etc. over HTTPS with public CAs).

py=python3.12
command -v "$py" >/dev/null || py=python3

venv="${root}/.ci-venv"
uv venv "$venv" --python "$py"
uv pip install --python "${venv}/bin/python" -e "$root"
