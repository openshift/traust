#!/usr/bin/env bash
# run_pqc_readiness.sh — Run PQC readiness skill against a repo
#
# Usage:
#   ./run_pqc_readiness.sh <repo-url> [local-checkout-path]
#
# If no local path given, clones to $PQC_REPOS_DIR (default
# ~/.cache/pqc-readiness/repos/<slug>).
# Produces (under $PQC_OUTPUT_DIR, default ~/.cache/pqc-readiness/output):
#   <slug>-pqc-facts.json      (Layer 1 — deterministic)
#   <slug>-pqc-readiness.json  (Layer 2 — agent output)
#
# To run the Layer 2 agent in a separate Cursor session, use:
#   ./run_pqc_readiness.sh --prompt-only <repo-url>
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Harness root: the directory holding VERSION, walked rather than counted,
# so nesting this skill under a stage directory (skill-usability plan 1.2)
# cannot silently repoint it.
HARNESS_ROOT="$HERE"
while [ ! -f "$HARNESS_ROOT/VERSION" ] && [ "$HARNESS_ROOT" != / ]; do
  HARNESS_ROOT="$(dirname "$HARNESS_ROOT")"
done
[ -f "$HARNESS_ROOT/VERSION" ] || { echo "harness root not found above $HERE" >&2; exit 1; }
SKILL_BASE="$HERE"   # this script lives in the skill directory
# per-user 0700 cache, never a fixed world-writable /tmp name (S6)
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/pqc-readiness"
OUTPUT_DIR="${PQC_OUTPUT_DIR:-$CACHE_ROOT/output}"
REPOS_DIR="${PQC_REPOS_DIR:-$CACHE_ROOT/repos}"
mkdir -p "$CACHE_ROOT" && chmod 700 "$CACHE_ROOT"

prompt_only=false
if [[ "${1:-}" == "--prompt-only" ]]; then
    prompt_only=true
    shift
fi

repo_url="${1:?Usage: $0 [--prompt-only] <repo-url> [local-path]}"
local_path="${2:-}"

# https only — blocks ext::/ssh helpers and --option injection (S3)
if [[ ! "$repo_url" =~ ^https:// ]]; then
    echo "ERROR: repo-url must be https:// (got: $repo_url)" >&2
    exit 1
fi
export GIT_ALLOW_PROTOCOL=https

slug=$(basename "$repo_url" .git)
if [[ ! "$slug" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$slug" == ".." ]]; then
    echo "ERROR: cannot derive a safe slug from: $repo_url" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$REPOS_DIR"

# Clone if needed
if [[ -z "$local_path" ]]; then
    local_path="$REPOS_DIR/$slug"
    if [[ ! -d "$local_path/.git" ]]; then
        echo ">>> Cloning $repo_url → $local_path"
        case "$repo_url" in https://*) ;; *) echo "refuse: non-https url" >&2; exit 1;; esac
        GIT_ALLOW_PROTOCOL=https git clone --depth 1 -- "$repo_url" "$local_path"
    else
        echo ">>> Using existing clone: $local_path"
    fi
fi

facts_file="$OUTPUT_DIR/${slug}-pqc-facts.json"
readiness_file="$OUTPUT_DIR/${slug}-pqc-readiness.json"

# Layer 1: gather facts
if [[ ! -f "$facts_file" ]] || [[ "${FORCE_RESCAN:-}" == "1" ]]; then
    echo ">>> Running pqc_facts.py on $slug..."
    PYTHONPATH="$HARNESS_ROOT/scripts" python3 "$SKILL_BASE/pqc_facts.py" \
        --repo-dir "$local_path" \
        --repo-url "$repo_url" \
        --out "$facts_file"
else
    echo ">>> Facts exist: $facts_file (set FORCE_RESCAN=1 to re-run)"
fi

echo ""
echo ">>> Layer 1 complete: $facts_file"
echo ""

if $prompt_only; then
    cat <<PROMPT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PASTE THIS INTO A NEW CURSOR SESSION to run Layer 2 (agent reasoning):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run the pqc-readiness skill against $slug.

Facts are pre-computed at: $facts_file
Repo checkout is at: $local_path
Repo URL: $repo_url

Follow the SKILL.md at:
  $SKILL_BASE/SKILL.md

Steps:
1. Load the facts from $facts_file
2. Walk the control chain (who sets TLS, platform governance, app-level)
3. Consult the capability cards in $SKILL_BASE/notes/capabilities/
4. Produce the readiness report at: $readiness_file
5. Validate: python3 $SKILL_BASE/pqc_facts.py --validate-readiness $readiness_file

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROMPT
    exit 0
fi

echo ">>> To run Layer 2 in this session, paste the prompt above."
echo ">>> Or run with --prompt-only to get a copy-paste prompt for a new session."
echo ""
echo ">>> To validate a completed report:"
echo "    PYTHONPATH=$HARNESS_ROOT/scripts python3 $SKILL_BASE/pqc_facts.py --validate-readiness $readiness_file"
