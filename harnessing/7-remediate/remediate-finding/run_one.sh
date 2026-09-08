#!/usr/bin/env bash
# Scaffold ONE remediation working tree for a manifest row.
#
# Pure shell/python — sets up the fork, working tree, and fix branch, then
# stops.  The actual code change is produced by the AI-driven
# `remediate-finding` skill (see SKILL.md), which calls this script for
# Phase 1 and ``emit_remediation_report.py`` + ``run_checks.sh`` for
# Phases 4–5.  Mirrors the structure of validate-operator-live/run_one.sh.
#
# Usage:
#   run_one.sh <rem_id>
#   run_one.sh --next [--product <p>]
#
# Output (stdout): JSON describing the prepared workspace.

set -euo pipefail
export GIT_ALLOW_PROTOCOL=https  # local mirrors + https fetches only (plan P0.1)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Harness root: the directory holding VERSION, walked rather than counted,
# so nesting this skill under a stage directory (skill-usability plan 1.2)
# cannot silently repoint it.
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/VERSION" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/VERSION" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
# shellcheck source=../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
WORKSPACE="$WS"
MANIFEST_DIR="$AR/remediations/_manifest"

REM_ID=""
PRODUCT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --next)    REM_ID="__next__"; shift;;
    --product) PRODUCT="$2"; shift 2;;
    *)         REM_ID="$1"; shift;;
  esac
done

if [[ "$REM_ID" == "__next__" || -z "$REM_ID" ]]; then
  REM_ID="$(python3 "$HERE/next_pending_remediation.py" 1 ${PRODUCT:+--product "$PRODUCT"})"
  [[ -z "$REM_ID" ]] && { echo "[run_one] no pending candidates" >&2; exit 0; }
fi

# REM_ID becomes a filename component (log path, progress updates) —
# same gate as the manifest names below (self-audit -013): no
# separators, no dot-runs, campaign-id charset only
if [[ ! "$REM_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ || "$REM_ID" == *..* ]]; then
  echo "[run_one] unsafe rem_id: $REM_ID" >&2
  exit 1
fi

ROW="$(python3 "$HERE/next_pending_remediation.py" --rem-id "$REM_ID" --json)"
[[ -z "$ROW" ]] && { echo "[run_one] unknown rem_id: $REM_ID" >&2; exit 1; }

field() { echo "$ROW" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

UPSTREAM="$(field upstream_url)"
FORK_URL="$(field fork_url)"
SHA="$(field audited_commit)"
FIX_BRANCH="$(field fix_branch)"
LOGICAL="$(field logical_product)"
REPO="$(field repo_name)"
# manifest-derived names become path components under rm -rf / mkdir —
# no separators, no dot-runs (audit F6, plan P0.2)
for v in "$LOGICAL" "$REPO"; do
  if [[ ! "$v" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$v" == *..* ]]; then
    echo "[run_one] unsafe manifest name: $v" >&2
    exit 1
  fi
done
OUT="$AR/remediations/$LOGICAL/$REPO"
mkdir -p "$OUT"
LOG="$OUT/$REM_ID-run.log"
exec > >(tee -a "$LOG") 2>&1

echo "================================================================"
echo "[run_one] $(date -Is) rem_id=$REM_ID upstream=$UPSTREAM sha=$SHA"
echo "[run_one] fork=$FORK_URL fix_branch=$FIX_BRANCH out=$OUT"

python3 "$HERE/update_remediation_progress.py" "$REM_ID" forked || true

# --- 1. ensure private fork exists & is synced -----------------------------
FORK_INFO="$(bash "$HERE/ensure_fork.sh" "$UPSTREAM" "$FORK_URL" "$SHA")"
echo "[run_one] fork: $FORK_INFO"

# --- 2. prepare working tree at audited commit, cut fix branch -------------
WORK="$WORKSPACE/.fork-staging/work/$REPO"
# envtest / vendored toolchains can leave read-only dirs behind
[[ -d "$WORK" ]] && chmod -R u+w "$WORK" 2>/dev/null || true
rm -rf "$WORK"
# local bare-mirror clone — file transport only, made explicit
GIT_ALLOW_PROTOCOL=file \
  git clone --quiet "$WORKSPACE/.fork-staging/${REPO}.git" "$WORK"
# upstream is fetch-only; disable its push URL so an accidental `git push
# upstream` cannot reach the public repo even if ambient credentials exist.
git -C "$WORK" remote add upstream "$UPSTREAM" 2>/dev/null || true
git -C "$WORK" remote set-url --push upstream DISABLED_no_push_to_upstream
# fork remote uses a clean URL; auth is supplied at push time by an
# env-reading credential helper so the token is never written to
# .git/config, never visible in `git remote -v`, and never lands in the
# tee'd run log above.
case "$FORK_URL" in https://*) ;; *) echo "refuse: non-https FORK_URL" >&2; exit 1;; esac
git -C "$WORK" remote add fork "${FORK_URL%.git}.git" 2>/dev/null || \
  git -C "$WORK" remote set-url fork "${FORK_URL%.git}.git"
GH_CRED_HELPER='!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "${GITHUB_TOKEN:?GITHUB_TOKEN not set}"; }; f'
git -C "$WORK" config --local credential.useHttpPath false
git -C "$WORK" config --local --replace-all 'credential.https://github.com.helper' ''
git -C "$WORK" config --local --add         'credential.https://github.com.helper' "$GH_CRED_HELPER"

if [[ "$SHA" != "HEAD" ]] && git -C "$WORK" cat-file -e "${SHA}^{commit}" 2>/dev/null; then
  git -C "$WORK" checkout -B "$FIX_BRANCH" "$SHA"
else
  echo "[run_one] WARN: audited SHA unavailable; branching from default HEAD"
  git -C "$WORK" checkout -B "$FIX_BRANCH"
fi

python3 "$HERE/update_remediation_progress.py" "$REM_ID" patching || true

# --- 3. dump the finding context next to the worktree ---------------------
echo "$ROW" > "$OUT/$REM_ID-context.json"
TRIAGE="$(field triage_path)"
AUDIT="$(field audit_path)"
[[ -n "$TRIAGE" ]] && cp -f "$(traust_resolve_campaign_path "$TRIAGE")" "$OUT/" || true
[[ -n "$AUDIT" ]]  && cp -f "$(traust_resolve_campaign_path "$AUDIT")"  "$OUT/" || true

printf '{"rem_id":"%s","worktree":"%s","fix_branch":"%s","fork_url":"%s","upstream_url":"%s","audited_commit":"%s","out":"%s"}\n' \
  "$REM_ID" "$WORK" "$FIX_BRANCH" "$FORK_URL" "$UPSTREAM" "$SHA" "$OUT"

echo "[run_one] worktree ready — hand off to remediate-finding skill (Phase 2+)" >&2
