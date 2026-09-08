#!/usr/bin/env bash
# Run every FuzzXxx in targets.json for FUZZTIME each, capturing per-fuzzer logs.
# Darwin-compatible targets run natively; goos=linux targets run in podman.
#
#   FUZZTIME=1h ./run-sweep.sh            # full overnight sweep
#   FUZZTIME=1h ./run-sweep.sh linux      # only the container leg
#   FUZZTIME=1h ./run-sweep.sh native     # only the host leg
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/targets.json"
CLONES="$HERE/clones"
LOGS="$HERE/logs"
FUZZTIME="${FUZZTIME:-1h}"
HOST_GOOS="$(go env GOOS)"
LEG="${1:-all}"                      # all | native | linux
BATCH="${BATCH:-}"                   # optional: only targets with .batch == N
ONLY="${ONLY:-}"                     # optional: comma-separated target ids
CONTAINER="${CONTAINER:-podman}"     # podman | docker
IMAGE="${IMAGE:-golang:1.26}"

mkdir -p "$LOGS"
: >"$LOGS/sweep.log"
log() { printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOGS/sweep.log"; }

# Ensure harnesses are copied into the clone tree.
make -C "$HERE" install >/dev/null

run_native() {
  local id="$1" wd="$2" pkg="$3" fn="$4" dir="${5:-$1}"
  local out="$LOGS/$id/$fn.log"; mkdir -p "$(dirname "$out")"
  log "native  $id :: $fn ($pkg) FUZZTIME=$FUZZTIME"
  ( cd "$CLONES/$dir/$wd" && \
    go test -run '^$' -fuzz "^${fn}\$" -fuzztime "$FUZZTIME" "$pkg" ) &>"$out"
  log "        $id :: $fn -> exit=$? ($(grep -c '^--- FAIL' "$out") crash groups)"
}

run_linux() {
  local id="$1" wd="$2" pkg="$3" fn="$4" dir="${5:-$1}"
  local out="$LOGS/$id/$fn.log"; mkdir -p "$(dirname "$out")"
  log "podman  $id :: $fn ($pkg) FUZZTIME=$FUZZTIME"
  "$CONTAINER" run --rm \
    -v "$CLONES/$dir":/src:Z \
    -v fuzz-gocache:/go \
    -w "/src/$wd" \
    -e GOFLAGS=-buildvcs=false \
    -e GOMAXPROCS="${LINUX_GOMAXPROCS:-3}" \
    "$IMAGE" \
    go test -run '^$' -fuzz "^${fn}\$" -fuzztime "$FUZZTIME" -parallel "${LINUX_GOMAXPROCS:-3}" "$pkg" &>"$out"
  log "        $id :: $fn -> exit=$? ($(grep -c '^--- FAIL' "$out") crash groups)"
}

log "sweep start FUZZTIME=$FUZZTIME LEG=$LEG HOST_GOOS=$HOST_GOOS"

jq -r --arg batch "$BATCH" --arg only "$ONLY" '.targets[]
       | if $batch=="" then . else select((.batch|tostring)==$batch) end
       | if $only =="" then . else select(.id as $i | ($only|split(",")) | index($i)) end
       | .id as $id | .goos as $goos | .workdir as $wd | .fuzztime as $ft | .clone_alias as $ca
       | .harnesses[] | select(.fuzz!="")
       | [$id, ($goos // "any"), ($wd // "."), .pkg, .fuzz, (.fuzztime // $ft // ""), ($ca // $id)] | @tsv' "$MANIFEST" |
while IFS=$'\t' read -r id goos wd pkg fn ft dir; do
  [[ -n "$ft" ]] && FUZZTIME="$ft"
  if [[ "$goos" == "any" || "$goos" == "$HOST_GOOS" ]]; then
    [[ "$LEG" == "linux" ]] && continue
    run_native "$id" "$wd" "$pkg" "$fn" "$dir"
  else
    [[ "$LEG" == "native" ]] && continue
    run_linux "$id" "$wd" "$pkg" "$fn" "$dir"
  fi
done

log "sweep leg=$LEG complete"
touch "$LOGS/.done-${DONE_TAG:-$LEG}"
# Reports are generated separately once all legs finish (see gen-reports.sh).
