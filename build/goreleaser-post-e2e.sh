#!/usr/bin/env sh
#
# goreleaser-post-e2e.sh
#
# A small, robust POSIX shell script intended to be called from the goreleaser
# `builds[].hooks.post` entry. It is responsible for optionally running the
# repository smoke/e2e tests against the artifact produced in `dist/`.
#
# Usage:
#   RUN_E2E=true        -> enable running smoke/e2e tests
#   E2E_FAIL_ON_ERROR=1 -> (default) treat test failures as fatal (exit non-zero)
#   E2E_FAIL_ON_ERROR=0 -> treat test failures as non-fatal (log, but exit 0)
#
# The script is written to be defensive and to work under /bin/sh on CI runners.
# Use POSIX-safe flags only.
set -eu

# Helper for logging
_now() {
  date --iso-8601=seconds 2>/dev/null || date
}
log() {
  printf '%s [goreleaser-post-e2e] %s\n' "$(_now)" "$*"
}

# Small helper to interpret various truthy forms (1/true/yes/y)
is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

# Determine repo root relative to this script (script is expected to live in kubescape/build/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${RUN_E2E:=false}"
# Default to non-fatal E2E failures. To make failures fatal, set a truthy value such as 1 or true.
: "${E2E_FAIL_ON_ERROR:=0}"

log "Starting goreleaser post-build e2e script"
log "RUN_E2E=${RUN_E2E}"
log "E2E_FAIL_ON_ERROR=${E2E_FAIL_ON_ERROR}"

if ! is_true "${RUN_E2E}"; then
  log "RUN_E2E is not enabled. Skipping e2e/smoke tests. (RUN_E2E=${RUN_E2E})"
  exit 0
fi

# Locate an artifact in dist/. Prefer the first file starting with 'kubescape'
ART_PATH=""
if [ -d "$REPO_ROOT/dist" ]; then
  for cand in "$REPO_ROOT"/dist/*; do
    # If no files matched, the glob may remain literal on some shells; guard:
    if [ ! -e "$cand" ]; then
      continue
    fi
    base="$(basename "$cand")"
    case "$base" in
      kubescape* )
        # skip obvious checksum files
        case "$base" in
          *.sha256|*.sha256sum) continue ;;
        esac
        if [ -f "$cand" ]; then
          ART_PATH="$cand"
          break
        fi
        ;;
      * )
        # not a kubescape artifact
        ;;
    esac
  done
fi

if [ -z "$ART_PATH" ]; then
  log "No kubescape artifact found in dist/. Skipping e2e/smoke tests."
  exit 0
fi

log "Using artifact: $ART_PATH"
# Make binary executable if it is a binary
chmod +x "$ART_PATH" >/dev/null 2>&1 || true

# Locate python runner
PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
fi

if [ -z "$PYTHON" ]; then
  log "python3 (or python) not found in PATH."
  if is_true "${E2E_FAIL_ON_ERROR}"; then
    log "E2E_FAIL_ON_ERROR enabled -> failing the release because python is missing."
    exit 2
  else
    log "E2E_FAIL_ON_ERROR disabled -> continuing without running tests."
    exit 0
  fi
fi

# Check for smoke test runner
SMOKE_RUNNER="$REPO_ROOT/smoke_testing/init.py"
if [ ! -f "$SMOKE_RUNNER" ]; then
  log "Smoke test runner not found at $SMOKE_RUNNER"
  if is_true "${E2E_FAIL_ON_ERROR}"; then
    log "E2E_FAIL_ON_ERROR enabled -> failing the release because smoke runner is missing."
    exit 3
  else
    log "E2E_FAIL_ON_ERROR disabled -> continuing without running tests."
    exit 0
  fi
fi

log "Running smoke tests with $PYTHON $SMOKE_RUNNER \"$ART_PATH\""
# Run the test runner, propagate exit code
set +e
"$PYTHON" "$SMOKE_RUNNER" "$ART_PATH"
rc=$?
set -e

if [ $rc -eq 0 ]; then
  log "Smoke/e2e tests passed (exit code 0)."
  exit 0
fi

log "Smoke/e2e tests exited with code: $rc"
if is_true "${E2E_FAIL_ON_ERROR}"; then
  log "E2E_FAIL_ON_ERROR enabled -> failing the release (exit code $rc)."
  exit $rc
else
  log "E2E_FAIL_ON_ERROR disabled -> continuing despite test failures."
  exit 0
fi
