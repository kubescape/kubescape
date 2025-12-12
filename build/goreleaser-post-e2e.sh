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

# GitHub Actions log grouping helpers (no-op outside Actions)
gha_group_start() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    # Titles must be on a single line
    printf '::group::%s\n' "$*"
  fi
}
gha_group_end() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    printf '::endgroup::\n'
  fi
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
# Default to fatal E2E failures.
: "${E2E_FAIL_ON_ERROR:=1}"

log "Starting goreleaser post-build e2e script"
log "RUN_E2E=${RUN_E2E}"
log "E2E_FAIL_ON_ERROR=${E2E_FAIL_ON_ERROR}"

# Only run on linux/amd64 to avoid running multiple times (once per build)
# and to ensure we can run the binary on the current host (assuming host is amd64).
if [ -n "${GOARCH:-}" ] && [ "${GOARCH}" != "amd64" ]; then
  log "Skipping e2e/smoke tests for non-amd64 build (GOARCH=${GOARCH})."
  exit 0
fi

if ! is_true "${RUN_E2E}"; then
  log "RUN_E2E is not enabled. Skipping e2e/smoke tests. (RUN_E2E=${RUN_E2E})"
  exit 0
fi

# Locate the amd64 artifact in dist/.
# Goreleaser v2 puts binaries in dist/<id>_<os>_<arch>_<version>/<binary>
# Example: dist/cli_linux_amd64_v1/kubescape
ART_PATH=""
if [ -d "$REPO_ROOT/dist" ]; then
  # Find any file named 'kubescape' inside a directory containing 'linux_amd64' inside 'dist'
  # We use 'find' for robustness against varying directory names
  ART_PATH=$(find "$REPO_ROOT/dist" -type f -name "kubescape" -path "*linux_amd64*" | head -n 1)
fi

if [ -z "$ART_PATH" ] || [ ! -f "$ART_PATH" ]; then
  log "No kubescape artifact found in dist/ matching *linux_amd64*/kubescape. Skipping e2e/smoke tests."
  # If we are supposed to run E2E, not finding the artifact is probably an error.
  if is_true "${E2E_FAIL_ON_ERROR}"; then
     log "E2E_FAIL_ON_ERROR enabled -> failing because artifact was not found."
     exit 1
  fi
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

# Prefer Python 3.9 for system-tests (matches historical CI workflow)
SYSTEST_PYTHON_BIN=""
if command -v python3.9 >/dev/null 2>&1; then
  SYSTEST_PYTHON_BIN=python3.9
fi

# If you want system-tests to fall back instead of failing when 3.9 is missing,
# set SYSTEST_REQUIRE_PY39=0.
: "${SYSTEST_REQUIRE_PY39:=1}"

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

gha_group_start "Smoke tests"
log "Running smoke tests with $PYTHON $SMOKE_RUNNER \"$ART_PATH\""
# Run the test runner, propagate exit code
set +e
"$PYTHON" "$SMOKE_RUNNER" "$ART_PATH"
rc=$?
set -e

if [ $rc -eq 0 ]; then
  log "Smoke/e2e tests passed (exit code 0)."
fi

log "Smoke/e2e tests exited with code: $rc"
gha_group_end

if [ $rc -ne 0 ]; then
  if is_true "${E2E_FAIL_ON_ERROR}"; then
    log "E2E_FAIL_ON_ERROR enabled -> failing the release (exit code $rc)."
    exit $rc
  else
    log "E2E_FAIL_ON_ERROR disabled -> continuing despite test failures."
  fi
fi

# -----------------------------------------------------------------------------
# System Tests (replicating b-binary-build-and-e2e-tests.yaml)
# -----------------------------------------------------------------------------

log "Starting System Tests (armosec/system-tests)..."

# Check if we have connectivity to a cluster
if ! command -v kubectl >/dev/null 2>&1; then
  log "kubectl not found. Skipping system tests that require a cluster."
elif ! kubectl config current-context >/dev/null 2>&1; then
  log "No active kubernetes context found (kubectl config current-context failed). Skipping system tests."
else
  log "Kubernetes cluster connection verified."

  # Create a temporary directory for system tests
  SYSTEST_DIR=$(mktemp -d)
  log "Cloning system-tests into $SYSTEST_DIR"

  if git clone --depth 1 https://github.com/armosec/system-tests.git "$SYSTEST_DIR"; then

    # Save current directory to return later
    PUSHED_DIR=$(pwd)
    cd "$SYSTEST_DIR"

    # Setup Python Environment
    log "Setting up system tests python environment..."
    if [ -f "./create_env.sh" ]; then
      # The script expects to run inside the dir
      chmod +x ./create_env.sh

      # Require Python 3.9 by default (matches b-binary-build-and-e2e-tests.yaml)
      if [ -z "${SYSTEST_PYTHON_BIN:-}" ]; then
        if is_true "${SYSTEST_REQUIRE_PY39}"; then
          log "python3.9 not found in PATH; refusing to run system-tests because other Python versions may fail (deps/tooling mismatch)."
          log "Install python3.9 or set SYSTEST_REQUIRE_PY39=0 to allow fallback."

          # Honor E2E_FAIL_ON_ERROR: if enabled, fail the release; otherwise skip system tests.
          if is_true "${E2E_FAIL_ON_ERROR}"; then
            exit 4
          else
            log "E2E_FAIL_ON_ERROR disabled -> skipping system tests due to missing python3.9."
            cd "$PUSHED_DIR"
            rm -rf "$SYSTEST_DIR"
            exit 0
          fi
        else
          log "python3.9 not found in PATH; continuing with default python (may fail depending on deps)."
        fi
      else
        log "Using ${SYSTEST_PYTHON_BIN} for system-tests environment creation"
        export PYTHON="${SYSTEST_PYTHON_BIN}"
        export PYTHON_BIN="${SYSTEST_PYTHON_BIN}"
        export Python_BIN="${SYSTEST_PYTHON_BIN}"
      fi

      ./create_env.sh >/dev/null 2>&1 || log "Warning: create_env.sh returned non-zero"

      # Activate the environment if it exists
      if [ -f "systests_python_env/bin/activate" ]; then
        # shellcheck disable=SC1091
        . "systests_python_env/bin/activate"
      else
        log "Warning: systests_python_env/bin/activate not found. Trying global python."
      fi
    else
      log "create_env.sh not found. Attempting to use existing python environment."
    fi

    # List of tests to run (from b-binary-build-and-e2e-tests.yaml defaults)
    TESTS="scan_nsa \
scan_mitre \
scan_with_exceptions \
scan_repository \
scan_local_file \
scan_local_glob_files \
scan_local_list_of_files \
scan_nsa_and_submit_to_backend \
scan_mitre_and_submit_to_backend \
scan_local_repository_and_submit_to_backend \
scan_repository_from_url_and_submit_to_backend \
scan_with_custom_framework \
scan_customer_configuration \
scan_compliance_score \
scan_custom_framework_scanning_file_scope_testing \
scan_custom_framework_scanning_cluster_scope_testing \
scan_custom_framework_scanning_cluster_and_file_scope_testing"

    FAILURES=0

    # Prefer the virtualenv interpreter; otherwise use python3.11 if available
    if [ -x "systests_python_env/bin/python" ]; then
      SYSTEST_PYTHON="systests_python_env/bin/python"
    elif [ -n "${SYSTEST_PYTHON_BIN:-}" ]; then
      SYSTEST_PYTHON="${SYSTEST_PYTHON_BIN}"
    else
      SYSTEST_PYTHON="python3"
    fi

    SYSTEST_PY_VER="$($SYSTEST_PYTHON --version 2>/dev/null || true)"
    log "System tests will run with: $SYSTEST_PYTHON ($SYSTEST_PY_VER)"

    # Abort if the venv ended up on Python 3.10+ when we're expecting 3.9 (matches historical CI)
    if is_true "${SYSTEST_REQUIRE_PY39}"; then
      case "$SYSTEST_PY_VER" in
        "Python 3.10."*|"Python 3.11."*|"Python 3.12."*|"Python 3.13."*|"Python 3.14."*)
          log "System-tests virtualenv was created with $SYSTEST_PY_VER; refusing to run (expected Python 3.9.x)."
          log "Ensure python3.9 is available and that create_env.sh uses it."

          # Honor E2E_FAIL_ON_ERROR: if enabled, fail the release; otherwise skip system tests.
          if is_true "${E2E_FAIL_ON_ERROR}"; then
            exit 5
          else
            log "E2E_FAIL_ON_ERROR disabled -> skipping system tests due to unexpected Python version."
            cd "$PUSHED_DIR"
            rm -rf "$SYSTEST_DIR"
            exit 0
          fi
          ;;
      esac
    fi

    # Where to store per-test logs (helps diagnosing failures in CI)
    RESULTS_DIR="$SYSTEST_DIR/results"
    mkdir -p "$RESULTS_DIR"

    # Run tests
    for t in $TESTS; do
      gha_group_start "System test: $t"
      log "Running system test: $t"

      LOG_FILE="$RESULTS_DIR/${t}.log"

      set +e
      # Note: We must pass the absolute path to kubescape binary
      # Capture output to file and also print to console for live feedback.
      $SYSTEST_PYTHON systest-cli.py \
        -t "$t" \
        -b production \
        -c CyberArmorTests \
        --duration 3 \
        --logger DEBUG \
        --kwargs kubescape="$ART_PATH" 2>&1 | tee "$LOG_FILE"

      t_rc=$?
      set -e

      if [ $t_rc -ne 0 ]; then
        log "Test $t FAILED. (log: $LOG_FILE)"
        FAILURES=$((FAILURES + 1))
      else
        log "Test $t PASSED. (log: $LOG_FILE)"
      fi
      gha_group_end
    done

    # Copy JUnit XML results (if any) into a stable workspace path for reporting
    # Old workflow used glob '**/results_xml_format/**.xml'
    DEST_DIR="$REPO_ROOT/test-results/system-tests"
    mkdir -p "$DEST_DIR"

    if find "$SYSTEST_DIR" -type f -path "*/results_xml_format/*.xml" -print -quit 2>/dev/null | grep -q .; then
      gha_group_start "Collect system-tests JUnit XML"
      log "Copying system-tests JUnit XML results into: $DEST_DIR"
      # Preserve directory structure under results_xml_format to avoid filename collisions
      find "$SYSTEST_DIR" -type f -path "*/results_xml_format/*.xml" -print0 2>/dev/null | while IFS= read -r -d '' f; do
        rel="${f#"$SYSTEST_DIR"/}"
        out_dir="$DEST_DIR/$(dirname "$rel")"
        mkdir -p "$out_dir"
        cp -f "$f" "$out_dir/"
      done
      gha_group_end
    else
      log "No system-tests JUnit XML results found under results_xml_format/."
    fi

    # Cleanup
    # deactivate 2>/dev/null || true
    cd "$PUSHED_DIR"
    rm -rf "$SYSTEST_DIR"

    if [ $FAILURES -gt 0 ]; then
      log "System tests completed with $FAILURES failures."
      if is_true "${E2E_FAIL_ON_ERROR}"; then
        exit 1
      fi
    else
      log "All system tests passed."
    fi

  else
    log "Failed to clone system-tests repo. Skipping."
    if is_true "${E2E_FAIL_ON_ERROR}"; then
       exit 1
    fi
  fi
fi

exit 0
