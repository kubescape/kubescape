# TODO: Goreleaser E2E / Smoke Test Integration
Path: `kubescape/docs/TODO_GORELEASER_E2E.md`

Summary
-------
This document lists ideas, constraints, and next steps for moving e2e / smoke testing into the `goreleaser` pipeline via `build` hooks. The repository already contains a smoke test runner at `smoke_testing/init.py`. The goal is to provide a robust, configurable, and CI-friendly approach that runs tests only when the environment supports them.

Design principles
-----------------
- Keep heavy integration/tests opt-in. Building and releasing should not require kind/docker/python unless explicitly requested.
- Make the goreleaser hook a single shell script (single invocation) so `if/fi`, variables, and state persist across lines.
- Prefer discovery of artifacts (glob) over hardcoded filenames when possible, but keep sensible defaults.
- Make failures configurable: sometimes tests should fail the release; sometimes they should be advisory (continue on error).

Prerequisites (runner)
----------------------
- `python3` available on PATH (or adjust to use a virtualenv in CI).
- Container runtime and `kind` if running cluster-based tests.
- Sufficient disk and RAM for `kind` clusters.
- Required secrets/environment variables present in CI for any tests that need authentication (see "Secrets" below).

High-level TODOs
----------------
1. Ensure goreleaser hook is a single script
   - Update `builds[].hooks.post` in `.goreleaser.yaml` to be one multi-line script (YAML literal) so the entire script runs in a single shell.
   - Confirm behavior locally by running goreleaser snapshot in an environment with `RUN_E2E=true`.

2. Add opt-in trigger and documented env flag
   - Use `RUN_E2E` (boolean-like) to decide whether to run post-build tests.
   - Document how to enable it in CI:
     - Example (GitHub Actions env):
       - `RUN_E2E: "true"`
       - `RELEASE: ${{ inputs.RELEASE }}`
       - `CLIENT: ${{ inputs.CLIENT }}`
   - Consider also adding a `GORELEASER_E2E_MODE` with values `smoke|system|none`.

3. Artifact discovery
   - Avoid relying on a single filename. Implement a small discovery step:
     - Look for `dist/kubescape*` and pick the most appropriate artifact (prefer linux binary or the packaged format you want).
     - Example logic:
       - `ARTIFACT="$(ls dist | grep kubescape | grep -v '\.sha256' | head -n1)"`
       - Use `ART_PATH="$(pwd)/dist/$ARTIFACT"`
   - Add a fallback or an informative message when no artifact is found.

4. Decide failure policy
   - Two possible behaviors:
     - Fail the goreleaser run when tests fail (useful for gating releases).
     - Allow the release to continue and treat tests as best-effort (useful when you want to still publish).
   - Implement via environment flag `E2E_FAIL_ON_ERROR=true|false`. If `false`, wrap test command with `|| true`.

5. Integrate with existing smoke tests
   - Use the existing `smoke_testing/init.py` to run basic smoke tests.
   - Ensure the test runner can accept local artifact path as an argument (it already does in repository).
   - If tests require additional args or secrets, allow passing them via env vars into the goreleaser hook.

6. Optional: Run full system-tests (more complex)
   - Steps the goreleaser hook would perform if `GORELEASER_E2E_MODE=system`:
     - Clone `armosec/system-tests` into a temp directory.
     - Create and activate Python virtualenv and `pip install -r requirements.txt`.
     - Create a `kind` cluster (requires docker + kind).
     - Pass the built artifact path to the test runner (similar to the GitHub workflow `run-tests` job).
   - This is heavy and should be gated behind explicit flags and runner capabilities.
   - Consider running this only in a dedicated CI job (not on goreleaser invoked in arbitrary environments).

7. Secrets and CI environment
   - Document secrets required by system tests (examples found in current GH Actions workflow):
     - `CUSTOMER`, `USERNAME`, `PASSWORD`, `CLIENT_ID_PROD`, `SECRET_KEY_PROD`, `REGISTRY_USERNAME`, `REGISTRY_PASSWORD`.
   - If tests need image pushes or pulls, ensure `QUAYIO_REGISTRY_USERNAME` and `QUAYIO_REGISTRY_PASSWORD` (or equivalent) are available.
   - Ensure secrets are not echoed in logs.

8. Logging and artifacts
   - Ensure test output is streamed to the goreleaser logs for debugging.
   - Upload test results (JUnit XML, screenshots) as artifacts in CI (not possible directly from goreleaser, but CI can capture logs/artifacts).
   - If goreleaser is running in GitHub Actions, consider writing a step after goreleaser to run tests instead of embedding them in goreleaser. This allows richer workflows and artifact uploading.

9. Implement robust teardown / cleanup
   - If running `kind` clusters, ensure proper cleanup of clusters and temporary resources on success or failure.

10. Security considerations
    - Don't run privileged operations or accept untrusted input in the goreleaser hook.
    - Avoid storing secrets in plaintext in config files. Use CI secret stores.
    - If running tests that push signed artifacts or containers, ensure signing keys/passwords are protected (e.g., use cosign with ephemeral or protected secrets).

11. Optional: Containerize test runner
    - Create a small container image that contains all test dependencies (python, kind, kubectl, etc.).
    - Instead of running tests directly in the goreleaser hook, run the container and mount the `dist/` dir into it. This reduces host dependency issues and makes execution reproducible.
    - Example pattern: `docker run --rm -v $(pwd)/dist:/dist my-test-runner:latest /dist/kubescape-...`

12. Example hook behaviour (concept)
   - Single-script pattern to put in `.goreleaser.yaml`:
     - check `RUN_E2E`
     - discover artifact
     - set `E2E_FAIL_ON_ERROR` behavior
     - run `python3 smoke_testing/init.py "$ART_PATH"`
     - exit non-zero or continue depending on policy

13. Testing and validation
   - Test the hook locally with goreleaser snapshot on a machine that has python3 installed:
     - `RUN_E2E=true goreleaser release --snapshot --clean`
   - Validate the script works both when `RUN_E2E` is unset and when set.
   - Add unit/integration tests for the discovery logic if possible (small shell script unit tests).

14. Documentation
   - Add a short how-to in `CONTRIBUTING.md` or `docs/` describing:
     - How to enable e2e tests in CI (env vars).
     - What prerequisites the runner must provide.
     - The meaning of `RUN_E2E`, `E2E_FAIL_ON_ERROR`, and `GORELEASER_E2E_MODE`.

Concrete next steps (priority order)
-----------------------------------
1. Replace the current split-line hook with a single-script hook (already implemented locally). Verify the script runs end-to-end in CI.
2. Implement artifact discovery (glob) in the script and add `E2E_FAIL_ON_ERROR` support.
3. Add a short README entry (this TODO) into `docs/` explaining how to enable the tests and what runner prerequisites exist.
4. If required, implement an optional containerized test-runner image to reduce host dependencies.
5. If full system-tests are desired in goreleaser, implement a gated flow using `GORELEASER_E2E_MODE=system` that clones `armosec/system-tests` and runs the test runner (requires careful gating, secrets and runner capability checks).
6. Add a CI job (GitHub Actions) that runs goreleaser with `RUN_E2E=true` on a runner that has all required tools, captures test artifacts and test reports, and properly tears down resources.

Notes & caveats
--------------
- Running heavy system tests from within goreleaser can make releases brittle. Consider keeping goreleaser focused on build/release and run heavyweight tests as separate CI jobs that depend on goreleaser artifacts.
- The goreleaser action may run in containers where tools are limited; prefer invoking goreleaser in a full runner if you want to run `kind` and docker-based tests.
- If you want the release to be atomic (only publish if tests pass), make sure the goreleaser invocation happens in a CI job that has the necessary environment and ensures test success before pushing artifacts upstream.

Where to go from here
---------------------
- I can:
  - Provide a ready-to-drop `hooks.post` script with artifact discovery and configurable failure behavior.
  - Prepare a sample GitHub Actions job that runs goreleaser with `RUN_E2E=true` on a runner that has `python3`, `docker`, and `kind`.
  - Draft a simple containerized test-runner Dockerfile for reliable execution.

Pick which of these you'd like me to do next and I will produce the code/snippets (hook script, GitHub Actions job, or Dockerfile).
