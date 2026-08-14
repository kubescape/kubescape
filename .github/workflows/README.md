# Kubescape workflows

Tag terminology: `v<major>.<minor>.<patch>`

## Developing process

Kubescape's default branch is `master`; open every PR against `master`.

### Opening a PR

Opening a PR triggers `00-pr-scanner.yaml`, which calls the reusable `a-pr-scanner.yaml` workflow. That runs, in order: `go test -race ./...`; a second race-enabled run over `./core/cautils/...` with `CGO_ENABLED=1`; the `httphandler` module tests, which run without the race detector; a cross-platform GoReleaser snapshot build; the `smoke_testing/init.py` smoke test against the built binary; and `golangci-lint` in `only-new-issues` mode.

Two GitHub Apps report alongside it: the DCO check, which requires a `Signed-off-by:` trailer on every commit, and GitGuardian secret scanning.

`00-pr-scanner.yaml` carries a `paths-ignore` filter, so a PR that touches nothing else can skip the build entirely. It ignores `**.md`, `**.yaml`, `**.yml` and `**.sh` at any depth, plus files sitting directly in `website/`, `examples/`, `docs/`, `build/` and `.github/`. Those last five are single-level patterns: a nested file such as `docs/guide/diagram.svg` does not match and will still start the workflow. The build is skipped only when *every* changed file in the PR matches one of the patterns.

### Reviewing a PR

The E2E system tests do not live in this repository. `00-pr-scanner.yaml` dispatches them to a private repository and polls for the result.

They run automatically on every PR — there is no label to add and no approval gate. The `run-system-tests` job is gated only on the `wf-preparation` job finding the required organization secrets, which means it is **skipped on PRs from forks**. If you are contributing from a fork, the unit tests and the smoke test are the only automated verification available to you, so cover your change with unit tests.

### Approving a PR

Once a maintainer approves and the required checks are green, the PR can be merged.

### Merging a PR

The code is merged, no other actions are needed


## Release process

Every two weeks, we will create a new tag by bumping the minor version, this will create the release and publish the artifacts.
If we are introducing breaking changes, we will update the `major` version instead.

When we wish to push a hot-fix/feature within the two weeks, we will bump the `patch`.

### Creating a new tag

Every two weeks or upon the decision of the maintainers, a maintainer can create a tag.

The tag should look as follows: `v<A>.<B>.<C>`. Pushing it triggers `02-release.yaml`, whose tag filter matches release tags only — a pre-release suffix such as `-rc.0` will not start a release.

`02-release.yaml` then:

1. Builds the cross-platform binaries and container images with GoReleaser.
2. Runs the system tests against a Kind cluster and publishes a JUnit report.
3. Signs the artifacts with Cosign and generates an SBOM with Syft.
4. Attests the build provenance.
5. Publishes the artifacts and the container images to `quay.io`.
6. Opens the version bump against the krew index.

The workflow can also be started manually via `workflow_dispatch`, which exposes a `skip_publish` input for dry runs.

## Additional Information

Reusable workflows — the ones invoked by another workflow through `on: workflow_call` — carry an alphabetic prefix (`a-pr-scanner.yaml`). A workflow that invokes one carries a numeric prefix (`00-pr-scanner.yaml`). `02-release.yaml` also carries a numeric prefix, but it invokes nothing: it is an event-triggered entrypoint that does its work inline. Workflows that are neither reusable nor callers, such as `scorecard.yml` and `comments.yaml`, sit outside the convention.

## Screenshot

<img width="1469" alt="image" src="https://user-images.githubusercontent.com/64066841/212532727-e82ec9e7-263d-408b-b4b0-a8c943f0109a.png">
