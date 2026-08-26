# Krew Release Automation Guide

This document explains how kubescape automates publishing to the Kubernetes plugin package manager, krew.

## What is Krew?

Krew is a plugin manager for `kubectl`. It allows users to discover and install `kubectl` plugins easily. You can learn more about krew at [https://krew.sigs.k8s.io/](https://krew.sigs.k8s.io/).

## How kubescape publishes to krew

We use the [krew-release-bot](https://github.com/rajatjindal/krew-release-bot) to automatically create pull requests to the [kubernetes-sigs/krew-index](https://github.com/kubernetes-sigs/krew-index) repository whenever a new release of kubescape is published.

### Setup Overview

The automation consists of three components:

1. **`.krew.yaml`** - A template file that the bot uses to generate the krew plugin manifest
2. **`.github/workflows/02-release.yaml`** - GitHub Actions workflow that runs the krew-release-bot after a successful release
3. **`.goreleaser.yaml`** - GoReleaser configuration that defines the krew manifest (though upload is skipped)

### Why Use krew-release-bot Instead of GoReleaser's Built-in Krew Support?

You might have noticed that **GoReleaser has built-in krew support** in its `krews` section. However, almost all projects (including stern) use `skip_upload: true` and rely on **krew-release-bot** instead. Here's why:

#### Problems with GoReleaser's Built-in Krew Publishing

To use GoReleaser's direct krew publishing, you would need to:

```yaml
krews:
  - name: kubescape
    skip_upload: false  # Instead of true
    repository:
      owner: kubernetes-sigs
      name: krew-index
      token: "{{ .Env.KREW_INDEX_TOKEN }}"  # Required!
      pull_request:
        enabled: true  # Requires GoReleaser Pro for cross-repo PRs
```

This approach has several critical issues:

1. **Permission Barrier**: Almost no one has write access to `kubernetes-sigs/krew-index`. You would need special permissions from the Krew maintainers, which is rarely granted.

2. **Security Risk**: You'd need to store a GitHub personal access token with write access to the krew-index in your repository secrets. This token could be compromised and used to make unauthorized changes to the krew-index.

3. **GoReleaser Pro Required**: To create pull requests to a different repository (cross-repository), you need GoReleaser Pro, which is a paid product.

4. **Manual Work**: Even if you had access, you'd need to manually configure and maintain the repository settings, tokens, and potentially deal with rate limits and authentication issues.

#### Why krew-release-bot is the Right Solution

The **krew-release-bot** was created by the Kubernetes community (in collaboration with the Krew team) specifically to solve these problems:

- **No Repository Access Required**: The bot acts as an intermediary with pre-configured access to krew-index. You don't need write permissions.

- **No Tokens Needed**: It uses GitHub's `GITHUB_TOKEN` (automatically available in GitHub Actions) via webhooks and events. No personal access tokens required.

- **Designed for Krew**: It's specifically built for the krew-index workflow and integrates with Krew's automation.

- **Automatic Merging**: The Krew team has configured their CI to automatically test and merge PRs from krew-release-bot (usually within 5-10 minutes).

- **Officially Recommended**: The Krew team explicitly recommends this approach in their documentation as the standard way to automate plugin updates.

- **Free and Open Source**: No paid subscriptions required.

#### The Real-World Evidence

Looking at recent pull requests to `kubernetes-sigs/krew-index`, **almost all automated plugin updates are created by krew-release-bot**. You'll see patterns like:

```
Author: krew-release-bot
Title: "release new version v0.6.11 of radar"
```

This demonstrates that the entire Kubernetes ecosystem has standardized on krew-release-bot, not GoReleaser's built-in publishing.

#### Summary

While GoReleaser's built-in krew support exists in the code, it's **practically unusable for the krew-index repository** due to permission and security constraints. The krew-release-bot is the de facto standard because:
- It works without special permissions
- It's more secure
- It integrates with Krew's automation
- It's free and recommended by the Krew team

This is why we use `skip_upload: true` in GoReleaser and let krew-release-bot handle the actual publishing.

### The Template File

The `.krew.yaml` file in the repository root is a Go template that contains placeholders for dynamic values:

```yaml
{{/*
krew-release-bot renders this file with a function map holding exactly two
entries, `indent` and `addURIAndSha` (see pkg/source/template.go upstream).
There is no sprig, so no trimPrefix, and addURIAndSha takes two arguments: a URL
- itself a template, over a value carrying only .TagName and no functions - and
the tag. Anything else has to be computed out here and interpolated with printf.

GoReleaser names archives {{"{{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}"}},
and .Version is the tag without its leading "v", so a v4.0.12 release publishes
kubescape_4.0.12_linux_amd64.tar.gz. The URL path needs the tag; the file name
needs the trimmed form. 02-release.yaml only fires on v[0-9]+.[0-9]+.[0-9]+, so
the leading "v" is guaranteed to be there to strip.
*/}}
{{- $version := slice .TagName 1 -}}
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: kubescape
spec:
  version: {{ .TagName }}
  platforms:
  - selector:
      matchLabels:
        os: linux
        arch: amd64
    {{ addURIAndSha (printf "https://github.com/kubescape/kubescape/releases/download/%s/kubescape_%s_linux_amd64.tar.gz" .TagName $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: linux
        arch: arm64
    {{ addURIAndSha (printf "https://github.com/kubescape/kubescape/releases/download/%s/kubescape_%s_linux_arm64.tar.gz" .TagName $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: darwin
        arch: amd64
    {{ addURIAndSha (printf "https://github.com/kubescape/kubescape/releases/download/%s/kubescape_%s_darwin_amd64.tar.gz" .TagName $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: darwin
        arch: arm64
    {{ addURIAndSha (printf "https://github.com/kubescape/kubescape/releases/download/%s/kubescape_%s_darwin_arm64.tar.gz" .TagName $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: windows
        arch: amd64
    {{ addURIAndSha (printf "https://github.com/kubescape/kubescape/releases/download/%s/kubescape_%s_windows_amd64.tar.gz" .TagName $version) .TagName }}
    bin: kubescape.exe
  - selector:
      matchLabels:
        os: windows
        arch: arm64
    {{ addURIAndSha (printf "https://github.com/kubescape/kubescape/releases/download/%s/kubescape_%s_windows_arm64.tar.gz" .TagName $version) .TagName }}
    bin: kubescape.exe
  shortDescription: Scan resources and cluster configs against security frameworks.
  description: |
    Kubescape is the first tool for testing if Kubernetes is deployed securely
    according to mitigations and best practices. It includes risk analysis,
    security compliance, and misconfiguration scanning with an easy-to-use
    CLI interface, flexible output formats, and automated scanning capabilities.

    Features:
    - Risk analysis: Identify vulnerabilities and security risks in your cluster
    - Security compliance: Check your cluster against multiple security frameworks
    - Misconfiguration scanning: Detect security misconfigurations in your workloads
    - Flexible output: Results in JSON, SARIF, HTML, JUnit, and Prometheus formats
    - CI/CD integration: Easily integrate into your CI/CD pipeline
  homepage: https://kubescape.io/
  caveats: |
    Requires kubectl and basic knowledge of Kubernetes.
    Run 'kubescape scan' to scan your Kubernetes cluster or manifests.
```

`{{ .TagName }}` is replaced with the release tag (e.g. `v4.0.12`). `{{ addURIAndSha <url> <tag> }}` downloads the asset at `<url>` and emits both the `uri:` and `sha256:` lines for it.

Two constraints are easy to get wrong, and the template carries a comment about both:

- **`addURIAndSha` takes exactly two arguments.** Its first argument is a *single* URL string, which the bot renders as a nested template with only `.TagName` available and no functions at all. Passing the base URL and the file name as separate arguments fails at render time with `wrong number of args for addURIAndSha: want 2 got 4`, so the full URL is assembled with `printf` before it is passed in.
- **The tag and the file name differ.** GoReleaser names archives `{{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}`, and `.Version` is the tag without its leading `v` — so tag `v4.0.12` publishes `kubescape_4.0.12_linux_amd64.tar.gz`. The URL *path* needs the tag; the *file name* needs the trimmed form. The bot's function map is only `indent` and `addURIAndSha`, with no sprig, so there is no `trimPrefix` to call — `{{ $version := slice .TagName 1 }}` does the trimming instead.

### Release Workflow

The release workflow (`.github/workflows/02-release.yaml`) can be triggered in two ways:

1. **Automatic**: When a new tag matching the pattern `v[0-9]+.[0-9]+.[0-9]+` is pushed to the repository
2. **Manual**: Via `workflow_dispatch` with an optional `skip_publish` input

When the workflow is triggered:

1. GoReleaser builds and publishes the release artifacts (unless `skip_publish=true` is set)
2. The krew-release-bot step runs conditionally:
   - It **runs** when triggered by a tag push OR by `workflow_dispatch` with `skip_publish=false`
   - It **skips** when triggered by `workflow_dispatch` with `skip_publish=true` (default)
3. When it runs, the bot:
   - Reads the manifest named by the step's `krew_template_file` input
   - Fills in the template with release information
   - Creates a pull request to the `kubernetes-sigs/krew-index` repository
   - The PR is automatically tested and merged by krew's infrastructure

> **Which file the bot actually reads.** The step sets
> `krew_template_file: dist/krew/kubescape.yaml`, so the released manifest is the
> one GoReleaser writes from the `krews:` block in `.goreleaser.yaml` — which is
> why the published entry in `kubernetes-sigs/krew-index` carries a
> `# This file was generated by GoReleaser. DO NOT EDIT.` header.
>
> `.krew.yaml` is the bot's **default** template path (its `krew_template_file`
> input is documented as "defaults to .krew.yaml"), so it is kept correct and
> renderable: dropping that one line from the workflow would silently promote it
> into the release path. It is also what the `krew-release-bot template` command
> below renders. `internal/ghworkflows/krew_test.go` asserts it stays renderable
> and keeps naming the assets GoReleaser actually publishes.

### Workflow Permissions

The release job has the following permissions:

```yaml
permissions:
  actions: read
  checks: read
  contents: write
  deployments: read
  discussions: read
  id-token: write
  issues: read
  models: read
  packages: write
  pages: read
  pull-requests: read
  repository-projects: read
  statuses: read
  security-events: read
  attestations: read
  artifact-metadata: read
```

These permissions are necessary for GoReleaser to create releases and upload artifacts.

### Testing the Template

Before committing changes to `.krew.yaml`, you can test how the template will be rendered using Docker:

```bash
docker run --rm -v $(pwd)/.krew.yaml:/tmp/.krew.yaml ghcr.io/rajatjindal/krew-release-bot:v0.0.46 \
  krew-release-bot template --tag v4.0.12 --template-file /tmp/.krew.yaml
```

Use a tag that has already shipped. `addURIAndSha` downloads each asset to checksum it, so an unreleased tag fails with a 404 — which is exactly what makes this a real end-to-end check of the URLs.

Note the image tag is `v0.0.46` even though `02-release.yaml` pins the action at `v0.0.47`: the action is a Docker action, and its `action.yml` runs `ghcr.io/rajatjindal/krew-release-bot:v0.0.46`. There is no `v0.0.47` image to pull.

This will output the generated krew manifest file, allowing you to verify:
- The version field is correct
- All download URLs are properly formatted
- The SHA256 checksum will be calculated correctly

For a released tag the output should be identical to that release's entry in [`kubernetes-sigs/krew-index`](https://github.com/kubernetes-sigs/krew-index/blob/master/plugins/kubescape.yaml), which is generated from `.goreleaser.yaml`. If the two differ, the two manifest definitions have drifted.

### Why skip_upload in GoReleaser?

In `.goreleaser.yaml`, the `krews` section has `skip_upload: true`:

```yaml
krews:
  - name: kubescape
    ids:
      - cli
    skip_upload: true  # We use krew-release-bot instead
    homepage: https://kubescape.io/
    description: It includes risk analysis, security compliance, and misconfiguration scanning with an easy-to-use CLI interface, flexible output formats, and automated scanning capabilities.
    short_description: Scan resources and cluster configs against security frameworks.
```

This is intentional because:
- GoReleaser generates the manifest but doesn't have built-in support for submitting PRs to krew-index
- krew-release-bot is the recommended tool for krew automation by the Krew team
- Using krew-release-bot provides automatic testing and merging of version bump PRs

### Manual Release Testing

You can test the release workflow manually without publishing to krew by using `workflow_dispatch`:

1. Go to Actions tab in GitHub
2. Select "02-create_release" workflow
3. Click "Run workflow"
4. The `skip_publish` input defaults to `true` (publishing will be skipped)
5. Set `skip_publish` to `false` if you want to test the full release process including krew indexing

### Making Changes to the Template

If you need to update the krew manifest (e.g., change the description, add platforms, or update the binary location), change **both** definitions — the released manifest comes from `.goreleaser.yaml`, and `.krew.yaml` is the fallback that has to keep matching it:

1. Edit the `krews:` block in `.goreleaser.yaml`. This is what the next release publishes.
2. Make the matching edit to `.krew.yaml`.
3. Test `.krew.yaml` with the Docker command shown above.
4. Run `go test ./internal/ghworkflows/... -run TestKrew`. It renders `.krew.yaml` under the bot's real function map and checks the asset names still match what GoReleaser publishes, so a change to only one of the two files fails here rather than at the next tag.
5. Commit and push the changes.

Adding or removing a platform also means updating `krewPlatforms` in `internal/ghworkflows/krew_test.go`.

### Installing kubescape via krew

Once the plugin is indexed in krew, users can install it with:

```bash
kubectl krew install kubernetes-sigs/kubescape
```

Or after index update:

```bash
kubectl krew install kubescape
```

### Further Reading

- [Krew official documentation](https://krew.sigs.k8s.io/docs/developer-guide/)
- [krew-release-bot repository](https://github.com/rajatjindal/krew-release-bot)
- [Krew plugin submission guide](https://krew.sigs.k8s.io/docs/developer-guide/develop/plugins/)