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
    {{ $version := trimPrefix "v" .TagName }}{{ addURIAndSha "https://github.com/kubescape/kubescape/releases/download/" .TagName (printf "kubescape_%s_linux_amd64.tar.gz" $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: linux
        arch: arm64
    {{ $version := trimPrefix "v" .TagName }}{{ addURIAndSha "https://github.com/kubescape/kubescape/releases/download/" .TagName (printf "kubescape_%s_linux_arm64.tar.gz" $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: darwin
        arch: amd64
    {{ $version := trimPrefix "v" .TagName }}{{ addURIAndSha "https://github.com/kubescape/kubescape/releases/download/" .TagName (printf "kubescape_%s_darwin_amd64.tar.gz" $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: darwin
        arch: arm64
    {{ $version := trimPrefix "v" .TagName }}{{ addURIAndSha "https://github.com/kubescape/kubescape/releases/download/" .TagName (printf "kubescape_%s_darwin_arm64.tar.gz" $version) .TagName }}
    bin: kubescape
  - selector:
      matchLabels:
        os: windows
        arch: amd64
    {{ $version := trimPrefix "v" .TagName }}{{ addURIAndSha "https://github.com/kubescape/kubescape/releases/download/" .TagName (printf "kubescape_%s_windows_amd64.tar.gz" $version) .TagName }}
    bin: kubescape.exe
  - selector:
      matchLabels:
        os: windows
        arch: arm64
    {{ $version := trimPrefix "v" .TagName }}{{ addURIAndSha "https://github.com/kubescape/kubescape/releases/download/" .TagName (printf "kubescape_%s_windows_arm64.tar.gz" $version) .TagName }}
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

The `{{ .TagName }}` is replaced with the release tag (e.g., `v3.0.0`), `{{ trimPrefix "v" .TagName }}` removes the version prefix, and `{{ addURIAndSha ... }}` calculates the SHA256 checksum for the binary archive.

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
   - Reads the `.krew.yaml` template
   - Fills in the template with release information
   - Creates a pull request to the `kubernetes-sigs/krew-index` repository
   - The PR is automatically tested and merged by krew's infrastructure

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
docker run -v $(pwd)/.krew.yaml:/tmp/.krew.yaml ghcr.io/rajatjindal/krew-release-bot:v0.0.47 \
  krew-release-bot template --tag v3.0.0 --template-file /tmp/.krew.yaml
```

This will output the generated krew manifest file, allowing you to verify:
- The version field is correct
- All download URLs are properly formatted
- The SHA256 checksum will be calculated correctly

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

If you need to update the krew manifest (e.g., change the description, add platforms, or update the binary location):

1. Edit the `.krew.yaml` file
2. Test your changes with the Docker command shown above
3. Commit and push the changes
4. The next release will use the updated template

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