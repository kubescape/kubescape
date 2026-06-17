# Azure Pipelines Integration

This guide explains how to integrate Kubescape with [Azure Pipelines](https://azure.microsoft.com/en-us/products/devops/pipelines) to automatically scan Kubernetes manifests, Helm charts, and container images for misconfigurations and vulnerabilities as part of your CI/CD pipeline.

## Prerequisites

- An Azure DevOps account with a project and a connected repository
- Kubernetes manifests, Helm charts, or a container image to scan
- An `azure-pipelines.yml` file in the root of your repository

## How It Works

Kubescape runs as a step inside an Azure Pipelines job. The CLI is installed at runtime, scans the repository or a specified path, and exits with a non-zero code if the compliance score falls below the configured threshold — failing the pipeline.

```text
Push / PR → Azure Pipelines → Install Kubescape → kubescape scan
                                                         ↓
                                                 Compliance check
                                                         ↓
                                           Pass (exit 0) / Fail (exit 1)
```

## Setting Up the Integration

### Step 1 — Create the Azure Pipelines Configuration File

Create an `azure-pipelines.yml` file in the root of your repository if one does not already exist:

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps: []
```

### Step 2 — Install Kubescape

Add a step to install the Kubescape CLI:

```yaml
- script: |
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    echo "##vso[task.prependpath]$HOME/.kubescape/bin"
  displayName: Install Kubescape
```

The `##vso[task.prependpath]` logging command adds the Kubescape binary to `PATH` for all subsequent steps in the pipeline.

### Step 3 — Scan Kubernetes Manifests

Add a step to scan all Kubernetes manifests in the repository against all frameworks:

```yaml
- script: kubescape scan framework all . --compliance-threshold 80
  displayName: Scan Kubernetes manifests
```

Kubescape exits with code `1` if the compliance score is below the threshold, marking the Azure Pipelines job as failed.

> **Note:** `--compliance-threshold` only applies to `scan framework`, `scan control`, and `--view resource|control`. Using `kubescape scan .` without a framework does not enforce the compliance threshold.

To scan a specific directory instead of the entire repository, pass the path explicitly:

```bash
kubescape scan framework all ./manifests/ --compliance-threshold 80
```

### Step 4 — Scan with a Specific Framework

To scan against a specific security framework such as NSA, MITRE, or CIS:

```yaml
- script: kubescape scan framework nsa . --compliance-threshold 80
  displayName: Scan with NSA framework
```

Available built-in frameworks: `allcontrols`, `nsa`, `mitre`. Run `kubescape list frameworks` to see all available frameworks including downloadable ones.

### Step 5 — Scan a Container Image

To scan a container image for vulnerabilities, add a separate step:

```yaml
- script: kubescape scan image nginx:latest
  displayName: Scan container image
```

> **Note:** Kubescape pulls images directly from the registry using Syft/Grype and does not require a Docker daemon for registry-hosted images. `--format junit` is not supported for image scans — use `pretty-printer`, `json`, or `sarif` instead.

### Step 6 — Save Scan Results as Pipeline Artifacts

To store scan results as a downloadable Azure Pipelines artifact for later review:

```yaml
- script: |
    kubescape scan framework all . --format json --output $(Build.ArtifactStagingDirectory)/results.json || true
  displayName: Save scan results

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: $(Build.ArtifactStagingDirectory)
    artifactName: kubescape-results
  displayName: Publish scan results
```

The `|| true` prevents the step from failing before the artifact is published. Add a separate threshold enforcement step after publishing results:

```yaml
- script: kubescape scan framework all . --compliance-threshold 80
  displayName: Enforce compliance threshold
```

## Full Example

The following is a complete `azure-pipelines.yml` that installs Kubescape, scans manifests, saves results as a pipeline artifact, and enforces a compliance threshold:

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - script: |
      curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
      echo "##vso[task.prependpath]$HOME/.kubescape/bin"
    displayName: Install Kubescape

  - script: |
      kubescape scan framework all . --format json --output $(Build.ArtifactStagingDirectory)/results.json || true
    displayName: Save scan results

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: kubescape-results
    displayName: Publish scan results

  - script: kubescape scan framework all . --compliance-threshold 80
    displayName: Enforce compliance threshold
```

## Configuration

Kubescape behaviour is controlled via CLI flags passed to the `kubescape scan` command.

| Flag | Default | Description |
|---|---|---|
| `--compliance-threshold` | `0` | Minimum compliance score (0–100). The pipeline fails if the score is below this value. |
| `--format` | `pretty-printer` | Output format for manifest/framework scans. Accepted values: `pretty-printer`, `json`, `junit`, `sarif`, `html`, `pdf`, `prometheus`. Image scans support `pretty-printer`, `json`, and `sarif` only (no `junit`). |
| `--output` | stdout | Path to write the scan results file. |
| `--severity-threshold` | (unset) | Fail the pipeline if any control failure at or above this severity is found. Accepted values: `low`, `medium`, `high`, `critical`. |
| `--exceptions` | — | Path to an exceptions file to suppress known findings. |

### Scanning Multiple Frameworks

To scan against multiple frameworks in the same pipeline, add a separate step for each:

```yaml
- script: kubescape scan framework nsa . --compliance-threshold 80
  displayName: Scan NSA framework

- script: kubescape scan framework mitre . --compliance-threshold 80
  displayName: Scan MITRE framework
```

### Publishing SARIF Results to Azure DevOps

Azure DevOps supports SARIF output for static analysis results. To publish SARIF results:

```yaml
- script: |
    kubescape scan framework all . --format sarif --output $(Build.ArtifactStagingDirectory)/results.sarif || true
  displayName: Save SARIF results

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: $(Build.ArtifactStagingDirectory)
    artifactName: CodeAnalysisLogs
  displayName: Publish SARIF results
```

## Troubleshooting

### Kubescape command not found after install

The install script adds Kubescape to `~/.kubescape/bin`. In Azure Pipelines, use the `##vso[task.prependpath]` logging command to add it to `PATH` for all subsequent steps:

```bash
echo "##vso[task.prependpath]$HOME/.kubescape/bin"
```

Using `export PATH` inside a `script` step does not persist across steps in Azure Pipelines.

### Pipeline fails with exit code 1 but no scan errors

This means the compliance score is below the `--compliance-threshold` value. Review the scan output in the pipeline logs and fix the flagged misconfigurations, or adjust the threshold value.

### No resources found during scan

Kubescape scans the current directory by default. If your manifests are in a subdirectory, pass the path explicitly:

```bash
kubescape scan ./manifests/ --compliance-threshold 80
```

### Artifact not published when scan fails

The `|| true` in the save step prevents the step from exiting with code `1` before the artifact is published. Make sure threshold enforcement is a separate step placed after the `PublishBuildArtifacts` task.

## Further Reading

- [Azure Pipelines documentation](https://learn.microsoft.com/en-us/azure/devops/pipelines/)
- [Azure Pipelines YAML schema reference](https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/)
- [Kubescape CLI documentation](https://kubescape.io/docs/getting-started/)
- [Kubescape frameworks and controls](https://kubescape.io/docs/frameworks-and-controls/)
- [Kubescape GitHub Actions integration](https://github.com/kubescape/github-action)
