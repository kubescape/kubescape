# CircleCI Integration

This guide explains how to integrate Kubescape with [CircleCI](https://circleci.com) to automatically scan Kubernetes manifests, Helm charts, and container images for misconfigurations and vulnerabilities as part of your CI/CD pipeline.

## Prerequisites

- A CircleCI account with a connected repository
- Kubernetes manifests, Helm charts, or a container image to scan
- `curl` available in your CircleCI executor (available by default in `cimg/base`)

## How It Works

Kubescape runs as a step inside a CircleCI job. The CLI is installed at runtime, scans the repository or a specified path, and exits with a non-zero code if the compliance score falls below the configured threshold — failing the pipeline.

```text
Push / PR → CircleCI pipeline → Install Kubescape → kubescape scan
                                                           ↓
                                                   Compliance check
                                                           ↓
                                             Pass (exit 0) / Fail (exit 1)
```

## Setting Up the Integration

### Step 1 — Create the CircleCI Configuration File

Create a `.circleci/config.yml` file in the root of your repository if one does not already exist:

```yaml
version: 2.1

jobs:
  kubescape-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout

workflows:
  security-scan:
    jobs:
      - kubescape-scan
```

### Step 2 — Install Kubescape

Add a step to install the Kubescape CLI inside the job. The install script places the binary under `~/.kubescape/bin`, which must be exported to `$BASH_ENV` so it persists across steps:

```yaml
- run:
    name: Install Kubescape
    command: |
      curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
      echo 'export PATH=$PATH:$HOME/.kubescape/bin' >> $BASH_ENV
      source $BASH_ENV
```

### Step 3 — Scan Kubernetes Manifests

Add a step to scan all Kubernetes manifests in the repository:

```yaml
- run:
    name: Scan Kubernetes manifests
    command: kubescape scan . --compliance-threshold 80
```

Kubescape exits with code `1` if the compliance score is below the threshold, marking the CircleCI job as failed.

To scan a specific directory instead of the entire repository, pass the path explicitly:

```bash
kubescape scan ./manifests/ --compliance-threshold 80
```

### Step 4 — Scan with a Specific Framework

To scan against a specific security framework such as NSA, MITRE, or CIS:

```yaml
- run:
    name: Scan with NSA framework
    command: kubescape scan framework nsa . --compliance-threshold 80
```

Available frameworks: `nsa`, `mitre`, `cis-v1.23-t1.0.1`. Run `kubescape list frameworks` to see all options.

### Step 5 — Scan a Container Image

To scan a container image for vulnerabilities, add a separate step:

```yaml
- run:
    name: Scan container image
    command: kubescape scan image nginx:latest
```

> **Note:** Image scanning requires Docker access. If your job uses the `docker` executor, use the `setup_remote_docker` step. For full Docker access without extra configuration, use the `machine` executor instead (see [Troubleshooting](#image-scan-fails-in-circleci)).

### Step 6 — Save Scan Results as Artifacts

To store scan results as a downloadable CircleCI artifact for later review:

```yaml
- run:
    name: Save scan results
    command: |
      kubescape scan . --format json --output results.json || true
- store_artifacts:
    path: results.json
    destination: kubescape-results
```

The `|| true` prevents the step from failing before the artifact is stored. Add a separate threshold enforcement step after storing results:

```yaml
- run:
    name: Enforce compliance threshold
    command: kubescape scan . --compliance-threshold 80
```

## Full Example

The following is a complete `.circleci/config.yml` that installs Kubescape, scans manifests, saves results as an artifact, and enforces a compliance threshold:

```yaml
version: 2.1

jobs:
  kubescape-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install Kubescape
          command: |
            curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
            echo 'export PATH=$PATH:$HOME/.kubescape/bin' >> $BASH_ENV
            source $BASH_ENV
      - run:
          name: Save scan results
          command: |
            kubescape scan . --format json --output results.json || true
      - store_artifacts:
          path: results.json
          destination: kubescape-results
      - run:
          name: Enforce compliance threshold
          command: kubescape scan . --compliance-threshold 80

workflows:
  security-scan:
    jobs:
      - kubescape-scan
```

## Configuration

Kubescape behaviour is controlled via CLI flags passed to the `kubescape scan` command.

| Flag | Default | Description |
|---|---|---|
| `--compliance-threshold` | `0` | Minimum compliance score (0–100). The job fails if the score is below this value. |
| `--format` | `pretty-printer` | Output format. Accepted values: `pretty-printer`, `json`, `junit`, `sarif`. |
| `--output` | stdout | Path to write the scan results file. |
| `--severity-threshold` | `none` | Fail the job if any vulnerability at or above this severity is found. Accepted values: `low`, `medium`, `high`, `critical`. |
| `--exceptions` | — | Path to an exceptions file to suppress known findings. |

### Scanning Multiple Frameworks

To scan against multiple frameworks in the same job, add a separate step for each:

```yaml
- run:
    name: Scan NSA framework
    command: kubescape scan framework nsa . --compliance-threshold 80
- run:
    name: Scan MITRE framework
    command: kubescape scan framework mitre . --compliance-threshold 80
```

## Troubleshooting

### Kubescape command not found after install

The install script adds Kubescape to `~/.kubescape/bin`. In CircleCI, environment variable changes only persist across steps when written to `$BASH_ENV`:

```bash
echo 'export PATH=$PATH:$HOME/.kubescape/bin' >> $BASH_ENV
source $BASH_ENV
```

### Pipeline fails with exit code 1 but no scan errors

This means the compliance score is below the `--compliance-threshold` value. Review the scan output in the CircleCI job log and fix the flagged misconfigurations, or adjust the threshold value.

### Image scan fails in CircleCI

Container image scanning requires Docker access. When using the `docker` executor, add `setup_remote_docker` before the scan step:

```yaml
- setup_remote_docker:
    docker_layer_caching: true
- run:
    name: Scan container image
    command: kubescape scan image nginx:latest
```

Alternatively, use the `machine` executor for full Docker access without extra configuration:

```yaml
jobs:
  image-scan:
    machine:
      image: ubuntu-2204:current
    steps:
      - checkout
      - run:
          name: Install Kubescape
          command: |
            curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
            echo 'export PATH=$PATH:$HOME/.kubescape/bin' >> $BASH_ENV
            source $BASH_ENV
      - run:
          name: Scan container image
          command: kubescape scan image nginx:latest
```

### No resources found during scan

Kubescape scans the current directory by default. If your manifests are in a subdirectory, pass the path explicitly:

```bash
kubescape scan ./manifests/ --compliance-threshold 80
```

## Further Reading

- [CircleCI configuration reference](https://circleci.com/docs/configuration-reference/)
- [Kubescape CLI documentation](https://kubescape.io/docs/getting-started/)
- [Kubescape frameworks and controls](https://kubescape.io/docs/frameworks-and-controls/)
- [Kubescape GitHub Actions integration](https://github.com/kubescape/github-action)
