# GitHub Code Scanning Integration

This guide explains how to integrate Kubescape with [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning), GitHub's native security dashboard. Kubescape produces output in [SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format), which GitHub ingests to display Kubernetes misconfigurations directly in the **Security** tab of your repository.

## Prerequisites

- A GitHub repository (public, or private with GitHub Advanced Security enabled)
- Kubernetes manifest files, Helm charts, or Kustomize configurations in your repository
- GitHub Actions enabled on your repository

> **Note:** GitHub Code Scanning is free for public repositories. Private repositories require [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security).

## How It Works

Kubescape scans your Kubernetes manifests during a GitHub Actions workflow and writes results to a `.sarif` file. The workflow then uploads that file to GitHub using the `github/codeql-action/upload-sarif` action. GitHub parses the SARIF file and surfaces each finding as a **Code Scanning alert** in your repository's **Security → Code scanning** dashboard.

```
Push / PR → GitHub Actions → Kubescape scan → results.sarif → GitHub Security dashboard
```

## Basic Example

Create the file `.github/workflows/kubescape.yml` in your repository:

```yaml
name: Kubescape

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  kubescape:
    name: Scan Kubernetes manifests
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required to upload SARIF results
      actions: read
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Kubescape
        run: |
          curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
          echo "$HOME/.kubescape/bin" >> "$GITHUB_PATH"

      - name: Run Kubescape scan
        run: |
          kubescape scan . \
            --format sarif \
            --output results.sarif \
            --verbose
        continue-on-error: true   # upload results even when findings are detected

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

After the workflow runs, navigate to **Security → Code scanning** in your repository to view the results.

## Scanning Specific Paths

If your manifests are in a subdirectory, pass the path directly to Kubescape:

```yaml
- name: Install Kubescape
  run: |
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
    echo "$HOME/.kubescape/bin" >> "$GITHUB_PATH"

- name: Run Kubescape scan
  run: |
    kubescape scan ./k8s/ \
      --format sarif \
      --output results.sarif
  continue-on-error: true
```

You can also scan Helm charts or Kustomize directories by pointing to their root:

```yaml
- name: Install Kubescape
  run: |
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
    echo "$HOME/.kubescape/bin" >> "$GITHUB_PATH"

- name: Run Kubescape scan
  run: |
    kubescape scan ./charts/my-app/ \
      --format sarif \
      --output results.sarif
  continue-on-error: true
```

## Scanning with a Specific Framework

To limit the scan to a particular compliance framework, use the `framework` subcommand:

```yaml
- name: Install Kubescape
  run: |
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
    echo "$HOME/.kubescape/bin" >> "$GITHUB_PATH"

- name: Run Kubescape scan (NSA framework)
  run: |
    kubescape scan framework nsa . \
      --format sarif \
      --output results.sarif
  continue-on-error: true
```

Supported frameworks include `nsa`, `mitre`, and `cis-v1.23-t1.0.1`. Run `kubescape list frameworks` to see the full list.

## Setting a Compliance Threshold

To fail the workflow when the compliance score falls below a threshold, use `--compliance-threshold`. Combine this with `continue-on-error: true` on the scan step so the SARIF upload still runs:

```yaml
- name: Install Kubescape
  run: |
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash
    echo "$HOME/.kubescape/bin" >> "$GITHUB_PATH"

- name: Run Kubescape scan
  run: |
    kubescape scan . \
      --format sarif \
      --output results.sarif
  continue-on-error: true

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Enforce compliance threshold
  run: |
    kubescape scan . \
      --compliance-threshold 80 \
      --format pretty-printer
```

> **Note:** Running Kubescape twice (once for SARIF, once for threshold enforcement) is intentional. The first run always produces the SARIF file; the second run applies the threshold and fails the job if the score is too low.

## Using the Official Kubescape GitHub Action

As an alternative to installing Kubescape manually, you can use the [kubescape/github-action](https://github.com/kubescape/github-action):

```yaml
name: Kubescape

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  kubescape:
    name: Scan Kubernetes manifests
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Kubescape scan
        uses: kubescape/github-action@main
        continue-on-error: true
        with:
          format: sarif
          outputFile: results.sarif
          args: "."

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Viewing Results in GitHub Security Dashboard

Once the workflow completes:

1. Open your repository on GitHub.
2. Click the **Security** tab.
3. Select **Code scanning** from the left sidebar.
4. Each Kubescape finding is listed as an alert with:
   - The control name and ID (e.g., `Privileged container` / `C-0057`)
   - The affected file and line number
   - Severity level (`error`, `warning`, or `note`)
   - A link to the Kubescape control documentation for remediation guidance

Alerts found on a pull request are also annotated inline in the **Files changed** tab.

## Branch Protection Rules

To block pull requests that introduce new security findings, configure a branch protection rule that requires the Code Scanning check to pass:

1. Go to **Settings → Branches** in your repository.
2. Click **Add branch protection rule** (or edit an existing rule for `main`).
3. Enable **Require status checks to pass before merging**.
4. Search for and select the Kubescape workflow check (e.g., `Kubescape / Scan Kubernetes manifests`).
5. Optionally enable **Require branches to be up to date before merging**.
6. Click **Save changes**.

With this rule in place, the Kubescape workflow check must pass before a pull request can be merged.

> **Note:** The Basic Example and the official-action example both use `continue-on-error: true` on the scan step, which marks the step as failed but lets the overall job succeed. Branch protection gates on the job conclusion, so those workflows will always pass the check regardless of findings. To block merges on security findings, use the **Setting a Compliance Threshold** pattern above, where the dedicated `Enforce compliance threshold` step has no `continue-on-error` and fails the job when the threshold is not met. Alternatively, configure a failure severity under **Settings → Code security → Code scanning** to have GitHub itself block the merge.

## Troubleshooting

### No alerts appear in the Security tab

- Confirm the workflow ran successfully in the **Actions** tab.
- Verify the `permissions` block includes `security-events: write`. Without this permission, the SARIF upload silently fails.
- For private repositories, check that GitHub Advanced Security is enabled under **Settings → Security & analysis**.
- Ensure the `sarif_file` path in the upload step matches the `--output` path in the scan step.

### `results.sarif: no such file or directory`

The scan step failed before writing the file. Check the workflow logs. Common causes:

- `kubescape: command not found` — the PATH was not persisted after install. Ensure the Install Kubescape step includes `echo "$HOME/.kubescape/bin" >> "$GITHUB_PATH"`.
- No Kubernetes manifest files found at the scanned path.
- Kubescape installation failed (network issue or missing `curl`/`bash`).

Add `--verbose` to the scan command to get detailed output.

### Scan exits with code 1 even when `continue-on-error: true` is set

This is expected behaviour. `continue-on-error: true` allows subsequent steps to run but marks the step as failed. The overall job succeeds as long as later steps (including the SARIF upload) complete without error.

### Duplicate alerts after multiple workflow runs

GitHub deduplicates Code Scanning alerts by rule ID and location. If duplicates appear, check that you are not uploading results from both `push` and `pull_request` events for the same commit.

### Alerts show severity `none`

Kubescape maps control severity to SARIF levels. If controls are reported with no severity, ensure you are running Kubescape v3 or later:

```bash
kubescape version
```

## Further Reading

- [Kubescape GitHub Action](https://github.com/kubescape/github-action)
- [GitHub Code Scanning documentation](https://docs.github.com/en/code-security/code-scanning)
- [SARIF support for Code Scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [Kubescape controls library](https://kubescape.io/docs/controls/)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
