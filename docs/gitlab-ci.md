# Integrating with GitLab CI/CD

Use GitLab CI to scan your Kubernetes manifests for misconfigurations with Kubescape. Scan results are published as part of your GitLab CI/CD pipeline.

## Prerequisites

- GitLab account with a repository
- GitLab Runner configured (Docker executor recommended)
- Network access to GitHub.com from the runner
  
## Basic Example

1. Create a .gitlab-ci.yml file in the root of your repository.
2. Add the following configuration:

```yaml
stages:
  - scan

scan_with_kubescape:
  stage: scan
  image: alpine:latest
  script:
    - apk add --no-cache bash curl gcompat
    - curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    - export PATH=$PATH:$HOME/.kubescape/bin
    - kubescape scan . --format junit --output results.xml --exclude-namespaces kube-system,kube-public
  artifacts:
    reports:
      junit: results.xml
    paths:
      - results.xml
    expire_in: 30 days
  only:
    - merge_requests
    - main
```
3. Push the .gitlab-ci.yml file to your repository.
4. Create a merge request or push to the main branch.
5. Check the pipeline status in your GitLab project.
   
Using a Security Gate
To enforce a security gate, add the --compliance-threshold option
```yaml
stages:
  - scan

scan_with_kubescape:
  stage: scan
  image: alpine:latest
  script:
    - apk add --no-cache bash curl gcompat
    - curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    - export PATH=$PATH:$HOME/.kubescape/bin
    - kubescape scan framework nsa . --format junit --output results.xml --compliance-threshold 80
  artifacts:
    reports:
      junit: results.xml
    paths:
      - results.xml
    expire_in: 30 days
  only:
    - merge_requests
    - main
```
The pipeline will fail if fewer than 80% of controls pass.

Scan a Specific Framework

To scan against a specific compliance framework:
```yaml
stages:
  - scan

scan_nsa_framework:
  stage: scan
  image: alpine:latest
  script:
    - apk add --no-cache bash curl gcompat
    - curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    - export PATH=$PATH:$HOME/.kubescape/bin
    - kubescape scan framework nsa . --format junit --output results.xml
  artifacts:
    reports:
      junit: results.xml
```
Supported frameworks: nsa, mitre, cis-v1.23-t1.0.1. Run kubescape list frameworks for the full list.

Troubleshooting

kubescape: command not found
This occurs when the install script runs in one shell step and kubescape is invoked in another. The solution is to export the PATH in the same script step:
script:
  - curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
  - export PATH=$PATH:$HOME/.kubescape/bin
  - kubescape scan . --format junit --output results.xml
    
Findings point at paths that do not exist in the repository
GitLab resolves the `location.file` of every SAST finding from the repository root. Kubescape anchors reported paths on the root of the repository the scanned path belongs to, so scanning a subdirectory keeps its prefix:

```bash
kubescape scan framework nsa workloads/ --format gitlab-sast --output gl-sast-report.json
# "file": "workloads/apps/base/app/cronjobs.yaml"
```

If findings are missing the prefix, the scanned path is not inside a git worktree the runner can see. Check that the job clones the repository rather than copying files into the container, and that `GIT_STRATEGY` is not set to `none`.

Findings reappear as new after upgrading
A finding's identity is derived in part from the file path it was reported at. Releases that correct those paths therefore change the identity of the affected findings, and GitLab reports them as new once. Previously dismissed findings from affected scans have to be dismissed again on that first pipeline run; identities are stable across subsequent scans.

Some resources are missing from the report
The GitLab SAST format can only anchor a finding to a file inside the repository, so resources with no file path, or with a path outside the repository root, are excluded. Kubescape logs a warning with the count when this happens. Cluster scans have no file paths at all and cannot be reported in this format; use `--format json` or `--format sarif` for those.

Further Reading
- Kubescape CLI Reference
- GitLab CI/CD Documentation
- Kubescape Getting Started Guide
