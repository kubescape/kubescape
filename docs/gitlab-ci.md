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

Show Findings in Merge Requests with Code Quality

The `gitlab-codequality` format writes failed controls as a GitLab Code Quality report. GitLab compares it with the report from the target branch and lists the findings a merge request introduces or resolves in the merge request widget, which is available on every GitLab tier. Each finding points at the file and line of the failing field.

```yaml
stages:
  - scan

scan_code_quality:
  stage: scan
  image: alpine:latest
  script:
    - apk add --no-cache bash curl gcompat
    - curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    - export PATH=$PATH:$HOME/.kubescape/bin
    - kubescape scan framework nsa . --format gitlab-codequality --output gl-code-quality-report.json
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

Kubescape severities map to Code Quality severities as Critical → `critical`, High → `major`, Medium → `minor`, and Low → `info`. Each finding carries a fingerprint built from the control, the resource's API group, kind, namespace and name, and the file, so GitLab tracks it across pipelines and only reports it as new when one of those changes. Moving the resource within its file, or scanning from another checkout directory, does not change it. Like `gitlab-sast`, the format only covers local file, directory and repository scans, and resources with no path inside the repository are left out with a warning. Image vulnerabilities have no file to anchor to, so `--scan-images` and `scan image` are rejected with this format.

Report Image Vulnerabilities with Container Scanning

The `gitlab-container-scanning` format writes image vulnerabilities as a GitLab Container Scanning report, so they appear in the merge request security widget and the vulnerability report next to GitLab's own container scanning results (GitLab Ultimate tier required; the security widget and vulnerability report are not available on Free or Premium tiers). Each finding names the image, its operating system and the vulnerable package, and carries the upgrade path when a fix is available.

The image being scanned (for example, `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA`) must already exist in the registry, built and pushed by an earlier job in your pipeline.

```yaml
stages:
  - scan

scan_container:
  stage: scan
  image: alpine:latest
  variables:
    KUBESCAPE_REGISTRY_USERNAME: $CI_REGISTRY_USER
    KUBESCAPE_REGISTRY_PASSWORD: $CI_REGISTRY_PASSWORD
  script:
    - apk add --no-cache bash curl gcompat
    - curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    - export PATH=$PATH:$HOME/.kubescape/bin
    - kubescape scan image "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" --format gitlab-container-scanning --output gl-container-scanning-report.json
  artifacts:
    when: always
    reports:
      container_scanning: gl-container-scanning-report.json
```

The `KUBESCAPE_REGISTRY_USERNAME` and `KUBESCAPE_REGISTRY_PASSWORD` variables let Kubescape pull the image from the project's private container registry without putting the job token on the command line. The format also works with `kubescape scan --scan-images`, in which case it reports only the image vulnerabilities; write posture findings with `gitlab-sast` or `gitlab-codequality` from a separate scan. Grype's Negligible severity is reported as `Info`, an image without a detectable operating system is reported as `Unknown`, and each vulnerability keeps a stable identifier so dismissals carry over between pipelines. Each finding also lists whether the vulnerability is on the CISA Known Exploited Vulnerabilities catalog and its EPSS exploit probability in the vulnerability details, as do image findings in `gitlab-sast` reports, so the most likely exploited issues can be triaged first.

When the same image is scanned for several platforms, each finding names its platform in the operating system field and in its description. GitLab's vulnerability report, though, tracks a container finding by the image name and the package, with the tag left out unless it is a version, and does not look at the operating system, so it merges the same vulnerability found in the `linux/amd64` and `linux/arm64` variants of one image into a single entry. Writing each platform to its own report keeps the per-platform results in the report files, but GitLab still shows them as one vulnerability.

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
The GitLab SAST format can only anchor a finding to a file inside the repository, so resources with no file path, or with a path outside the repository root, are excluded. Kubescape logs a warning with the count when this happens. Cluster scans have no file paths at all, so Kubescape rejects this format for them. `--format sarif` and `--format json` both work for a cluster scan, but SARIF locations there are virtual resource identifiers, not repository files; scan the manifests to get findings on real file locations.

Further Reading
- Kubescape CLI Reference
- GitLab CI/CD Documentation
- Kubescape Getting Started Guide
