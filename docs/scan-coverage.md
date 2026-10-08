# Scan Coverage Reporting

Kubescape provides comprehensive scan coverage reporting across all supported output formats. This document explains what scan coverage is, how it is calculated, when a scan is considered degraded, how coverage is surfaced in each report format, and the guarantees provided to automated pipelines and human reviewers.

---

## Table of Contents

- [Overview](#overview)
- [Why Scan Coverage Matters](#why-scan-coverage-matters)
- [How Coverage is Calculated](#how-coverage-is-calculated)
- [Degraded Scan Coverage](#degraded-scan-coverage)
- [Format-by-Format Behavior](#format-by-format-behavior)
  - [Summary Matrix](#summary-matrix)
  - [Terminal / Pretty Printer](#terminal--pretty-printer)
  - [JSON](#json)
  - [JUnit XML](#junit-xml)
  - [SARIF](#sarif)
  - [GitHub Actions](#github-actions)
  - [Markdown](#markdown)
  - [HTML](#html)
  - [CSV](#csv)
  - [PDF](#pdf)
- [Coverage Reporting Guarantees](#coverage-reporting-guarantees)
- [Troubleshooting Incomplete Scans](#troubleshooting-incomplete-scans)

---

## Overview

When Kubescape evaluates a Kubernetes cluster or static manifest files against security frameworks (such as NSA, MITRE ATT&CK®, or CIS Benchmarks), it inspects various Kubernetes API resources (Group/Version/Resource, or GVRs) required by each control.

In real-world environments, not all controls can always be evaluated. For example:
- A required Custom Resource Definition (CRD) or API endpoint may not exist in the target cluster.
- The scanning identity may lack RBAC permissions to read certain cluster resources.
- A control may be irrelevant to the scanned workload type or deployment model.
- An execution policy may explicitly configure specific controls to be skipped.

**Scan coverage** quantifies how completely the requested controls were evaluated, surfaces the exact reasons for any unevaluated or skipped controls, and indicates whether scan findings represent a complete assessment.

---

## Why Scan Coverage Matters

Without coverage reporting, **a scan that evaluates only 5 out of 100 controls with zero failures could appear as a 100% compliant cluster**.

This creates a dangerous false sense of security:
- Security teams might assume non-evaluated controls passed.
- CI/CD quality gates could let misconfigurations slip into production because the verifying control failed to run due to missing permissions or unavailable APIs.
- Compliance auditors cannot verify whether hardening standards were actually checked or silently bypassed.

Kubescape addresses this by treating scan coverage as a first-class metric alongside compliance scores and vulnerability counts.

---

## How Coverage is Calculated

- **Total Controls**: The number of unique controls in scope for the selected framework(s) or scan target. If zero controls are in scope, the coverage score is reported as 0%.
- **Evaluated Controls**: The number of controls that were actually evaluated (`TotalControls - len(NotEvaluatedControls)`).
- **Skipped / Unevaluated Controls**: Controls that were bypassed due to missing resources, configuration settings, execution policy, or manual-review requirements.
- **Coverage Score**: Calculated by `ComputeCoverageScore` using the baseline ratio of evaluated controls to total controls, discounted by penalties for data collection degradations:

$$\text{Base Score} = \frac{\text{Evaluated Controls}}{\text{Total Controls}} \times 100$$

$$\text{Coverage Score} = \max\left(0, \min\left(100, \text{Base Score} - P_{\text{failedGVR}} - P_{\text{partialGVR}} - P_{\text{policy}} - P_{\text{manifest}}\right)\right)$$

Where penalties reflect data-quality degradations:
- **Silent Failed GVR Pulls** ($P_{\text{failedGVR}} = 3\%$ per silent failed GVR pull): Required Kubernetes API resources could not be retrieved at all.
- **Partial GVR Pulls** ($P_{\text{partialGVR}} = 2\%$ per partial pull): Resources were only partially retrievable (e.g. scoped selector or namespace listing failure).
- **Policy Input Degradations** ($P_{\text{policy}} = 5\%$ per degraded policy input): A configured policy input (exceptions, control inputs) failed to load from its source and fell back to defaults.
- **Skipped Manifests** ($P_{\text{manifest}} = 5\%$ per skipped manifest): Manifest files that failed parsing or schema validation.

Because penalties are applied for partial data collection and degraded policy inputs, evaluating every control in scope does not necessarily result in a 100% score if data collection was incomplete or degraded. A 100% Coverage Score requires that all applicable controls were evaluated with complete resource discovery, successful GVR pulls, intact policy inputs, and valid manifests.

---

## Degraded Scan Coverage

A scan is flagged as **Degraded** (`degraded: true`) when the evaluation could not be completed as intended due to missing inputs or runtime impediments. Common causes include:

1. **Missing Kubernetes Resources (GVRs)**: The control requires specific Kubernetes APIs (e.g., `batch/v1/cronjobs`, `networking.k8s.io/v1/networkpolicies`, or CRDs) that could not be retrieved from the cluster or manifest stream.
2. **Insufficient RBAC Permissions**: The scanning credentials cannot `get` or `list` required resources (e.g., `secrets`, `nodes`, `clusterroles`).
3. **Partial Resource Pulls**: Network timeouts or API server rate limits interrupted resource collection.
4. **Execution Policy Exclusions**: A policy or configuration explicitly marked controls or whole-cluster checks as skipped.
5. **Manifest Exclusions**: Manifests failed schema validation or could not be parsed.

When a scan is degraded, Kubescape surfaces a prominent warning indicator across all output formats and provides the missing resources or reason for each affected control.

---

## Format-by-Format Behavior

### Summary Matrix

| Output Format | Coverage Score | Degraded Indicator | Skipped Controls Listed | Skip Reasons Included | Gating Behavior |
|---|---|---|---|---|---|
| **Terminal** | Yes | Yes (warning badge) | Yes | Yes | Displayed when controls skipped or degraded |
| **JSON** | Yes (`coverageScore`) | Yes (`degraded: bool`) | Yes (`notEvaluatedControls`) | Yes (`missingGVRs`, status info) | Always included |
| **JUnit XML** | Yes (`<property name="coverageScore">`) | Yes (`<property name="degraded">`) | Yes (`<testcase>` skipped) | Yes (`<skipped message="...">`) | Included in child `<testsuite>` when `totalControls > 0`; omitted when `totalControls == 0` |
| **SARIF** | Yes (`runs[].invocations[].properties`) | Yes (`runs[].invocations[].properties` & `toolExecutionNotifications`) | Yes (`toolExecutionNotifications` when degraded) | Yes (notification text & `associatedRule`) | Properties recorded when `totalControls > 0`; notifications emitted strictly when degraded (`degraded == true`) |
| **GitHub Actions** | Yes (step summary) | Yes (`::warning` annotations) | Yes (summary table) | Yes (reasons column) | Emitted when degraded or controls skipped |
| **Markdown** | Yes | Yes (`⚠️ Degraded` badge) | Yes (table) | Yes | Omitted when 100% coverage, non-degraded, and no skips |
| **HTML** | Yes | Yes (card indicator) | Yes (table) | Yes | Omitted when 100% coverage, non-degraded, and no skips |
| **CSV** | No (row-level only) | No | Yes (appended rows with `Status = "skipped"`) | Yes (`Remediation` column) | Appends rows for skipped controls; cannot gate on aggregate score or degraded status |
| **PDF** | Yes | Yes (`(Degraded)` label) | Yes (zebra-striped table) | Yes | Omitted when 100% coverage, non-degraded, no skips, and no unexamined resource kinds |

---

### Terminal / Pretty Printer

In interactive terminal output, scan coverage appears in the scan overview. If controls were skipped or coverage is degraded, a dedicated table lists each skipped control along with its identifier, title, and diagnostic skip reason.

```bash
kubescape scan --verbose
```

---

### JSON

The raw JSON output (`--format json --output results.json`) includes the `scanCoverage` object within the posture report:

```json
{
  "scanCoverage": {
    "coverageScore": 85.0,
    "evaluatedControls": 17,
    "totalControls": 20,
    "degraded": true,
    "notEvaluatedControls": [
      {
        "controlID": "C-0099",
        "missingGVRs": ["apps/v1/daemonsets"],
        "reason": "missing: apps/v1/daemonsets"
      }
    ]
  }
}
```

---

### JUnit XML

In JUnit XML reports (`--format junit --output results.xml`), the document contains a root `<testsuites>` element enclosing one or more child `<testsuite>` elements (e.g. `kubescape` or named frameworks). Coverage metrics are attached as properties inside each child `<testsuite>`:

```xml
<testsuites>
  <testsuite name="kubescape" tests="20" failures="3" skipped="3" time="1.450">
    <properties>
      <property name="complianceScore" value="85.00"/>
      <property name="coverageScore" value="85.00"/>
      <property name="evaluatedControls" value="17"/>
      <property name="totalControls" value="20"/>
      <property name="degraded" value="true"/>
    </properties>
    <testcase classname="Kubescape" name="C-0099 Test Control">
      <skipped message="missing: apps/v1/daemonsets"/>
    </testcase>
  </testsuite>
</testsuites>
```

The specific coverage properties emitted are:
- `coverageScore`: Scan coverage percentage formatted to two decimal places (e.g., `85.00`).
- `evaluatedControls`: Total number of evaluated controls.
- `totalControls`: Total number of controls in scope.
- `degraded`: Boolean string (`true` or `false`).

> [!NOTE]
> When `totalControls` is 0 (for example, when scanning a manifest that matches no controls in scope), coverage properties are omitted entirely from `<properties>`.

CI systems parsing JUnit XML (Jenkins, GitLab CI, Azure DevOps) can read these properties or alert on skipped test cases.

---

### SARIF

In SARIF reports (`--format sarif --output results.sarif`), Kubescape records aggregate coverage metrics and degraded execution notifications within the `invocations` array under standard OASIS SARIF structures:

- **`runs[].invocations[].properties`**: Whenever controls are in scope (`totalControls > 0`), Kubescape records aggregate metrics in the invocation property bag:
  - `coverageScore`: Formatted coverage percentage (e.g., `"85.00"`).
  - `evaluatedControls`: Number of evaluated controls as a string.
  - `totalControls`: Number of total controls as a string.
  - `degraded`: Boolean string (`"true"` or `"false"`).
- **`runs[].invocations[].toolExecutionNotifications`**: Emitted **strictly when `ScanCoverage.Degraded == true`**. When a scan is degraded, Kubescape generates:
  1. A summary warning notification specifying the degraded coverage score and evaluated control ratio.
  2. Individual warning notifications for each skipped control, detailing the control ID, the diagnostic skip reason (e.g., missing GVR or RBAC rights), and an `associatedRule` reference linking to the rule descriptor in `runs[].tool.driver.rules`.

```json
{
  "runs": [
    {
      "invocations": [
        {
          "executionSuccessful": true,
          "properties": {
            "coverageScore": "85.00",
            "evaluatedControls": "17",
            "totalControls": "20",
            "degraded": "true"
          },
          "toolExecutionNotifications": [
            {
              "level": "warning",
              "message": {
                "text": "Scan coverage is degraded (85.00%): 17 of 20 controls evaluated"
              }
            },
            {
              "level": "warning",
              "associatedRule": {
                "id": "C-0099"
              },
              "message": {
                "text": "Control C-0099 was not evaluated: missing: apps/v1/daemonsets"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

> [!NOTE]
> If a scan skips controls but is not flagged as degraded (for example, through execution policy configurations where `Degraded == false`), `toolExecutionNotifications` are omitted, while `runs[].invocations[].properties` still records the exact control counts and coverage score.
>
> Platforms supporting execution notifications can inspect these records to alert on incomplete scans. Note that code scanning tools with strict property subsets (such as GitHub Code Scanning) process finding results while omitting `toolExecutionNotifications`; for GitHub environments, use the GitHub Actions output format (`--format github-actions`) or step summaries to ensure coverage diagnostics are prominently displayed.

---

### GitHub Actions

When running in GitHub Actions (`--format github-actions` or during CI runs), Kubescape outputs:

- **Workflow Commands (`::warning`)**: Emits workflow warnings for degraded scan coverage and un-evaluated controls so they appear directly in the GitHub Actions summary and pull request checks.
- **Job Summary**: Renders a markdown-formatted `### Scan Coverage` table in the GitHub Actions Step Summary:
  - Coverage Score with degraded indicator
  - Evaluated vs. total control count
  - Skipped controls table with reasons

---

### Markdown

In Markdown reports (`--format markdown --output report.md`), a `## Scan Coverage` section is generated:

```markdown
## Scan Coverage

**Coverage Score:** 85% ⚠️ Degraded

Evaluated 17 of 20 controls

| Control ID | Name | Reason |
|---|---|---|
| C-0099 | Test Control | missing: apps/v1/daemonsets |
```

*Note: If coverage is 100%, non-degraded, and no controls were skipped, this section is omitted to keep the report concise.*

---

### HTML

HTML reports (`--format html --output report.html`) include a dedicated `Scan Coverage` card:

- A coverage progress indicator and score percentage.
- A "Degraded" badge when applicable.
- Evaluated vs. total controls counter.
- A responsive, styled table listing all skipped controls with IDs, names, and exact skip reasons.

*Note: Omitted when coverage is 100% and no controls were skipped.*

---

### CSV

In CSV exports (`--format csv --output report.csv`), controls that were skipped or not evaluated are appended as dedicated rows to the tabular finding list:

- **Status**: Set to `skipped` or `not evaluated`.
- **Resource Details**: Set to `N/A` for `Resource Name`, `Resource Kind`, `Resource Namespace`, and `API Version` (since no resource evaluation occurred).
- **Remediation**: Contains the human-readable diagnostic reason (e.g., `configuration: missing RBAC rights` or `missing: apps/v1/daemonsets`).
- **Control Name / Control ID / Severity**: Preserved from the control metadata.

This allows spreadsheet tools, BigQuery, or data pipelines to filter on `Status = "skipped"` without losing diagnostic context.

> [!WARNING]
> **CSV cannot be used to gate CI/CD pipelines on degraded scan coverage or aggregate coverage score.**
> CSV is strictly a tabular export of individual evaluated resources and skipped control rows. It contains no top-level fields, headers, or metadata rows for `coverageScore`, `totalControls`, `evaluatedControls`, or `degraded`. If a scan suffers from degraded data collection (such as silent/partial GVR pull failures, degraded policy inputs, or unexamined manifests) that does not produce individual skipped controls, the CSV output will contain no indication of degradation.
>
> Automated CI/CD pipelines that require gating on scan coverage thresholds or degraded execution **must** consume machine-readable formats that carry aggregate coverage metadata: **JSON** (`scanCoverage`), **JUnit XML** (`<property name="coverageScore">` / `degraded`), or **SARIF** (`runs[].invocations[].properties`).

---

### PDF

PDF reports (`--format pdf --output report.pdf`) include a clean, publication-ready **Scan Coverage** summary row and diagnostic tables:

- The coverage summary row is positioned immediately following the posture resource summary, preceding the info footnotes; the skipped controls table follows the info footnotes and precedes the container image vulnerability section.
- Header row showing **Scan coverage**, **Evaluated X of Y controls**, and **Coverage Score** (appended with `(Degraded)` when applicable).
- When unexamined resource kinds are present (e.g., resources found in manifests or cluster state that were not mapped to any control), they are explicitly itemized below the coverage row.
- When controls are skipped, a dedicated zebra-striped table details each skipped control with its **Severity**, **Control reference**, **Control name**, and **Skip reason**.

*Note: The coverage summary row is displayed whenever coverage is degraded (`degraded == true`), any controls were skipped, unexamined resource kinds exist, or the coverage score is under 100%. It is omitted only when the scan achieves 100% coverage, is non-degraded, has no skipped controls, and has no unexamined resource kinds.*

---

## Coverage Reporting Guarantees

Kubescape provides the following guarantees across all scanning modes and output formats:

1. **Reason Preservation**: Whenever a control is skipped or not evaluated, the underlying diagnostic reason (missing GVR, configuration rule, exception, manual-review necessity) is never discarded. It is preserved and propagated to human-readable summaries and machine-readable outputs. For SARIF, individual skipped-control notifications in `toolExecutionNotifications` are emitted when the scan is degraded (`degraded == true`).
2. **Transparent Compliance**: An incomplete or degraded scan will never present a false 100% coverage score.
3. **Cross-Format Consistency**: Document-style reports (Markdown, HTML, PDF) consistently surface incomplete evaluations. PDF and terminal output also explicitly report unexamined resource kinds.
4. **Structured CI/CD Gating vs. Tabular Exports**: Machine-readable formats with aggregate metadata structures (JSON, JUnit XML, SARIF) provide explicit `coverageScore` and `degraded` indicators to support automated CI/CD gating and threshold enforcement. Tabular exports (CSV) provide row-level visibility into skipped controls and remediation reasons, but intentionally omit aggregate score and degradation flags and should not be used for aggregate coverage gating.

---

## Troubleshooting Incomplete Scans

If your scan coverage is degraded or controls are skipped:

1. **Run with `--verbose`**:
   ```bash
   kubescape scan --verbose
   ```
   Verbose output lists all resources pulled, APIs requested, and specific failure points.

2. **Verify Cluster RBAC**:
   Ensure the service account or kubeconfig user has cluster-wide read access (`get`, `list`) for required resources. Review the [required RBAC permissions](https://kubescape.io/docs/install-operator/#rbac-permissions).

3. **Check Custom Resource Definitions (CRDs)**:
   Controls checking ingress controllers, service meshes, or admission webhooks may require specific CRDs installed in the cluster. If your cluster does not use those components, those controls are safely skipped as irrelevant.

4. **Static Manifest Scans**:
   When scanning directories of YAML manifests, cluster-only controls (such as control plane API server configuration checks) will be skipped as they require a live cluster connection. To scan only workload controls, use an appropriate framework or control filter.
