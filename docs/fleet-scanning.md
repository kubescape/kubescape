# Scanning a fleet of clusters

Kubescape can scan several clusters in one run and combine what it finds into a
single fleet report: one compliance score for the whole fleet, the controls the
clusters disagree on, and which clusters it could not scan and why.

## Quick start

```bash
kubescape scan framework nsa \
  --kube-contexts prod,staging,dr \
  --output report.json \
  --fleet-report fleet.json
```

This scans the `prod`, `staging` and `dr` contexts from your kubeconfig one after
another, and then:

- writes one report per cluster, named after `--output`: `report.prod.json`,
  `report.staging.json` and `report.dr.json`
- writes `fleet.json`, the combined report for the whole fleet
- prints a fleet summary in the terminal

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--kube-contexts <ctx,...>` | Kube contexts to scan, one after another. Comma-separated, or repeat the flag. Requires `--output`. | - |
| `--fleet-report <path>` | Also write one combined JSON report across every context to this path. Not supported with `--hide` or `--encrypt`. | - |
| `--reference-cluster <ctx>` | With `--fleet-report`, the context the other clusters are compared against. Must be one of `--kube-contexts`. | - |
| `--retries <n>` | How many more times to try a cluster whose API server never answered. `0` disables retries. | `2` |
| `--fleet-config <path>` | Read the fleet settings from a file instead. See [fleet config file](#fleet-config-file). | - |
| `--fail-coverage-below <float>` | Also used as the coverage floor for the fleet score: a cluster scanned with less coverage is left out of it. | `0` |
| `--scan-timeout <duration>` | Limits each scan attempt of each cluster. An attempt that runs out of time is `cancelled` and is not retried. | - |

`--kube-contexts` works with `kubescape scan` (security view), `scan framework`,
`scan control` and `scan workload`. Contexts are scanned one at a time, and one
cluster failing never stops the others from being scanned.

## Fleet config file

Instead of repeating the fleet flags on every run, you can keep them in a file
and pass it with `--fleet-config`:

```yaml
apiVersion: config.kubescape.io/v1alpha1
kind: FleetConfig
metadata:
  name: production
spec:
  contexts: [prod, staging, dr]
  output: report.json
  fleetReport: fleet.json
  referenceCluster: prod
  retries: 2
```

```bash
kubescape scan framework nsa --fleet-config fleet.yaml
```

Each field sets the matching flag: `contexts` is `--kube-contexts`,
`output` is `--output`, `fleetReport` is `--fleet-report`, `referenceCluster`
is `--reference-cluster` and `retries` is `--retries`. Every field under `spec`
is optional, but the contexts have to come from somewhere: the file or
`--kube-contexts`.
Paths are read relative to where you run the command, as they are for the
flags.

A flag given on the command line overrides the same setting in the file, so
`--fleet-config fleet.yaml --retries 0` scans the same contexts without
retrying. Values from the file are checked exactly as the flags are, and a
misspelt or unknown field is an error rather than being ignored. Scan settings such as frameworks,
thresholds and timeouts are not part of the fleet config; they stay on the
command line or in a scan contract (`--scan-contract`).

## Cluster statuses

Every requested context appears in the fleet report with exactly one status:

| Status | Meaning |
|--------|---------|
| `scanned` | The scan completed and the cluster has a report. |
| `unreachable` | The cluster's API server never answered: the connection was refused, the name did not resolve, or the request timed out before any response. |
| `error` | Something answered but the scan failed, for example a request was forbidden, or the kubeconfig entry for the cluster could not be loaded. |
| `cancelled` | The run was stopped, by Ctrl-C or `--scan-timeout`, before the cluster finished. Nothing was learned about it. |

A cluster that was scanned but breached a threshold such as
`--compliance-threshold` is still `scanned`: it was measured, and the breach is
reported through the exit code.

## Retries

A cluster that is `unreachable` is tried again, up to `--retries` more times
(2 by default, so 3 attempts in all). Only `unreachable` clusters are retried: a
cluster that answered with an error, or whose scan was cancelled, will not do
better on a second try.

Between attempts Kubescape waits 2 seconds, then 4, doubling up to 30 seconds.
With the default of 2 retries the waits add 6 seconds. How long the attempts
themselves take depends on how the cluster fails:

- a refused connection or a name that does not resolve fails within a few
  seconds, so three attempts take well under a minute
- an address that silently drops traffic makes every request wait for the 30
  second connection timeout, and one attempt makes many requests, so a single
  attempt can take around 15 minutes and three attempts around 45

Use `--retries 0` to fail fast. `--scan-timeout` caps each attempt, but an
attempt that runs out of time is `cancelled` and is not retried.

Each attempt starts from a fresh copy of the scan settings. Pressing Ctrl-C
during a wait stops it at once: the cluster keeps the result of its last
attempt, `unreachable`, any clusters not yet scanned are reported as
`cancelled`, and the fleet report and summary are still written.

When a cluster needed more than one attempt, the fleet report records it in the
cluster's `attempts` field and the summary shows it, for example
`unreachable (3 attempts)`.

## Reading the summary

```
Fleet summary
╭──────────────┬─────────────┬────────────┬──────────┬──────────╮
│ Cluster      │ Status      │ Compliance │ Coverage │ Duration │
├──────────────┼─────────────┼────────────┼──────────┼──────────┤
│ prod         │ scanned     │ 88%        │ 100%     │ 41s      │
│ staging      │ scanned     │ 71%        │ 100%     │ 44s      │
│ dr           │ unreachable │ -          │ -        │ 2s       │
╰──────────────┴─────────────┴────────────┴──────────┴──────────╯

Fleet compliance: 80%  (from 2 of 3 clusters)
```

- Every requested cluster keeps its row, including the ones that could not be
  scanned, with the reason printed below the table.
- A value nobody measured is shown as `-`, never `0%`.
- The fleet score is the mean of the clusters that could be scored, and always
  says how many clusters it is based on. Clusters left out are named with the
  reason.
- The last table lists the controls the clusters disagree on, worst severity
  first. `posture` means one cluster passed and another failed. `coverage` means
  a cluster could not evaluate the control while another could.

## The fleet report

`fleet.json` has five sections:

| Section | Contents |
|---------|----------|
| `metadata` | When the report was generated, the Kubescape version, and the contexts that were requested. |
| `clusters` | One entry per context: `status`, `error`, `complianceScore`, `coverage`, `duration`, `attempts`, and the cluster's own report when it was scanned. |
| `compliance` | The fleet score, how many clusters it came from, per-framework scores, and every cluster left out with the reason. |
| `controlMatrix` | Every control against every cluster: passed, failed, skipped or not evaluated. |
| `divergence` | The controls the clusters disagree on, which clusters landed where, and what the reference cluster found. |

For example, to list each cluster's status:

```bash
jq '.clusters[] | {clusterID, status, attempts}' fleet.json
```

## Exit code

A fleet run tells CI whether the fleet failed a check or could not be fully
scanned:

| Code | Meaning |
|------|---------|
| `0` | Every cluster was scanned and passed. |
| `1` | Every cluster was scanned, but at least one failed a gate: `--compliance-threshold`, `--severity-threshold`, `--fail-coverage-below`, `--fail-on-degraded-config` or `--baseline-fail-on-new`. |
| `2` | At least one cluster was `unreachable`, `error` or `cancelled`, a cluster's report could not be written, or the fleet report could not be written. |

If one cluster fails a gate and another could not be scanned, the run exits
with `2`, since part of the fleet was never checked. An invalid command line still exits with `1`, as it does for any
other scan. The fleet report and the summary are still produced for the
clusters that were scanned.

## Performance

Clusters are scanned one after another, so a fleet scan takes about as long as
its clusters' scans added together.

Memory depends on whether a fleet report is written. Without `--fleet-report`,
each cluster's results are released once its own report is written, so memory
stays about the same however many clusters you scan. With `--fleet-report`,
each cluster's results are kept until the fleet report is written, minus the
raw Kubernetes objects, which the fleet report leaves out. Memory then grows
with the number of clusters.

Measured against fake clusters with 200 pods each, as peak memory of the whole
process (about 136 MiB of it is the binary itself):

| Clusters | Peak memory with `--fleet-report` | Peak memory without |
|----------|-----------------------------------|---------------------|
| 1        | 202 MiB                           | 196 MiB             |
| 5        | 239 MiB                           | 201 MiB             |
| 10       | 329 MiB                           | 204 MiB             |

Time grew with the number of clusters, at around half a second to a second
each: ten clusters took between 5 and 11 seconds across runs on the same
machine. Real clusters are slower, since every request crosses the network and
they usually hold more objects, so treat these numbers as a comparison rather
than a prediction.

To reproduce them, from `cmd/scan`:

```bash
go test -c -o scan.test .
/usr/bin/time -v ./scan.test -test.run '^$' -test.bench 'BenchmarkFleetScan/report=true/clusters=10$' -test.benchtime 1x
```
