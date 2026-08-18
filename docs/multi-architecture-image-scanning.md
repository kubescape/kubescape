# Multi-architecture image scanning

Container tags can point to an OCI image index instead of one image manifest. The index may contain different filesystems for `linux/amd64`, `linux/arm64`, Windows, and other platforms. Those variants often contain different operating system packages and therefore have different vulnerabilities.

Kubescape keeps the target platform attached to each image scan. This prevents a scan performed on a developer laptop or CI runner from silently selecting that machine's architecture when the workload will run somewhere else.

## Scan one image for a specific platform

Use `--platform` with `kubescape scan image`:

```bash
kubescape scan image nginx:1.27 --platform linux/amd64
kubescape scan image nginx:1.27 --platform linux/arm64
kubescape scan image mcr.microsoft.com/windows/nanoserver:ltsc2022 --platform windows/amd64
```

Architecture-only values are accepted and use Linux as the operating system:

```bash
kubescape scan image nginx:1.27 --platform arm64
```

This is normalized to `linux/arm64` before the image provider is called.

The accepted syntax is:

```text
os/architecture[/variant]
```

Examples include:

| Input | Canonical platform |
|-------|--------------------|
| `amd64` | `linux/amd64` |
| `x86_64` | `linux/amd64` |
| `aarch64` | `linux/arm64` |
| `linux/arm/v7` | `linux/arm/v7` |
| `windows/amd64` | `windows/amd64` |

Invalid or incomplete platforms are rejected before the vulnerability database or registry is opened. This gives CI an immediate configuration error instead of a misleading scan of a fallback image.

## Scan workload images

When `--scan-images` is used with a Kubernetes scan, Kubescape tries to identify the platform from hard scheduling information already present in the scan:

1. If a Pod has `spec.nodeName` and that Node was collected, Kubescape uses the Node's `kubernetes.io/os` and `kubernetes.io/arch` labels.
2. Otherwise, it evaluates exact OS and architecture values in `spec.nodeSelector`.
3. It also evaluates platform expressions in `requiredDuringSchedulingIgnoredDuringExecution` node affinity.
4. Partial and negative constraints such as `NotIn` filter the platforms observed on collected Nodes.
5. If a workload can run on multiple platform variants in a heterogeneous cluster, each allowed observed variant is scanned once.
6. If no platform constraint is present and no Node platform is available, Kubescape preserves the image provider's existing default behavior.

Preferred node affinity is not treated as a platform guarantee. The Kubernetes scheduler may ignore a preference, so narrowing a scan from preferred affinity could omit the image that actually runs.

### Override inference

Use `--image-platform` to force one platform for every image found by `--scan-images`:

```bash
kubescape scan --scan-images --image-platform linux/amd64
kubescape scan framework nsa --scan-images --image-platform linux/arm64
kubescape scan workload Deployment/api --scan-images --image-platform linux/amd64
```

An explicit override takes precedence over Node data, node selectors, and required node affinity. This is useful for offline manifests that do not include Node objects, or for CI jobs that scan manifests intended for a known deployment platform.

## Heterogeneous clusters

Consider a cluster with these Nodes:

```yaml
apiVersion: v1
kind: Node
metadata:
  name: amd-worker
  labels:
    kubernetes.io/os: linux
    kubernetes.io/arch: amd64
---
apiVersion: v1
kind: Node
metadata:
  name: arm-worker
  labels:
    kubernetes.io/os: linux
    kubernetes.io/arch: arm64
```

An unconstrained workload can run on either Node. With `--scan-images`, Kubescape creates two scan targets for a multi-architecture tag:

```text
registry.example.com/team/api:v2 [linux/amd64]
registry.example.com/team/api:v2 [linux/arm64]
```

The image and platform pair is the deduplication key. If ten Pods use the same tag on ARM64, that variant is scanned once. If the same tag is also used on amd64, the amd64 variant is scanned separately.

Platform-qualified target names are used in human-facing output such as the pretty, HTML, and PDF reports. Machine formats preserve the existing image identity for compatibility. Where the format supports separate metadata, Prometheus adds an optional `platform` label, JUnit adds a `platform` suite property, and GitLab includes the platform in the description without changing its finding fingerprint or `location.file`.

When this automatic fan-out includes a platform that the image index does not publish, Kubescape logs and skips only that unavailable inferred variant. Authentication, network, parsing, and other registry failures still fail the scan. Explicit `--platform` and `--image-platform` selections also remain strict.

## Node selector examples

An exact node selector gives Kubescape a single safe platform:

```yaml
spec:
  template:
    spec:
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/arch: arm64
      containers:
        - name: api
          image: registry.example.com/team/api:v2
```

Required node affinity can describe several valid variants:

```yaml
spec:
  template:
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: kubernetes.io/os
                    operator: In
                    values: [linux]
                  - key: kubernetes.io/arch
                    operator: In
                    values: [amd64, arm64]
      containers:
        - name: api
          image: registry.example.com/team/api:v2
```

Both variants are scanned. OR branches that do not fully constrain OS and architecture are evaluated against the observed Node platforms. Kubescape scans only observed platforms that satisfy the platform expressions in at least one required branch.

## CI recommendations

For an image built for one deployment platform, pass that platform explicitly:

```bash
kubescape scan image "$IMAGE" \
  --platform linux/amd64 \
  --severity-threshold high \
  --format sarif \
  --output kubescape.sarif
```

For manifests deployed to a heterogeneous cluster, let Kubescape infer platforms from the collected Nodes and workload constraints:

```bash
kubescape scan --scan-images --severity-threshold high
```

For offline manifests, use `--image-platform` whenever the manifests do not constrain both OS and architecture:

```bash
kubescape scan ./manifests \
  --scan-images \
  --image-platform linux/arm64 \
  --severity-threshold high
```

## Platform selection reference

The following table summarizes which source wins when more than one source of platform information is available:

| Scan mode | Available information | Selected platform |
|-----------|-----------------------|-------------------|
| `scan image` | `--platform` is set | The explicit platform |
| `scan image` | No platform flag | The image provider default, retained for compatibility |
| `--scan-images` | `--image-platform` is set | The explicit platform for every image |
| `--scan-images` | Scheduled Pod and collected Node | The Node platform |
| `--scan-images` | Exact OS and architecture node selector | The selected platform |
| `--scan-images` | Complete required node affinity | Every platform allowed by the hard constraint |
| `--scan-images` | Partial or negative constraint and collected Nodes | Every observed platform allowed by the constraint |
| `--scan-images` | Offline, platform constraint, no Node inventory | No guessed platform; use `--image-platform` |
| `--scan-images` | Offline, no platform constraint or Node inventory | The image provider default |

The scheduled Node takes precedence over selectors because it records the scheduler's completed decision. An explicit CLI override takes precedence over everything because it is a direct operator instruction.

### What counts as a hard constraint

Kubescape recognizes the stable labels:

```text
kubernetes.io/os
kubernetes.io/arch
```

It also recognizes their deprecated beta forms so older manifests and clusters remain usable:

```text
beta.kubernetes.io/os
beta.kubernetes.io/arch
```

For required node affinity, `operator: In` provides an enumerable set of possible values. `NotIn` is evaluated against platforms observed on collected Nodes, so excluded architectures are not scanned. `Exists`, `DoesNotExist`, `Gt`, and `Lt` do not enumerate an OCI operating system or architecture and therefore do not narrow the observed platform set.

### Reading multi-platform results

A platform suffix is display metadata, not part of the registry reference:

```text
registry.example.com/team/api:v2 [linux/arm64]
```

Kubescape still pulls `registry.example.com/team/api:v2` and passes `linux/arm64` separately to the image provider. This distinction matters for registry credentials, registry mapping, digest parsing, and local archive prefixes. None of those mechanisms receive a modified image name.

Threshold evaluation is performed over every selected variant. If any variant contains a vulnerability at or above `--severity-threshold`, the scan fails. This prevents a clean ARM64 result from hiding a vulnerable amd64 image that the same workload can run.

If two variants contain the same CVE, both scans contribute to summary totals. Human-facing reports show their platform-qualified targets, while machine formats keep the historical image identifier and expose separate platform metadata where their schema supports it.

## Limitations

- Platform selection applies to image vulnerability scanning. It does not change the platform used by `kubescape patch`.
- Local archives and daemon images must contain the requested platform. A mismatch is returned as an error.
- An unconstrained offline manifest has no Node inventory to consult. Without `--image-platform`, the underlying provider default is retained for compatibility.
- Preferred node affinity, taints, tolerations, and topology spread constraints are not platform guarantees and are not used to narrow the scan.

These cases are explicit so a successful platform-specific scan always means Kubescape asked the image provider for that exact variant.
