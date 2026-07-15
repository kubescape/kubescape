# Scanning ICS/OT Workloads

This guide explains how to use Kubescape to scan Industrial Control System (ICS) and Operational Technology (OT) workloads running on Kubernetes. It targets OT security engineers running containerized SCADA components, PLC protocol bridges, and OPC-UA servers where standard Kubernetes hardening controls frequently conflict with Layer-1 protocol requirements.

## Prerequisites

- The `kubescape` CLI installed
- The example manifests under `examples/ics-ot/` in this repository
- (Optional) A kubeconfig pointing at a target cluster. No cluster is required for the walkthrough because the scan target is a manifest file. `--keep-local` additionally prevents results from being sent to the configured backend
- (Optional) `jq` for slicing the JSON output

## How It Works

Kubescape evaluates Kubernetes manifests against controls from the NSA, MITRE, and CIS frameworks. In OT namespaces, the same controls that flag misconfigurations in cloud-native workloads also flag legitimate OT deviations such as `hostNetwork: true` for Modbus bridges or `privileged: true` for vendor SCADA containers. This guide walks through scanning two example OT workloads, then shows how to scope an exception for a documented deviation without muting other findings.

## Common ICS/OT Protocols and Ports

| Protocol | Default port | Transport | Typical use |
|----------|--------------|-----------|-------------|
| Modbus TCP | 502 | TCP | PLC read/write, HMI polling |
| DNP3 | 20000 | TCP | SCADA to RTU communication |
| OPC-UA | 4840 | TCP | Vendor-neutral SCADA data exchange |
| S7Comm | 102 | TCP | Siemens S7 PLC programming and data |
| EtherNet/IP | 44818 | TCP/UDP | Rockwell/Allen-Bradley PLCs |
| BACnet | 47808 | UDP | Building automation |
| IEC 60870-5-104 | 2404 | TCP | Power system telecontrol |

Several of these protocols (Modbus, S7Comm, BACnet) lack authentication at the protocol layer and rely on network segmentation for isolation, which is why Kubescape findings on `hostNetwork`, `hostPort`, and `NET_ADMIN` capability additions matter disproportionately in OT namespaces.

## Kubescape Controls Relevant to ICS/OT

The controls below are the ones most commonly triggered by legitimate OT workloads. Control names are quoted from the vendored ValidatingAdmissionPolicy bundle at `core/pkg/opaprocessor/cel/vapdata/kubescape-validating-admission-policies.yaml`.

| Control ID | Control name | OT relevance |
|------------|--------------|--------------|
| C-0016 | Allow privilege escalation | Vendor containers with setuid helpers to bind privileged ports |
| C-0038 | Deny resources with host IPC or PID privileges | COM/DCOM bridges that mirror host process state |
| C-0041 | Deny resources with host network access | Modbus/DNP3 bridges that require direct fieldbus reachability |
| C-0044 | Deny resources with host port | Legacy HMIs that connect to a well-known TCP/502 |
| C-0046 | Deny resources with insecure capabilities | Multicast discovery, raw-socket protocol bridges |
| C-0048 | Deny workloads with hostpath mounts | USB-to-RS-485 adapters, PLC tag databases |
| C-0057 | Privileged container denied | Vendor SCADA containers requiring `/dev/mem` access |
| C-0074 | Resources mounting docker socket denied | Edge nodes that bootstrap sibling OT containers |

## Scanning an ICS/OT Workload

The example manifest at `examples/ics-ot/modbus-deployment.yaml` defines a Modbus TCP controller in the `ot-modbus` namespace. It deliberately violates C-0041 (`hostNetwork: true`), C-0044 (`hostPort: 502`), C-0048 (`hostPath` mount for `/dev/ttyUSB0`), and C-0057 (`privileged: true`).

Scan it directly from the manifest file with `--keep-local` so no cluster connection is required:

```bash
kubescape scan --keep-local examples/ics-ot/modbus-deployment.yaml --format json --output /tmp/modbus-scan.json
```

The pretty-printer output groups failed controls by resource. For the Modbus example, the table includes rows for `HostNetwork access` (C-0041), `HostPath mount` (C-0048), `Privileged container` (C-0057), and several additional controls that fire on the same manifest (non-root user, default service account, host port, and others). The exact set depends on the framework bundle currently in use; pass `--format json` for an authoritative list.

To scan both example manifests together:

```bash
kubescape scan --keep-local examples/ics-ot/ --format json --output /tmp/ot-scan.json
```

The OPC-UA manifest at `examples/ics-ot/opcua-deployment.yaml` triggers C-0057 (`privileged: true`), C-0016 (`allowPrivilegeEscalation: true`), C-0038 (`hostPID: true`), and C-0046 (`CAP_NET_ADMIN` added), plus the same set of secondary findings.

### Filtering the JSON output

The JSON output nests control results under `results[].controls[]`, with the per-control status at `status.status`. To extract a flat list of failed controls:

```bash
jq -r '.results[].controls[] | select(.status.status=="failed") | "\(.controlID) \(.name)"' \
  /tmp/ot-scan.json | sort -u
```

### Severity thresholds in CI

For OT pipelines, a common pattern is to fail the build only on `critical` or `high` severity findings and surface lower-severity findings as informational. Use `--severity-threshold` for this:

```bash
kubescape scan --keep-local examples/ics-ot/ \
  --severity-threshold high --format junit --output /tmp/ot-scan-junit.xml
```

## Applying Exceptions for Legitimate OT Use Cases

When a finding represents a documented and risk-accepted OT deviation, suppress it with a scoped exception rather than a global disable. The exception file at `examples/exceptions/ics-ot-exceptions.json` targets C-0041 (`hostNetwork`) for resources labeled `sector: ics-ot`:

```json
[
    {
        "name": "exclude-ot-sector-host-network",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": { "sector": "ics-ot" }
            }
        ],
        "posturePolicies": [
            { "controlID": "C-0041" }
        ]
    }
]
```

Re-scan with the exception applied:

```bash
kubescape scan --keep-local examples/ics-ot/ \
  --exceptions examples/exceptions/ics-ot-exceptions.json \
  --format json --output /tmp/ot-scan-exc.json
```

The C-0041 finding against `modbus-controller` moves out of the failed set (it appears as `passed` with `subStatus: w/exceptions` in the JSON). The other findings (C-0044, C-0048, C-0057 on the Modbus controller; C-0016, C-0038, C-0046, C-0057 on the OPC-UA server) remain in `failed` state because they are not covered by the exception. Scope exceptions narrowly so that genuinely new misconfigurations still surface.

## Network Policies for OT Namespaces

Suppressing a Kubescape finding does not remove the underlying risk, it only acknowledges it. For every OT exception, document a compensating control. The most common compensating control in OT namespaces is a NetworkPolicy that restricts which pods may open a session to the protocol port.

The following pattern works for Modbus controllers: default-deny all ingress to the `ot-modbus` namespace, then allow TCP/502 only from the HMI namespace.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: ot-modbus
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-modbus-from-hmi
  namespace: ot-modbus
spec:
  podSelector:
    matchLabels:
      app: modbus-controller
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              sector: ics-ot-hmi
      ports:
        - protocol: TCP
          port: 502
```

Kubescape does not enforce NetworkPolicies, it only inspects them. Maintaining a one-exception-one-policy mapping makes it possible to answer an auditor's question (what stops an attacker in the HMI namespace from reaching the SIS) with a pointer to a single named resource.

A second, often-overlooked pattern is to default-deny egress from OT namespaces as well. Vendor containers frequently phone home to vendor update endpoints; an explicit egress allowlist keeps that traffic on a known path and prevents a compromised OT container from becoming a beacon host.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: ot-modbus
spec:
  podSelector: {}
  policyTypes: [Egress]
```

In a plant-network deployment, combine this with upstream firewall rules at the OT/IT boundary so that the egress allowlist is enforced at both the Kubernetes layer and the L3 boundary layer.

## Framework Mappings

NIST SP 800-82 Rev. 3 and IEC 62443-4-2 both acknowledge that OT systems have legitimate deviations from IT hardening baselines, as long as those deviations are documented, scoped, and compensated for with network segmentation. The Kubescape controls listed above map most naturally to the network integrity and least-functionality families of those frameworks (PR.AC-5 and PR.PT-3 in 800-82 r3; SR 5.1, SR 5.2, and SR 7.6 in 62443-4-2). Treat these as "maps to" relationships rather than one-to-one equivalences. Always confirm the identifiers against the current source publication before including them in a compliance report; Kubescape findings are an input to the protective-requirement analysis, not a substitute for it.

## Troubleshooting

### Scan returns zero findings on an OT pod

Confirm the pod's namespace and labels match what Kubescape evaluates. If the namespace is in a `kube-system`-style exception file passed via `--exceptions`, all findings for that namespace are suppressed. Run the scan without `--exceptions` to confirm the findings exist in the raw output, then layer the exception file back in.

### C-0041 is suppressed for workloads outside the OT namespace

The exception file uses attribute-based selectors. If the `sector: ics-ot` label has been applied to non-OT workloads, those workloads will also be matched. Audit labels with `kubectl get pods -A -l sector=ics-ot -o wide` and remove misapplied labels before re-scanning.

### Exception file is silently ignored

Kubescape requires both a `resources` entry and a `posturePolicies` entry in each exception object. A file containing only `posturePolicies` will not match any resources and will produce no `excluded` rows. Validate the JSON syntax (`python3 -m json.tool examples/exceptions/ics-ot-exceptions.json`) and confirm that the `designatorType` is `Attributes` and that the attribute keys match either a Kubernetes resource label or a built-in field (`name`, `kind`, `namespace`, `cluster`).

### `kubescape scan` fails with "failed to download policies"

The first scan in an environment requires outbound HTTPS to download the regolibrary frameworks. Air-gapped environments must pre-populate the local cache or use the `--use-from` flag to point at a pre-downloaded bundle. See `docs/getting-started.md` for the offline workflow.

### The JSON output shows `status: passed` for an obviously violated control

Some controls require a cluster-side admission webhook to fully evaluate. The `--keep-local` scan evaluates the manifest against the static rule set, which may not catch every condition. For authoritative results, scan against a live cluster with a kubeconfig that has read access to the target namespaces.

## Further Reading

- [NIST SP 800-82 Rev. 3, Guide to Operational Technology (OT) Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [IEC 62443-4-2, Security for industrial automation and control systems](https://www.iec.ch/dyn/www/f?p=103:7:0::::FSP_ORG_ID:1257)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [Kubescape documentation hub](https://kubescape.io/docs/)
- [Kubescape controls reference](https://kubescape.io/docs/controls/)
- [Kubescape exceptions guide](../examples/exceptions/README.md)
- [Azure Pipelines integration](azure-pipelines.md)
