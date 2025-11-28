# Kubescape Exceptions

Kubescape Exceptions allow you to exclude specific resources from affecting your security risk score. This is useful when certain resources intentionally deviate from security best practices and you want to acknowledge this without impacting your overall compliance metrics.

## Table of Contents

- [Use Cases](#use-cases)
- [Exception Structure](#exception-structure)
- [Usage](#usage)
- [Examples](#examples)
- [Related Documentation](#related-documentation)

---

## Use Cases

- Exclude `kube-system` resources that are expected to have elevated privileges
- Ignore development/test namespaces from production compliance reports
- Accept known risks for specific workloads after security review
- Temporarily exclude resources while fixes are being implemented

---

## Exception Structure

An exception file is a JSON array containing one or more exception objects:

```json
[
    {
        "name": "exception-name",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [...],
        "posturePolicies": [...]
    }
]
```

### Fields

| Field | Description |
|-------|-------------|
| `name` | Unique name for this exception |
| `policyType` | Must be `"postureExceptionPolicy"` |
| `actions` | List of actions. Currently only `"alertOnly"` is supported |
| `resources` | List of resources to apply this exception to |
| `posturePolicies` | List of policies/controls to exclude |

### Resource Attributes

Resources are defined using attribute-based selectors. Supported attributes:

| Attribute | Description | Regex Support |
|-----------|-------------|---------------|
| `name` | Kubernetes resource name | ✅ Yes |
| `kind` | Kubernetes resource kind (e.g., `Deployment`, `Pod`) | ✅ Yes |
| `namespace` | Kubernetes namespace | ✅ Yes |
| `cluster` | Cluster name (usually the `current-context`) | ✅ Yes |
| `<label-key>` | Any resource label (e.g., `app`, `environment`) | ❌ No |

### Policy Attributes

Policies can be specified by:

| Attribute | Description | Regex Support |
|-----------|-------------|---------------|
| `frameworkName` | Framework name (e.g., `NSA`, `MITRE`) | ✅ Yes |
| `controlName` | Control name (e.g., `HostPath mount`) | ✅ Yes |
| `controlID` | Control ID (e.g., `C-0048`) | ✅ Yes |

Find framework names in the [frameworks directory](https://github.com/kubescape/regolibrary/tree/master/frameworks) and control information in the [controls directory](https://github.com/kubescape/regolibrary/tree/master/controls).

---

## Usage

### Running a Scan with Exceptions

```bash
kubescape scan --exceptions /path/to/exceptions.json
```

Resources matching exceptions will be marked as `excluded` rather than `failed` in the results.

### Logic Rules

> ⚠️ **Important**: You must declare at least one resource AND one policy in each exception.

#### Within a list: OR logic

Multiple items in the `resources` list are evaluated with **OR** logic:

```json
"resources": [
    { "attributes": { "namespace": "dev" } },
    { "attributes": { "namespace": "test" } }
]
```
This matches resources in the `dev` namespace **OR** the `test` namespace.

#### Within an object: AND logic

Multiple attributes in a single object are evaluated with **AND** logic:

```json
"resources": [
    { "attributes": { "namespace": "production", "kind": "Deployment" } }
]
```
This matches only `Deployment` resources **AND** in the `production` namespace.

---

## Examples

### Exclude a Specific Control Everywhere

Exclude control [C-0048 (HostPath mount)](https://kubescape.io/docs/controls/c-0048/) for all resources:

```json
[
    {
        "name": "exclude-hostpath-control",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "kind": ".*"
                }
            }
        ],
        "posturePolicies": [
            {
                "controlID": "C-0048"
            }
        ]
    }
]
```

### Exclude All kube-system Resources

Exclude all resources in the `kube-system` namespace from all frameworks:

```json
[
    {
        "name": "exclude-kube-system",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "namespace": "kube-system"
                }
            }
        ],
        "posturePolicies": [
            {
                "frameworkName": ".*"
            }
        ]
    }
]
```

### Exclude Deployments in Default Namespace for a Specific Control

```json
[
    {
        "name": "exclude-deployments-in-default",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "namespace": "default",
                    "kind": "Deployment"
                }
            }
        ],
        "posturePolicies": [
            {
                "controlName": "HostPath mount"
            }
        ]
    }
]
```

### Exclude Resources by Label

Exclude resources with label `environment=dev` from NSA and MITRE frameworks:

```json
[
    {
        "name": "exclude-dev-environment",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "environment": "dev"
                }
            }
        ],
        "posturePolicies": [
            {
                "frameworkName": "NSA"
            },
            {
                "frameworkName": "MITRE"
            }
        ]
    }
]
```

### Exclude Specific Workload in Specific Cluster

Exclude nginx resources in a minikube cluster:

```json
[
    {
        "name": "exclude-nginx-minikube",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "cluster": "minikube",
                    "app": "nginx"
                }
            }
        ],
        "posturePolicies": [
            {
                "frameworkName": ".*"
            }
        ]
    }
]
```

### Multiple Exceptions in One File

You can combine multiple exceptions in a single file:

```json
[
    {
        "name": "exclude-kube-namespaces",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "namespace": "kube-system"
                }
            },
            {
                "designatorType": "Attributes",
                "attributes": {
                    "namespace": "kube-public"
                }
            }
        ],
        "posturePolicies": [
            {
                "frameworkName": ".*"
            }
        ]
    },
    {
        "name": "exclude-privileged-control-for-monitoring",
        "policyType": "postureExceptionPolicy",
        "actions": ["alertOnly"],
        "resources": [
            {
                "designatorType": "Attributes",
                "attributes": {
                    "namespace": "monitoring"
                }
            }
        ],
        "posturePolicies": [
            {
                "controlID": "C-0057"
            }
        ]
    }
]
```

---

## Related Documentation

- [Getting Started Guide](../../docs/getting-started.md)
- [CLI Reference](../../docs/cli-reference.md)
- [Controls Reference](https://kubescape.io/docs/controls/)
- [Regolibrary - Frameworks](https://github.com/kubescape/regolibrary/tree/master/frameworks)
- [Regolibrary - Controls](https://github.com/kubescape/regolibrary/tree/master/controls)
- [Accepting Risk Documentation](https://kubescape.io/docs/accepting-risk/)