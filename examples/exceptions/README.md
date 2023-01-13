# Kubescape Exceptions

Kubescape Exceptions is the proper way of excluding failed resources from affecting the risk score.

e.g. When a `kube-system` resource fails and it is ok, simply add the resource to the exceptions configurations.

## Definitions


* `name`- Exception name - unique name representing the exception
* `policyType`- Do not change
* `actions`- List of available actions. Currently, alertOnly is supported
* `resources`- List of resources to apply this exception on
    * `designatorType: Attributes`- An attribute-based declaration {key: value}
    Supported keys:
    * `name`: k8s resource name (case-sensitive, regex supported)
    * `kind`: k8s resource kind (case-sensitive, regex supported)
    * `namespace`: k8s resource namespace (case-sensitive, regex supported)
    * `cluster`: k8s cluster name (usually it is the `current-context`) (case-sensitive, regex supported)
    * resource labels as key value (case-sensitive, regex NOT supported)
* `posturePolicies`- An attribute-based declaration {key: value}
    * `frameworkName` - Framework names can be found [here](https://github.com/armosec/regolibrary/tree/master/frameworks) (regex supported)
    * `controlName` - Control names can be found [here](https://github.com/armosec/regolibrary/tree/master/controls) (regex supported)
    * `controlID` - Control ID can be found [here](https://github.com/armosec/regolibrary/tree/master/controls) (regex supported)
    * `ruleName` - Rule names can be found [here](https://github.com/armosec/regolibrary/tree/master/rules) (regex supported)
 
You can find [here](https://github.com/kubescape/kubescape/tree/master/examples/exceptions) some examples of exceptions files

## Usage

The `resources` list and `posturePolicies` list are designed to be a combination of the resources and policies to exclude.

> **Warning** 
> You must declare at least one resource and one policy.

e.g. If you wish to exclude all namespaces with the label `"environment": "dev"`, the resource list should look as follows:
```
"resources": [
    {
        "designatorType": "Attributes",
        "attributes": {
            "namespace": ".*",
            "environment": "dev"
        }
    }
]
```

But if you wish to exclude all namespaces **OR** any resource with the label `"environment": "dev"`, the resource list should look as follows:
```
"resources": [
    {
        "designatorType": "Attributes",
        "attributes": {
            "namespace": ".*"
        }
    },
    {
        "designatorType": "Attributes",
        "attributes": {
            "environment": "dev"
        }
    }
]
```

Same works with the `posturePolicies` list ->

e.g. If you wish to exclude the resources declared in the `resources` list that failed when scanning the `NSA` framework **AND** failed the `HostPath mount` control, the `posturePolicies` list should look as follows:
```
"posturePolicies": [
    {
        "frameworkName": "NSA",
        "controlName": "HostPath mount" 
    }
]
```

But if you wish to exclude the resources declared in the `resources` list that failed when scanning the `NSA` framework **OR** failed the `HostPath mount` control, the `posturePolicies` list should look as follows:
```
"posturePolicies": [
    {
        "frameworkName": "NSA" 
    },
    {
        "controlName": "HostPath mount" 
    }
]
```

## Examples

Here are some examples demonstrating the different ways the exceptions file can be configured


### Exclude  control

Exclude the [C-0060 control](https://github.com/armosec/regolibrary/blob/master/controls/allowedhostpath.json#L2) by declaring the control ID in the `"posturePolicies"` section.

The resources

```
[
    {
        "name": "exclude-allowed-hostPath-control",
        "policyType": "postureExceptionPolicy",
        "actions": [
            "alertOnly"
        ],
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
                "controlID": "C-0060" 
            }
        ]
    }
]
```

### Exclude deployments in the default namespace that failed the "HostPath mount" control 
```
[
    {
        "name": "exclude-deployments-in-ns-default",
        "policyType": "postureExceptionPolicy",
        "actions": [
            "alertOnly"
        ],
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

### Exclude resources with label "app=nginx" running in a minikube cluster that failed the "NSA" or "MITRE" framework 
```
[
    {
        "name": "exclude-nginx-minikube",
        "policyType": "postureExceptionPolicy",
        "actions": [
            "alertOnly"
        ],
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
                "frameworkName": "NSA" 
            },
            {
                "frameworkName": "MITRE" 
            }
        ]
    }
]
```
