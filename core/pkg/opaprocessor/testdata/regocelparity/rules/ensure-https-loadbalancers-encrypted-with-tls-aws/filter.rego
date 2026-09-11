# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

import data.kubernetes.api.client

deny contains msga if {
	obj := input[_]
	obj.kind == "Service"
	obj.spec.type == "LoadBalancer"
	msga := {"alertObject": {"k8sApiObjects": [obj]}}
}
