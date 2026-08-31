# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Filter returns only the workload resources that could potentially fail this rule
# This is used by Kubescape to calculate the risk score accurately
# We only check Deployments, DaemonSets, and StatefulSets
deny contains msga if {
	workload := input[_]
	workload.kind == "Deployment"
	msga := {
		"alertMessage": "",
		"alertObject": {"k8sApiObjects": [workload]},
	}
}

deny contains msga if {
	workload := input[_]
	workload.kind == "DaemonSet"
	msga := {
		"alertMessage": "",
		"alertObject": {"k8sApiObjects": [workload]},
	}
}

deny contains msga if {
	workload := input[_]
	workload.kind == "StatefulSet"
	msga := {
		"alertMessage": "",
		"alertObject": {"k8sApiObjects": [workload]},
	}
}
