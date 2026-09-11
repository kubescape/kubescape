# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if namespace does not have baseline pod security admission label
deny contains msga if {
	namespace := input[_]
	namespace.kind == "Namespace"
	not baseline_admission_policy_enabled(namespace)

	msga := {
		"alertMessage": sprintf("Namespace: %v does not enable baseline pod security admission", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}

baseline_admission_policy_enabled(namespace) if {
	namespace.metadata.labels["pod-security.kubernetes.io/enforce"] in ["baseline", "restricted"]
}
