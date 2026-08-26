# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if namespace does not have restricted pod security admission label
deny contains msga if {
	namespace := input[_]
	namespace.kind == "Namespace"
	not restricted_admission_policy_enabled(namespace)

	msga := {
		"alertMessage": sprintf("Namespace: %v does not enable restricted pod security admission", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}

restricted_admission_policy_enabled(namespace) if {
	namespace.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"
}
