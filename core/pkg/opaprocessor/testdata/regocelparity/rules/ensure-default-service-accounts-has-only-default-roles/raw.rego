# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# deny if a default ServiceAccount has rules bound to it that are not defaults.
deny contains msga if {
	spec_template_spec_patterns := {"RoleBinding", "ClusterRoleBinding"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]

	# filter service accounts
	wl.subjects[i].kind == "ServiceAccount"

	# filter defaults
	wl.subjects[i].name == "default"

	not wl.metadata.labels["kubernetes.io/bootstrapping"] == "rbac-defaults"

	msga := {
		"alertMessage": sprintf("%s: %v has for ServiceAccount 'default' rules bound to it that are not defaults", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [sprintf("subjects[%d]", [i])],
		"failedPaths": [sprintf("subjects[%d]", [i])],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
