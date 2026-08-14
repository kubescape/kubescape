# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# creating a pod in a privileged namespace lets the subject set
# spec.serviceAccountName to any SA in that namespace and inherit its token
deny contains msga if {
	verbs := ["create", "*"]
	api_groups := ["", "*"]
	resources := ["pods", "*"]

	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_privileged_namespace(role, rolebinding)

	rule := role.rules[p]
	not rule.resourceNames

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	finalpath := matched_paths(rule, i, j, k, p, verbs, api_groups, resources)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can create pods in privileged namespaces and assign them any service account", [subjectVector.kind, subjectVector.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# writing a pod controller in a privileged namespace reaches the same pod
# template indirectly, so it grants the same service account assignment
deny contains msga if {
	verbs := ["create", "update", "patch", "*"]

	# each API group is paired with the pod controllers it actually owns, so a
	# rule such as apiGroups:[apps] + resources:[cronjobs] is not matched
	controller := [
		{"api_groups": ["batch", "*"], "resources": ["cronjobs", "jobs", "*"]},
		{"api_groups": ["apps", "*"], "resources": ["daemonsets", "statefulsets", "deployments", "replicasets", "*"]},
		{"api_groups": ["", "*"], "resources": ["replicationcontrollers", "*"]},
	][_]

	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_privileged_namespace(role, rolebinding)

	rule := role.rules[p]
	not rule.resourceNames

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	finalpath := matched_paths(rule, i, j, k, p, verbs, controller.api_groups, controller.resources)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can control pod templates in privileged namespaces and assign them any service account", [subjectVector.kind, subjectVector.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# A ClusterRoleBinding grants the role in every namespace, a RoleBinding only in
# its own. Namespaces are listed inline because a package level constant would
# be evaluated as a rule response.
binds_privileged_namespace(role, rolebinding) if {
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)

	affects_privileged_namespace(rolebinding)
}

affects_privileged_namespace(rolebinding) if {
	rolebinding.kind == "ClusterRoleBinding"
}

affects_privileged_namespace(rolebinding) if {
	rolebinding.kind == "RoleBinding"
	rolebinding.metadata.namespace in {"kube-system"}
}

matched_paths(rule, i, j, k, p, verbs, api_groups, resources) := finalpath if {
	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) | verb = rule.verbs[l]; verb in verbs]
	count(verb_path) > 0

	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) | apiGroup = rule.apiGroups[a]; apiGroup in api_groups]
	count(api_groups_path) > 0

	resources_path := [sprintf("%s.resources[%d]", [rule_path, l]) | resource = rule.resources[l]; resource in resources]
	count(resources_path) > 0

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])
}

is_same_namespace(role, rolebinding) if {
	role.kind == "ClusterRole"
}

is_same_namespace(role, rolebinding) if {
	role.kind == "Role"
	role.metadata.namespace == rolebinding.metadata.namespace
}

is_same_subjects(subjectVector, subject) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}

is_same_subjects(subjectVector, subject) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.apiGroup == subject.apiGroup
}
