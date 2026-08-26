# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# update/patch on the pod object itself lets a subject rewrite a running pod's
# spec, which yields code execution on pods that already exist in the namespace
deny contains msga if {
	verbs := ["update", "patch", "*"]
	api_groups := ["", "*"]
	resources := ["pods", "*"]

	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_unprivileged_namespace(role, rolebinding)

	rule := role.rules[p]
	unrestricted_rule(rule)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	finalpath := matched_paths(rule, i, j, k, p, verbs, api_groups, resources)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can modify pods in unprivileged namespace %s, gaining code execution on existing pods", [subjectVector.kind, subjectVector.name, rolebinding.metadata.namespace]),
		"alertScore": 5,
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

# creating the pods/exec subresource attaches to a running pod directly
deny contains msga if {
	verbs := ["create", "*"]
	api_groups := ["", "*"]
	resources := ["pods/exec", "pods/*", "*"]

	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_unprivileged_namespace(role, rolebinding)

	rule := role.rules[p]
	unrestricted_rule(rule)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	finalpath := matched_paths(rule, i, j, k, p, verbs, api_groups, resources)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can exec into pods in unprivileged namespace %s", [subjectVector.kind, subjectVector.name, rolebinding.metadata.namespace]),
		"alertScore": 5,
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

# Kubernetes draws no distinction between an absent resourceNames and an
# explicitly empty one: ResourceNameMatches returns true as soon as the list is
# empty, so both mean the rule is not narrowed to named objects. Testing
# definedness alone (not rule.resourceNames) would treat resourceNames: [] as
# scoped and skip a subject that in fact holds unrestricted access.
unrestricted_rule(rule) if {
	count(object.get(rule, "resourceNames", [])) == 0
}

# Only RoleBindings outside the privileged namespaces are in scope here. A
# ClusterRoleBinding grants the role in every namespace, and those grants are
# not yet reported anywhere: modify-privileged-pods-v1 is still an open task in
# #3097, so until it lands cluster-wide and kube-system pod-write rights raise
# no alert from this rule or any other. The clusterrolebinding-clusterwide and
# role-kube-system fixtures assert that gap rather than hide it. Namespaces are
# listed inline because a package level constant would be evaluated as a rule
# response.
binds_unprivileged_namespace(role, rolebinding) if {
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)

	rolebinding.kind == "RoleBinding"
	not rolebinding.metadata.namespace in {"kube-system"}
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
