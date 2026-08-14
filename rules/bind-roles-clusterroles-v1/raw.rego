# regal ignore:directory-package-mismatch
package armo_builtins
import rego.v1

deny contains msga if {
	verbs := ["bind", "*"]
	api_groups := ["rbac.authorization.k8s.io", "*"]
	resources := ["roles", "clusterroles", "*"]
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")
	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)
	rule := role.rules[p]
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)
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
	msga := {
		"alertMessage": sprintf("Subject: %s-%s can bind roles/clusterroles with rights they do not already hold", [subjectVector.kind, subjectVector.name]),
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
