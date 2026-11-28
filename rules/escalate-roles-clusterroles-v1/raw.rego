# regal ignore:directory-package-mismatch
package armo_builtins
import rego.v1

deny contains msga if {
	verbs := ["escalate", "*"]
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

	names_a_role(rule)

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
		"alertMessage": sprintf("Subject: %s-%s can escalate roles/clusterroles beyond their own permissions", [subjectVector.kind, subjectVector.name]),
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

# The escalate check runs when a Role or ClusterRole is created or updated with
# rights the subject does not hold, and it is authorized with the name of the
# role being written. An entry narrowed with resourceNames still lets the
# subject put any rule into each role it names, so if the subject, or a
# workload it controls, is bound to that role, it can grant itself anything.
# resourceNames is matched literally, so "" names no role and "*" is not a
# wildcard. An entry narrowed to those two alone is treated as naming none, as
# the other rules here do.
names_a_role(rule) if count(resource_names(rule)) == 0

names_a_role(rule) if {
	some name in resource_names(rule)
	not name in {"", "*"}
}

# A manifest meant for "kubectl apply -n" may leave out the namespace, and the
# subject aggregator pairs it with either side; comparing the fields would drop it.
is_same_namespace(role, rolebinding) if {
	role.kind == "Role"
	not has_namespace(role)
	not release_namespace(role)
}

is_same_namespace(role, rolebinding) if {
	role.kind == "Role"
	not has_namespace(role)
	not has_namespace(rolebinding)
}

is_same_namespace(role, rolebinding) if {
	role.kind == "Role"
	not has_namespace(role)
	rolebinding.metadata.namespace == release_namespace(role)
}

is_same_namespace(role, rolebinding) if {
	role.kind == "Role"
	not has_namespace(rolebinding)
}

has_namespace(obj) if {
	is_string(obj.metadata.namespace)
	obj.metadata.namespace != ""
}

release_namespace(obj) := ns if {
	is_string(obj.metadata.annotations["meta.helm.sh/release-namespace"])
	obj.metadata.annotations["meta.helm.sh/release-namespace"] != ""
	ns := obj.metadata.annotations["meta.helm.sh/release-namespace"]
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

# A subject can carry neither qualifier. A ServiceAccount subject of a
# RoleBinding may leave out its namespace, which the authorizer then reads as
# the binding's own, and its apiGroup is empty, so the API server returns the
# subject with neither field set. A User or Group manifest may also leave out
# apiGroup, which the API server defaults. Both clauses above need one of the
# fields to be present, so read them with a default here instead.
is_same_subjects(subjectVector, subject) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	object.get(subjectVector, "namespace", "") == object.get(subject, "namespace", "")
	object.get(subjectVector, "apiGroup", "") == object.get(subject, "apiGroup", "")
}

# resource_names is a rule's resourceNames with an absent or null list read as
# the empty list. Kubernetes treats all three alike: ResourceNameMatches matches
# as soon as the list is empty, so the rule is not narrowed to named objects.
# Counting a null list directly is undefined and would drop the rule instead.
resource_names(rule) := names if {
	names := object.get(rule, "resourceNames", [])
	names != null
} else := []
