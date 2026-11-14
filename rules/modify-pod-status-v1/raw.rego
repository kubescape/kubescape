# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# A subject that can write a pod's status subresource can also change that
# pod's labels: the API server's status strategy restores spec on an update to
# pods/status, but it leaves metadata alone. Service selectors match on labels,
# so the grant lets a subject relabel a pod it controls until it matches a
# service's selector, at which point the endpoints controller adds it as a
# backend and the service starts routing traffic to it. That intercepts
# connections to services in the pod's namespace.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	pairs_with(role, rolebinding)

	rule := role.rules[p]
	modifies_pod_status(rule)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		some field, values in {
			"resources": {"pods/status", "*/status", "*"},
			"verbs": {"update", "patch", "*"},
			"apiGroups": {"", "*"},
		}
		value := rule[field][l]
		value in values
	])

	finalpath := array.concat(rule_paths, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can modify pods/status and so relabel a pod to match a service's selector, intercepting connections to services in the pod's namespace", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
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

# resourceNames is not required to be empty: narrowing the grant to named
# pods still allows rewriting the status of the named pod. However, an
# entry naming only "" or "*" admits no object, because requests on existing
# objects carry their real name, "" is never that name, and resourceNames has no
# wildcard. An omitted, null, or empty resourceNames list is unrestricted.
modifies_pod_status(rule) if {
	core_api_group(rule)
	targets_subresource(rule, "pods/status")
	update_patch_or_wildcard(rule.verbs)
	admits_objects(rule)
}

# An omitted, null, or empty resourceNames list is unrestricted.
admits_objects(rule) if object.get(rule, "resourceNames", null) == null

admits_objects(rule) if {
	names := rule.resourceNames
	names != null
	count(names) == 0
}

admits_objects(rule) if {
	names := rule.resourceNames
	names != null
	some name in names
	not name in {"", "*"}
}

# RBAC has no "pods/*" form, so a wildcard that reaches a subresource is
# either a bare "*" or "*/<subresource>".
targets_subresource(rule, combined) if rule.resources[_] == combined

targets_subresource(rule, combined) if {
	subresource := split(combined, "/")[1]
	rule.resources[_] == sprintf("*/%s", [subresource])
}

targets_subresource(rule, _) if rule.resources[_] == "*"

core_api_group(rule) if rule.apiGroups[_] in {"", "*"}

update_patch_or_wildcard(verbs) if verbs[_] in {"update", "patch", "*"}

pairs_with(role, rolebinding) if {
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)
}

is_same_namespace(role, _) if {
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
