# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	verbs := ["update", "patch", "*"]
	api_groups := ["", "*"]
	resources := ["pods/ephemeralcontainers", "*/ephemeralcontainers", "*"]
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)

	rule := role.rules[p]

	names_a_pod(rule)

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
		"alertMessage": sprintf("Subject: %s-%s can attach ephemeral containers to pods", [subjectVector.kind, subjectVector.name]),
		"alertScore": 8,
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

# Adding an ephemeral container is a request on the pods/ephemeralcontainers
# subresource, which carries the name of its parent pod, so an entry narrowed to
# named pods still lets the subject attach a container to each of those pods.
# The attack needs no arbitrary target: a container in the named pod already
# runs code with that pod's volumes and service account token. resourceNames is
# matched literally, so "*" only names a pod called "*", which no pod can be,
# and "" names no object at all; an entry narrowed to those two alone reaches no
# pod. An omitted, null or empty list is unrestricted.
names_a_pod(rule) if count(resource_names(rule)) == 0

names_a_pod(rule) if {
	some name in resource_names(rule)
	not name in {"", "*"}
}
