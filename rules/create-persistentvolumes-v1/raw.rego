# regal ignore:directory-package-mismatch
package armo_builtins
import rego.v1

deny contains msga if {
	verbs := ["create", "*"]
	api_groups := ["", "*"]
	resources := ["persistentvolumes", "*"]
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")
	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)

	# PersistentVolumes are cluster scoped, so only a ClusterRoleBinding carries
	# this grant. A RoleBinding confines the role to one namespace, where a rule
	# about PersistentVolumes matches nothing.
	rolebinding.kind == "ClusterRoleBinding"

	rule := role.rules[p]
	creates_through(rule, subjectVector)
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
		"alertMessage": sprintf("Subject: %s-%s can create arbitrary PersistentVolumes, including hostPath volumes", [subjectVector.kind, subjectVector.name]),
		"alertScore": 7,
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

# A plain create carries no object name when the authorizer runs, and
# ResourceNameMatches compares a non-empty resourceNames list with that empty
# name, so an entry narrowed to real names does not authorize it. Server-side
# apply is the exception: it creates a missing object through a patch, and the
# API server authorizes that create with the object's name, so a narrowed create
# entry still creates the named PersistentVolume when the subject can also patch
# that same name.
creates_through(rule, _) if count(object.get(rule, "resourceNames", [])) == 0

creates_through(rule, _) if "" in rule.resourceNames

# RBAC is additive, so the patch may come from any ClusterRole the same subject
# holds through a ClusterRoleBinding, not only the role that carries the create.
# The aggregator emits one subject vector per binding and role, so the subject's
# other grants are the other vectors of input that describe the same subject.
# PersistentVolumes are cluster scoped, so a RoleBinding contributes nothing.
creates_through(rule, subjectVector) if {
	other := input[_]
	is_same_subjects(subjectVector, other)

	binding := other.relatedObjects[_]
	binding.kind == "ClusterRoleBinding"
	binding.roleRef.kind == "ClusterRole"
	subject := binding.subjects[_]
	is_same_subjects(subjectVector, subject)

	patch_role := other.relatedObjects[_]
	patch_role.kind == "ClusterRole"
	patch_role.metadata.name == binding.roleRef.name

	patch_rule := patch_role.rules[_]
	patch_rule.apiGroups[_] in {"", "*"}
	patch_rule.resources[_] in {"persistentvolumes", "*"}
	patch_rule.verbs[_] in {"patch", "*"}
	names_overlap(rule, patch_rule)
}

# A create and a patch reach a common object when either is not narrowed to
# names, or when both name the same object. The names are literal: RBAC has no
# wildcard form for resourceNames. An empty name is the one a plain create is
# authorized with and is not an object that apply could create, so it never
# counts as the common name.
names_overlap(create_rule, patch_rule) if {
	unnamed(create_rule)
	unnamed(patch_rule)
}

names_overlap(create_rule, patch_rule) if {
	unnamed(create_rule)
	names_an_object(patch_rule)
}

names_overlap(create_rule, patch_rule) if {
	names_an_object(create_rule)
	unnamed(patch_rule)
}

names_overlap(create_rule, patch_rule) if {
	name := create_rule.resourceNames[_]
	name != ""
	name in patch_rule.resourceNames
}

# Kubernetes treats an absent and an empty resourceNames alike: neither narrows.
unnamed(rule) if count(object.get(rule, "resourceNames", [])) == 0

names_an_object(rule) if {
	name := rule.resourceNames[_]
	name != ""
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
