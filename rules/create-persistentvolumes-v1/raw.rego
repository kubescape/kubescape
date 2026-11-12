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
	creates_through(rule, role)
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
# API server authorizes that create with the object's name, so the narrowed
# entry still creates the named PersistentVolume when the role can also patch
# PersistentVolumes.
creates_through(rule, _) if count(object.get(rule, "resourceNames", [])) == 0

creates_through(rule, _) if "" in rule.resourceNames

creates_through(_, role) if {
	patch_rule := role.rules[_]
	patch_rule.apiGroups[_] in {"", "*"}
	patch_rule.resources[_] in {"persistentvolumes", "*"}
	patch_rule.verbs[_] in {"patch", "*"}
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
