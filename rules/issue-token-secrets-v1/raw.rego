# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Write access to secrets in a privileged namespace lets a subject mint a
# ServiceAccount token secret for an admin-equivalent SA and read the token
# back out of it, which is a direct path to cluster admin.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_privileged_namespace(role, rolebinding)

	can_issue_token_secret(role)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	# Verbs are evaluated across every secret-granting entry in the role rather
	# than within a single one, because RBAC unions the entries: 'create' in one
	# entry and 'get' in another is the same effective permission as both in one.
	# The reported paths therefore span all contributing entries.
	verb_path := sort([sprintf("relatedObjects[%d].rules[%d].verbs[%d]", [i, p, l]) |
		some p
		rule := role.rules[p]
		targets_secrets(rule)
		verb := rule.verbs[l]
		verb in {"create", "get", "update", "patch", "*"}
	])

	resources_path := sort([sprintf("relatedObjects[%d].rules[%d].resources[%d]", [i, p, l]) |
		some p
		rule := role.rules[p]
		targets_secrets(rule)
		resource := rule.resources[l]
		resource in {"secrets", "*"}
	])

	api_groups_path := sort([sprintf("relatedObjects[%d].rules[%d].apiGroups[%d]", [i, p, a]) |
		some p
		rule := role.rules[p]
		targets_secrets(rule)
		apiGroup := rule.apiGroups[a]
		apiGroup in {"", "*"}
	])

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can write secrets in privileged namespaces and issue service account tokens", [subjectVector.kind, subjectVector.name]),
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

# Only the verb bundles that actually yield a usable token are reported, so that
# a lone 'create' or a read-only grant does not raise an alert.

# create + get: create the token secret, then read the minted token back.
# RBAC cannot authorize a top-level create through an entry carrying
# resourceNames (the object name is unknown at authorization time), so the
# create has to come from an unrestricted entry. The get may be name restricted
# — the subject simply creates the secret under that name and reads it back.
can_issue_token_secret(role) if {
	grants_unrestricted(role, "create")
	grants(role, "get")
}

# create + patch: server side apply can bring the secret into existence even
# when every entry is restricted with resourceNames, which is what makes a named
# create reachable at all.
can_issue_token_secret(role) if {
	grants(role, "create")
	grants(role, "patch")
}

# blanket update or patch over unnamed secrets: overwrite an existing secret and
# turn it into a SA token secret. With resourceNames the named secret most
# likely already exists and is not of that type.
can_issue_token_secret(role) if {
	grants_unrestricted(role, "update")
}

can_issue_token_secret(role) if {
	grants_unrestricted(role, "patch")
}

# true if any entry in the role grants @verb over secrets
grants(role, verb) if {
	rule := role.rules[_]
	targets_secrets(rule)
	rule.verbs[_] in {verb, "*"}
}

# as above, but only from entries that are not narrowed with resourceNames
grants_unrestricted(role, verb) if {
	rule := role.rules[_]
	targets_secrets(rule)
	unrestricted_rule(rule)
	rule.verbs[_] in {verb, "*"}
}

# Kubernetes draws no distinction between an absent resourceNames and an
# explicitly empty one: ResourceNameMatches returns true as soon as the list is
# empty, so both mean the rule is not narrowed to named objects. Testing
# definedness alone (not rule.resourceNames) would treat resourceNames: [] as
# scoped and skip a subject that in fact holds unrestricted access.
unrestricted_rule(rule) if {
	count(object.get(rule, "resourceNames", [])) == 0
}

targets_secrets(rule) if {
	rule.resources[_] in {"secrets", "*"}
	rule.apiGroups[_] in {"", "*"}
}

# A ClusterRoleBinding grants the role in every namespace, a RoleBinding only in
# its own.
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
	rolebinding.metadata.namespace == "kube-system"
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
