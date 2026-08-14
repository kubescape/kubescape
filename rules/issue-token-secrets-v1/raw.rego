# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Write access to secrets in a privileged namespace lets a subject mint a
# ServiceAccount token secret for an admin-equivalent SA and read the token
# back out of it, which is a direct path to cluster admin.
deny contains msga if {
	api_groups := ["", "*"]
	resources := ["secrets", "*"]

	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_privileged_namespace(role, rolebinding)

	rule := role.rules[p]
	can_issue_token_secret(rule)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verb_path := sort([sprintf("%s.verbs[%d]", [rule_path, l]) |
		verb := rule.verbs[l]
		verb in {"create", "get", "update", "patch", "*"}
	])

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

# create + get: create the token secret, then read the minted token back. Needs
# an unnamed rule, since creating a named secret also requires patch.
can_issue_token_secret(rule) if {
	grants_verb(rule, "create")
	grants_verb(rule, "get")
	not rule.resourceNames
}

# create + patch: server side apply reaches the secret even when the rule is
# restricted with resourceNames.
can_issue_token_secret(rule) if {
	grants_verb(rule, "create")
	grants_verb(rule, "patch")
}

# blanket update or patch over unnamed secrets: overwrite an existing secret and
# turn it into a SA token secret. With resourceNames the named secret most
# likely already exists and is not of that type.
can_issue_token_secret(rule) if {
	grants_verb(rule, "update")
	not rule.resourceNames
}

can_issue_token_secret(rule) if {
	grants_verb(rule, "patch")
	not rule.resourceNames
}

grants_verb(rule, verb) if {
	verb in rule.verbs
}

grants_verb(rule, verb) if {
	"*" in rule.verbs
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
