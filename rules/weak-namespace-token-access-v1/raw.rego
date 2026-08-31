# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Secrets in an ordinary namespace still hold the tokens of the service accounts
# that live there, and those accounts are routinely granted far more than the
# namespace itself implies. A subject that can read a secret can lift such a
# token, and one that can write secrets can mint a service account token secret
# and read the token back out of it, so either way it ends up acting as an
# identity it was never bound to.
#
# Since v1.24 the API server no longer auto-creates a token secret for every
# service account, but such secrets are still honoured and are still created
# deliberately, and a scan has no view of whether the cluster has any left, so
# read access is reported rather than assumed harmless.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_unprivileged_namespace(role, rolebinding)

	rule := role.rules[p]
	targets_secrets(rule)
	verbs := token_verbs(rule)
	rule.verbs[_] in verbs

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	finalpath := matched_paths(rule, i, j, k, p, {
		"resources": {"secrets", "*"},
		"verbs": verbs,
		"apiGroups": {"", "*"},
	})

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can access secrets in unprivileged namespace %s and so obtain a service account token that may carry broader permissions over the cluster", [subjectVector.kind, subjectVector.name, rolebinding.metadata.namespace]),
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

# A TokenRequest against serviceaccounts/token returns a valid token for the
# named service account without touching a secret at all, which is the same
# outcome by the supported route.
#
# resourceNames is deliberately not consulted here. Unlike a top-level create,
# a create against a subresource carries the name of its parent object, so a
# narrowed entry still authorizes the request; it only decides which service
# account the subject may mint a token for, and minting one at all is the abuse.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_unprivileged_namespace(role, rolebinding)

	rule := role.rules[p]
	core_api_group(rule)
	targets_subresource(rule, "serviceaccounts/token")
	rule.verbs[_] in {"create", "*"}

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	finalpath := matched_paths(rule, i, j, k, p, {
		"resources": {"serviceaccounts/token", "*/token", "*"},
		"verbs": {"create", "*"},
		"apiGroups": {"", "*"},
	})

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can mint service account tokens in unprivileged namespace %s and so act as a service account that may carry broader permissions over the cluster", [subjectVector.kind, subjectVector.name, rolebinding.metadata.namespace]),
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

# The verbs over secrets that hand a subject a token, and which of them survive
# a resourceNames restriction.
#
# get, update and patch address a secret by name, so a narrowed entry still
# authorizes them against the named secret, and that secret may well be a
# service account token secret. list and top-level create carry no object name
# when the authorizer runs, so ResourceNameMatches never matches and a narrowed
# entry authorizes neither; reporting them there would flag a permission the
# subject does not hold.
token_verbs(rule) := {"get", "update", "patch", "*"} if not unrestricted_rule(rule)

token_verbs(rule) := {"get", "list", "create", "update", "patch", "*"} if unrestricted_rule(rule)

targets_secrets(rule) if {
	core_api_group(rule)
	rule.resources[_] in {"secrets", "*"}
}

# RBAC has no "serviceaccounts/*" form, so a wildcard that reaches a subresource
# is either a bare "*" or "*/<subresource>".
targets_subresource(rule, combined) if rule.resources[_] == combined

targets_subresource(rule, combined) if {
	subresource := split(combined, "/")[1]
	rule.resources[_] == sprintf("*/%s", [subresource])
}

targets_subresource(rule, _) if rule.resources[_] == "*"

core_api_group(rule) if rule.apiGroups[_] in {"", "*"}

# Kubernetes draws no distinction between an absent resourceNames and an
# explicitly empty one: ResourceNameMatches returns true as soon as the list is
# empty, so both mean the rule is not narrowed to named objects. Testing
# definedness alone (not rule.resourceNames) would treat resourceNames: [] as
# scoped and skip a subject that in fact holds unrestricted access.
unrestricted_rule(rule) if {
	count(object.get(rule, "resourceNames", [])) == 0
}

# Only RoleBindings outside the privileged namespaces are in scope, the same
# scoping weak-namespace-pod-rce-v1 uses. The two grants left out are the higher
# severity cases that already have rules of their own: a ClusterRoleBinding
# carries the role into every namespace, and a RoleBinding in kube-system reaches
# the control plane's own service accounts, which is what issue-token-secrets-v1
# reports. Namespaces are listed inline because a package level constant would be
# evaluated as a rule response.
#
# What is left is the low severity remainder, an ordinary namespace whose service
# accounts happen to be over-permissioned. create-serviceaccount-token-v1 and
# regolibrary's rule-can-list-get-secrets-v1 also match some of these grants, but
# they are cluster-wide and carry no namespace context, so on their own they
# leave an operator unable to tell this case apart from the critical one.
binds_unprivileged_namespace(role, rolebinding) if {
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)

	rolebinding.kind == "RoleBinding"
	not rolebinding.metadata.namespace in {"kube-system"}
}

matched_paths(rule, i, j, k, p, matches) := finalpath if {
	rule_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		some field, values in matches
		value := rule[field][l]
		value in values
	])

	finalpath := array.concat(rule_paths, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])
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
