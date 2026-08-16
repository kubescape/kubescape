# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Creating a CertificateSigningRequest and approving it (update on the
# approval subresource plus approve on signers) lets a subject mint an
# arbitrary client certificate, including one that authenticates as
# cluster-admin. Nodes already hold create/retrieve rights, so only the
# full chain is reported — any missing leg is ordinary and not enough on
# its own. See:
# https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	binds_cluster_scoped(role, rolebinding)

	can_create_and_approve_csrs(role)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	# Verbs and resources are collected across every CSR-related entry in the
	# role rather than within a single one, because RBAC unions the entries:
	# create in one rule and approve in another is the same effective grant.
	verb_path := sort([sprintf("relatedObjects[%d].rules[%d].verbs[%d]", [i, p, l]) |
		some p
		rule := role.rules[p]
		csr_related(rule)
		verb := rule.verbs[l]
		verb in {"create", "get", "list", "watch", "update", "patch", "approve", "*"}
	])

	resources_path := sort([sprintf("relatedObjects[%d].rules[%d].resources[%d]", [i, p, l]) |
		some p
		rule := role.rules[p]
		csr_related(rule)
		resource := rule.resources[l]
		resource in {
			"certificatesigningrequests",
			"certificatesigningrequests/approval",
			"*/approval",
			"signers",
			"*",
		}
	])

	api_groups_path := sort([sprintf("relatedObjects[%d].rules[%d].apiGroups[%d]", [i, p, a]) |
		some p
		rule := role.rules[p]
		csr_related(rule)
		apiGroup := rule.apiGroups[a]
		apiGroup in {"certificates.k8s.io", "*"}
	])

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can create and approve CertificateSigningRequests, and so mint arbitrary client certificates", [subjectVector.kind, subjectVector.name]),
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

# All four legs must be present in the same ClusterRole. Permissions split
# across different role bindings are not correlated here — the same limitation
# accepted by issue-token-secrets-v1.
can_create_and_approve_csrs(role) if {
	can_create_csrs(role)
	can_retrieve_csrs(role)
	can_update_csr_approval(role)
	can_approve_signers(role)
}

# resourceNames does not restrict create: the object has no name at
# authorization time, so Kubernetes ignores the field for this verb. A rule
# carrying resourceNames still creates any CSR.
can_create_csrs(role) if {
	rule := role.rules[_]
	certificates_api_group(rule)
	targets(rule, "certificatesigningrequests")
	verb_or_wildcard(rule.verbs, "create")
}

can_retrieve_csrs(role) if {
	rule := role.rules[_]
	certificates_api_group(rule)
	targets(rule, "certificatesigningrequests")
	rule.verbs[_] in {"get", "list", "watch", "*"}
}

# Admission accepts update or patch on the approval subresource.
# https://github.com/kubernetes/kubernetes/blob/442a69c3bdf6fe8e525b05887e57d89db1e2f3a5/plugin/pkg/admission/certificates/approval/admission.go#L77
can_update_csr_approval(role) if {
	rule := role.rules[_]
	certificates_api_group(rule)
	targets_subresource(rule, "certificatesigningrequests/approval")
	update_patch_or_wildcard(rule.verbs)
}

can_approve_signers(role) if {
	rule := role.rules[_]
	certificates_api_group(rule)
	targets(rule, "signers")
	verb_or_wildcard(rule.verbs, "approve")
}

# An entry contributes to the reported paths when it participates in any leg of
# the chain, so the alert points at every grant that made the subject dangerous.
csr_related(rule) if {
	certificates_api_group(rule)
	targets(rule, "certificatesigningrequests")
	rule.verbs[_] in {"create", "get", "list", "watch", "*"}
}

csr_related(rule) if {
	certificates_api_group(rule)
	targets_subresource(rule, "certificatesigningrequests/approval")
	update_patch_or_wildcard(rule.verbs)
}

csr_related(rule) if {
	certificates_api_group(rule)
	targets(rule, "signers")
	verb_or_wildcard(rule.verbs, "approve")
}

certificates_api_group(rule) if rule.apiGroups[_] in {"certificates.k8s.io", "*"}

targets(rule, resource) if rule.resources[_] in {resource, "*"}

# RBAC has no "certificatesigningrequests/*" form that expands to every
# subresource, so a wildcard reaching a subresource is either a bare "*" or
# "*/<subresource>".
targets_subresource(rule, combined) if rule.resources[_] == combined

targets_subresource(rule, combined) if {
	subresource := split(combined, "/")[1]
	rule.resources[_] == sprintf("*/%s", [subresource])
}

targets_subresource(rule, _) if rule.resources[_] == "*"

verb_or_wildcard(verbs, verb) if verbs[_] in {verb, "*"}

update_patch_or_wildcard(verbs) if verbs[_] in {"update", "patch", "*"}

# CertificateSigningRequests and signers are cluster scoped. A RoleBinding —
# even one that points at a ClusterRole that lists those resources — grants
# nothing over them.
binds_cluster_scoped(role, rolebinding) if {
	role.kind == "ClusterRole"
	rolebinding.kind == "ClusterRoleBinding"

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
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
