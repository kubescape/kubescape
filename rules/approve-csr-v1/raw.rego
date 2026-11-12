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
		csr_evidence(role, rule)
		verb := rule.verbs[l]
		verb in {"create", "get", "list", "watch", "update", "patch", "approve", "*"}
	])

	resources_path := sort([sprintf("relatedObjects[%d].rules[%d].resources[%d]", [i, p, l]) |
		some p
		rule := role.rules[p]
		csr_evidence(role, rule)
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
		csr_evidence(role, rule)
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

# A plain create carries no object name when the authorizer runs, and
# ResourceNameMatches compares a non-empty resourceNames list with that empty
# name, so an entry narrowed to real names does not authorize it at all.
# Server-side apply is the exception: it creates a missing object through a
# patch, and the API server authorizes that create with the object's name, so
# create and patch on CSRs reach a named CSR even when both are narrowed (the
# same route issue-token-secrets-v1 accepts for secrets).
can_create_csrs(role) if plain_create(role)

can_create_csrs(role) if ssa_create(role)

plain_create(role) if {
	rule := role.rules[_]
	csr_create_rule(rule)
	grants_unnamed_requests(rule)
}

# The create and the patch have to reach one common CSR name: create on "a" and
# patch on "b" cannot create either object. Either side may be unrestricted.
ssa_create(role) if {
	create_rule := role.rules[_]
	csr_create_rule(create_rule)
	patch_rule := role.rules[_]
	csr_patch_rule(patch_rule)
	names_overlap(create_rule, patch_rule)
}

csr_create_rule(rule) if {
	certificates_api_group(rule)
	targets(rule, "certificatesigningrequests")
	verb_or_wildcard(rule.verbs, "create")
}

csr_patch_rule(rule) if {
	certificates_api_group(rule)
	targets(rule, "certificatesigningrequests")
	verb_or_wildcard(rule.verbs, "patch")
}

# A create and a patch reach a common object when either is not narrowed to names,
# or when both name the same object. The names are literal: RBAC has no wildcard
# form for resourceNames. An empty name is the one a plain create is authorized
# with and is not an object that apply could create, so it never counts as the
# common name.
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

# An omitted or empty resourceNames list is unrestricted, and "" is the name a
# plain create is authorized with.
grants_unnamed_requests(rule) if unnamed(rule)

grants_unnamed_requests(rule) if "" in rule.resourceNames

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
    dangerous_signer_names(rule)
}

dangerous_signer_names(rule) if {
    not rule.resourceNames
}

dangerous_signer_names(rule) if {
    count(rule.resourceNames) == 0
}

dangerous_signer_names(rule) if {
    signer := rule.resourceNames[_]
    signer in {
        "kubernetes.io/kube-apiserver-client",
        "kubernetes.io/*",
    }
}
# An entry contributes to the reported paths when it participates in any leg of
# the chain, so the alert points at every grant that made the subject dangerous.
csr_evidence(_, rule) if csr_related(rule)

# A patch-only entry is not a leg of its own, but when the create is reached
# through server-side apply it is what enables that create, so it is evidence
# too. With a plain create in the role the patch enables nothing, and a patch
# that shares no name with a create is not part of the chain.
csr_evidence(role, rule) if {
	not plain_create(role)
	csr_patch_rule(rule)
	create_rule := role.rules[_]
	csr_create_rule(create_rule)
	names_overlap(create_rule, rule)
}

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
