# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# The API server sends every request that matches a webhook configuration's
# rules to the endpoint in its clientConfig. A subject that can write a
# MutatingWebhookConfiguration can point one at a server it controls and
# rewrite any object it admits, for example adding a privileged container or
# a hostPath mount to every new pod, or a different ServiceAccount. A
# ValidatingWebhookConfiguration receives the same requests, so it can read
# every Secret and other object submitted to the cluster, and deleting one
# switches off the policy engine (Gatekeeper, Kyverno and the like) that
# would otherwise reject a privileged workload.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	pairs_with(role, rolebinding)

	rule := role.rules[p]
	modifies_admission_webhooks(rule, rolebinding)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	granting_verbs := effective_verbs(rule)
	rule_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		some field, values in {
			"resources": {"validatingwebhookconfigurations", "mutatingwebhookconfigurations", "*"},
			"verbs": granting_verbs,
			"apiGroups": {"admissionregistration.k8s.io", "*"},
		}
		value := rule[field][l]
		value in values
	])

	finalpath := array.concat(rule_paths, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can create, modify or delete admission webhook configurations, and so read or mutate any object admitted to the cluster or switch off admission policy", [subjectVector.kind, subjectVector.name]),
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

# Webhook configurations are cluster scoped, so only a ClusterRoleBinding
# carries this grant. A RoleBinding confines the role to one namespace, where
# a rule about them matches nothing.
modifies_admission_webhooks(rule, rolebinding) if {
	rolebinding.kind == "ClusterRoleBinding"
	rule.apiGroups[_] in {"admissionregistration.k8s.io", "*"}
	rule.resources[_] in {"validatingwebhookconfigurations", "mutatingwebhookconfigurations", "*"}
	count(effective_verbs(rule)) > 0
}

# effective_verbs is the set of the rule's verbs that write webhook
# configurations, given its resourceNames. The authorizer matches
# resourceNames literally against the name in the request:
#
# - create and deletecollection name no object, so they are compared with
#   the empty string. A rule restricted to real names grants neither.
# - update, patch and delete name an existing configuration, so a rule
#   restricted to it still grants them. That is enough for the attack: the
#   subject rewrites the named configuration's rules and clientConfig to send
#   any request to its own server. "" and "*" are not valid object names, and
#   resourceNames has no wildcard, so a rule naming only those grants none of
#   these verbs.
#
# An omitted or empty resourceNames list is unrestricted.
effective_verbs(rule) := {verb |
	some verb in rule.verbs
	verb in {"create", "deletecollection", "*"}
	grants_unnamed_requests(rule)
} | {verb |
	some verb in rule.verbs
	verb in {"update", "patch", "delete", "*"}
	grants_named_requests(rule)
}

grants_unnamed_requests(rule) if count(object.get(rule, "resourceNames", [])) == 0

grants_unnamed_requests(rule) if "" in rule.resourceNames

grants_named_requests(rule) if count(object.get(rule, "resourceNames", [])) == 0

grants_named_requests(rule) if {
	some name in rule.resourceNames
	not name in {"", "*"}
}

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
