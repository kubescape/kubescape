# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# A subject that can write a service's status subresource can set
# status.loadBalancer.ingress.ip to an address it controls. The kube-proxy
# rules generated from that field then send traffic addressed to the service
# to the attacker instead (CVE-2020-8554), which turns the grant into a
# man-in-the-middle position over every in-cluster client of that service.
# The commonly deployed mitigations for CVE-2020-8554 reject services that set
# spec.externalIPs, so they leave this path open.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	pairs_with(role, rolebinding)

	rule := role.rules[p]
	modifies_service_status(rule)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		some field, values in {
			"resources": {"services/status", "*/status", "*"},
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
		"alertMessage": sprintf("Subject: %s-%s can modify services/status and so redirect traffic sent to a service to an address it controls (CVE-2020-8554)", [subjectVector.kind, subjectVector.name]),
		"alertScore": 5,
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

# resourceNames is deliberately not consulted. It narrows the grant to named
# services, but the attack rewrites the status of the very service that is
# named, so a restricted entry still hands over every client of that service.
modifies_service_status(rule) if {
	core_api_group(rule)
	targets_subresource(rule, "services/status")
	update_patch_or_wildcard(rule.verbs)
}

# RBAC has no "services/*" form, so a wildcard that reaches a subresource is
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
