# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# A subject that can write a node's status subresource can also change that
# node's labels: the API server's status strategy restores spec on an update to
# nodes/status, but it leaves metadata alone. Labels are what nodeSelector and
# nodeAffinity match on, so the grant lets a subject relabel nodes to attract
# sensitive workloads onto a node it already controls, or strip labels to push
# them off a trusted one. The NodeRestriction admission plugin closes this for
# kubelets editing their own node, but not for any other subject.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	pairs_with(role, rolebinding)

	rule := role.rules[p]
	modifies_node_status(rule, rolebinding)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		some field, values in {
			"resources": {"nodes/status", "*/status", "*"},
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
		"alertMessage": sprintf("Subject: %s-%s can modify nodes/status and so relabel nodes to defeat the nodeSelector and nodeAffinity constraints that keep sensitive workloads off untrusted nodes", [subjectVector.kind, subjectVector.name]),
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

# Nodes are cluster scoped, so only a ClusterRoleBinding carries this grant. A
# RoleBinding confines the role to one namespace, where a rule about nodes
# matches nothing.
#
# resourceNames is deliberately not consulted. It narrows the grant to named
# nodes, but the attack relabels the very node that is named, so a restricted
# entry still moves workloads onto or off that node.
modifies_node_status(rule, rolebinding) if {
	rolebinding.kind == "ClusterRoleBinding"
	core_api_group(rule)
	targets_subresource(rule, "nodes/status")
	update_patch_or_wildcard(rule.verbs)
}

# RBAC has no "nodes/*" form, so a wildcard that reaches a subresource is
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
