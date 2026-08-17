# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Removing pods from a privileged namespace while making other nodes
# unschedulable forces those pods to reschedule onto a node the subject already
# controls, where their service account tokens can be read off disk. Neither
# half is alarming on its own — both are ordinary node maintenance rights — so
# only the combination is reported.
deny contains msga if {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	pairs_with(role, rolebinding)
	affects_privileged_namespace(rolebinding)

	can_remove_pods(role, rolebinding)

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	# Second half of the chain. The aggregator emits one input element per
	# (binding, role, subject) triple, so a subject holding the two halves
	# through two different bindings shows up as two elements and the partner
	# has to be looked up across the input rather than inside relatedObjects.
	# The same element satisfies both halves when one role grants everything.
	cordon_vector := input[_]
	is_same_subject_vector(subjectVector, cordon_vector)
	cordon_role := cordon_vector.relatedObjects[_]
	cordon_binding := cordon_vector.relatedObjects[_]
	pairs_with(cordon_role, cordon_binding)

	# Nodes are cluster scoped, so a RoleBinding grants nothing over them no
	# matter which role it points at.
	cordon_binding.kind == "ClusterRoleBinding"
	can_cordon_nodes(cordon_role)

	# Paths are built only from this element's own role, so the alert is a
	# function of subjectVector alone and the deny set collapses the duplicates
	# that several qualifying partners would otherwise produce.
	removal_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		some p
		rule := role.rules[p]
		removes_pods(rule, rolebinding)
		some field, values in {
			"resources": {"pods", "pods/eviction", "pods/status", "nodes", "*/eviction", "*/status", "*"},
			"verbs": {"create", "delete", "update", "patch", "*"},
			"apiGroups": {"", "*"},
		}
		value := rule[field][l]
		value in values
	])

	# Only meaningful when this element is itself the cluster-wide half;
	# otherwise the cordon rights sit in a role this alert does not point at.
	cordon_paths := sort([sprintf("relatedObjects[%d].rules[%d].%s[%d]", [i, p, field, l]) |
		rolebinding.kind == "ClusterRoleBinding"
		some p
		rule := role.rules[p]
		cordons_nodes(rule)
		some field, values in {
			"resources": {"nodes", "nodes/status", "*/status", "*"},
			"verbs": {"update", "patch", "*"},
			"apiGroups": {"", "*"},
		}
		value := rule[field][l]
		value in values
	])

	rule_paths := array.concat(removal_paths, [p | some p in cordon_paths; not p in removal_paths])
	finalpath := array.concat(rule_paths, [
		sprintf("relatedObjects[%d].roleRef.name", [j]),
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can remove pods from privileged namespaces and make nodes unschedulable, and so steal pods onto a node it controls", [subjectVector.kind, subjectVector.name]),
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

can_remove_pods(role, rolebinding) if {
	rule := role.rules[_]
	removes_pods(rule, rolebinding)
}

# update/patch on pods: rewrite a pod's labels so its controller treats it as
# lost and schedules a replacement elsewhere. resourceNames does not blunt this
# — the labels being rewritten belong to the named pod itself.
removes_pods(rule, _) if {
	core_api_group(rule)
	targets(rule, "pods")
	update_patch_or_wildcard(rule.verbs)
}

# update/patch on pods/status reaches the same labels through the subresource.
removes_pods(rule, _) if {
	core_api_group(rule)
	targets_subresource(rule, "pods/status")
	update_patch_or_wildcard(rule.verbs)
}

# The remaining verbs act on a whole object rather than its contents, so
# resourceNames genuinely confines them and they are only reported unrestricted.

# delete a pod outright.
removes_pods(rule, _) if {
	core_api_group(rule)
	unrestricted_rule(rule)
	targets(rule, "pods")
	verb_or_wildcard(rule.verbs, "delete")
}

# evict a pod through the eviction subresource.
removes_pods(rule, _) if {
	core_api_group(rule)
	unrestricted_rule(rule)
	targets_subresource(rule, "pods/eviction")
	verb_or_wildcard(rule.verbs, "create")
}

# delete a node, evicting every pod on it. Cluster scoped, so a RoleBinding into
# a privileged namespace does not carry it.
removes_pods(rule, rolebinding) if {
	rolebinding.kind == "ClusterRoleBinding"
	core_api_group(rule)
	unrestricted_rule(rule)
	targets(rule, "nodes")
	verb_or_wildcard(rule.verbs, "delete")
}

# taint a node NoExecute, which evicts the pods already on it.
removes_pods(rule, rolebinding) if {
	rolebinding.kind == "ClusterRoleBinding"
	core_api_group(rule)
	unrestricted_rule(rule)
	targets(rule, "nodes")
	update_patch_or_wildcard(rule.verbs)
}

can_cordon_nodes(role) if {
	rule := role.rules[_]
	cordons_nodes(rule)
}

# cordon a node via spec.unschedulable, or taint it through either the object or
# its status subresource.
cordons_nodes(rule) if {
	core_api_group(rule)
	unrestricted_rule(rule)
	node_or_node_status(rule)
	update_patch_or_wildcard(rule.verbs)
}

node_or_node_status(rule) if targets(rule, "nodes")

node_or_node_status(rule) if targets_subresource(rule, "nodes/status")

targets(rule, resource) if rule.resources[_] in {resource, "*"}

# RBAC has no "pods/*" form, so a wildcard reaching a subresource is either a
# bare "*" or "*/<subresource>".
targets_subresource(rule, combined) if rule.resources[_] == combined

targets_subresource(rule, combined) if {
	subresource := split(combined, "/")[1]
	rule.resources[_] == sprintf("*/%s", [subresource])
}

targets_subresource(rule, _) if rule.resources[_] == "*"

core_api_group(rule) if rule.apiGroups[_] in {"", "*"}

verb_or_wildcard(verbs, verb) if verbs[_] in {verb, "*"}

update_patch_or_wildcard(verbs) if verbs[_] in {"update", "patch", "*"}

# Kubernetes draws no distinction between an absent resourceNames and an
# explicitly empty one: ResourceNameMatches returns true as soon as the list is
# empty, so both mean the entry is not narrowed to named objects. Testing
# definedness alone would read resourceNames: [] as scoped and skip a subject
# that in fact holds unrestricted access.
unrestricted_rule(rule) if {
	count(object.get(rule, "resourceNames", [])) == 0
}

pairs_with(role, rolebinding) if {
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rolebinding.roleRef.kind == role.kind
	rolebinding.roleRef.name == role.metadata.name
	is_same_namespace(role, rolebinding)
}

# A ClusterRoleBinding grants the role in every namespace, a RoleBinding only in
# its own. Namespaces are listed inline because a package level constant would
# be evaluated as a rule response by the rego processor.
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

# Unlike is_same_subjects above, this compares two aggregated elements rather
# than an element against a subject entry, so it cannot fall back to matching on
# apiGroup alone: two ServiceAccounts of the same name in different namespaces
# share an apiGroup and would be merged into one identity. Both qualifiers are
# read with a default instead, which keeps namespace-less subjects such as users
# and groups comparable without conflating namespaced ones.
is_same_subject_vector(subjectVector, other) if {
	subjectVector.kind == other.kind
	subjectVector.name == other.name
	object.get(subjectVector, "namespace", "") == object.get(other, "namespace", "")
	object.get(subjectVector, "apiGroup", "") == object.get(other, "apiGroup", "")
}
