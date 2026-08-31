# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	wl := input[_]
	selector := workload_selector(wl)
	selector_defined(selector)
	labels := workload_template_labels(wl)
	not selector_matches(selector, labels)
	failed_path := selector_failed_path(selector, labels, selector_match_labels_path(wl), selector_match_expressions_path(wl))

	msga := {
		"alertMessage": sprintf("%v: %v selector does not match pod template labels", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [failed_path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

workload_selector(wl) := selector if {
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	selector := object.get(wl.spec, "selector", {})
}

workload_selector(wl) := selector if {
	wl.kind == "ReplicationController"
	selector := {"matchLabels": object.get(wl.spec, "selector", {})}
}

workload_selector(wl) := selector if {
	wl.kind == "CronJob"
	selector := object.get(cronjob_spec(wl), "selector", {})
}

workload_template_labels(wl) := labels if {
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	labels := object.get(workload_template_metadata(wl), "labels", {})
}

workload_template_labels(wl) := labels if {
	wl.kind == "CronJob"
	labels := object.get(cronjob_template_metadata(wl), "labels", {})
}

workload_template_metadata(wl) := metadata if {
	spec := object.get(wl, "spec", {})
	template := object.get(spec, "template", {})
	metadata := object.get(template, "metadata", {})
}

cronjob_spec(wl) := spec if {
	wl_spec := object.get(wl, "spec", {})
	job_template := object.get(wl_spec, "jobTemplate", {})
	spec := object.get(job_template, "spec", {})
}

cronjob_template_metadata(wl) := metadata if {
	spec := cronjob_spec(wl)
	template := object.get(spec, "template", {})
	metadata := object.get(template, "metadata", {})
}

selector_match_labels_path(wl) := "spec.selector.matchLabels" if {
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
}

selector_match_labels_path(wl) := "spec.selector" if {
	wl.kind == "ReplicationController"
}

selector_match_labels_path(wl) := "spec.jobTemplate.spec.selector.matchLabels" if {
	wl.kind == "CronJob"
}

selector_match_expressions_path(wl) := "spec.selector.matchExpressions" if {
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
}

selector_match_expressions_path(wl) := "spec.jobTemplate.spec.selector.matchExpressions" if {
	wl.kind == "CronJob"
}

selector_match_expressions_path(wl) := "spec.selector" if {
	wl.kind == "ReplicationController"
}

selector_defined(selector) if {
	count(object.get(selector, "matchLabels", {})) > 0
}

selector_defined(selector) if {
	count(object.get(selector, "matchExpressions", [])) > 0
}

selector_matches(selector, labels) if {
	not match_labels_mismatch(object.get(selector, "matchLabels", {}), labels)
	not match_expressions_mismatch(object.get(selector, "matchExpressions", []), labels)
}

match_labels_mismatch(match_labels, labels) if {
	match_labels[k]
	not labels[k] == match_labels[k]
}

match_expressions_mismatch(expressions, labels) if {
	expression := expressions[_]
	not expression_matches(expression, labels)
}

expression_matches(expression, labels) if {
	expression.operator == "In"
	label_value := labels[expression.key]
	label_value in object.get(expression, "values", [])
}

expression_matches(expression, labels) if {
	expression.operator == "NotIn"
	not labels[expression.key]
}

expression_matches(expression, labels) if {
	expression.operator == "NotIn"
	label_value := labels[expression.key]
	not label_value in object.get(expression, "values", [])
}

expression_matches(expression, labels) if {
	expression.operator == "Exists"
	labels[expression.key]
}

expression_matches(expression, labels) if {
	expression.operator == "DoesNotExist"
	not labels[expression.key]
}

selector_failed_path(selector, labels, match_labels_path, _) := match_labels_path if {
	match_labels_mismatch(object.get(selector, "matchLabels", {}), labels)
}

selector_failed_path(selector, labels, _, match_expressions_path) := match_expressions_path if {
	not match_labels_mismatch(object.get(selector, "matchLabels", {}), labels)
	match_expressions_mismatch(object.get(selector, "matchExpressions", []), labels)
}
