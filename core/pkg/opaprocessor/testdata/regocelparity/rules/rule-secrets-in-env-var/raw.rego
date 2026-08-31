# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"

	container := pod.spec.containers[i]
	env := container.env[j]
	env.valueFrom.secretKeyRef

	path := sprintf("spec.containers[%v].env[%v].name", [format_int(i, 10), format_int(j, 10)])

	msga := {
		"alertMessage": sprintf("Pod: %v has secrets in environment variables", [pod.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	env := container.env[j]
	env.valueFrom.secretKeyRef

	path := sprintf("spec.template.spec.containers[%v].env[%v].name", [format_int(i, 10), format_int(j, 10)])

	msga := {
		"alertMessage": sprintf("%v: %v has secrets in environment variables", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	env := container.env[j]
	env.valueFrom.secretKeyRef

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [format_int(i, 10), format_int(j, 10)])

	msga := {
		"alertMessage": sprintf("Cronjob: %v has secrets in environment variables", [wl.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
