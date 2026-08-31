# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if pod has hostIPC enabled
deny contains msga if {
	path := "spec.hostIPC"
	pod := input[_]
	pod.kind == "Pod"
	is_host_ipc(pod.spec)
	msga := {
		"alertMessage": sprintf("Pod: %v has hostIPC enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload has hostIPC enabled
deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	path := "spec.template.spec.hostIPC"
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	is_host_ipc(wl.spec.template.spec)
	msga := {
		"alertMessage": sprintf("%v: %v has a pod with hostIPC enabled", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob has hostIPC enabled
deny contains msga if {
	path := "spec.jobTemplate.spec.template.spec.hostIPC"
	wl := input[_]
	wl.kind == "CronJob"
	is_host_ipc(wl.spec.jobTemplate.spec.template.spec)
	msga := {
		"alertMessage": sprintf("CronJob: %v has a pod with hostIPC enabled", [wl.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Check that hostIPC is set to false. Default is false. Only in pod spec

is_host_ipc(podspec) if {
	podspec.hostIPC == true
}
