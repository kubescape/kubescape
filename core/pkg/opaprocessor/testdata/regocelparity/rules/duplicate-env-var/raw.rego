# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

same_name_at_other_index(envs, j, name) if {
	k != j
	envs[k].name == name
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.containers[%v].env[%v].name", [i, j])

	msga := make_alert(pod, "Pod", pod.metadata.name, container, env.name, path)
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.initContainers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.initContainers[%v].env[%v].name", [i, j])

	msga := make_alert(pod, "Pod", pod.metadata.name, container, env.name, path)
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.ephemeralContainers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.ephemeralContainers[%v].env[%v].name", [i, j])

	msga := make_alert(pod, "Pod", pod.metadata.name, container, env.name, path)
}

deny contains msga if {
	wl := input[_]
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	container := wl.spec.template.spec.containers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.template.spec.containers[%v].env[%v].name", [i, j])

	msga := make_alert(wl, wl.kind, wl.metadata.name, container, env.name, path)
}

deny contains msga if {
	wl := input[_]
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	container := wl.spec.template.spec.initContainers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.template.spec.initContainers[%v].env[%v].name", [i, j])

	msga := make_alert(wl, wl.kind, wl.metadata.name, container, env.name, path)
}

deny contains msga if {
	wl := input[_]
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	container := wl.spec.template.spec.ephemeralContainers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.template.spec.ephemeralContainers[%v].env[%v].name", [i, j])

	msga := make_alert(wl, wl.kind, wl.metadata.name, container, env.name, path)
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [i, j])

	msga := make_alert(wl, "CronJob", wl.metadata.name, container, env.name, path)
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.initContainers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.jobTemplate.spec.template.spec.initContainers[%v].env[%v].name", [i, j])

	msga := make_alert(wl, "CronJob", wl.metadata.name, container, env.name, path)
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.ephemeralContainers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.jobTemplate.spec.template.spec.ephemeralContainers[%v].env[%v].name", [i, j])

	msga := make_alert(wl, "CronJob", wl.metadata.name, container, env.name, path)
}

make_alert(obj, kind, name, container, env_name, path) := {
	"alertMessage": sprintf("%v: %v container %v has duplicate environment variable name %v at this entry", [kind, name, container.name, env_name]),
	"packagename": "armo_builtins",
	"failedPaths": [path],
	"fixPaths": [],
	"alertScore": 3,
	"alertObject": {"k8sApiObjects": [obj]},
}
