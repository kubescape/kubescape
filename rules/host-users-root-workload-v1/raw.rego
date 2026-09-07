# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Reports workloads that run a root container in the host user namespace.
#
# Root detection is a static approximation, consistent with existing
# root-detection controls: a container counts as root when its effective
# runAsNonRoot (container-level securityContext overriding pod-level) is
# not true and its effective runAsUser is unset or 0. An unset runAsUser
# falls back to the image's default user, which a manifest scan cannot
# know, so unset is treated as root. One finding is emitted per root
# container.
#
# Workloads are exempt when user namespaces cannot apply: pods using
# hostPID, hostNetwork, hostIPC, or a privileged container (hostUsers:
# false is incompatible with all of these), and Windows pods (the field
# is Linux-only).

deny contains msga if {
	wl := input[_]
	not workloadExemptFromUserNamespace(wl)
	podSpec := workloadPodSpec(wl)
	workloadInHostUserNamespace(podSpec)
	entry := allContainerEntries(podSpec)[_]
	containerRunsAsRoot(podSpec, entry.container)
	msga := {
		"alertMessage": sprintf("container %v in %v %v runs as root in the host user namespace; set spec.hostUsers: false to map container root to an unprivileged host UID (GA in Kubernetes 1.36)", [entry.container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [sprintf("%s.%s", [specPrefix(wl), entry.path])],
		"reviewPaths": [sprintf("%s.%s", [specPrefix(wl), entry.path])],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

# workloadPodSpec resolves the pod spec for the supported workload kinds:
# a Pod carries it at spec, controllers at spec.template.spec, and a
# CronJob nests it at spec.jobTemplate.spec.template.spec.
workloadPodSpec(wl) := wl.spec if {
	wl.kind == "Pod"
} else := wl.spec.template.spec if {
	wl.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
} else := wl.spec.jobTemplate.spec.template.spec if {
	wl.kind == "CronJob"
}

# specPrefix is the path prefix from the workload root to its pod spec,
# used for failedPaths so they point at the real manifest location.
specPrefix(wl) := "spec" if {
	wl.kind == "Pod"
} else := "spec.template.spec" if {
	wl.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
} else := "spec.jobTemplate.spec.template.spec" if {
	wl.kind == "CronJob"
}

# workloadInHostUserNamespace holds when the pod spec does not opt into a
# user namespace. hostUsers is absent in most existing manifests, and an
# absent field must hold here, so the check is negated rather than
# compared directly (a direct comparison against false is undefined when
# the field is absent).
workloadInHostUserNamespace(podSpec) if {
	not podSpec.hostUsers == false
}

# workloadExemptFromUserNamespace covers every case where hostUsers:
# false cannot apply, so the workload must not be flagged.
workloadExemptFromUserNamespace(wl) if {
	podSpec := workloadPodSpec(wl)
	usesHostNamespaceOrPrivileged(podSpec)
}

workloadExemptFromUserNamespace(wl) if {
	podSpec := workloadPodSpec(wl)
	podSpec.os.name == "windows"
}

usesHostNamespaceOrPrivileged(podSpec) if {
	podSpec.hostPID == true
}

usesHostNamespaceOrPrivileged(podSpec) if {
	podSpec.hostNetwork == true
}

usesHostNamespaceOrPrivileged(podSpec) if {
	podSpec.hostIPC == true
}

usesHostNamespaceOrPrivileged(podSpec) if {
	container := allContainers(podSpec)[_]
	container.securityContext.privileged == true
}

# allContainers lists every container slice whose members can run as
# root: containers, initContainers and ephemeralContainers.
allContainers(podSpec) := array.concat(
	object.get(podSpec, "containers", []),
	array.concat(
		object.get(podSpec, "initContainers", []),
		object.get(podSpec, "ephemeralContainers", []),
	),
)

# allContainerEntries pairs each container with its index-qualified path
# fragment (relative to the pod spec), keeping the container slices
# distinct so failedPaths point at the real manifest location.
allContainerEntries(podSpec) := array.concat(
	entriesFor(podSpec, "containers"),
	array.concat(
		entriesFor(podSpec, "initContainers"),
		entriesFor(podSpec, "ephemeralContainers"),
	),
)

entriesFor(podSpec, fieldName) := entries if {
	containers := object.get(podSpec, fieldName, [])
	entries := [entry |
		some i
		container := containers[i]
		entry := {"container": container, "path": sprintf("%s[%d]", [fieldName, i])}
	]
}

# effectiveRunAsNonRoot resolves the securityContext cascade with explicit
# defaults: the container-level value overrides the pod-level one, and
# "unset" marks the absent case (an unset field is not the same as false —
# an explicit false means non-root enforcement is off and the container
# may run as root).
effectiveRunAsNonRoot(podSpec, container) := object.get(object.get(container, "securityContext", {}), "runAsNonRoot", object.get(object.get(podSpec, "securityContext", {}), "runAsNonRoot", "unset"))

# effectiveRunAsUser follows the same cascade; 0 marks the absent case,
# which counts as root (image default unknown to static analysis).
effectiveRunAsUser(podSpec, container) := object.get(object.get(container, "securityContext", {}), "runAsUser", object.get(object.get(podSpec, "securityContext", {}), "runAsUser", 0))

# containerRunsAsRoot is the static root approximation: runAsNonRoot not
# enforced (unset or explicitly false at the effective level), and either
# an explicit root UID or an unset UID (image default, treated as root).
containerRunsAsRoot(podSpec, container) if {
	effectiveRunAsNonRoot(podSpec, container) != true
	not containerHasNonRootUID(podSpec, container)
}

# containerHasNonRootUID holds only when an effective runAsUser is
# present and nonzero; the 0 default for an unset UID keeps unset counted
# as root.
containerHasNonRootUID(podSpec, container) if {
	uid := effectiveRunAsUser(podSpec, container)
	uid != 0
}
