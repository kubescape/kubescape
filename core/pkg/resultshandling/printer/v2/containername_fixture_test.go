package printer

import "github.com/kubescape/k8s-interface/workloadinterface"

// privilegedInitAndEphemeralPod is the shared fixture for container-name
// annotation tests: a Pod with one regular, one init, and one ephemeral
// container. HTML and SARIF reuse this so they cannot drift from the pretty
// printer's expected names.
func privilegedInitAndEphemeralPod() workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"kind": "Pod",
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "nginx",
					"image": "nginx:latest",
				},
			},
			"initContainers": []any{
				map[string]any{
					"name":  "init-db",
					"image": "busybox:latest",
				},
			},
			"ephemeralContainers": []any{
				map[string]any{
					"name":  "debugger",
					"image": "busybox:latest",
				},
			},
		},
	})
}

func privilegedInitAndEphemeralPaths() []string {
	return []string{
		"spec.initContainers[0].securityContext.privileged",
		"spec.ephemeralContainers[0].securityContext.privileged",
		"spec.template.spec.initContainers[0].securityContext.privileged",
		"spec.initContainers[5].securityContext.privileged",
		"spec.ephemeralContainers[3].securityContext.privileged",
	}
}

func privilegedInitAndEphemeralNamedPaths() []string {
	return []string{
		"spec.initContainers[0].securityContext.privileged (init-db)",
		"spec.ephemeralContainers[0].securityContext.privileged (debugger)",
		"spec.template.spec.initContainers[0].securityContext.privileged (init-db)",
		"spec.initContainers[5].securityContext.privileged",
		"spec.ephemeralContainers[3].securityContext.privileged",
	}
}
