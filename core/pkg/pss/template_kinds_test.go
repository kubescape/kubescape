package pss

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const replicationControllerManifest = `apiVersion: v1
kind: ReplicationController
metadata:
  name: legacy-rc
  namespace: default
spec:
  replicas: 1
  selector:
    app: legacy
  template:
    metadata:
      labels:
        app: legacy
      annotations:
        container.apparmor.security.beta.kubernetes.io/app: unconfined
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
`

const podTemplateManifest = `apiVersion: v1
kind: PodTemplate
metadata:
  name: legacy-pt
  namespace: default
template:
  metadata:
    labels:
      app: legacy
    annotations:
      container.apparmor.security.beta.kubernetes.io/app: unconfined
  spec:
    hostNetwork: true
    containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
`

func TestExtractPodAnnotations_TemplateKinds(t *testing.T) {
	for _, tc := range []struct {
		kind     string
		manifest string
	}{
		{"ReplicationController", replicationControllerManifest},
		{"PodTemplate", podTemplateManifest},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(tc.manifest), "template.yaml")
			require.NoError(t, err)
			require.Len(t, objects, 1)
			require.Equal(t, map[string]string{
				"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
			}, ExtractPodAnnotations(tc.kind, objects[0].Object))
		})
	}
}

func TestParseLocalWorkloads_TemplateKindsAreEvaluated(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"standalone manifests", replicationControllerManifest + "---\n" + podTemplateManifest},
		{"generic List", "apiVersion: v1\nkind: List\nitems:\n" + listItems(replicationControllerManifest, podTemplateManifest)},
		{"typed lists", "apiVersion: v1\nkind: ReplicationControllerList\nitems:\n" + listItems(replicationControllerManifest) +
			"---\napiVersion: v1\nkind: PodTemplateList\nitems:\n" + listItems(podTemplateManifest)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(tc.input), "templates.yaml")
			require.NoError(t, err)
			require.Len(t, objects, 2)
			require.Equal(t, "ReplicationController", objects[0].GetKind())
			require.Equal(t, "PodTemplate", objects[1].GetKind())

			result := Aggregate("", objects, Baseline)
			require.Equal(t, 2, result.TotalWorkloads)
			require.Equal(t, 2, result.FailingWorkloads)
			require.Zero(t, result.UnevaluatedWorkloads)
			for _, workload := range result.Results {
				require.Equal(t, Privileged, workload.PassesAt)
				var checks []string
				for _, v := range workload.Violations {
					checks = append(checks, v.Check)
				}
				require.Subset(t, checks, []string{"HostNetwork", "Privileged", "AppArmorProfile"}, "%s/%s", workload.Kind, workload.Name)
			}
		})
	}
}

// listItems indents manifests as entries of a List's items array.
func listItems(manifests ...string) string {
	var b strings.Builder
	for _, manifest := range manifests {
		for i, line := range strings.Split(strings.TrimSuffix(manifest, "\n"), "\n") {
			if i == 0 {
				b.WriteString("- " + line + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
	}
	return b.String()
}
