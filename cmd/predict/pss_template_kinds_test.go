package predict

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunPSSEvaluatesLocalTemplateKinds(t *testing.T) {
	dir := t.TempDir()
	manifests := map[string]string{
		"rc.yaml": `apiVersion: v1
kind: ReplicationController
metadata:
  name: legacy-rc
  namespace: default
spec:
  selector:
    app: legacy
  template:
    metadata:
      labels:
        app: legacy
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
`,
		"pt.yaml": `apiVersion: v1
kind: PodTemplate
metadata:
  name: legacy-pt
  namespace: default
template:
  metadata:
    labels:
      app: legacy
  spec:
    hostNetwork: true
    containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
`,
		"rs.yaml": `apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: legacy-rs
  namespace: default
spec:
  selector:
    matchLabels:
      app: legacy
  template:
    metadata:
      labels:
        app: legacy
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
`,
	}
	for name, content := range manifests {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
	}

	for _, tc := range []struct {
		name  string
		files []string
		want  []string
	}{
		{"ReplicationController", []string{"rc.yaml"}, []string{"ReplicationController/legacy-rc"}},
		{"PodTemplate", []string{"pt.yaml"}, []string{"PodTemplate/legacy-pt"}},
		{"mixed with ReplicaSet", []string{"rc.yaml", "pt.yaml", "rs.yaml"}, []string{
			"PodTemplate/legacy-pt", "ReplicaSet/legacy-rs", "ReplicationController/legacy-rc",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			for _, file := range tc.files {
				args = append(args, filepath.Join(dir, file))
			}
			output := filepath.Join(t.TempDir(), "report.json")
			err := runPSS(context.Background(), &pssFlags{level: "Baseline", format: "json", output: output}, args)
			require.ErrorContains(t, err, "PSS compliance check failed")

			data, err := os.ReadFile(output)
			require.NoError(t, err)
			var report jsonOutput
			require.NoError(t, json.Unmarshal(data, &report))
			require.Equal(t, len(tc.want), report.Summary.TotalWorkloads)
			require.Equal(t, len(tc.want), report.Summary.Failing)

			var got []string
			for _, workload := range report.FailingWorkload {
				got = append(got, workload.Kind+"/"+workload.Name)
				var checks []string
				for _, v := range workload.Violations {
					checks = append(checks, v.Check)
				}
				require.Subset(t, checks, []string{"HostNetwork", "Privileged"}, "%s/%s", workload.Kind, workload.Name)
			}
			require.Equal(t, tc.want, got)
		})
	}
}
