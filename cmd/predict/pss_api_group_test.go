package predict

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A custom resource that reuses a workload kind name is not that workload.
// Evaluating it as one could only fail, since its pod templates live
// elsewhere, and turned every local scan that included one into an
// incomplete evaluation.
func TestRunPSSSkipsCustomResourcesReusingWorkloadKinds(t *testing.T) {
	manifest := `apiVersion: batch.volcano.sh/v1alpha1
kind: Job
metadata:
  name: training
  namespace: default
spec:
  tasks:
  - name: worker
    replicas: 2
    template:
      spec:
        containers:
        - name: app
          image: nginx
---
apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
  namespace: default
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: app
        image: nginx
`
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.yaml")
	require.NoError(t, os.WriteFile(path, []byte(manifest), 0600))

	output := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, runPSS(context.Background(), &pssFlags{level: "Baseline", format: "json", output: output}, []string{path}))

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	var report jsonOutput
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, 1, report.Summary.TotalWorkloads)
	require.Equal(t, 1, report.Summary.Passing)
	require.Zero(t, report.Summary.Unevaluated)
	require.Empty(t, report.DecodeWarnings)
}
