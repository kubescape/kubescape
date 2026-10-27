package predict

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const stdinManifests = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: worker
  namespace: dev
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`

func readJSONReport(t *testing.T, path string) jsonOutput {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var report jsonOutput
	require.NoError(t, json.Unmarshal(data, &report))
	return report
}

func failingWorkloadIDs(report jsonOutput) []string {
	var ids []string
	for _, workload := range report.FailingWorkload {
		ids = append(ids, workload.Namespace+"/"+workload.Kind+"/"+workload.Name)
	}
	return ids
}

func TestRunPSSReadsManifestsFromStdin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		namespace string
		workload  string
		want      []string
	}{
		{"every workload", "", "", []string{"prod/Deployment/web", "dev/Pod/worker"}},
		{"scoped to a namespace", "dev", "", []string{"dev/Pod/worker"}},
		{"filtered to a workload", "", "Deployment/web", []string{"prod/Deployment/web"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report.json")
			err := runPSS(context.Background(), &pssFlags{
				level:     "Baseline",
				format:    "json",
				output:    output,
				namespace: tc.namespace,
				workload:  tc.workload,
				stdin:     strings.NewReader(stdinManifests),
			}, []string{"-"})
			require.ErrorContains(t, err, "PSS compliance check failed")

			report := readJSONReport(t, output)
			require.Equal(t, len(tc.want), report.Summary.TotalWorkloads)
			require.ElementsMatch(t, tc.want, failingWorkloadIDs(report))
		})
	}
}

func TestRunPSSStdinCompliantManifestPasses(t *testing.T) {
	const compliant = `apiVersion: v1
kind: Pod
metadata:
  name: hardened
spec:
  containers:
  - name: app
    image: nginx
`
	err := runPSS(context.Background(), &pssFlags{
		level:  "Baseline",
		format: "json",
		output: filepath.Join(t.TempDir(), "report.json"),
		stdin:  strings.NewReader(compliant),
	}, []string{"-"})
	require.NoError(t, err)
}

func TestRunPSSStdinNamesStdinInParseErrors(t *testing.T) {
	err := runPSS(context.Background(), &pssFlags{
		level:  "Baseline",
		format: "json",
		stdin:  strings.NewReader("apiVersion: v1\nmetadata:\n  name: no-kind\n"),
	}, []string{"-"})
	require.ErrorContains(t, err, "in stdin: kind is required")
}

func TestRunPSSRejectsStdinMixedWithPaths(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(stdinManifests), 0600))

	for _, args := range [][]string{{"-", manifest}, {manifest, "-"}} {
		stdin := strings.NewReader(stdinManifests)
		err := runPSS(context.Background(), &pssFlags{
			level:  "Baseline",
			format: "json",
			stdin:  stdin,
		}, args)
		require.EqualError(t, err, "usage: stdin input '-' cannot be combined with other input paths")
		require.Equal(t, len(stdinManifests), stdin.Len(), "stdin must not be read")
	}
}

func TestPSSCommandReadsCommandStdin(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	cmd := getPSSCmd()
	cmd.SetIn(strings.NewReader(stdinManifests))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"-", "--level", "Baseline", "-f", "json", "-o", output})

	require.ErrorContains(t, cmd.Execute(), "PSS compliance check failed")
	require.ElementsMatch(t, []string{"prod/Deployment/web", "dev/Pod/worker"}, failingWorkloadIDs(readJSONReport(t, output)))
}
