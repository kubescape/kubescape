package predict

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Invalid List members must fail before output is opened. A skipped member
// used to turn this input into a successful, empty compliance prediction.
func TestPSSListValidationCommandRejectsInvalidMembers(t *testing.T) {
	for _, format := range []string{"json", "junit", "sarif", "table", "pretty-printer"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "invalid.yaml")
			output := filepath.Join(dir, "existing-report")
			const body = `apiVersion: v1
kind: List
items:
- apiVersion: v1
  metadata:
    name: unsafe
  spec:
    containers:
    - name: main
      image: example.invalid/app:1
      securityContext:
        privileged: true
`
			require.NoError(t, os.WriteFile(input, []byte(body), 0o600))
			require.NoError(t, os.WriteFile(output, []byte("previous report"), 0o600))
			err := runPSS(context.Background(), &pssFlags{
				level: "Baseline", format: format, output: output,
			}, []string{input})
			require.ErrorContains(t, err, "List.items[0]")
			require.Contains(t, err.Error(), input)
			stored, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, "previous report", string(stored))
		})
	}
}

func TestPSSListValidationCommandKeepsTypedListSupport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "pods.yaml")
	output := filepath.Join(dir, "report.json")
	const body = `apiVersion: v1
kind: PodList
items:
- metadata:
    name: unsafe
  spec:
    containers:
    - name: main
      image: example.invalid/app:1
      securityContext:
        privileged: true
`
	require.NoError(t, os.WriteFile(input, []byte(body), 0o600))
	err := runPSS(context.Background(), &pssFlags{
		level: "Baseline", format: "json", output: output,
	}, []string{input})
	require.ErrorContains(t, err, "PSS compliance check failed")
	report, err := os.ReadFile(output)
	require.NoError(t, err)
	require.True(t, strings.Contains(string(report), "unsafe"))
	require.Contains(t, string(report), "Privileged")
}
