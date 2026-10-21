package predict

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunPSSRejectsEmptyContainerCompliance(t *testing.T) {
	input := filepath.Join(t.TempDir(), "empty.yaml")
	require.NoError(t, os.WriteFile(input, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: empty\nspec:\n  containers: []\n"), 0600))
	output := filepath.Join(t.TempDir(), "report.json")
	err := runPSS(context.Background(), &pssFlags{level: "Restricted", format: "json", output: output}, []string{input})
	require.ErrorContains(t, err, "evaluation incomplete")
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(data, &report))
	summary := report["summary"].(map[string]any)
	require.Equal(t, float64(0), summary["passing"])
	require.Equal(t, float64(1), summary["unevaluated"])
	require.Equal(t, false, summary["current_effective_level_complete"])
}
