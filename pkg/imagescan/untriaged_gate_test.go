package imagescan_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	"github.com/stretchr/testify/require"
)

func severityGateReport(t *testing.T, severity string) string {
	t.Helper()
	matches := []any{}
	if severity != "" {
		matches = append(matches, map[string]any{
			"vulnerability": map[string]any{
				"id": "CVE-2026-1000", "severity": imagescan.NormalizeSeverity(severity),
			},
			"artifact": map[string]any{"name": "libfixture", "version": "1.0", "type": "deb"},
		})
	}
	raw, err := json.Marshal(map[string]any{"matches": matches})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// Exercise the existing diff gate with the adaptor's public normalization
// result. Unknown must take its fail-closed route, not Negligible's exemption.
func TestUntriagedSeverityDoesNotBypassDiffGate(t *testing.T) {
	base := severityGateReport(t, "")
	for _, raw := range []string{"Untriaged", "Unassigned", "UNTRIAGED", "UNASSIGNED"} {
		t.Run(raw, func(t *testing.T) {
			changes, err := diff.ComputeVulnerabilities(base, severityGateReport(t, raw))
			require.NoError(t, err)
			require.Len(t, changes.New, 1)
			require.Equal(t, "Unknown", changes.New[0].Severity)
			for _, threshold := range []string{"Low", "Medium", "High", "Critical"} {
				require.Equal(t, 1, diff.NewVulnerabilitiesAtOrAbove(changes, threshold), threshold)
			}
		})
	}
}

func TestUntriagedSeverityKeepsNegligibleGateExemption(t *testing.T) {
	base := severityGateReport(t, "")
	for _, raw := range []string{"Negligible", "Minimal", "Informational", "None"} {
		t.Run(raw, func(t *testing.T) {
			changes, err := diff.ComputeVulnerabilities(base, severityGateReport(t, raw))
			require.NoError(t, err)
			require.Len(t, changes.New, 1)
			require.Equal(t, "Negligible", changes.New[0].Severity)
			require.Zero(t, diff.NewVulnerabilitiesAtOrAbove(changes, "Low"))
		})
	}
}
