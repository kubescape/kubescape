package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixDecryptedFileScanReport(t *testing.T) {
	const masterKey = "01234567890123456789012345678901"
	t.Setenv("KUBESCAPE_MASTER_KEY", masterKey)
	t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

	for _, tc := range []struct {
		name      string
		inputFile string
		files     map[string]string
	}{
		{"YAML", "pod.yaml", map[string]string{"pod.yaml": podManifest("web", false)}},
		{"JSON", "pod.json", map[string]string{"pod.json": `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web","namespace":"default"},"spec":{"containers":[{"name":"c","image":"nginx"}]}}`}},
		{"directory with matching identities", "", map[string]string{
			"one.yaml": podManifest("web", false),
			"two.yaml": podManifest("web", false),
		}},
		{"multiple YAML documents", "", map[string]string{
			"pods.yaml": podManifest("web", false) + "---\n" + podManifest("worker", false),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := t.TempDir()
			for name, content := range tc.files {
				writeManifest(t, input, name, content)
			}
			info := localScanTemplate(t, input)
			if tc.inputFile != "" {
				info.InputPatterns = []string{filepath.Join(input, tc.inputFile)}
			}
			info.EncryptionEnabled = true
			ks := &Kubescape{Ctx: context.Background()}
			results, err := ks.ScanContext(context.Background(), info, readOnlyRootFilesystem)
			require.NoError(t, err)
			encrypted, err := results.ToJson()
			require.NoError(t, err)
			decrypted, err := reportcrypto.DecryptReport(encrypted, []byte(masterKey))
			require.NoError(t, err)
			reportPath := filepath.Join(t.TempDir(), "decrypted.json")
			require.NoError(t, os.WriteFile(reportPath, decrypted, 0o600))
			output := filepath.Join(t.TempDir(), "fixed")
			require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: output, NoConfirm: true}))
			for name, content := range tc.files {
				require.FileExists(t, filepath.Join(output, name))
				original, err := os.ReadFile(filepath.Join(input, name))
				require.NoError(t, err)
				assert.Equal(t, content, string(original), "output-dir must preserve the original manifest")
			}

			rescanned, err := ks.ScanToReport(context.Background(), localScanTemplate(t, output), readOnlyRootFilesystem)
			require.NoError(t, err)
			require.False(t, rescanned.Degraded)
			var report reporthandlingv2.PostureReport
			require.NoError(t, json.Unmarshal(rescanned.JSON, &report))
			require.NotEmpty(t, report.Results)
			for _, result := range report.Results {
				require.Len(t, result.AssociatedControls, 1)
				assert.Equal(t, apis.StatusPassed, result.AssociatedControls[0].Status.InnerStatus)
			}
		})
	}
}
