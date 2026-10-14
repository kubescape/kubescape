package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestImageCommandGitLabWithScanImages(t *testing.T) {
	ks := &imageScanCaptureKubescape{}
	info := &cautils.ScanInfo{}
	parent := &cobra.Command{Use: "scan"}
	parent.PersistentFlags().StringVar(&info.Format, "format", "", "")
	parent.PersistentFlags().BoolVar(&info.ScanImages, "scan-images", false, "")
	parent.AddCommand(getImageCmd(ks, info))
	parent.SetArgs([]string{"image", "nginx", "--scan-images", "--format", "gitlab-sast"})

	require.NoError(t, parent.Execute())
	require.NotNil(t, ks.imgScanInfo, "image-only GitLab output must reach the scanner")
	require.Equal(t, cautils.ScanTypeImage, ks.scanInfo.ScanType)
}

func TestWorkloadCommandGitLabRejectsBeforeScanning(t *testing.T) {
	for _, input := range []string{"./manifests", "-"} {
		t.Run(input, func(t *testing.T) {
			ks := &workloadScanCaptureKubescape{}
			info := &cautils.ScanInfo{}
			output := filepath.Join(t.TempDir(), "report.json")
			require.NoError(t, os.WriteFile(output, []byte("existing report"), 0600))
			stdin := strings.NewReader("kind: Deployment\n")
			parent := &cobra.Command{Use: "scan"}
			parent.SetIn(stdin)
			parent.PersistentFlags().StringVar(&info.Format, "format", "", "")
			parent.PersistentFlags().StringVar(&info.Output, "output", "", "")
			parent.AddCommand(getWorkloadCmd(ks, info))
			parent.SetArgs([]string{"workload", "Deployment/nginx", input, "--format", "gitlab-sast", "--output", output})

			require.ErrorContains(t, parent.Execute(), "requires separate posture and image scans")
			require.Nil(t, ks.scanInfo, "invalid mixed output must not invoke the scanner")
			require.Equal(t, len("kind: Deployment\n"), stdin.Len(), "validation must precede stdin preparation")
			raw, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, "existing report", string(raw), "validation must not truncate output")
		})
	}
}
