package shared

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestValidateCommonScanFlags_GitLabMixedScan(t *testing.T) {
	for _, tc := range []struct {
		name       string
		format     string
		scanImages bool
		scanType   cautils.ScanTypes
		wantError  bool
	}{
		{name: "combined GitLab", format: "gitlab-sast", scanImages: true, wantError: true},
		{name: "multiple formats", format: "json,gitlab-sast", scanImages: true, wantError: true},
		{name: "whitespace", format: " json , gitlab-sast ", scanImages: true, wantError: true},
		{name: "posture only", format: "gitlab-sast"},
		{name: "image only", format: "gitlab-sast", scanType: cautils.ScanTypeImage},
		{name: "combined SARIF", format: "sarif", scanImages: true},
		{name: "combined JSON", format: "json", scanImages: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCommonScanFlags(&cobra.Command{}, &cautils.ScanInfo{
				Format: tc.format, ScanImages: tc.scanImages, ScanType: tc.scanType,
			}, ScanFormats)
			if tc.wantError {
				require.ErrorContains(t, err, "separate")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
