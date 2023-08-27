package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHostname(t *testing.T) {
	assert.NotEqual(t, "", getHostname())
}

func TestGetScanningContext(t *testing.T) {
	assert.Equal(t, ContextCluster, GetScanningContext(""))
	assert.Equal(t, ContextGitURL, GetScanningContext("https://github.com/kubescape/kubescape"))
}

func TestScanInfoFormats(t *testing.T) {
	testCases := []struct {
		Input string
		Want  []string
	}{
		{"", []string{}},
		{"json", []string{"json"}},
		{"pdf", []string{"pdf"}},
		{"html", []string{"html"}},
		{"sarif", []string{"sarif"}},
		{"html,pdf,sarif", []string{"html", "pdf", "sarif"}},
		{"pretty-printer,pdf,sarif", []string{"pretty-printer", "pdf", "sarif"}},
	}

	for _, tc := range testCases {
		t.Run(tc.Input, func(t *testing.T) {
			input := tc.Input
			want := tc.Want
			scanInfo := &ScanInfo{Format: input}

			got := scanInfo.Formats()

			assert.Equal(t, want, got)
		})
	}
}
