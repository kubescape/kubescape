package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHostname(t *testing.T) {
	// Test that the hostname is not empty
	assert.NotEqual(t, "", getHostname())
}

func TestGetScanningContext(t *testing.T) {
	// Test with empty input
	assert.Equal(t, ContextCluster, GetScanningContext(""))

	// Test with Git URL input
	assert.Equal(t, ContextGitURL, GetScanningContext("https://github.com/kubescape/kubescape"))

	// TODO: Add more tests with other input types
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

func TestGetScanningContextWithFile(t *testing.T) {
	// Test with a file
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	filePath := filepath.Join(dir, "file.txt")
	if _, err := os.Create(filePath); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ContextFile, GetScanningContext(filePath))
}

func TestGetScanningContextWithDir(t *testing.T) {
	// Test with a directory
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	assert.Equal(t, ContextDir, GetScanningContext(dir))
}
