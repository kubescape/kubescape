package main

import (
	"errors"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

type mockDownloader struct {
	errs  []error
	calls int
}

func (m *mockDownloader) Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error) {
	if m.calls >= len(m.errs) {
		return &metav1.DownloadResult{}, nil
	}
	err := m.errs[m.calls]
	m.calls++
	if err != nil {
		return nil, err
	}
	return &metav1.DownloadResult{
		Files: []string{"file1.json", "file2.json"},
	}, nil
}

func TestDownloadArtifacts(t *testing.T) {
	downloads := []metav1.DownloadInfo{
		{Target: "artifacts"},
		{Target: "framework", Identifier: "security"},
	}

	tests := []struct {
		name        string
		errs        []error
		expectError bool
	}{
		{
			name:        "all-succeed",
			errs:        []error{nil, nil},
			expectError: false,
		},
		{
			name:        "partial-failure",
			errs:        []error{nil, errors.New("download failed")},
			expectError: true, // Test should fail here because the bug causes it to return nil
		},
		{
			name:        "all-fail",
			errs:        []error{errors.New("fail 1"), errors.New("fail 2")},
			expectError: true, // Test should fail here as well
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockDownloader{errs: tt.errs}
			err := downloadArtifacts(m, downloads)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got error: %v", tt.expectError, err)
			}
		})
	}
}
