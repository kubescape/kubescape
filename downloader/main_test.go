package main

import (
	"errors"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDownloader records the targets it was asked for and fails the ones named
// in failFor, mirroring how Download reports a per-artifact failure.
type fakeDownloader struct {
	failFor   map[string]error
	requested []string
}

func (f *fakeDownloader) Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error) {
	f.requested = append(f.requested, targetID(*downloadInfo))
	if err, ok := f.failFor[downloadInfo.Target]; ok {
		return nil, err
	}
	return &metav1.DownloadResult{Files: []string{downloadInfo.Target + ".json"}}, nil
}

func TestDownloadAll(t *testing.T) {
	artifactsErr := errors.New("artifacts unreachable")
	frameworkErr := errors.New("framework unreachable")

	tests := []struct {
		name          string
		failFor       map[string]error
		wantErr       bool
		wantErrParts  []string
		wantRequested []string
	}{
		{
			name:          "all targets succeed",
			wantRequested: []string{"artifacts", "framework/security"},
		},
		{
			name:          "a failing target is reported",
			failFor:       map[string]error{"artifacts": artifactsErr},
			wantErr:       true,
			wantErrParts:  []string{"1 of 2", "artifacts"},
			wantRequested: []string{"artifacts", "framework/security"},
		},
		{
			name:          "every failing target is reported",
			failFor:       map[string]error{"artifacts": artifactsErr, "framework": frameworkErr},
			wantErr:       true,
			wantErrParts:  []string{"2 of 2", "artifacts", "framework/security"},
			wantRequested: []string{"artifacts", "framework/security"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			downloader := &fakeDownloader{failFor: test.failFor}

			err := downloadAll(downloader, defaultTargets())

			// Every target is attempted regardless of earlier failures, so one
			// unreachable artifact cannot mask the state of the others.
			assert.Equal(t, test.wantRequested, downloader.requested)
			if !test.wantErr {
				require.NoError(t, err)
				return
			}
			// A non-nil error is what drives the non-zero exit that lets
			// build/Dockerfile's RUN step fail the image build.
			require.Error(t, err)
			for _, part := range test.wantErrParts {
				assert.Contains(t, err.Error(), part)
			}
		})
	}
}

func TestDefaultTargetsAreIsolatedBetweenCalls(t *testing.T) {
	// Download fills in Path/FileName on the struct it is handed. Callers must
	// not observe those mutations on a later call, or a retry would inherit the
	// previous run's resolved paths.
	first := defaultTargets()
	first[0].Path = "/tmp/mutated"

	assert.Empty(t, defaultTargets()[0].Path)
}
