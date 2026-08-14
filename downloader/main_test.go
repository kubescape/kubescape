package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cenkalti/backoff/v4"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

func init() {
	// Override backoff factory to make tests fast and predictable
	backoffFactory = func() backoff.BackOff {
		return backoff.WithMaxRetries(backoff.NewConstantBackOff(0), 3)
	}
}

type mockDownloader struct {
	errsByTarget  map[string][]error
	callsByTarget map[string]int
}

func (m *mockDownloader) Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error) {
	target := downloadInfo.Target
	if m.callsByTarget == nil {
		m.callsByTarget = make(map[string]int)
	}
	calls := m.callsByTarget[target]

	errs := m.errsByTarget[target]
	var err error
	if calls >= len(errs) {
		err = nil
	} else {
		err = errs[calls]
	}

	m.callsByTarget[target]++

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
		name            string
		errsByTarget    map[string][]error
		expectError     bool
		wantErrContains []string
		expectedCalls   map[string]int
	}{
		{
			name:          "all-succeed",
			errsByTarget:  map[string][]error{},
			expectError:   false,
			expectedCalls: map[string]int{"artifacts": 1, "framework": 1},
		},
		{
			name: "transient-failure-then-succeed",
			errsByTarget: map[string][]error{
				"artifacts": {errors.New("transient"), nil},
			},
			expectError:   false,
			expectedCalls: map[string]int{"artifacts": 2, "framework": 1},
		},
		{
			name: "persistent-failure",
			errsByTarget: map[string][]error{
				"artifacts": {errors.New("fail"), errors.New("fail"), errors.New("fail"), errors.New("fail")}, // 4 total attempts
			},
			expectError:   true,
			expectedCalls: map[string]int{"artifacts": 4, "framework": 1},
		},
		{
			name: "permanent-error-no-retry",
			errsByTarget: map[string][]error{
				"artifacts": {context.Canceled}, // Should not retry, so only 1 attempt
			},
			expectError:   true,
			expectedCalls: map[string]int{"artifacts": 1, "framework": 1}, // Continues processing next target
		},
		{
			name: "all-targets-fail-are-aggregated",
			errsByTarget: map[string][]error{
				"artifacts": {errors.New("artifacts unreachable"), errors.New("artifacts unreachable"), errors.New("artifacts unreachable"), errors.New("artifacts unreachable")},
				"framework": {errors.New("framework unreachable"), errors.New("framework unreachable"), errors.New("framework unreachable"), errors.New("framework unreachable")},
			},
			expectError: true,
			// Every failure has to surface, not just the first one: the joined
			// error is what main turns into the non-zero exit that fails the
			// image build in build/Dockerfile.
			wantErrContains: []string{"artifacts unreachable", "framework unreachable"},
			expectedCalls:   map[string]int{"artifacts": 4, "framework": 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockDownloader{errsByTarget: tt.errsByTarget}
			err := downloadArtifacts(m, downloads)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got error: %v", tt.expectError, err)
			}

			for _, want := range tt.wantErrContains {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("expected error to mention %q, got: %v", want, err)
				}
			}

			for target, expected := range tt.expectedCalls {
				actual := m.callsByTarget[target]
				if actual != expected {
					t.Errorf("for target %q: expected %d calls, got %d", target, expected, actual)
				}
			}
		})
	}
}
