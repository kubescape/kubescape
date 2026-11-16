// Package ghworkflows guards repository hygiene and workflow configuration.
package ghworkflows

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const expectedPublishResultsGuard = "github.repository == 'kubescape/kubescape'"

// validatePublishResultsGuard checks that a workflow condition strictly gates
// execution to the upstream repository. It strips ${{ ... }} expression markers
// and trims whitespace before checking for exact equivalence, preventing weakened
// guards (such as adding '|| github.event_name == ...') that permit runs on forks.
func validatePublishResultsGuard(condition string) error {
	trimmed := strings.TrimSpace(condition)
	trimmed = strings.TrimPrefix(trimmed, "${{")
	trimmed = strings.TrimSuffix(trimmed, "}}")
	trimmed = strings.TrimSpace(trimmed)

	if trimmed != expectedPublishResultsGuard {
		return fmt.Errorf("publish job must be strictly gated to %q to prevent scheduled or dispatched runs on forks from publishing; got %q",
			expectedPublishResultsGuard, condition)
	}
	return nil
}

// TestPublishResultsIsGuardedAgainstForks verifies that the OSPS Baseline
// publisher workflow runs only in the upstream repository. Scheduled workflows
// trigger on forks by default, but only the upstream repository holds OIDC
// publishing rights for the kubescape namespace on hub.grc.store.
func TestPublishResultsIsGuardedAgainstForks(t *testing.T) {
	path := filepath.Join(workflowsDir(t), "publish-results.yml")
	content, ok := workflowFiles(t)["publish-results.yml"]
	require.Truef(t, ok, "missing %s", path)

	var workflow struct {
		Jobs map[string]struct {
			If string `yaml:"if"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(content, &workflow))

	job, ok := workflow.Jobs["publish"]
	require.True(t, ok, "publish-results.yml has no 'publish' job")

	require.NoError(t, validatePublishResultsGuard(job.If))
}

// TestValidatePublishResultsGuardRejectsWeakenedGuards exercises weakened guards
// and expressions to ensure the regression guard catches conditions that permit
// executions on repository forks.
func TestValidatePublishResultsGuardRejectsWeakenedGuards(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantErr   bool
	}{
		{
			name:      "exact upstream condition",
			condition: "github.repository == 'kubescape/kubescape'",
			wantErr:   false,
		},
		{
			name:      "exact upstream condition wrapped in expression markers",
			condition: "${{ github.repository == 'kubescape/kubescape' }}",
			wantErr:   false,
		},
		{
			name:      "weakened guard with workflow_dispatch disjunction",
			condition: "github.repository == 'kubescape/kubescape' || github.event_name == 'workflow_dispatch'",
			wantErr:   true,
		},
		{
			name:      "weakened guard with tautology",
			condition: "github.repository == 'kubescape/kubescape' || true",
			wantErr:   true,
		},
		{
			name:      "substring match on different repository",
			condition: "github.repository == 'other/kubescape' || github.repository == 'kubescape/kubescape-fork'",
			wantErr:   true,
		},
		{
			name:      "empty condition",
			condition: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublishResultsGuard(tt.condition)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
