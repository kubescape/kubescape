package resourcehandler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A glob input is skipped because the ignore file in its directory is
// unusable, and the directory, whose name could also be read as a glob, is gone
// by the time --hide runs. The report must still not name it.
func TestHideCoversTheIgnoreFileOfASkippedGlobWhoseDirectoryIsGone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "acme-payroll[prod]")
	require.NoError(t, os.MkdirAll(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, cautils.IgnoreFileName), []byte("[\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "bad.yaml"), []byte(singlePodManifest), 0o600))
	validPath := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(validPath, []byte(singlePodManifest), 0o600))

	match := reporthandling.RuleMatchObjects{
		APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"},
	}
	framework := *mockFramework("test-framework", []reporthandling.Control{
		mockControl("test-control", []reporthandling.PolicyRule{
			mockRule("test-rule", []reporthandling.RuleMatchObjects{match}, ""),
		}),
	})
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{filepath.Join(root, "*.yaml"), validPath}}
	session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)
	_, resources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, resources, 1, "the valid input must still be scanned")
	require.Len(t, session.SkippedManifests, 1)
	require.Contains(t, session.SkippedManifests[0].Reason, "acme-payroll[prod]")

	require.NoError(t, os.RemoveAll(root))
	require.NoError(t, anonymizer.Apply(&resultshandling.ResultsHandler{ScanData: session}))

	assert.NotContains(t, session.SkippedManifests[0].Reason, "acme-payroll")
	assert.Contains(t, session.SkippedManifests[0].Reason, cautils.IgnoreFileName)
	assert.Contains(t, session.SkippedManifests[0].Reason, cautils.ErrInvalidIgnorePattern.Error())
}
