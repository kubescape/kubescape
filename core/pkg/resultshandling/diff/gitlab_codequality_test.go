package diff

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintGitLabCodeQuality_Posture(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID:  "apps/v1/default/Deployment/web",
				ControlID:   "C-0017",
				ControlName: "Immutable container filesystem",
				Severity:    "High",
				BaseStatus:  "passed",
				HeadStatus:  "failed",
				Path:        "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
				SourcePath:  "deploy/web.yaml",
			},
			{
				ResourceID: "v1/default/Pod/low-pod",
				ControlID:  "C-LOW",
				Severity:   "Low",
				BaseStatus: "passed",
				HeadStatus: "failed",
				SourcePath: "deploy/low.yaml",
			},
		},
		Incomparable: []ControlChange{
			{
				ResourceID: "apps/v1/default/Deployment/api",
				ControlID:  "C-CRIT",
				Severity:   "Critical",
				HeadStatus: "failed",
				Reason:     "baseline truncated",
				SourcePath: "deploy/api.yaml",
			},
			{
				ResourceID: "apps/v1/default/Deployment/no-file",
				ControlID:  "C-NOFILE",
				Severity:   "Critical",
				HeadStatus: "failed",
				Reason:     "cluster resource without repository file",
			},
		},
		Resolved: []ControlChange{
			{
				ResourceID: "v1/default/Pod/fixed",
				ControlID:  "C-FIXED",
				Severity:   "Critical",
				SourcePath: "deploy/fixed.yaml",
			},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitLabCodeQuality(&out, cs, "High"))

	var issues []diffCodeQualityIssue
	require.NoError(t, json.Unmarshal(out.Bytes(), &issues))
	require.Len(t, issues, 2, "only High+ regressions with repository-relative SourcePath must be emitted")

	assert.Equal(t, "issue", issues[0].Type)
	assert.Equal(t, "C-CRIT", issues[0].CheckName)
	assert.Equal(t, "critical", issues[0].Severity)
	assert.Equal(t, "deploy/api.yaml", issues[0].Location.Path)
	assert.Equal(t, 1, issues[0].Location.Lines.Begin)
	assert.Contains(t, issues[0].Content.Body, "baseline truncated")
	assert.NotEmpty(t, issues[0].Fingerprint)

	assert.Equal(t, "C-0017", issues[1].CheckName)
	assert.Equal(t, "major", issues[1].Severity)
	assert.Equal(t, "deploy/web.yaml", issues[1].Location.Path)
	assert.Equal(t, []string{"Security"}, issues[1].Categories)
	assert.Equal(t, "kubescape", issues[1].EngineName)
	assert.NotEqual(t, issues[0].Fingerprint, issues[1].Fingerprint)
}

func TestPrintGitLabCodeQuality_SkipsFindingsWithoutSourcePath(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID: "apps/v1/default/Deployment/api",
				ControlID:  "C-0017",
				Severity:   "High",
				Path:       "spec.template.spec.containers[0]",
			},
			{
				ResourceID: "apps/v1/default/Deployment/outside",
				ControlID:  "C-0018",
				Severity:   "High",
				SourcePath: "../outside/deploy.yaml",
			},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitLabCodeQuality(&out, cs, ""))
	assert.Equal(t, "[]\n", out.String())
}

func TestComputeFromJSON_PopulatesSourcePathFromReport(t *testing.T) {
	baseJSON := []byte(`{
		"summaryDetails": {"controls": {"C-0017": {"controlID": "C-0017", "name": "Immutable rootfs", "scoreFactor": 7.0}}},
		"resources": [{"resourceID": "apps/v1/default/Deployment/web", "source": {"relativePath": "deploy/web.yaml"}}],
		"results": [{"resourceID": "apps/v1/default/Deployment/web", "controls": [{"controlID": "C-0017", "status": {"status": "passed"}}]}]
	}`)
	headJSON := []byte(`{
		"summaryDetails": {"controls": {"C-0017": {"controlID": "C-0017", "name": "Immutable rootfs", "scoreFactor": 7.0}}},
		"resources": [{"resourceID": "apps/v1/default/Deployment/web", "source": {"relativePath": "deploy/web.yaml"}}],
		"results": [{"resourceID": "apps/v1/default/Deployment/web", "controls": [{"controlID": "C-0017", "status": {"status": "failed"}}]}]
	}`)

	cs, err := ComputeFromJSON(baseJSON, headJSON, Options{Granularity: GranularityControl})
	require.NoError(t, err)
	require.Len(t, cs.New, 1)
	assert.Equal(t, "deploy/web.yaml", cs.New[0].SourcePath)

	var out bytes.Buffer
	require.NoError(t, PrintGitLabCodeQuality(&out, cs, "High"))
	var issues []diffCodeQualityIssue
	require.NoError(t, json.Unmarshal(out.Bytes(), &issues))
	require.Len(t, issues, 1)
	assert.Equal(t, "deploy/web.yaml", issues[0].Location.Path)
}

func TestPrintGitLabCodeQuality_NormalizesWindowsSeparators(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID:  "apps/v1/default/Deployment/web",
				ControlID:   "C-0017",
				ControlName: "Immutable container filesystem",
				Severity:    "High",
				BaseStatus:  "passed",
				HeadStatus:  "failed",
				SourcePath:  `deploy\web.yaml`,
			},
			{
				ResourceID: "apps/v1/default/Deployment/win-abs",
				ControlID:  "C-0018",
				Severity:   "High",
				SourcePath: `C:\repo\deploy\web.yaml`,
			},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitLabCodeQuality(&out, cs, ""))

	var issues []diffCodeQualityIssue
	require.NoError(t, json.Unmarshal(out.Bytes(), &issues))
	require.Len(t, issues, 1)
	assert.Equal(t, "deploy/web.yaml", issues[0].Location.Path)
}
