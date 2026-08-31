package resultshandling

import (
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newWorkload(t *testing.T, kind, name string) workloadinterface.IMetadata {
	t.Helper()

	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
	})
	require.NotNil(t, workload)
	return workload
}

func TestBuildScanOutcomeNilSessionStillReportsTarget(t *testing.T) {
	outcome := buildScanOutcome(nil, nil, &cautils.ScanInfo{ScanType: cautils.ScanTypeImage})

	assert.Equal(t, string(cautils.ScanTypeImage), outcome.Target)
	assert.False(t, outcome.HasComplianceScore)
	assert.Empty(t, outcome.Controls)
	assert.Empty(t, outcome.ResourcesByKind)
}

func TestBuildScanOutcomeNilScanInfo(t *testing.T) {
	assert.NotPanics(t, func() {
		outcome := buildScanOutcome(nil, nil, nil)
		assert.Empty(t, outcome.Target)
	})
}

func TestBuildScanOutcomeSessionWithoutReport(t *testing.T) {
	outcome := buildScanOutcome(&cautils.OPASessionObj{}, nil, &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster})

	assert.Equal(t, string(cautils.ScanTypeCluster), outcome.Target)
	assert.False(t, outcome.HasComplianceScore)
}

func TestBuildScanOutcomeExtractsControlsAndResources(t *testing.T) {
	failed := reportsummary.ControlSummary{ControlID: "C-0001", ScoreFactor: 7}
	failed.StatusInfo = apis.StatusInfo{InnerStatus: apis.StatusFailed}
	passed := reportsummary.ControlSummary{ControlID: "C-0002", ScoreFactor: 4}
	passed.StatusInfo = apis.StatusInfo{InnerStatus: apis.StatusPassed}

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{
			"a": newWorkload(t, "Deployment", "api"),
			"b": newWorkload(t, "Deployment", "web"),
			"c": newWorkload(t, "Service", "api-svc"),
			"d": nil,
		},
	}
	session.Report.SummaryDetails.ComplianceScore = 76.5
	session.Report.SummaryDetails.Controls = map[string]reportsummary.ControlSummary{
		"C-0001": failed,
		"C-0002": passed,
	}

	outcome := buildScanOutcome(session, nil, &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster})

	assert.Equal(t, string(cautils.ScanTypeCluster), outcome.Target)
	assert.True(t, outcome.HasComplianceScore)
	assert.InDelta(t, 76.5, outcome.ComplianceScore, 0.001)
	assert.Equal(t, map[string]int64{"Deployment": 2, "Service": 1}, outcome.ResourcesByKind)

	assert.ElementsMatch(t, []telemetry.ControlOutcome{
		{Severity: apis.ControlSeverityToString(7), Status: string(apis.StatusFailed)},
		{Severity: apis.ControlSeverityToString(4), Status: string(apis.StatusPassed)},
	}, outcome.Controls)
}

func TestBuildScanOutcomeZeroComplianceScoreIsReported(t *testing.T) {
	session := &cautils.OPASessionObj{Report: &reporthandlingv2.PostureReport{}}

	outcome := buildScanOutcome(session, nil, &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster})

	// A scan that genuinely scored zero must be distinguishable from one that
	// produced no posture score at all.
	assert.True(t, outcome.HasComplianceScore)
	assert.Zero(t, outcome.ComplianceScore)
}

func TestBuildImageOutcomesCountsSeverityAndFixability(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		{
			Image: "nginx:1.25",
			Matches: newMatches(t,
				newMatch("CVE-1", "Critical", vulnerability.FixStateFixed),
				newMatch("CVE-2", "Critical", vulnerability.FixStateNotFixed),
				newMatch("CVE-3", "Low", vulnerability.FixStateFixed),
			),
		},
	}

	outcomes := buildImageOutcomes(imageScanData, false)

	require.Len(t, outcomes, 1)
	assert.Equal(t, "nginx:1.25", outcomes[0].Image)
	assert.Equal(t, map[string]int64{"Critical": 2, "Low": 1}, outcomes[0].BySeverity)
	assert.Equal(t, map[string]int64{"Critical": 1, "Low": 1}, outcomes[0].FixableBySeverity)
}

func TestBuildImageOutcomesCarriesVulnDBBuilt(t *testing.T) {
	built := time.Date(2026, 8, 26, 9, 30, 0, 0, time.UTC)
	imageScanData := []cautils.ImageScanData{
		{
			Image:       "nginx:1.25",
			VulnDBBuilt: &built,
			Matches:     newMatches(t, newMatch("CVE-1", "Critical", vulnerability.FixStateFixed)),
		},
	}

	outcomes := buildImageOutcomes(imageScanData, false)

	require.Len(t, outcomes, 1)
	assert.True(t, outcomes[0].HasVulnDBBuilt)
	assert.Equal(t, built, outcomes[0].VulnDBBuilt)
}

func TestBuildImageOutcomesOmitsUnknownVulnDBBuilt(t *testing.T) {
	outcomes := buildImageOutcomes([]cautils.ImageScanData{{
		Image:   "nginx:1.25",
		Matches: newMatches(t, newMatch("CVE-1", "Critical", vulnerability.FixStateFixed)),
	}}, false)

	require.Len(t, outcomes, 1)
	assert.False(t, outcomes[0].HasVulnDBBuilt)
	assert.True(t, outcomes[0].VulnDBBuilt.IsZero())
}

func TestSetOldestVulnDBBuilt(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	older := base.Add(-2 * time.Hour)
	newer := base.Add(-time.Hour)
	zero := time.Time{}

	tests := []struct {
		name  string
		input []*time.Time
		want  time.Time
		set   bool
	}{
		{name: "nil input ignored", input: []*time.Time{nil}},
		{name: "zero input ignored", input: []*time.Time{&zero}},
		{name: "single timestamp selected", input: []*time.Time{&newer}, want: newer, set: true},
		{name: "older timestamp wins", input: []*time.Time{&newer, &older}, want: older, set: true},
		{name: "zero does not replace existing timestamp", input: []*time.Time{&older, &zero}, want: older, set: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := telemetry.ImageOutcome{}
			for _, built := range tt.input {
				setOldestVulnDBBuilt(&outcome, built)
			}

			assert.Equal(t, tt.set, outcome.HasVulnDBBuilt)
			assert.Equal(t, tt.want, outcome.VulnDBBuilt)
		})
	}
}

func TestBuildImageOutcomesEmptyInput(t *testing.T) {
	assert.Nil(t, buildImageOutcomes(nil, false))
	assert.Nil(t, buildImageOutcomes([]cautils.ImageScanData{}, false))
}

func TestBuildImageOutcomesToleratesUnenrichedMatches(t *testing.T) {
	unenriched := newMatch("CVE-9", "", vulnerability.FixStateNotFixed)
	unenriched.Vulnerability.Metadata = nil

	outcomes := buildImageOutcomes([]cautils.ImageScanData{{
		Image:   "alpine:3.20",
		Matches: newMatches(t, unenriched),
	}}, false)

	require.Len(t, outcomes, 1)
	assert.Equal(t, map[string]int64{"": 1}, outcomes[0].BySeverity)
}

func TestBuildImageOutcomesImageWithoutFindings(t *testing.T) {
	outcomes := buildImageOutcomes([]cautils.ImageScanData{{Image: "alpine:3.20"}}, false)

	require.Len(t, outcomes, 1)
	assert.Empty(t, outcomes[0].BySeverity)
	assert.Empty(t, outcomes[0].FixableBySeverity)
}

func newMatch(id, severity string, fixState vulnerability.FixState) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        id,
				Namespace: "test",
			},
			Fix:      vulnerability.Fix{State: fixState},
			Metadata: &vulnerability.Metadata{ID: id, Severity: severity},
		},
		Details: match.Details{{Type: match.ExactDirectMatch}},
	}
}

func newMatches(t *testing.T, matches ...match.Match) match.Matches {
	t.Helper()

	collection := match.NewMatches()
	collection.Add(matches...)
	return collection
}

func TestBuildImageOutcomesRedactedCollapsesImageNames(t *testing.T) {
	older := time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	imageScanData := []cautils.ImageScanData{
		{
			Image:       "registry.internal.example.com/team/api:v1.2",
			VulnDBBuilt: &newer,
			Matches:     newMatches(t, newMatch("CVE-1", "Critical", vulnerability.FixStateFixed)),
		},
		{
			Image:       "registry.internal.example.com/team/web:v3",
			VulnDBBuilt: &older,
			Matches:     newMatches(t, newMatch("CVE-2", "Low", vulnerability.FixStateNotFixed)),
		},
	}

	outcomes := buildImageOutcomes(imageScanData, true)

	// --hide anonymizes image references in the report, so they must not reach
	// the collector as metric attributes either.
	require.Len(t, outcomes, 1)
	assert.Empty(t, outcomes[0].Image)
	assert.True(t, outcomes[0].HasVulnDBBuilt)
	assert.Equal(t, older, outcomes[0].VulnDBBuilt)
	assert.Equal(t, map[string]int64{"Critical": 1, "Low": 1}, outcomes[0].BySeverity)
	assert.Equal(t, map[string]int64{"Critical": 1}, outcomes[0].FixableBySeverity)
}

func TestBuildScanOutcomeRedactsWhenHideOrEncryptSet(t *testing.T) {
	imageScanData := []cautils.ImageScanData{{
		Image:   "registry.internal.example.com/team/api:v1.2",
		Matches: newMatches(t, newMatch("CVE-1", "High", vulnerability.FixStateFixed)),
	}}

	for _, tt := range []struct {
		name     string
		scanInfo *cautils.ScanInfo
		redacted bool
	}{
		{name: "default", scanInfo: &cautils.ScanInfo{}, redacted: false},
		{name: "hide", scanInfo: &cautils.ScanInfo{Hide: true}, redacted: true},
		{name: "encrypt", scanInfo: &cautils.ScanInfo{EncryptionEnabled: true}, redacted: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outcome := buildScanOutcome(nil, imageScanData, tt.scanInfo)

			require.Len(t, outcome.Images, 1)
			if tt.redacted {
				assert.Empty(t, outcome.Images[0].Image)
				return
			}
			assert.Equal(t, "registry.internal.example.com/team/api:v1.2", outcome.Images[0].Image)
		})
	}
}
