package printer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

func policyReportImageMatch(id, severity, packageName string, fixVersions ...string) match.Match {
	state := vulnerability.FixStateNotFixed
	if len(fixVersions) > 0 {
		state = vulnerability.FixStateFixed
	}
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: id, Namespace: "nvd"},
			Metadata:  &vulnerability.Metadata{ID: id, Severity: severity},
			Fix:       vulnerability.Fix{Versions: fixVersions, State: state},
		},
		Package: grypepkg.Package{
			ID:      grypepkg.ID(packageName + "-" + id),
			Name:    packageName,
			Version: "1.0.0",
		},
	}
}

func resultByPolicy(t *testing.T, results []policyReportResult, policy string) policyReportResult {
	t.Helper()
	for _, r := range results {
		if r.Policy == policy {
			return r
		}
	}
	require.Failf(t, "result not found", "no result for policy %s", policy)
	return policyReportResult{}
}

func TestBuildImagePolicyReports(t *testing.T) {
	kev := policyReportImageMatch("CVE-2024-0001", "Critical", "openssl", "3.0.2", "3.1.1")
	kev.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{CVE: "CVE-2024-0001"}}
	kev.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: "CVE-2024-0001", EPSS: 0.5, Percentile: 0.9}}

	imageScanData := []cautils.ImageScanData{
		{
			Image: "registry.example.com/team/app:1.0",
			Matches: match.NewMatches(
				kev,
				policyReportImageMatch("CVE-2024-0002", "Negligible", "zlib"),
				policyReportImageMatch("CVE-2024-0003", "High", "curl", "8.0.0"),
			),
			VexStatuses: map[string]cautils.VexStatus{
				"CVE-2024-0003": {Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"},
			},
		},
		{
			Image:    "registry.example.com/team/app:1.0",
			Platform: "linux/arm64",
			Matches:  match.NewMatches(policyReportImageMatch("CVE-2024-0004", "Medium", "busybox")),
		},
	}

	generated := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	reports := buildImagePolicyReports(imageScanData, "prod-cluster", generated)
	require.Len(t, reports, 2)

	first, second := reports[0], reports[1]
	for _, report := range reports {
		assert.Equal(t, policyReportAPIVersion, report.APIVersion)
		assert.Equal(t, clusterPolicyReportKind, report.Kind)
		assert.Empty(t, report.Metadata.Namespace)
		assert.Empty(t, validation.IsDNS1123Subdomain(report.Metadata.Name))
		assert.True(t, strings.HasPrefix(report.Metadata.Name, "kubescape-prod-cluster-image-registry-example-com-team-app-1-0-"))
		assert.Equal(t, "prod-cluster", report.Metadata.Labels["kubescape.io/cluster"])
		assert.Equal(t, policyReportTypeImage, report.Metadata.Labels[policyReportTypeLabel])
		assert.Equal(t, "registry.example.com/team/app:1.0", report.Metadata.Annotations[policyReportImageAnnotation])
	}
	assert.NotEqual(t, first.Metadata.Name, second.Metadata.Name, "platform variants of one image must not share a name")
	assert.NotContains(t, first.Metadata.Annotations, policyReportPlatformAnnotation)
	assert.Equal(t, "linux/arm64", second.Metadata.Annotations[policyReportPlatformAnnotation])

	assert.Equal(t, policyReportSummary{Fail: 2, Skip: 1}, first.Summary)
	assert.Equal(t, policyReportSummary{Fail: 1}, second.Summary)
	require.Len(t, first.Results, 3)

	critical := resultByPolicy(t, first.Results, "CVE-2024-0001")
	assert.Equal(t, policyReportSource, critical.Source)
	assert.Equal(t, "openssl", critical.Rule)
	assert.Equal(t, policyReportImageCategory, critical.Category)
	assert.Equal(t, "critical", critical.Severity)
	assert.Equal(t, policyReportResultFail, critical.Result)
	assert.Equal(t, "Critical severity vulnerability in openssl 1.0.0, fixed in 3.0.2, 3.1.1", critical.Message)
	assert.Equal(t, generated.Unix(), critical.Timestamp.Seconds)
	assert.Empty(t, critical.Resources)
	assert.Equal(t, map[string]string{
		"image":            "registry.example.com/team/app:1.0",
		"package":          "openssl",
		"installedVersion": "1.0.0",
		"fixState":         "fixed",
		"fixedVersions":    "3.0.2, 3.1.1",
		"knownExploited":   "true",
		"epss":             "50.0% (90th)",
	}, critical.Properties)

	negligible := resultByPolicy(t, first.Results, "CVE-2024-0002")
	assert.Equal(t, "info", negligible.Severity)
	assert.Equal(t, "Negligible severity vulnerability in zlib 1.0.0, no fix available", negligible.Message)
	assert.Equal(t, "false", negligible.Properties["knownExploited"])
	assert.NotContains(t, negligible.Properties, "fixedVersions")
	assert.NotContains(t, negligible.Properties, "epss")

	suppressed := resultByPolicy(t, first.Results, "CVE-2024-0003")
	assert.Equal(t, policyReportResultSkip, suppressed.Result)
	assert.Equal(t, "not_affected", suppressed.Properties["vexStatus"])
	assert.Equal(t, "vulnerable_code_not_in_execute_path", suppressed.Properties["vexJustification"])

	assert.Equal(t, "linux/arm64", resultByPolicy(t, second.Results, "CVE-2024-0004").Properties["platform"])
}

func TestBuildImagePolicyReports_CleanImageKeepsEmptyResults(t *testing.T) {
	reports := buildImagePolicyReports([]cautils.ImageScanData{{Image: "alpine:3.20"}}, "", time.Now())
	require.Len(t, reports, 1)
	assert.Equal(t, policyReportSummary{}, reports[0].Summary)
	assert.NotContains(t, reports[0].Metadata.Labels, "kubescape.io/cluster")

	encoded, err := yaml.Marshal(reports[0])
	require.NoError(t, err)
	assert.Contains(t, string(encoded), "results: []", "the PolicyReport CRD requires the results field")
}

func TestImageVulnerabilityResult_OmitsUnknownMatchDetails(t *testing.T) {
	bare := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "GHSA-xxxx-yyyy-zzzz"}},
		Package:       grypepkg.Package{ID: "bare", Name: "left-pad"},
	}
	cves := extractCVEs(match.NewMatches(bare), "node:20", nil)
	require.Len(t, cves, 1)

	result := imageVulnerabilityResult(cves[0], "", metav1.Timestamp{})
	assert.Equal(t, "info", result.Severity)
	assert.Equal(t, policyReportResultFail, result.Result)
	assert.Equal(t, map[string]string{"image": "node:20", "package": "left-pad"}, result.Properties)
}

func TestBuildImagePolicyReports_NoImages(t *testing.T) {
	assert.Empty(t, buildImagePolicyReports(nil, "prod-cluster", time.Now()))
}

func TestImagePolicyReportName(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		platform string
	}{
		{name: "tag", image: "app:1.0"},
		{name: "sanitizes to the same reference as the tag", image: "app-1.0"},
		{name: "platform variant", image: "app:1.0", platform: "linux/amd64"},
		{name: "digest", image: "ghcr.io/org/app@sha256:" + strings.Repeat("a", 64)},
		{name: "long reference", image: "registry.example.com/" + strings.Repeat("segment/", 40) + "app:1.0"},
		{name: "nothing survives sanitizing", image: "::@@"},
	}

	seen := map[string]string{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := imagePolicyReportName(strings.Repeat("c", 300), tt.image, tt.platform)
			assert.Empty(t, validation.IsDNS1123Subdomain(got))
			assert.Equal(t, got, imagePolicyReportName(strings.Repeat("c", 300), tt.image, tt.platform), "names must be stable across runs")
			assert.Contains(t, got, "-image-")
			if previous, ok := seen[got]; ok {
				t.Fatalf("%q and %q collapsed onto %s", previous, tt.name, got)
			}
			seen[got] = tt.name
		})
	}
}

func TestPolicyReportActionPrint_ImageScan(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "images.yaml")
	pp := NewPolicyReportPrinter()
	require.NoError(t, pp.SetWriter(context.Background(), outputPath))

	imageScanData := []cautils.ImageScanData{
		{Image: "nginx:1.25", Matches: match.NewMatches(policyReportImageMatch("CVE-2024-1000", "High", "libxml2"))},
		{Image: "redis:7", Matches: match.NewMatches(policyReportImageMatch("CVE-2024-2000", "Low", "lua"))},
	}
	require.NoError(t, pp.ActionPrint(context.Background(), &cautils.OPASessionObj{}, imageScanData))
	require.NoError(t, pp.CloseWriter())

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	documents := bytes.Split(content, []byte("---\n"))
	require.Len(t, documents, 2)

	for i, document := range documents {
		var decoded policyReport
		require.NoError(t, yaml.Unmarshal(document, &decoded))
		assert.Equal(t, clusterPolicyReportKind, decoded.Kind)
		assert.Equal(t, imageScanData[i].Image, decoded.Metadata.Annotations[policyReportImageAnnotation])
		assert.Equal(t, 1, decoded.Summary.Fail)
	}
}

func TestPolicyReportActionPrint_CombinedScanKeepsImageFindings(t *testing.T) {
	const resourceID = "/v1/default/Pod/demo"
	const controlID = "C-0017"

	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{}
	session.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{ContextName: "prod-cluster"}
	session.AllResources[resourceID] = localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "demo", "namespace": "default"},
	})
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: controlID, Name: "Immutable container filesystem", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
		},
	}
	generated := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	session.Report = &reporthandlingv2.PostureReport{
		ReportGenerationTime: generated,
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				controlID: reportsummary.ControlSummary{ControlID: controlID, Name: "Immutable container filesystem", ScoreFactor: 3},
			},
		},
	}

	outputPath := filepath.Join(t.TempDir(), "combined.yaml")
	pp := NewPolicyReportPrinter()
	require.NoError(t, pp.SetWriter(context.Background(), outputPath))
	imageScanData := []cautils.ImageScanData{
		{Image: "nginx:1.25", Matches: match.NewMatches(policyReportImageMatch("CVE-2024-1000", "High", "libxml2"))},
	}
	require.NoError(t, pp.ActionPrint(context.Background(), session, imageScanData))
	require.NoError(t, pp.CloseWriter())

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	documents := bytes.Split(content, []byte("---\n"))
	require.Len(t, documents, 2)

	var posture, image policyReport
	require.NoError(t, yaml.Unmarshal(documents[0], &posture))
	require.NoError(t, yaml.Unmarshal(documents[1], &image))

	assert.Equal(t, policyReportKind, posture.Kind)
	assert.Equal(t, "default", posture.Metadata.Namespace)
	assert.Equal(t, controlID, posture.Results[0].Policy)

	assert.Equal(t, clusterPolicyReportKind, image.Kind)
	assert.Equal(t, "prod-cluster", image.Metadata.Labels["kubescape.io/cluster"])
	require.Len(t, image.Results, 1)
	assert.Equal(t, "CVE-2024-1000", image.Results[0].Policy)
	assert.Equal(t, generated.Unix(), image.Results[0].Timestamp.Seconds, "image results share the posture report timestamp")
}
