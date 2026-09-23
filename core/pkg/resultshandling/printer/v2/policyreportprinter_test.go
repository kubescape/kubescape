package printer

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

// TestNewPolicyReportPrinter tests that NewPolicyReportPrinter constructs a valid instance.
func TestNewPolicyReportPrinter(t *testing.T) {
	pp := NewPolicyReportPrinter()
	assert.NotNil(t, pp)
	assert.Nil(t, pp.writer)
}

// TestCloseWriter_PolicyReport tests that SetWriter and CloseWriter succeed on standard output files.
func TestCloseWriter_PolicyReport(t *testing.T) {
	pp := NewPolicyReportPrinter()
	require.NoError(t, pp.SetWriter(context.TODO(), ""))
	assert.NotNil(t, pp.writer)
	assert.NoError(t, pp.CloseWriter())
}

// Regression for issue-3407: PolicyReportPrinter previously implemented the
// void CloseWriter() signature every other v2 printer moved away from in
// #3214, so a real close failure had no way to reach the caller. CloseWriter
// must now return the error, matching every sibling printer.
func TestCloseWriter_PolicyReport_ReturnsCloseError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "policyreport-*.yaml")
	require.NoError(t, err)
	require.NoError(t, f.Close()) // pre-close so the printer's own Close() call fails

	pp := &PolicyReportPrinter{writer: f}
	err = pp.CloseWriter()

	require.Error(t, err, "a genuine close failure must be surfaced, not silently discarded")
	assert.ErrorIs(t, err, os.ErrClosed)
}

// TestCloseWriter_PolicyReport_NilWriter verifies that CloseWriter does not error when writer is nil.
func TestCloseWriter_PolicyReport_NilWriter(t *testing.T) {
	pp := NewPolicyReportPrinter()
	assert.NoError(t, pp.CloseWriter())
}

// TestCloseWriter_PolicyReport_Stdout verifies that CloseWriter never closes os.Stdout.
func TestCloseWriter_PolicyReport_Stdout(t *testing.T) {
	pp := &PolicyReportPrinter{writer: os.Stdout}
	assert.NoError(t, pp.CloseWriter(), "must never close stdout")
}

// Regression for issue-3469: scanContextName() returns a kubeconfig context name, which in
// practice is often an EKS ARN or an API server URL. Both were interpolated straight into
// metadata.name and into the kubescape.io/cluster label value, producing manifests that
// `kubectl apply` rejects outright.
func TestPolicyReportName_SanitizesClusterAndNamespace(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		namespace   string
		expected    string
	}{
		{
			name:     "no cluster or namespace",
			expected: "kubescape",
		},
		{
			name:        "already valid values are untouched",
			clusterName: "prod-cluster",
			namespace:   "kube-system",
			expected:    "kubescape-prod-cluster-kube-system",
		},
		{
			name:        "eks arn loses colons and slashes",
			clusterName: "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
			namespace:   "default",
			expected:    "kubescape-arn-aws-eks-us-east-1-123456789012-cluster-prod-cluster-default",
		},
		{
			name:        "api server url is lowercased and stripped of scheme punctuation",
			clusterName: "https://k8s-cluster.example.com",
			expected:    "kubescape-https-k8s-cluster-example-com",
		},
		{
			name:        "uppercase is folded",
			clusterName: "Prod-Cluster-EU",
			namespace:   "Default",
			expected:    "kubescape-prod-cluster-eu-default",
		},
		{
			name:        "underscores become hyphens",
			clusterName: "gke_my-project_us-central1_prod",
			expected:    "kubescape-gke-my-project-us-central1-prod",
		},
		{
			name:        "runs of invalid characters collapse to one hyphen",
			clusterName: "cluster:://__..name",
			expected:    "kubescape-cluster-name",
		},
		{
			name:        "leading and trailing punctuation is dropped",
			clusterName: "---prod-cluster___",
			expected:    "kubescape-prod-cluster",
		},
		{
			name:        "a cluster name with nothing usable is treated as absent",
			clusterName: ":::///___",
			namespace:   "default",
			expected:    "kubescape-default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyReportName(tt.clusterName, tt.namespace)
			assert.Equal(t, tt.expected, got)
			assert.Empty(t, validation.IsDNS1123Subdomain(got),
				"metadata.name must be a valid RFC 1123 subdomain")
		})
	}
}

// A context name long enough to exhaust the apiserver's 253-character name budget must not push
// the namespace out of the name: two namespaces sharing one metadata.name would collide when the
// multi-document report is applied.
func TestPolicyReportName_TruncatesWithoutLosingNamespace(t *testing.T) {
	got := policyReportName(strings.Repeat("a", 300), "default")

	assert.LessOrEqual(t, len(got), validation.DNS1123SubdomainMaxLength)
	assert.True(t, strings.HasSuffix(got, "-default"),
		"the namespace must survive truncation, got %q", got)
	assert.Empty(t, validation.IsDNS1123Subdomain(got))

	// Two namespaces under the same over-long cluster name must still differ.
	other := policyReportName(strings.Repeat("a", 300), "kube-system")
	assert.NotEqual(t, got, other)
	assert.Empty(t, validation.IsDNS1123Subdomain(other))
}

// Truncation can land on a separator, which would leave a trailing hyphen and fail validation.
func TestPolicyReportName_TruncationNeverEndsOnSeparator(t *testing.T) {
	got := policyReportName(strings.Repeat("ab:", 100), "")

	assert.False(t, strings.HasSuffix(got, "-"), "got %q", got)
	assert.LessOrEqual(t, len(got), validation.DNS1123SubdomainMaxLength)
	assert.Empty(t, validation.IsDNS1123Subdomain(got))
}

// TestPolicyReportLabels_SanitizesClusterLabelValue tests that policyReportLabels produces valid Kubernetes label values.
func TestPolicyReportLabels_SanitizesClusterLabelValue(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		expected    string // "" means the cluster label must be absent
	}{
		{
			name:        "no cluster name",
			clusterName: "",
			expected:    "",
		},
		{
			name:        "already valid value is untouched",
			clusterName: "prod-cluster",
			expected:    "prod-cluster",
		},
		{
			name:        "eks arn loses colons and slashes",
			clusterName: "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
			expected:    "arn-aws-eks-us-east-1-123456789012-cluster-prod-cluster",
		},
		{
			name:        "dots survive as legal separators",
			clusterName: "https://k8s-cluster.example.com",
			expected:    "https-k8s-cluster.example.com",
		},
		{
			name:        "case is preserved because label values permit it",
			clusterName: "Prod-Cluster-EU",
			expected:    "Prod-Cluster-EU",
		},
		{
			name:        "underscores survive as legal separators",
			clusterName: "gke_my-project_us-central1_prod",
			expected:    "gke_my-project_us-central1_prod",
		},
		{
			name:        "a value with nothing usable drops the label entirely",
			clusterName: ":::///",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := policyReportLabels(tt.clusterName)

			assert.Equal(t, policyReportSource, labels["app.kubernetes.io/managed-by"])

			got, present := labels["kubescape.io/cluster"]
			if tt.expected == "" {
				assert.False(t, present, "an unusable cluster name must not emit an empty label")
				return
			}
			require.True(t, present)
			assert.Equal(t, tt.expected, got)
			assert.Empty(t, validation.IsValidLabelValue(got),
				"label value must satisfy the apiserver's label constraints")
		})
	}
}

// TestPolicyReportLabels_TruncatesToLabelValueLimit verifies that labels longer than 63 chars are truncated.
func TestPolicyReportLabels_TruncatesToLabelValueLimit(t *testing.T) {
	got := policyReportLabels(strings.Repeat("a", 300))["kubescape.io/cluster"]

	assert.Len(t, got, validation.LabelValueMaxLength)
	assert.Empty(t, validation.IsValidLabelValue(got))
}

// scope.name references the cluster the report describes rather than naming a Kubernetes object,
// so it is deliberately left as the operator configured it — sanitizing it would discard the only
// place the full context name still appears.
func TestPolicyReportClusterScope_PreservesRawContextName(t *testing.T) {
	const arn = "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster"

	scope := policyReportClusterScope(arn)
	require.NotNil(t, scope)
	assert.Equal(t, arn, scope.Name)

	assert.Nil(t, policyReportClusterScope(""))
}

func TestBuildPolicyReports_TimestampMatchesCRDSchema(t *testing.T) {
	const resourceID = "path=1/api/v1/default/Pod/demo"
	const controlID = "C-0012"

	lw := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "demo", "namespace": "default"},
		"spec":       map[string]interface{}{},
	})

	session := cautils.NewOPASessionObjMock()
	session.AllResources[resourceID] = lw
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: controlID, Name: "Applications credentials in configuration files", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
		},
	}

	built := time.Date(2026, 9, 21, 8, 26, 56, 0, time.UTC)
	session.Report = &reporthandlingv2.PostureReport{
		ReportGenerationTime: built,
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				controlID: reportsummary.ControlSummary{ControlID: controlID, Name: "Applications credentials in configuration files", ScoreFactor: 7.0},
			},
		},
	}

	reports := buildPolicyReports(session)
	require.Len(t, reports, 1)
	require.NotEmpty(t, reports[0].Results)

	encoded, err := yaml.Marshal(reports[0])
	require.NoError(t, err)

	var decoded struct {
		Results []struct {
			Timestamp struct {
				Seconds *int64 `json:"seconds"`
				Nanos   *int32 `json:"nanos"`
			} `json:"timestamp"`
		} `json:"results"`
	}
	require.NoError(t, yaml.Unmarshal(encoded, &decoded), "wgpolicyk8s types results[].timestamp as an object with seconds and nanos")
	require.NotEmpty(t, decoded.Results)

	require.NotNil(t, decoded.Results[0].Timestamp.Seconds, "the CRD requires results[].timestamp.seconds")
	require.NotNil(t, decoded.Results[0].Timestamp.Nanos, "the CRD requires results[].timestamp.nanos")
	assert.Equal(t, built.Unix(), *decoded.Results[0].Timestamp.Seconds)
	assert.NotContains(t, string(encoded), built.Format(time.RFC3339), "an RFC 3339 string is rejected by the PolicyReport CRD")
}
