package mcpserver

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func scannedControl(id, status, severity string) storagev1beta1.ScannedControl {
	return storagev1beta1.ScannedControl{
		ControlID: id,
		Name:      "control " + id,
		Severity:  storagev1beta1.ControlSeverity{Severity: severity},
		Status:    storagev1beta1.ScannedControlStatus{Status: status},
		Rules: []storagev1beta1.ScannedControlRule{{
			Name:   "rule-" + id,
			Status: storagev1beta1.RuleStatus{Status: status},
		}},
	}
}

func configScanFixture() *storagev1beta1.WorkloadConfigurationScan {
	return &storagev1beta1.WorkloadConfigurationScan{
		ObjectMeta: metav1.ObjectMeta{Name: "deployment-nginx", Namespace: "kubescape", Labels: map[string]string{"kubescape.io/workload-kind": "Deployment"}},
		Spec: storagev1beta1.WorkloadConfigurationScanSpec{
			Controls: map[string]storagev1beta1.ScannedControl{
				"C-0001": scannedControl("C-0001", "failed", "Critical"),
				"C-0002": scannedControl("C-0002", "failed", "Medium"),
				"C-0003": scannedControl("C-0003", "passed", "High"),
				"C-0004": scannedControl("C-0004", "passed", "Low"),
				"C-0005": scannedControl("C-0005", "skipped", "High"),
				"C-0006": scannedControl("C-0006", "failed", ""),
			},
			RelatedObjects: []storagev1beta1.WorkloadScanRelatedObject{{Kind: "ServiceAccount", Name: "nginx", Namespace: "default"}},
		},
	}
}

func configScanServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	return &KubescapeMcpserver{ksClient: storagefake.NewClientset(configScanFixture()).SpdxV1beta1()}
}

func getConfigScan(t *testing.T, args map[string]any) storagev1beta1.WorkloadConfigurationScan {
	t.Helper()
	args["manifest_name"] = "deployment-nginx"
	result, err := configScanServer(t).CallTool(context.Background(), "get_configuration_security_scan_manifest", args)
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var got storagev1beta1.WorkloadConfigurationScan
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &got))
	return got
}

func controlIDs(controls map[string]storagev1beta1.ScannedControl) []string {
	ids := make([]string, 0, len(controls))
	for id := range controls {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func TestGetConfigurationScanManifest_NoFilterReturnsEverything(t *testing.T) {
	got := getConfigScan(t, map[string]any{})
	assert.Equal(t, configScanFixture().Spec, got.Spec)

	got = getConfigScan(t, map[string]any{"status": nil, "min_severity": nil})
	assert.Equal(t, configScanFixture().Spec, got.Spec, "null arguments are treated as absent")
}

func TestGetConfigurationScanManifest_Filters(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		want []string
	}{
		{"failed only", map[string]any{"status": "failed"}, []string{"C-0001", "C-0002", "C-0006"}},
		{"several statuses, any case and spacing", map[string]any{"status": " Failed , SKIPPED"}, []string{"C-0001", "C-0002", "C-0005", "C-0006"}},
		{"passed only", map[string]any{"status": "passed"}, []string{"C-0003", "C-0004"}},
		{"min severity drops lower and unrated controls", map[string]any{"min_severity": "High"}, []string{"C-0001", "C-0003", "C-0005"}},
		{"min severity is case-insensitive", map[string]any{"min_severity": "critical"}, []string{"C-0001"}},
		{"status and min severity together", map[string]any{"status": "failed", "min_severity": "Medium"}, []string{"C-0001", "C-0002"}},
		{"nothing matches", map[string]any{"status": "skipped", "min_severity": "Critical"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getConfigScan(t, tt.args)
			assert.Equal(t, tt.want, controlIDs(got.Spec.Controls))
			for id, c := range got.Spec.Controls {
				assert.Equal(t, configScanFixture().Spec.Controls[id], c, "a kept control is returned unchanged")
			}
			want := configScanFixture()
			assert.Equal(t, want.ObjectMeta.Name, got.Name)
			assert.Equal(t, want.ObjectMeta.Labels, got.Labels)
			assert.Equal(t, want.Spec.RelatedObjects, got.Spec.RelatedObjects)
		})
	}
}

func TestGetConfigurationScanManifest_NothingMatchesIsEmptyObject(t *testing.T) {
	result, err := configScanServer(t).CallTool(context.Background(), "get_configuration_security_scan_manifest",
		map[string]any{"manifest_name": "deployment-nginx", "status": "skipped", "min_severity": "Critical"})
	require.NoError(t, err)
	var raw struct {
		Spec struct {
			Controls json.RawMessage `json:"controls"`
		} `json:"spec"`
	}
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &raw))
	assert.JSONEq(t, `{}`, string(raw.Spec.Controls))
}

func TestGetConfigurationScanManifest_InvalidFilterArguments(t *testing.T) {
	// No storage client and no cluster: a bad filter must be rejected before
	// any connection is attempted.
	t.Setenv("KUBECONFIG", "/nonexistent")
	tests := []struct {
		name      string
		args      map[string]any
		wantError string
	}{
		{"unknown status", map[string]any{"status": "failed,broken"}, "status must be a comma-separated list of failed, passed, skipped"},
		{"empty status item", map[string]any{"status": "failed,"}, "status must be a comma-separated list of failed, passed, skipped"},
		{"status not a string", map[string]any{"status": []any{"failed"}}, "status argument must be a string"},
		{"unknown min severity", map[string]any{"min_severity": "Severe"}, "min_severity must be one of Critical, High, Medium, Low"},
		{"negligible does not apply to controls", map[string]any{"min_severity": "Negligible"}, "min_severity must be one of Critical, High, Medium, Low"},
		{"min severity not a string", map[string]any{"min_severity": 3}, "min_severity argument must be a string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args["manifest_name"] = "deployment-nginx"
			result, err := (&KubescapeMcpserver{}).CallTool(context.Background(), "get_configuration_security_scan_manifest", tt.args)
			require.NoError(t, err)
			require.True(t, result.IsError)
			text := toolResultText(t, result)
			assert.Contains(t, text, tt.wantError)
			assert.Contains(t, text, string(ErrCodeInvalidArgument))
		})
	}
}

func TestGetConfigurationScanManifest_ResourceStillReturnsEverything(t *testing.T) {
	ks := configScanServer(t)
	_, err := ks.CallTool(context.Background(), "get_configuration_security_scan_manifest",
		map[string]any{"manifest_name": "deployment-nginx", "status": "failed"})
	require.NoError(t, err)

	request := mcp.ReadResourceRequest{}
	request.Params.URI = "kubescape://configuration-manifests/kubescape/deployment-nginx"
	contents, err := ks.ReadConfigurationResource(context.Background(), request)
	require.NoError(t, err)
	require.Len(t, contents, 1)
	var got storagev1beta1.WorkloadConfigurationScan
	require.NoError(t, json.Unmarshal([]byte(contents[0].(mcp.TextResourceContents).Text), &got))
	assert.Equal(t, configScanFixture().Spec, got.Spec)
}

func TestFilterScannedControls_DoesNotModifyInput(t *testing.T) {
	controls := configScanFixture().Spec.Controls
	out := filterScannedControls(controls, scannedControlFilter{statuses: map[string]bool{"failed": true}})
	assert.Len(t, out, 3)
	assert.Len(t, controls, 6)
	assert.Equal(t, configScanFixture().Spec.Controls, controls)
}
