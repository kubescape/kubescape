package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func controlSummary(status, severity string) storagev1beta1.ScannedControlSummary {
	return storagev1beta1.ScannedControlSummary{
		Severity: storagev1beta1.ControlSeverity{Severity: severity},
		Status:   storagev1beta1.ScannedControlStatus{Status: status},
	}
}

func configScanSummary(namespace, name, kind, workloadName, workloadNamespace string, controls map[string]storagev1beta1.ScannedControlSummary) *storagev1beta1.WorkloadConfigurationScanSummary {
	return &storagev1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			helpersv1.RelatedKindMetadataKey:      kind,
			helpersv1.RelatedNameMetadataKey:      workloadName,
			helpersv1.RelatedNamespaceMetadataKey: workloadNamespace,
		}},
		Spec: storagev1beta1.WorkloadConfigurationScanSummarySpec{Controls: controls},
	}
}

func configScanSummaryServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	web := configScanSummary("default", "deployment-web", "Deployment", "web", "default", map[string]storagev1beta1.ScannedControlSummary{
		"C-0013": controlSummary("failed", "Medium"),
		"C-0017": controlSummary("failed", "Low"),
		"C-0016": controlSummary("failed", "Medium"),
		"C-0057": controlSummary("failed", "High"),
		"C-0012": controlSummary("passed", "High"),
		"C-0034": controlSummary("skipped", "Medium"),
	})
	clean := configScanSummary("default", "configmap-settings", "ConfigMap", "settings", "default", map[string]storagev1beta1.ScannedControlSummary{
		"C-0012": controlSummary("passed", "High"),
	})
	// RBAC results are stored in the Kubescape namespace, not in the subject's.
	rbac := configScanSummary("kubescape", "serviceaccount-admin", "ServiceAccount", "admin", "kube-system", map[string]storagev1beta1.ScannedControlSummary{
		"C-0035": controlSummary("failed", "High"),
	})
	return &KubescapeMcpserver{ksClient: storagefake.NewClientset(web, clean, rbac).SpdxV1beta1()}
}

func callConfigScanSummaries(t *testing.T, ks *KubescapeMcpserver, args map[string]any) configScanSummaryListResponse {
	t.Helper()
	result, err := ks.CallTool(context.Background(), "list_configuration_security_scan_summaries", args)
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var resp configScanSummaryListResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
	return resp
}

func summariesByName(entries []configScanSummaryEntry) map[string]configScanSummaryEntry {
	m := map[string]configScanSummaryEntry{}
	for _, e := range entries {
		m[e.ManifestName] = e
	}
	return m
}

func TestListConfigScanSummaries(t *testing.T) {
	ks := configScanSummaryServer(t)

	all := callConfigScanSummaries(t, ks, map[string]any{})
	require.Len(t, all.Summaries, 3, "all namespaces by default")
	byName := summariesByName(all.Summaries)

	assert.Equal(t, configScanSummaryEntry{
		Namespace:         "default",
		ManifestName:      "deployment-web",
		Kind:              "Deployment",
		Name:              "web",
		WorkloadNamespace: "default",
		FailedControls: []configScanFailedEntry{
			{ID: "C-0057", Severity: "High"},
			{ID: "C-0013", Severity: "Medium"},
			{ID: "C-0016", Severity: "Medium"},
			{ID: "C-0017", Severity: "Low"},
		},
		StatusCounts: map[string]int{"failed": 4, "passed": 1, "skipped": 1},
	}, byName["deployment-web"], "failed controls are sorted by severity, then ID")
	assert.Empty(t, byName["configmap-settings"].FailedControls)
	assert.NotNil(t, byName["configmap-settings"].FailedControls, "no failed controls is [], not null")
	assert.Equal(t, "kube-system", byName["serviceaccount-admin"].WorkloadNamespace)
	assert.Equal(t, "kubescape", byName["serviceaccount-admin"].Namespace)

	resp := callConfigScanSummaries(t, ks, map[string]any{"namespace": "default"})
	assert.ElementsMatch(t, []string{"deployment-web", "configmap-settings"}, []string{resp.Summaries[0].ManifestName, resp.Summaries[1].ManifestName})

	result, err := ks.CallTool(context.Background(), "list_configuration_security_scan_summaries", map[string]any{"namespace": "nobody"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"summaries":[]}`, toolResultText(t, result))
}

func TestListConfigScanSummaries_MinSeverity(t *testing.T) {
	ks := configScanSummaryServer(t)

	resp := callConfigScanSummaries(t, ks, map[string]any{"min_severity": "high"})
	byName := summariesByName(resp.Summaries)
	require.Len(t, byName, 2, "resources without a High or Critical failure are left out")
	assert.Equal(t, []configScanFailedEntry{{ID: "C-0057", Severity: "High"}}, byName["deployment-web"].FailedControls)
	assert.Equal(t, map[string]int{"failed": 4, "passed": 1, "skipped": 1}, byName["deployment-web"].StatusCounts, "counts are not filtered")
	assert.Equal(t, []configScanFailedEntry{{ID: "C-0035", Severity: "High"}}, byName["serviceaccount-admin"].FailedControls)

	resp = callConfigScanSummaries(t, ks, map[string]any{"min_severity": "Low"})
	assert.Len(t, resp.Summaries, 2, "Low keeps every resource with a failed control")

	resp = callConfigScanSummaries(t, ks, map[string]any{"min_severity": "Critical"})
	assert.Empty(t, resp.Summaries)
}

func TestListConfigScanSummaries_InvalidArguments(t *testing.T) {
	ks := configScanSummaryServer(t)
	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"unknown severity":    {map[string]any{"min_severity": "severe"}, "min_severity must be one of Critical, High, Medium, Low"},
		"negligible severity": {map[string]any{"min_severity": "Negligible"}, "min_severity must be one of Critical, High, Medium, Low"},
		"namespace type":      {map[string]any{"namespace": 1}, "namespace argument must be a string"},
		"continue type":       {map[string]any{"continue": true}, "continue argument must be a string"},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := ks.CallTool(context.Background(), "list_configuration_security_scan_summaries", tc.args)
			require.NoError(t, err)
			require.True(t, result.IsError)
			assert.Contains(t, toolResultText(t, result), tc.want)
			assert.Contains(t, toolResultText(t, result), ErrCodeInvalidArgument)
		})
	}
}

func TestListConfigScanSummaries_FullSpecAndContinue(t *testing.T) {
	first := configScanSummary("default", "deployment-web", "Deployment", "web", "default", nil)
	second := configScanSummary("default", "deployment-api", "Deployment", "api", "default", nil)
	client := storagefake.NewClientset()
	// Storage returns only metadata on a LIST without fullSpec. The fake
	// clientset does not page, so serve two pages by continue token.
	client.PrependReactor("list", "workloadconfigurationscansummaries", func(action k8stesting.Action) (bool, runtime.Object, error) {
		opts := action.(k8stesting.ListActionImpl).GetListOptions()
		assert.Equal(t, softwarecomposition.ResourceVersionFullSpec, opts.ResourceVersion)
		assert.Equal(t, int64(100), opts.Limit)
		if opts.Continue == "" {
			return true, &storagev1beta1.WorkloadConfigurationScanSummaryList{
				ListMeta: metav1.ListMeta{Continue: "page-2"},
				Items:    []storagev1beta1.WorkloadConfigurationScanSummary{*first},
			}, nil
		}
		assert.Equal(t, "page-2", opts.Continue)
		return true, &storagev1beta1.WorkloadConfigurationScanSummaryList{Items: []storagev1beta1.WorkloadConfigurationScanSummary{*second}}, nil
	})
	ks := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	page1 := callConfigScanSummaries(t, ks, map[string]any{})
	require.Len(t, page1.Summaries, 1)
	assert.Equal(t, "deployment-web", page1.Summaries[0].ManifestName)
	assert.Equal(t, "page-2", page1.Continue)

	page2 := callConfigScanSummaries(t, ks, map[string]any{"continue": page1.Continue})
	require.Len(t, page2.Summaries, 1)
	assert.Equal(t, "deployment-api", page2.Summaries[0].ManifestName)
	assert.Empty(t, page2.Continue)
}

func TestListConfigScanSummaries_ReadOnlyAnnotations(t *testing.T) {
	tool := newRegisteredStorageToolTestServer().s.GetTool("list_configuration_security_scan_summaries")
	require.NotNil(t, tool, "list_configuration_security_scan_summaries must be registered")
	require.NotNil(t, tool.Tool.Annotations.ReadOnlyHint)
	assert.True(t, *tool.Tool.Annotations.ReadOnlyHint)
	require.NotNil(t, tool.Tool.Annotations.DestructiveHint)
	assert.False(t, *tool.Tool.Annotations.DestructiveHint)
}

func TestListConfigScanSummaries_ListError(t *testing.T) {
	client := storagefake.NewClientset()
	client.PrependReactor("list", "workloadconfigurationscansummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("simulated list error")
	})
	ks := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	result, err := ks.CallTool(context.Background(), "list_configuration_security_scan_summaries", map[string]any{})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, toolResultText(t, result), "failed to list configuration scan summaries: simulated list error")
}
