package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestPredictPSSDoesNotPassEmptyContainerTemplate(t *testing.T) {
	deployment := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	require.NoError(t, unstructured.SetNestedSlice(deployment.Object, []any{}, "spec", "template", "spec", "containers"))
	server := newPSSPredictorTestServer(t, deployment)
	result := registeredToolResult(t, dispatchRegisteredTool(t, server, "predict_pss_compliance", map[string]any{"namespace": "test-pss", "level": "Restricted"}))
	require.False(t, result.IsError, "a decode warning is reported in the analysis result")
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	require.Equal(t, float64(0), summary["passing"])
	require.Equal(t, float64(1), summary["unevaluated"])
	require.Equal(t, false, summary["current_effective_level_complete"])
	require.NotEmpty(t, parsed["decode_warnings"])
}
