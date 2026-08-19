package opaprocessor

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestMarkNotEvaluatedControlsSkipped_LeavesPartiallyCollectedControlPassed(t *testing.T) {
	const discoveryKey = "discovery:example.com/v1"
	allFailed := reportsummary.ControlSummary{ControlID: "C-ALL-FAILED"}
	allFailed.SetStatus(&apis.StatusInfo{InnerStatus: apis.StatusPassed})
	partiallyCollected := reportsummary.ControlSummary{ControlID: "C-PARTIAL"}
	partiallyCollected.SetStatus(&apis.StatusInfo{InnerStatus: apis.StatusPassed})

	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-ALL-FAILED": allFailed,
		"C-PARTIAL":    partiallyCollected,
	}
	session.ScanCoverage = cautils.BuildScanCoverage(
		nil,
		map[string][]string{
			discoveryKey:           {"C-ALL-FAILED", "C-PARTIAL"},
			"other.com/v1/gadgets": {"C-PARTIAL"},
		},
		nil,
		[]cautils.PartialGVRPull{{GVR: discoveryKey, Selector: "discovery", Error: "forbidden"}},
		nil,
	)

	opap := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.markNotEvaluatedControlsSkipped()

	allFailed = session.Report.SummaryDetails.Controls["C-ALL-FAILED"]
	assert.Equal(t, apis.StatusSkipped, allFailed.GetStatus().Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, allFailed.GetSubStatus())
	partiallyCollected = session.Report.SummaryDetails.Controls["C-PARTIAL"]
	assert.Equal(t, apis.StatusPassed, partiallyCollected.GetStatus().Status())
}

func TestProcessWithStreaming_PartialDiscoveryFailureDoesNotPassCRDOnlyControl(t *testing.T) {
	ctx := context.Background()

	discoveryClient := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discoveryClient.PrependReactor("get", "resource", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
			{Group: "example.com", Version: "v1"}: errors.New("forbidden"),
		}}
	})

	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "ValidatingAdmissionPolicyList"},
		&unstructured.UnstructuredList{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "ValidatingAdmissionPolicyBindingList"},
		&unstructured.UnstructuredList{},
	)

	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: kubernetesfake.NewClientset(),
		DynamicClient:    dynamicfake.NewSimpleDynamicClient(scheme),
		DiscoveryClient:  discoveryClient,
		Context:          ctx,
	}
	handler := resourcehandler.NewK8sResourceHandler(ctx, k8s, nil, nil, "test-cluster")

	rule := reporthandling.PolicyRule{
		Rule: `package armo_builtins

deny[msga] {
	widget := input[_]
	widget.kind == "Widget"
	msga := {
		"alertMessage": "widget is present",
		"packagename": "armo_builtins",
		"alertScore": 5,
		"fixPaths": [],
		"failedPaths": ["metadata.name"],
		"alertObject": {"k8sApiObjects": [widget]},
	}
}`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{"example.com"},
			APIVersions: []string{"v1"},
			Resources:   []string{"Widget"},
		}},
	}
	rule.Name = "widget-rule"
	control := reporthandling.Control{ControlID: "C-WIDGET", Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "widget control"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "widget framework"

	scanInfo := &cautils.ScanInfo{}
	session := cautils.NewOPASessionObj(ctx, []reporthandling.Framework{framework}, nil, scanInfo, nil)
	session.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

	batchChan, errChan, expectedBatches, err := handler.StreamResourcesBatches(ctx, session, scanInfo)
	require.NoError(t, err)

	opap := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test-cluster", "", "", false, nil)
	require.NoError(t, opap.ProcessWithStreaming(ctx, batchChan, errChan, cautils.NewProgressHandler(""), expectedBatches))

	require.Len(t, session.PartialGVRFailures, 1)
	assert.Equal(t, "discovery:example.com/v1", session.PartialGVRFailures[0].GVR)
	assert.Equal(t, []string{"C-WIDGET"}, session.ResourceToControlsMap["discovery:example.com/v1"])
	require.Contains(t, session.Report.SummaryDetails.Controls, "C-WIDGET")
	widgetSummary := session.Report.SummaryDetails.Controls["C-WIDGET"]
	assert.Equal(t, apis.StatusSkipped, widgetSummary.GetStatus().Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, widgetSummary.GetSubStatus())
	assert.Empty(t, session.ScanCoverage.FailedGVRPulls,
		"the discovery failure is already represented in partialGVRPulls")
	require.Len(t, session.ScanCoverage.PartialGVRPulls, 1)
	require.Len(t, session.ScanCoverage.NotEvaluatedControls, 1)
	assert.Equal(t, "C-WIDGET", session.ScanCoverage.NotEvaluatedControls[0].ControlID)
	assert.Equal(t, []string{"discovery:example.com/v1"}, session.ScanCoverage.NotEvaluatedControls[0].MissingGVRs)
	assert.Equal(t, 0, session.ScanCoverage.EvaluatedControls)
	assert.Equal(t, 1, session.ScanCoverage.TotalControls)
	assert.Zero(t, session.ScanCoverage.CoverageScore)
	assert.True(t, session.ScanCoverage.Degraded)
}
