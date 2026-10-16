package resultshandling

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestFrameworkScopedVAPCoverage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mitre bool
		want  int
	}{{name: "NSA only"}, {name: "NSA and MITRE", mitre: true, want: 1}} {
		t.Run(tc.name, func(t *testing.T) {
			resource := workloadinterface.NewWorkloadObj(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "app", "namespace": "default"}})
			id := resource.GetID()
			control := reportsummary.ControlSummary{ControlID: "C-0034", ScoreFactor: 7}
			policy := unstructured.Unstructured{}
			policy.SetName("policy")
			policy.SetLabels(map[string]string{"controlId": "C-0034"})
			binding := unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"policyName": "policy"}}}
			binding.SetName("binding")
			session := &cautils.OPASessionObj{
				Report:          &reporthandlingv2.PostureReport{SummaryDetails: reportsummary.SummaryDetails{Controls: reportsummary.ControlSummaries{"C-0034": control}, Frameworks: []reportsummary.FrameworkSummary{{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0034": control}}}}},
				ResourcesResult: map[string]resourcesresults.Result{id: {ResourceID: id, AssociatedControls: []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "R1", Status: apis.StatusFailed, Exception: []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"}}}}}}}}}},
				AllResources:    map[string]workloadinterface.IMetadata{id: resource}, VAPPolicies: []unstructured.Unstructured{policy}, VAPBindings: []unstructured.Unstructured{binding},
			}
			if tc.mitre {
				session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: "MITRE", Controls: reportsummary.ControlSummaries{"C-0034": control}})
			}
			handler := &ResultsHandler{ScanData: session, UiPrinter: &SpyPrinter{}}
			require.NoError(t, handler.HandleResults(context.Background(), &cautils.ScanInfo{}))
			if tc.want == 0 {
				require.NotContains(t, session.VAPCoverage, "C-0034")
			} else {
				require.Contains(t, session.VAPCoverage, "C-0034")
				require.Len(t, session.VAPCoverage["C-0034"].Resources, tc.want)
			}
			require.Equal(t, apis.StatusFailed, session.ResourcesResult[id].AssociatedControls[0].ResourceAssociatedRules[0].Status)
		})
	}
}
