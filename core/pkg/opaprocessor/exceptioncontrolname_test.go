package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An exception that picks its control only by controlName (deprecated) must not
// hide every failed control on the resource (#5810). A controlID exception still
// hides just that control.
func TestExceptionByControlNameDoesNotHideOtherControls(t *testing.T) {
	for _, tc := range []struct {
		name         string
		policy       armotypes.PosturePolicy
		wantExcepted []string
	}{
		{"controlName only", armotypes.PosturePolicy{ControlName: "Privileged container"}, nil},
		{"controlName with framework", armotypes.PosturePolicy{FrameworkName: "NSA", ControlName: "Privileged container"}, nil},
		{"controlID", armotypes.PosturePolicy{ControlID: "C-0057"}, []string{"C-0057"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.Exceptions = []armotypes.PostureExceptionPolicy{{
				PortalBase: armotypes.PortalBase{Name: "exclude-privileged"},
				Actions:    []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
				Resources: []identifiers.PortalDesignator{{
					DesignatorType: identifiers.DesignatorAttributes,
					Attributes:     map[string]string{identifiers.AttributeName: "web"},
				}},
				PosturePolicies: []armotypes.PosturePolicy{tc.policy},
			}}
			session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{
				"C-0048": {ControlID: "C-0048", PortalBase: armotypes.PortalBase{Name: "HostPath mount"}},
				"C-0057": {ControlID: "C-0057", PortalBase: armotypes.PortalBase{Name: "Privileged container"}},
			}}
			session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
				"C-0048": {ControlID: "C-0048", Name: "HostPath mount"},
				"C-0057": {ControlID: "C-0057", Name: "Privileged container"},
			}
			resource := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"name": "web", "namespace": "default"},
			})
			session.AllResources[resource.GetID()] = resource
			failed := func(id, name string) resourcesresults.ResourceAssociatedControl {
				return resourcesresults.ResourceAssociatedControl{
					ControlID:               id,
					Name:                    name,
					Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule-" + id, Status: apis.StatusFailed}},
				}
			}
			session.ResourcesResult[resource.GetID()] = resourcesresults.Result{
				ResourceID: resource.GetID(),
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					failed("C-0048", "HostPath mount"),
					failed("C-0057", "Privileged container"),
				},
			}

			opap := &OPAProcessor{OPASessionObj: session, clusterName: "cluster-a"}
			opap.updateResults(context.Background())

			result := session.ResourcesResult[resource.GetID()]
			require.Len(t, result.AssociatedControls, 2)
			var excepted []string
			for i := range result.AssociatedControls {
				control := &result.AssociatedControls[i]
				if len(control.ResourceAssociatedRules[0].Exception) > 0 {
					excepted = append(excepted, control.GetID())
					continue
				}
				assert.True(t, control.GetStatus(nil).IsFailed(), "%s should stay failed: %s", control.GetID(), control.GetStatus(nil).Status())
			}
			assert.Equal(t, tc.wantExcepted, excepted)
		})
	}
}
