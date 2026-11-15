package opaprocessor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type precedenceExceptionsGetter []armotypes.PostureExceptionPolicy

func (g precedenceExceptionsGetter) GetExceptions(context.Context, string) ([]armotypes.PostureExceptionPolicy, error) {
	return g, nil
}

// TestMergedExceptionAPIGroupPrecedence exercises loading through status, audit,
// and report serialization, including resources outside each primary's scope.
func TestMergedExceptionAPIGroupPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		primary, secondary         map[string]string
		wantPrimary, wantSecondary []string
		configurePrimary           func(*armotypes.PostureExceptionPolicy)
	}{
		{"core primary and omitted CRD", map[string]string{"apiGroup": ""}, nil, []string{"v1"}, []string{"apps/v1", "applications/v1", "batch/v1", "networking/v1", "xapps/v1"}, nil},
		{"omitted primary and core CRD", nil, map[string]string{"apiGroup": ""}, []string{"v1", "apps/v1", "applications/v1", "batch/v1", "networking/v1", "xapps/v1"}, nil, nil},
		{"regex primary and concrete CRD", map[string]string{"apiGroup": "app.*"}, map[string]string{"apiGroup": "apps"}, []string{"apps/v1", "applications/v1"}, nil, nil},
		{"concrete primary and regex CRD", map[string]string{"apiGroup": "apps"}, map[string]string{"apiGroup": "app.*"}, []string{"apps/v1"}, []string{"applications/v1"}, nil},
		{"regex primary and omitted CRD", map[string]string{"apiGroup": "app.*"}, nil, []string{"apps/v1", "applications/v1"}, []string{"v1", "batch/v1", "networking/v1", "xapps/v1"}, nil},
		{"overlapping regex groups", map[string]string{"apiGroup": "apps|batch"}, map[string]string{"apiGroup": "apps|networking"}, []string{"apps/v1", "batch/v1"}, []string{"networking/v1"}, nil},
		{"selector primary keeps CRD outside labels", nil, map[string]string{"apiGroup": ""}, []string{"apps/v1"}, []string{"v1"}, func(p *armotypes.PostureExceptionPolicy) {
			p.ObjectSelector = &armotypes.LabelSelector{MatchLabels: map[string]string{"group": "apps"}}
		}},
		{"designator label primary keeps CRD outside labels", map[string]string{"group": "apps"}, map[string]string{"apiGroup": ""}, []string{"apps/v1"}, []string{"v1"}, nil},
		{"expired primary keeps CRD", nil, nil, nil, []string{"v1", "apps/v1", "applications/v1", "batch/v1", "networking/v1", "xapps/v1"}, func(p *armotypes.PostureExceptionPolicy) {
			expired := time.Now().Add(-time.Hour)
			p.ExpirationDate = &expired
		}},
		{"different cluster primary keeps CRD", map[string]string{"cluster": "other-cluster"}, map[string]string{"apiGroup": ""}, nil, []string{"v1"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makePolicy := func(name string, attrs map[string]string, action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
				attributes := map[string]string{identifiers.AttributeName: "web"}
				for k, v := range attrs {
					attributes[k] = v
				}
				return armotypes.PostureExceptionPolicy{PortalBase: armotypes.PortalBase{Name: name}, Actions: []armotypes.PostureExceptionPolicyActions{action}, Resources: []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorAttributes, Attributes: attributes}}, PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001"}}}
			}
			primary := precedenceExceptionsGetter{makePolicy("primary", tc.primary, armotypes.AlertOnly)}
			secondary := precedenceExceptionsGetter{makePolicy("crd", tc.secondary, armotypes.Disable)}
			if tc.configurePrimary != nil {
				tc.configurePrimary(&primary[0])
			}
			before, err := json.Marshal([]precedenceExceptionsGetter{primary, secondary})
			require.NoError(t, err)
			merged, err := getter.NewMergedExceptionsGetter(primary, secondary).GetExceptions(context.Background(), "cluster-a")
			require.NoError(t, err)
			after, err := json.Marshal([]precedenceExceptionsGetter{primary, secondary})
			require.NoError(t, err)
			assert.JSONEq(t, string(before), string(after), "merging must not mutate its inputs")
			// Source provenance must also survive a policy JSON round trip.
			data, err := json.Marshal(merged)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, &merged))
			session := cautils.NewOPASessionObjMock()
			session.Exceptions = merged
			session.AuditExceptions = true
			session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}}}
			session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0001": {ControlID: "C-0001"}}
			expected := map[string]string{}
			for _, v := range tc.wantPrimary {
				expected[v] = "primary"
			}
			for _, v := range tc.wantSecondary {
				expected[v] = "crd"
			}
			for _, v := range []string{"v1", "apps/v1", "applications/v1", "batch/v1", "networking/v1", "xapps/v1"} {
				resource := workloadinterface.NewWorkloadObj(map[string]any{"apiVersion": v, "kind": "Pod", "metadata": map[string]any{"name": "web", "namespace": "default", "labels": map[string]any{"group": strings.Split(v, "/")[0]}}})
				session.AllResources[resource.GetID()] = resource
				session.ResourcesResult[resource.GetID()] = resourcesresults.Result{ResourceID: resource.GetID(), AssociatedControls: []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0001", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "test-rule", Status: apis.StatusFailed}}}}}
			}
			opap := &OPAProcessor{OPASessionObj: session, clusterName: "cluster-a"}
			opap.updateResults(context.Background())
			for id, result := range session.ResourcesResult {
				version := session.AllResources[id].GetObject()["apiVersion"].(string)
				want := expected[version]
				check := func(result resourcesresults.Result) {
					matched := result.AssociatedControls[0].ResourceAssociatedRules[0].Exception
					if want == "" {
						assert.Empty(t, matched, version)
					} else if assert.Len(t, matched, 1, version) {
						assert.Equal(t, want, matched[0].Name, version)
					}
					assert.Equal(t, want == "crd", result.GetStatus(nil).IsPassed(), version)
				}
				check(result)
				encoded, err := json.Marshal(result)
				require.NoError(t, err)
				var restored resourcesresults.Result
				require.NoError(t, json.Unmarshal(encoded, &restored))
				check(restored)
			}
			for _, item := range session.ExceptionAudit.Items {
				want := len(tc.wantPrimary)
				if item.Name == "crd" {
					want = len(tc.wantSecondary)
				}
				assert.Equal(t, want, item.MatchCount, item.Name)
			}
		})
	}
}
