package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A primary AlertOnly exception whose framework scope covers a CRD's Disable takes
// precedence over it, so the finding stays failed for that framework. Real framework
// names have dots in them (cis-v1.10.0), and the primary must cover those as well.
func TestMergedExceptionPrecedenceForFrameworkNamesWithDots(t *testing.T) {
	for _, tc := range []struct{ name, primaryFramework, crdFramework string }{
		{"a pattern covers a CIS framework name", "cis-.*", "cis-v1.10.0"},
		{"the same name in another case", "CIS-v1.10.0", "cis-v1.10.0"},
		{"a name without dots", "CIS.*", "CIS-Benchmark"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := func(name, framework string, action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
				return armotypes.PostureExceptionPolicy{
					PortalBase: armotypes.PortalBase{Name: name},
					Actions:    []armotypes.PostureExceptionPolicyActions{action},
					Resources: []identifiers.PortalDesignator{{
						DesignatorType: identifiers.DesignatorAttributes,
						Attributes:     map[string]string{identifiers.AttributeName: "web"},
					}},
					PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001", FrameworkName: framework}},
				}
			}
			primary := precedenceExceptionsGetter{policy("primary", tc.primaryFramework, armotypes.AlertOnly)}
			secondary := precedenceExceptionsGetter{policy("crd", tc.crdFramework, armotypes.Disable)}
			merged, err := getter.NewMergedExceptionsGetter(primary, secondary).GetExceptions(context.Background(), "cluster-a")
			require.NoError(t, err)

			session := cautils.NewOPASessionObjMock()
			session.Exceptions = merged
			session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}}}
			session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0001": {ControlID: "C-0001"}}
			resource := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"name": "web", "namespace": "default"},
			})
			session.AllResources[resource.GetID()] = resource
			session.ResourcesResult[resource.GetID()] = resourcesresults.Result{
				ResourceID: resource.GetID(),
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
					ControlID:               "C-0001",
					Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "test-rule", Status: apis.StatusFailed}},
				}},
			}

			opap := &OPAProcessor{OPASessionObj: session, clusterName: "cluster-a"}
			opap.updateResults(context.Background())

			result := session.ResourcesResult[resource.GetID()]
			var names []string
			for _, exception := range result.AssociatedControls[0].ResourceAssociatedRules[0].Exception {
				names = append(names, exception.Name)
			}
			assert.Equal(t, []string{"primary"}, names, "the primary exception takes precedence")
			status := result.GetStatus(&helpersv1.Filters{FrameworkNames: []string{tc.crdFramework}})
			assert.True(t, status.IsFailed(), "the finding is hidden for %s: %s", tc.crdFramework, status.Status())
		})
	}
}

// An escaped-dot primary pattern does not cover a dot-only CRD regex, because the
// CRD regex matches framework names with hyphens (cis-v1-10-0) outside the primary's
// scope. The CRD exception must not be dropped, and its Disable action must take
// effect for framework names outside the primary's scope.
func TestMergedExceptionPrecedenceForDotOnlyRegexes(t *testing.T) {
	policy := func(name, framework string, action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
		return armotypes.PostureExceptionPolicy{
			PortalBase: armotypes.PortalBase{Name: name},
			Actions:    []armotypes.PostureExceptionPolicyActions{action},
			Resources: []identifiers.PortalDesignator{{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeName: "web"},
			}},
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001", FrameworkName: framework}},
		}
	}
	// Primary specifies literal dot (\.), whereas CRD specifies unescaped dot (.).
	primary := precedenceExceptionsGetter{policy("primary", "cis\\.v1.*", armotypes.AlertOnly)}
	secondary := precedenceExceptionsGetter{policy("crd", "cis.v1.10.0", armotypes.Disable)}
	merged, err := getter.NewMergedExceptionsGetter(primary, secondary).GetExceptions(context.Background(), "cluster-a")
	require.NoError(t, err)

	session := cautils.NewOPASessionObjMock()
	session.Exceptions = merged
	session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}}}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0001": {ControlID: "C-0001"}}
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "web", "namespace": "default"},
	})
	session.AllResources[resource.GetID()] = resource
	session.ResourcesResult[resource.GetID()] = resourcesresults.Result{
		ResourceID: resource.GetID(),
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
			ControlID:               "C-0001",
			Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "test-rule", Status: apis.StatusFailed}},
		}},
	}

	opap := &OPAProcessor{OPASessionObj: session, clusterName: "cluster-a"}
	opap.updateResults(context.Background())

	result := session.ResourcesResult[resource.GetID()]
	var names []string
	for _, exception := range result.AssociatedControls[0].ResourceAssociatedRules[0].Exception {
		names = append(names, exception.Name)
	}
	assert.Contains(t, names, "crd", "the CRD exception must not be dropped when primary only covers a literal dot")

	// For a framework name matching the CRD regex's dot wildcard but not the primary's literal dot:
	// The CRD exception was preserved, so its Disable action takes effect.
	statusHyphen := result.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"cis-v1-10-0"}})
	assert.True(t, statusHyphen.IsPassed(), "CRD Disable must take effect for framework outside primary scope: %s", statusHyphen.Status())
}

func TestMergedExceptionPrecedenceForCharacterClassVsDotOnlyRegex(t *testing.T) {
	policy := func(name, framework string, action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
		return armotypes.PostureExceptionPolicy{
			PortalBase: armotypes.PortalBase{Name: name},
			Actions:    []armotypes.PostureExceptionPolicyActions{action},
			Resources: []identifiers.PortalDesignator{{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes:     map[string]string{identifiers.AttributeName: "web"},
			}},
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001", FrameworkName: framework}},
		}
	}
	primary := precedenceExceptionsGetter{policy("primary", "cis[-_.]v1[-_.]10[-_.]0", armotypes.AlertOnly)}
	secondary := precedenceExceptionsGetter{policy("crd", "cis.v1.10.0", armotypes.Disable)}
	merged, err := getter.NewMergedExceptionsGetter(primary, secondary).GetExceptions(context.Background(), "cluster-a")
	require.NoError(t, err)

	session := cautils.NewOPASessionObjMock()
	session.Exceptions = merged
	session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}}}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0001": {ControlID: "C-0001"}}
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "web", "namespace": "default"},
	})
	session.AllResources[resource.GetID()] = resource
	session.ResourcesResult[resource.GetID()] = resourcesresults.Result{
		ResourceID: resource.GetID(),
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
			ControlID:               "C-0001",
			Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "test-rule", Status: apis.StatusFailed}},
		}},
	}

	opap := &OPAProcessor{OPASessionObj: session, clusterName: "cluster-a"}
	opap.updateResults(context.Background())

	result := session.ResourcesResult[resource.GetID()]
	var names []string
	for _, exception := range result.AssociatedControls[0].ResourceAssociatedRules[0].Exception {
		names = append(names, exception.Name)
	}
	assert.Contains(t, names, "crd", "the CRD exception must not be dropped when primary only covers a character class")

	// For a framework name with '+' matching the CRD regex's dot wildcard but not the primary's character class [-_.]:
	// The CRD exception was preserved, so its Disable action takes effect.
	statusPlus := result.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"cis+v1+10+0"}})
	assert.True(t, statusPlus.IsPassed(), "CRD Disable must take effect for framework outside primary scope: %s", statusPlus.Status())
}
