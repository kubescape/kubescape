package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertFrameworksToPolicies(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()
	scanningScope := cautils.GetScanningScope(v2.ContextMetadata{ClusterContextMetadata: &v2.ClusterMetadata{}})
	policies := convertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, nil, scanningScope)
	assert.Equal(t, 2, len(policies.Frameworks))
	assert.Equal(t, 3, len(policies.Controls))

	// with excluded rules map
	excludedRulesMap := map[string]bool{
		"alert-rw-hostpath": true,
	}
	fw0 = mocks.MockFramework_0006_0013()
	fw1 = mocks.MockFramework_0044()
	policies = convertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, excludedRulesMap, scanningScope)
	assert.Equal(t, 2, len(policies.Frameworks))
	assert.Equal(t, 2, len(policies.Controls))

}
func TestInitializeSummaryDetails(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()
	scanningScope := cautils.GetScanningScope(v2.ContextMetadata{ClusterContextMetadata: &v2.ClusterMetadata{}})

	summaryDetails := reportsummary.SummaryDetails{}
	frameworks := []reporthandling.Framework{*fw0, *fw1}
	policies := convertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, nil, scanningScope)
	ConvertFrameworksToSummaryDetails(&summaryDetails, frameworks, policies)
	assert.Equal(t, 2, len(summaryDetails.Frameworks))
	// assert.Equal(t, 3, len(summaryDetails.Controls))
}

func TestInitializeSummaryDetails_ManualReviewControl(t *testing.T) {
	framework := reporthandling.Framework{
		PortalBase: armotypes.PortalBase{Name: "test-framework"},
		Controls: []reporthandling.Control{
			{
				PortalBase:  armotypes.PortalBase{Name: "manual review control"},
				ControlID:   "C-0001",
				Description: "requires human review",
				Remediation: "inspect manually",
				BaseScore:   3.5,
			},
			{
				PortalBase:  armotypes.PortalBase{Name: "not selected"},
				ControlID:   "C-0002",
				Description: "should be skipped because it is not in policies",
			},
		},
	}
	framework.Controls[0].Attributes = map[string]interface{}{
		reporthandling.ActionRequiredAttribute: string(apis.SubStatusManualReview),
	}

	policies := cautils.NewPolicies()
	policies.Frameworks = []string{framework.Name}
	policies.Controls = map[string]reporthandling.Control{
		"C-0001": framework.Controls[0],
	}

	summaryDetails := reportsummary.SummaryDetails{}
	ConvertFrameworksToSummaryDetails(&summaryDetails, []reporthandling.Framework{framework}, policies)

	require.Len(t, summaryDetails.Frameworks, 1)
	require.Contains(t, summaryDetails.Controls, "C-0001")
	assert.NotContains(t, summaryDetails.Controls, "C-0002")

	ctrl := summaryDetails.Controls["C-0001"]
	assert.Equal(t, apis.StatusSkipped, ctrl.Status)
	assert.Equal(t, apis.StatusSkipped, ctrl.StatusInfo.InnerStatus)
	assert.Equal(t, apis.SubStatusManualReview, ctrl.StatusInfo.SubStatus)
	assert.Equal(t, string(apis.SubStatusManualReviewInfo), ctrl.StatusInfo.InnerInfo)
	assert.Equal(t, float32(3.5), ctrl.ScoreFactor)
	assert.Equal(t, "requires human review", ctrl.Description)
	assert.Equal(t, "inspect manually", ctrl.Remediation)
	assert.NotNil(t, summaryDetails.Frameworks[0].Controls)
	assert.Contains(t, summaryDetails.Frameworks[0].Controls, "C-0001")
	assert.NotContains(t, summaryDetails.Frameworks[0].Controls, "C-0002")
}
