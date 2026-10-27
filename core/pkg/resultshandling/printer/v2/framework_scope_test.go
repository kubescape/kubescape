package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameworkScopedSARIFEvidenceKeepsCorrelatedRule(t *testing.T) {
	summary := reportsummary.SummaryDetails{Frameworks: []reportsummary.FrameworkSummary{{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}}}}
	rule := resourcesresults.ResourceAssociatedRule{Name: "R1", Status: apis.StatusFailed, Paths: []armotypes.PosturePaths{{ReviewPath: "spec.replicas"}}, Exception: []armotypes.PostureExceptionPolicy{
		{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-OTHER", RuleName: "R1"}}},
		{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"}}},
	}}
	control := resourcesresults.ResourceAssociatedControl{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{rule}}
	evidence := cautils.FailedRules(&summary, control)
	require.Len(t, evidence.ResourceAssociatedRules, 1)
	fragments := sarifEvidenceIdentity(&evidence)
	require.Len(t, fragments, 1)
	assert.Equal(t, "R1", fragments[0].RuleName)
	assert.Equal(t, []string{"spec.replicas"}, fragments[0].ReviewPaths)
}
