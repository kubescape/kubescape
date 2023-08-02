package opaprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func TestConvertFrameworksToPolicies(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()
	scanningScope := cautils.GetScanningScope(&cautils.ScanInfo{InputPatterns: []string{""}})
	policies := ConvertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, "", nil, scanningScope)
	assert.Equal(t, 2, len(policies.Frameworks))
	assert.Equal(t, 3, len(policies.Controls))

	// with excluded rules map
	excludedRulesMap := map[string]bool{
		"alert-rw-hostpath": true,
	}
	fw0 = mocks.MockFramework_0006_0013()
	fw1 = mocks.MockFramework_0044()
	policies = ConvertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, "", excludedRulesMap, scanningScope)
	assert.Equal(t, 2, len(policies.Frameworks))
	assert.Equal(t, 2, len(policies.Controls))

}
func TestInitializeSummaryDetails(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()
	scanningScope := cautils.GetScanningScope(&cautils.ScanInfo{InputPatterns: []string{""}})

	summaryDetails := reportsummary.SummaryDetails{}
	frameworks := []reporthandling.Framework{*fw0, *fw1}
	policies := ConvertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, "", nil, scanningScope)
	ConvertFrameworksToSummaryDetails(&summaryDetails, frameworks, policies)
	assert.Equal(t, 2, len(summaryDetails.Frameworks))
	// assert.Equal(t, 3, len(summaryDetails.Controls))
}
