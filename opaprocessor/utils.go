package opaprocessor

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
)

// ConvertFrameworksToPolicies convert list of frameworks to list of policies
func ConvertFrameworksToPolicies(frameworks []reporthandling.Framework, version string) *cautils.Policies {
	policies := cautils.NewPolicies()
	policies.Set(frameworks, version)
	return policies
}

// initializeReport initialize the summary details for the report object
func initializeSummaryDetails(summaryDetails *reportsummary.SummaryDetails, frameworks []reporthandling.Framework) {

	for i := range frameworks {
		controls := map[string]reportsummary.ControlSummary{}
		for j := range frameworks[i].Controls {
			id := frameworks[i].Controls[j].ControlID
			c := reportsummary.ControlSummary{
				Name: frameworks[i].Controls[j].Name,
			}
			controls[frameworks[i].Controls[j].ControlID] = c
			summaryDetails.Controls[id] = c
		}
		summaryDetails.Frameworks = append(summaryDetails.Frameworks, reportsummary.FrameworkSummary{
			Name:     frameworks[i].Name,
			Controls: controls,
		})
	}

	// opap.Report.GenerateSummary()
}
