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

// ConvertFrameworksToSummaryDetails initialize the summary details for the report object
func ConvertFrameworksToSummaryDetails(summaryDetails *reportsummary.SummaryDetails, frameworks []reporthandling.Framework, policies *cautils.Policies) {
	if summaryDetails.Controls == nil {
		summaryDetails.Controls = make(map[string]reportsummary.ControlSummary)
	}
	for i := range frameworks {
		controls := map[string]reportsummary.ControlSummary{}
		for j := range frameworks[i].Controls {
			id := frameworks[i].Controls[j].ControlID
			if _, ok := policies.Controls[id]; ok {
				c := reportsummary.ControlSummary{
					Name:        frameworks[i].Controls[j].Name,
					ControlID:   id,
					ScoreFactor: frameworks[i].Controls[j].BaseScore,
					Description: frameworks[i].Controls[j].Description,
					Remediation: frameworks[i].Controls[j].Remediation,
				}
				controls[frameworks[i].Controls[j].ControlID] = c
				summaryDetails.Controls[id] = c
			}
		}
		if cautils.StringInSlice(policies.Frameworks, frameworks[i].Name) != cautils.ValueNotFound {
			summaryDetails.Frameworks = append(summaryDetails.Frameworks, reportsummary.FrameworkSummary{
				Name:     frameworks[i].Name,
				Controls: controls,
			})
		}
	}

}
