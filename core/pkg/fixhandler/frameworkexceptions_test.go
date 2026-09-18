package fixhandler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

func TestFrameworkScopedFixes(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		mitre, otherControl, mixed bool
		want                       int
	}{
		{name: "single framework"},
		{name: "partial framework coverage", mitre: true, want: 1},
		{name: "unrelated framework control", mitre: true, otherControl: true},
		{name: "mixed rules", mixed: true, want: 1},
	} {
		for _, helm := range []bool{false, true} {
			name := tc.name + "/yaml"
			if helm {
				name = tc.name + "/helm"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec: {}\n")
				resource := buildResource(t, dir, "deploy.yaml", "Deployment", "app", 0)
				if helm {
					resource.Source.FileType = reporthandling.SourceTypeHelmChart
					resource.Source.HelmPath = "/chart"
				}
				rule := failedRuleWithFix("spec.replicas", "2")
				rule.Exception = []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: rule.Name}}}}
				control := failedControl("C-0034", "test", rule)
				if tc.mixed {
					control.ResourceAssociatedRules = append(control.ResourceAssociatedRules, failedRuleWithFix("spec.hostNetwork", "false"))
				}
				h := newHandlerForResources(dir, []resourcesresults.Result{{ResourceID: resource.GetID(), AssociatedControls: []resourcesresults.ResourceAssociatedControl{control}}}, []reporthandling.Resource{*resource}, false)
				h.reportObj.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}}}
				if tc.mitre {
					id := "C-0034"
					if tc.otherControl {
						id = "C-0286"
					}
					h.reportObj.SummaryDetails.Frameworks = append(h.reportObj.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: "MITRE", Controls: reportsummary.ControlSummaries{id: {ControlID: id}}})
				}
				before, err := json.Marshal(h.reportObj)
				require.NoError(t, err)
				selected, total := h.controlSelectionCounts()
				require.Equal(t, tc.want, selected)
				require.Equal(t, tc.want, total)
				if helm {
					suggestions := h.PrepareHelmSuggestions(context.Background())
					require.Len(t, suggestions, tc.want)
					if tc.want > 0 {
						require.Len(t, suggestions[0].FixPaths, 1)
						if tc.mixed {
							require.Equal(t, "spec.hostNetwork", suggestions[0].FixPaths[0].Path)
						}
					}
				} else {
					fixes := h.PrepareResourcesToFix(context.Background())
					require.Len(t, fixes, tc.want)
					require.Empty(t, h.UnfixedControls())
					require.Equal(t, tc.want, h.FixedControlsCount())
					if tc.want > 0 {
						require.Len(t, fixes[0].YamlExpressions, 1)
						if tc.mixed {
							for _, path := range fixes[0].YamlExpressions {
								require.Equal(t, "spec.hostNetwork", path.Path)
							}
						}
					}
				}
				after, err := json.Marshal(h.reportObj)
				require.NoError(t, err)
				require.JSONEq(t, string(before), string(after))
				require.Equal(t, apis.StatusFailed, h.reportObj.Results[0].AssociatedControls[0].ResourceAssociatedRules[0].Status)
			})
		}
	}
}

func TestFrameworkScopedPlannedPathCoverage(t *testing.T) {
	excepted := failedRuleNoFixAtPath("spec.replicas")
	excepted.Exception = []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: excepted.Name}}}}
	control := failedControl("C-0034", "mixed", excepted, failedRuleNoFixAtPath("spec.hostNetwork"))
	summary := reportsummary.SummaryDetails{Frameworks: []reportsummary.FrameworkSummary{{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}}}}
	planned := []plannedFix{{Path: "spec.hostNetwork", Value: "false"}}
	require.True(t, controlIsCoveredByPlannedPaths(&control, planned, &summary), "excepted rule must not block coverage of the remaining failure")
	summary.Frameworks = append(summary.Frameworks, reportsummary.FrameworkSummary{Name: "MITRE", Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}})
	require.False(t, controlIsCoveredByPlannedPaths(&control, planned, &summary), "MITRE still requires remediation of the first rule")
}
