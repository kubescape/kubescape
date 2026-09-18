package opaprocessor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameworkScopedManualExceptions(t *testing.T) {
	tests := []struct {
		name       string
		policies   []armotypes.PosturePolicy
		frameworks []string
		excepted   map[string]bool
		aggregate  bool
	}{
		{name: "none", frameworks: []string{"NSA", "MITRE"}},
		{name: "NSA", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "MITRE", policies: []armotypes.PosturePolicy{{FrameworkName: "MITRE", ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"MITRE": true}},
		{name: "global", policies: []armotypes.PosturePolicy{{ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true, "MITRE": true}, aggregate: true},
		{name: "case insensitive", policies: []armotypes.PosturePolicy{{FrameworkName: "nsa", ControlID: "c-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "regex", policies: []armotypes.PosturePolicy{{FrameworkName: "N.*", ControlID: "C-028[6]"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "regex mismatch", policies: []armotypes.PosturePolicy{{FrameworkName: "N.*", ControlID: "C-0286"}}, frameworks: []string{"XNSA", "MITRE"}},
		{name: "tuples", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0287"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "both", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true, "MITRE": true}, aggregate: true},
		{name: "single", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}}, frameworks: []string{"NSA"}, excepted: map[string]bool{"NSA": true}, aggregate: true},
		{name: "missing framework scoped", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}}},
		{name: "missing framework global", policies: []armotypes.PosturePolicy{{ControlID: "C-0286"}}, aggregate: true},
		{name: "unnamed framework", policies: []armotypes.PosturePolicy{{FrameworkName: ".*", ControlID: "C-0286"}}, frameworks: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				session := cautils.NewOPASessionObjMock()
				session.AuditExceptions = true
				manual := reportsummary.ControlSummary{ControlID: "C-0286", StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}}
				session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0286": manual}
				for i := range tt.frameworks {
					if reverse {
						i = len(tt.frameworks) - 1 - i
					}
					session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: tt.frameworks[i], Controls: reportsummary.ControlSummaries{"C-0286": manual}})
				}
				if tt.policies != nil {
					session.Exceptions = []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{Name: "manual exception"}, PosturePolicies: tt.policies}}
				}
				before, err := json.Marshal(session.Exceptions)
				require.NoError(t, err)
				opap := &OPAProcessor{OPASessionObj: session}
				opap.updateResults(context.Background())
				after, err := json.Marshal(session.Exceptions)
				require.NoError(t, err)
				assert.JSONEq(t, string(before), string(after), "input policies must remain intact")
				check := func(sd reportsummary.SummaryDetails) {
					assertManualExceptionStatus(t, sd.Controls["C-0286"], tt.aggregate)
					for _, fw := range sd.Frameworks {
						assertManualExceptionStatus(t, fw.Controls["C-0286"], tt.excepted[fw.Name])
					}
				}
				check(session.Report.SummaryDetails)
				data, err := json.Marshal(session.Report.SummaryDetails)
				require.NoError(t, err)
				var restored reportsummary.SummaryDetails
				require.NoError(t, json.Unmarshal(data, &restored))
				check(restored)
				if tt.policies != nil {
					require.Len(t, opap.ExceptionAudit.Items, 1)
					wantCount := 0
					if tt.aggregate || len(tt.excepted) > 0 {
						wantCount = 1
					}
					assert.Equal(t, wantCount, opap.ExceptionAudit.Items[0].MatchCount)
				}
			}
		})
	}
}

func assertManualExceptionStatus(t *testing.T, ctrl reportsummary.ControlSummary, excepted bool) {
	t.Helper()
	status, sub := apis.StatusSkipped, apis.SubStatusManualReview
	if excepted {
		status, sub = apis.StatusPassed, apis.SubStatusException
	}
	assert.Equal(t, status, ctrl.GetStatus().Status())
	assert.Equal(t, sub, ctrl.GetStatus().GetSubStatus())
}

func TestFrameworkScopedManualMembershipAndAudit(t *testing.T) {
	for _, action := range []armotypes.PostureExceptionPolicyActions{"", armotypes.Disable, armotypes.AlertOnly} {
		name := string(action)
		if name == "" {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.AuditExceptions = true
			manual := reportsummary.ControlSummary{ControlID: "C-0286", StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}}
			session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0286": manual}
			session.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{
				{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0286": manual}},
				{Name: "MITRE", Controls: reportsummary.ControlSummaries{}},
			}
			session.Exceptions = []armotypes.PostureExceptionPolicy{{
				PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0287"}},
			}}
			if action != "" {
				session.Exceptions[0].Actions = []armotypes.PostureExceptionPolicyActions{action}
			}
			key := exceptionAuditKey(session.Exceptions[0])
			opap := &OPAProcessor{OPASessionObj: session}
			opap.updateResults(context.Background())
			assertManualExceptionStatus(t, session.Report.SummaryDetails.Controls["C-0286"], true)
			require.Len(t, session.ExceptionAudit.Items, 1)
			assert.Equal(t, 1, session.ExceptionAudit.Items[0].MatchCount)
			assert.Equal(t, key, exceptionAuditKey(session.Exceptions[0]), "unnamed exception identity remains intact")
			assert.Len(t, session.ExceptionAudit.Items[0].ControlIDs, 2, "audit retains original tuples, including unmatched controls")
		})
	}
}

func TestFrameworkScopedResourceExceptions(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		frameworks  []string
		want        map[string]apis.ScanningStatus
		aggregate   apis.ScanningStatus
	}{
		{"none", "none", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusFailed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"NSA", "NSA", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"global", "", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusPassed}, apis.StatusPassed},
		{"single", "NSA", []string{"NSA"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed}, apis.StatusPassed},
		{"case insensitive", "nsa", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"regex", "N.*", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"tuples", "NSA", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				session := cautils.NewOPASessionObjMock()
				resource := workloadinterface.NewWorkloadObj(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "test", "namespace": "default"}})
				session.AllResources[resource.GetID()] = resource
				session.ResourcesResult[resource.GetID()] = resourcesresults.Result{ResourceID: resource.GetID(), AssociatedControls: []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "R1", Status: apis.StatusFailed}}}}}
				session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{"C-0034": {ControlID: "C-0034"}}}
				session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}
				for i := range tc.frameworks {
					if reverse {
						i = len(tc.frameworks) - 1 - i
					}
					session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: tc.frameworks[i], Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}})
				}
				if tc.scope != "none" {
					session.Exceptions = []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: tc.scope, ControlID: "C-0034", RuleName: "R1"}}}}
				}
				if tc.name == "tuples" {
					session.Exceptions[0].PosturePolicies = append(session.Exceptions[0].PosturePolicies, armotypes.PosturePolicy{FrameworkName: "MITRE", ControlID: "C-0034", RuleName: "R2"})
				}
				opap := &OPAProcessor{OPASessionObj: session}
				opap.updateResults(context.Background())
				check := func(sd reportsummary.SummaryDetails) {
					ctrl := sd.Controls["C-0034"]
					assert.Equal(t, tc.aggregate, ctrl.GetStatus().Status())
					assert.Equal(t, tc.aggregate, sd.GetStatus().Status())
					for _, fw := range sd.Frameworks {
						c := fw.Controls["C-0034"]
						assert.Equal(t, tc.want[fw.Name], c.GetStatus().Status(), fw.Name)
						wantSub := apis.SubStatusUnknown
						if tc.want[fw.Name] == apis.StatusPassed {
							wantSub = apis.SubStatusException
						}
						assert.Equal(t, wantSub, c.GetStatus().GetSubStatus(), fw.Name)
					}
				}
				check(session.Report.SummaryDetails)
				data, err := json.Marshal(session.Report.SummaryDetails)
				require.NoError(t, err)
				var restored reportsummary.SummaryDetails
				require.NoError(t, json.Unmarshal(data, &restored))
				check(restored)
				resultData, err := json.Marshal(session.ResourcesResult[resource.GetID()])
				require.NoError(t, err)
				var restoredResult resourcesresults.Result
				require.NoError(t, json.Unmarshal(resultData, &restoredResult))
				assert.Equal(t, tc.aggregate, cautils.ResourceStatus(&restored, &restoredResult).Status())
				assert.Equal(t, apis.StatusFailed, session.ResourcesResult[resource.GetID()].AssociatedControls[0].ResourceAssociatedRules[0].Status, "raw evaluation remains failed")
			}
		})
	}
}
