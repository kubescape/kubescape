package v1

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v4/core/pkg/policyhandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/stretchr/testify/require"
)

var exclusionProbeSequence atomic.Uint64

type exclusionFixtureGetter struct {
	framework reporthandling.Framework
	loads     int
}

func (g *exclusionFixtureGetter) ShouldPersistPolicyArtifacts() bool { return false }
func (g *exclusionFixtureGetter) GetFramework(string) (*reporthandling.Framework, error) {
	g.loads++
	return &g.framework, nil
}
func (g *exclusionFixtureGetter) GetFrameworks() ([]reporthandling.Framework, error) {
	return []reporthandling.Framework{g.framework}, nil
}
func (g *exclusionFixtureGetter) GetControl(string) (*reporthandling.Control, error) {
	return nil, fmt.Errorf("fixture only supports framework scans")
}
func (g *exclusionFixtureGetter) ListFrameworks() ([]string, error) {
	return []string{g.framework.Name}, nil
}
func (g *exclusionFixtureGetter) ListControls() ([]string, error) { return nil, nil }
func (g *exclusionFixtureGetter) GetExceptions(context.Context, string) ([]armotypes.PostureExceptionPolicy, error) {
	return nil, nil
}
func (g *exclusionFixtureGetter) GetControlsInputs(context.Context, string) (map[string][]string, error) {
	return map[string][]string{"C-9901": {}, "C-9902": {}}, nil
}

func TestControlExclusionsBeforeEvaluationScoringAndCachedReplay(t *testing.T) {
	t.Setenv(policyhandler.PoliciesCacheTtlEnvVar, "10m")
	var failCalls, passCalls atomic.Int32
	// The probe observes real Rego execution, so filtering a report afterwards cannot pass.
	probe := fmt.Sprintf("independent_exclusion_probe_%d", exclusionProbeSequence.Add(1))
	rego.RegisterBuiltin1(&rego.Function{Name: probe, Decl: types.NewFunction(types.Args(types.S), types.B)}, func(_ rego.BuiltinContext, term *ast.Term) (*ast.Term, error) {
		if term.Value == ast.String("fail") {
			failCalls.Add(1)
		} else {
			passCalls.Add(1)
		}
		return ast.BooleanTerm(true), nil
	})
	control := func(id, outcome string) reporthandling.Control {
		kind := "Pod"
		if outcome == "fail" {
			kind = "Deployment"
		}
		return reporthandling.Control{
			ControlID: id, PortalBase: armotypes.PortalBase{Name: outcome}, BaseScore: 5,
			Rules: []reporthandling.PolicyRule{{
				PortalBase: armotypes.PortalBase{Name: "fixture-" + outcome}, RuleLanguage: reporthandling.RegoLanguage, RuleQuery: "armo_builtins",
				Match: []reporthandling.RuleMatchObjects{{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"Deployment"}}},
				Rule: fmt.Sprintf(`package armo_builtins
import rego.v1
deny := [msg |
  obj := input[_]
  obj.kind == %q
  msg := {"alertMessage": "fixture failure", "alertObject": {"k8sApiObjects": [obj]}}
] if {
  %s(%q)
}`, kind, probe, outcome),
			}},
		}
	}
	g := &exclusionFixtureGetter{framework: reporthandling.Framework{PortalBase: armotypes.PortalBase{Name: "independent-fixture"}, Controls: []reporthandling.Control{control("C-9901", "fail"), control("C-9902", "pass")}}}
	getters := &cautils.Getters{PolicyGetter: g, ExceptionsGetter: g, ControlsInputsGetter: g}
	handler := policyhandler.NewRequestScopedPolicyHandler("independent-fixture")
	defer handler.Close()
	resource := mocks.MockDevelopmentWithHostpath()
	run := func(exclusions string, wantControls int, wantScore float32) {
		t.Helper()
		body := `{"targetType":"framework","targetNames":["independent-fixture"]` + exclusions + `}`
		params, err := getScanParamsFromRequest(httptest.NewRequest("POST", "/v1/scan", strings.NewReader(body)), "fixture")
		require.NoError(t, err)
		session, err := handler.CollectPolicies(context.Background(), params.policyIdentifiers, params.scanInfo, getters)
		require.NoError(t, err)
		session.AllResources[resource.GetID()] = resource
		session.K8SResources = cautils.K8SResources{"apps/v1/deployments": workloadinterface.ListMetaIDs([]workloadinterface.IMetadata{resource})}
		processor := opaprocessor.NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "independent-fixture", "", "", false, nil)
		require.NoError(t, processor.ProcessRulesListener(context.Background(), nil))
		require.Len(t, session.Report.SummaryDetails.Controls, wantControls)
		require.Contains(t, session.Report.SummaryDetails.Controls, "C-9902", "the remaining control still runs")
		if wantControls == 1 {
			require.NotContains(t, session.Report.SummaryDetails.Controls, "C-9901")
		} else {
			require.Contains(t, session.Report.SummaryDetails.Controls, "C-9901")
		}
		require.InDelta(t, wantScore, session.Report.SummaryDetails.ComplianceScore, 0.01)
	}
	run("", 2, 50)
	require.Positive(t, failCalls.Load(), "baseline proves the excluded rule's probe can actually execute")
	require.Positive(t, passCalls.Load())
	beforeFailure, beforePassing := failCalls.Load(), passCalls.Load()
	run(`,"excludeControls":["C-9901"]`, 1, 100)
	require.Equal(t, beforeFailure, failCalls.Load(), "excluded rule must never execute")
	require.Greater(t, passCalls.Load(), beforePassing, "retained rule must execute")
	run("", 2, 50)
	require.Greater(t, failCalls.Load(), beforeFailure, "ordinary scan must restore the previously excluded rule")
	require.Equal(t, 1, g.loads, "all three scans must exercise the same cached framework")
}
