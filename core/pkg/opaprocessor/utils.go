package opaprocessor

import (
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
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

var cosignVerifySignatureDeclaration = &rego.Function{
	Name:    "cosign.verify",
	Decl:    types.NewFunction(types.Args(types.S, types.A), types.B),
	Memoize: true,
}
var cosignVerifySignatureDefinition = func(bctx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %v", err)
	}
	bStr, err := builtins.StringOperand(b.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %v", err)
	}
	result, err := verify(string(aStr), string(bStr))
	if err != nil {
		// Do not change this log from debug level. We might find a lot of images without signature
		logger.L().Debug("failed to verify signature", helpers.String("image", string(aStr)), helpers.String("key", string(bStr)), helpers.Error(err))
	}
	return ast.BooleanTerm(result), nil
}

var cosignHasSignatureDeclaration = &rego.Function{
	Name:    "cosign.has_signature",
	Decl:    types.NewFunction(types.Args(types.S), types.B),
	Memoize: true,
}
var cosignHasSignatureDefinition = func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %v", err)
	}
	return ast.BooleanTerm(has_signature(string(aStr))), nil
}
