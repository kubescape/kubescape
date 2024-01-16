package opaprocessor

import (
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"golang.org/x/exp/slices"
)

// convertFrameworksToPolicies convert list of frameworks to list of policies
func convertFrameworksToPolicies(frameworks []reporthandling.Framework, excludedRules map[string]bool, scanningScope reporthandling.ScanningScopeType) *cautils.Policies {
	policies := cautils.NewPolicies()
	policies.Set(frameworks, excludedRules, scanningScope)
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
					Category:    frameworks[i].Controls[j].Category,
				}
				if frameworks[i].Controls[j].GetActionRequiredAttribute() == string(apis.SubStatusManualReview) {
					c.Status = apis.StatusSkipped
					c.StatusInfo.InnerStatus = apis.StatusSkipped
					c.StatusInfo.SubStatus = apis.SubStatusManualReview
					c.StatusInfo.InnerInfo = string(apis.SubStatusManualReviewInfo)
				}
				controls[frameworks[i].Controls[j].ControlID] = c
				summaryDetails.Controls[id] = c
			}
		}
		if slices.Contains(policies.Frameworks, frameworks[i].Name) {
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
	// Replace double backslashes with single backslashes
	bbStr := strings.Replace(string(bStr), "\\n", "\n", -1)
	result, err := verify(string(aStr), bbStr)
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

var imageNameNormalizeDeclaration = &rego.Function{
	Name:    "image.parse_normalized_name",
	Decl:    types.NewFunction(types.Args(types.S), types.S),
	Memoize: true,
}
var imageNameNormalizeDefinition = func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %v", err)
	}
	normalizedName, err := cautils.NormalizeImageName(string(aStr))
	return ast.StringTerm(normalizedName), err
}
