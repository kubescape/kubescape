package opaprocessor

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/open-policy-agent/opa/v1/util"
	"sigs.k8s.io/yaml"
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
		fw := &frameworks[i]
		controls := map[string]reportsummary.ControlSummary{}
		for j := range fw.Controls {
			ctrl := &fw.Controls[j]
			id := ctrl.ControlID
			if _, ok := policies.Controls[id]; ok {
				c := reportsummary.ControlSummary{
					Name:        ctrl.Name,
					ControlID:   id,
					ScoreFactor: ctrl.BaseScore,
					Description: ctrl.Description,
					Remediation: ctrl.Remediation,
					Category:    ctrl.Category,
				}
				if ctrl.GetActionRequiredAttribute() == string(apis.SubStatusManualReview) {
					c.Status = apis.StatusSkipped
					c.StatusInfo.InnerStatus = apis.StatusSkipped
					c.StatusInfo.SubStatus = apis.SubStatusManualReview
					c.StatusInfo.InnerInfo = string(apis.SubStatusManualReviewInfo)
				}
				controls[ctrl.ControlID] = c
				summaryDetails.Controls[id] = c
			}
		}
		if slices.Contains(policies.Frameworks, fw.Name) {
			summaryDetails.Frameworks = append(summaryDetails.Frameworks, reportsummary.FrameworkSummary{
				Name:     fw.Name,
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
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}
	bStr, err := builtins.StringOperand(b.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}
	// Replace double backslashes with single backslashes
	bbStr := strings.ReplaceAll(string(bStr), "\\n", "\n")
	result, err := verify(bctx.Context, string(aStr), bbStr)
	if err != nil {
		// Do not change this log from debug level. We might find a lot of images without signature
		logger.L().Debug("failed to verify signature", helpers.String("image", string(aStr)), helpers.String("key", string(bStr)), helpers.Error(err))
	}
	return ast.BooleanTerm(result), nil
}

var cosignVerifyKeylessDeclaration = &rego.Function{
	Name:    "cosign.verify_keyless",
	Decl:    types.NewFunction(types.Args(types.S), types.B),
	Memoize: true,
}
var cosignVerifyKeylessDefinition = func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}
	result, err := verifyKeyless(bctx.Context, string(aStr))
	if err != nil {
		// Do not change this log from debug level. We might find a lot of images without signature
		logger.L().Debug("failed to verify keyless signature", helpers.String("image", string(aStr)), helpers.Error(err))
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
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}
	return ast.BooleanTerm(has_signature(bctx.Context, string(aStr))), nil
}

var imageNameNormalizeDeclaration = &rego.Function{
	Name:    "image.parse_normalized_name",
	Decl:    types.NewFunction(types.Args(types.S), types.S),
	Memoize: true,
}
var imageNameNormalizeDefinition = func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}
	normalizedName, err := cautils.NormalizeImageName(string(aStr))
	return ast.StringTerm(normalizedName), err
}

// k8sYAMLUnmarshal implements OPA's yaml.unmarshal builtin using sigs.k8s.io/yaml,
// matching the YAML-to-JSON conversion used by Kubernetes (k8s.io/apimachinery) and
// OPA prior to v1.21.0 so that YAML 1.1 boolean scalars (yes/no/on/off) in raw
// Kubernetes configuration files (such as kubelet config.yaml) are decoded as booleans.
func k8sYAMLUnmarshal(_ topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	bs, err := builtins.StringOperandByteSlice(operands[0].Value, 1)
	if err != nil {
		return err
	}

	js, err := yaml.YAMLToJSON(bs)
	if err != nil {
		return err
	}

	reader := ast.BytesReaderPool.Get()
	defer ast.BytesReaderPool.Put(reader)
	reader.Reset(js)

	var val any
	if err = util.NewJSONDecoder(reader).Decode(&val); err != nil {
		return err
	}

	v, err := ast.InterfaceToValue(val)
	if err != nil {
		return err
	}
	return iter(ast.NewTerm(v))
}
