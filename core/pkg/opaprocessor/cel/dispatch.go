package cel

import "context"

// ControlEvaluation is the outcome of evaluating one control against one object.
type ControlEvaluation struct {
	// Applicable is false when the object's kind falls outside the policy's
	// matchConstraints. Results is then nil: at admission the object would not
	// be matched, so the scan must not treat it as evaluated (let alone passed).
	Applicable bool
	// Results holds one entry per validation, in order, when Applicable.
	Results []ValidationResult
}

// EvaluateControl loads the ValidatingAdmissionPolicy for a control from the
// embedded bundle, checks the object is in the policy's scope, resolves params,
// and evaluates the validations against the object.
//
// It is the single entry point the scanner (package opaprocessor) dispatches
// through: loadVAP and resolveParams are unexported, so the scan path cannot
// assemble a control evaluation itself. controlID is threaded down from the
// scanner (processControl), never read off the rule.
//
// namespaceObject is the object's Namespace (nil for cluster-scoped resources
// or when the scan did not capture it). params come from the embedded bundle
// via resolveParams, matching what a live binding's ParamRef would supply.
//
// A control the offline engine cannot honor with scan/admission parity (e.g.
// one gated on matchConditions) is refused by loadVAP and surfaces here as an
// error. The scanner maps that to a skipped status, never a silent pass. An
// object outside the policy's matchConstraints returns Applicable=false rather
// than an error, since it is a normal not-matched case, not a failure.
func (e *Evaluator) EvaluateControl(ctx context.Context, controlID string, obj, namespaceObject map[string]any) (ControlEvaluation, error) {
	vap, err := loadVAP(controlID)
	if err != nil {
		return ControlEvaluation{}, err
	}
	if !vap.appliesTo(obj) {
		return ControlEvaluation{Applicable: false}, nil
	}
	params, err := resolveParams(vap)
	if err != nil {
		return ControlEvaluation{}, err
	}
	results, err := e.EvaluateOnObject(ctx, obj, namespaceObject, params, vap.Variables, vap.Validations)
	if err != nil {
		return ControlEvaluation{}, err
	}
	return ControlEvaluation{Applicable: true, Results: results}, nil
}
