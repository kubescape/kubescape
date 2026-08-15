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
	// FailOnError reports whether the policy's failurePolicy is Fail (the
	// default, and the only value the embedded bundle uses). When true, a
	// validation whose expression errored denies the object at admission, and
	// the scanner reports it as failed rather than skipped.
	FailOnError bool
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
// one narrowed by a namespaceSelector) is refused by loadVAP and surfaces here
// as an error. The scanner maps that to a skipped status, never a silent pass.
// An object outside the policy's matchConstraints returns Applicable=false
// rather than an error, since it is a normal not-matched case, not a failure —
// and so does an object a matchCondition gates out (see matchConditionsGate).
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
	matched, err := e.matchConditionsHold(ctx, vap.matchConditions, obj, namespaceObject, params, vap.Variables)
	if err != nil {
		return matchConditionsGate(vap, err), nil
	}
	if !matched {
		return ControlEvaluation{Applicable: false}, nil
	}
	results, err := e.EvaluateOnObject(ctx, obj, namespaceObject, params, vap.Variables, vap.Validations)
	if err != nil {
		return ControlEvaluation{}, err
	}
	return ControlEvaluation{Applicable: true, Results: results, FailOnError: vap.failOnError()}, nil
}

// matchConditionsGate turns a matchCondition that did not reach a verdict into
// the outcome admission would produce.
//
// Under failurePolicy Ignore the apiserver skips the whole policy, so the object
// is simply not evaluated. Under Fail it denies the request, so we hand back one
// errored result and let the scanner report the failure (it applies FailOnError
// to expression errors exactly as it does for a validation).
//
// An offline-only failure — a gate that will not compile, an exhausted budget, a
// cancelled scan — is not a verdict admission can reach, so failurePolicy does
// not apply to it. It stays an unknown verdict either way, which is what the
// scanner does with an error IsExpressionError rejects. The result carries no
// Expression because the gate is not a validation; the error names the condition.
func matchConditionsGate(vap *VAP, err error) ControlEvaluation {
	if IsExpressionError(err) && !vap.failOnError() {
		return ControlEvaluation{Applicable: false}
	}
	return ControlEvaluation{
		Applicable:  true,
		Results:     []ValidationResult{{Err: err}},
		FailOnError: vap.failOnError(),
	}
}
