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
// embedded bundle, checks the object is in the policy's scope, resolves the
// bundled params, and evaluates the validations against the object.
func (e *Evaluator) EvaluateControl(ctx context.Context, controlID string, obj, namespaceObject map[string]any) (ControlEvaluation, error) {
	vap, err := loadVAP(controlID)
	if err != nil {
		return ControlEvaluation{}, err
	}
	params, err := resolveParams(vap)
	if err != nil {
		return ControlEvaluation{}, err
	}
	return e.EvaluateVAP(ctx, vap, obj, namespaceObject, params)
}

// EvaluateVAP evaluates a loaded VAP against a single object. The caller is
// responsible for resolving params (e.g. from a per-binding paramRef), which
// makes it the path for binding-specific parameter objects.
func (e *Evaluator) EvaluateVAP(ctx context.Context, vap *VAP, obj, namespaceObject map[string]any, params any) (ControlEvaluation, error) {
	if !vap.AppliesTo(obj) {
		return ControlEvaluation{Applicable: false}, nil
	}
	// namespaceObject is not threaded into the gate: admission evaluates
	// matchConditions with it bound to null and only resolves the real Namespace
	// for the validations below (see matchConditionsHold).
	matched, err := e.matchConditionsHold(ctx, vap.matchConditions, obj, params, vap.Variables)
	if err != nil {
		return matchConditionsGate(vap, err), nil
	}
	if !matched {
		return ControlEvaluation{Applicable: false}, nil
	}
	results, err := e.EvaluateOnObject(ctx, obj, namespaceObject, params, vap.Variables, vap.Validations, &vap.failurePolicy)
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
