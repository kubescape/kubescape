package cel

import "context"

// EvaluateControl loads the ValidatingAdmissionPolicy for a control from the
// embedded bundle, resolves its params, and evaluates it against one object.
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
// error. The scanner maps that to a skipped status, never a silent pass.
func (e *Evaluator) EvaluateControl(ctx context.Context, controlID string, obj, namespaceObject map[string]any) ([]ValidationResult, error) {
	vap, err := loadVAP(controlID)
	if err != nil {
		return nil, err
	}
	params, err := resolveParams(vap)
	if err != nil {
		return nil, err
	}
	return e.EvaluateOnObject(ctx, obj, namespaceObject, params, vap.Variables, vap.Validations)
}
