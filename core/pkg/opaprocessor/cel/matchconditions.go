package cel

import (
	"context"
	"fmt"
)

// MatchCondition is one entry from a VAP's spec.matchConditions: a CEL
// expression gating whether the policy runs against an object at all. Name
// labels the condition in the error a broken gate produces.
type MatchCondition struct {
	Name       string
	Expression string
}

// matchConditionsHold reports whether every matchCondition admits the object.
//
// At admission a policy whose matchConditions do not all evaluate to true is
// skipped and none of its validations run, so offline we must do the same:
// running a gated policy's validations emits violations admission never raises.
// Conditions evaluate in order and the first false one short-circuits, as the
// apiserver does.
//
// The error return is the unknown case — a condition that would not compile or
// failed to evaluate. Whether that denies the object or skips the policy depends
// on failurePolicy, so the caller decides (see EvaluateControl).
//
// The gate gets its own budget and its own activation. Its own budget because
// the apiserver's matcher runs on a fresh RuntimeCELCostBudget and discards the
// remainder, so charging the validations for the gate would exhaust a scan where
// admission is fine. Its own activation because variables memoize per
// activation: sharing one would hand the validations variables the gate already
// paid for, making the policy cheaper offline than at admission.
func (e *Evaluator) matchConditionsHold(ctx context.Context, conditions []MatchCondition, obj, namespaceObject map[string]any, params any, variables []Variable) (bool, error) {
	if len(conditions) == 0 {
		return true, nil
	}

	budget := newCostBudget(e.budgetLimit())
	activation := e.activationFor(ctx, obj, namespaceObject, params, variables, budget)

	for _, condition := range conditions {
		// cel-go only notices a cancelled context every InterruptCheckFrequency
		// steps within one expression, so without this a gate of cheap conditions
		// runs to completion after Ctrl+C (same guard as EvaluateOnObject).
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("matchCondition %q: evaluation stopped: %w", condition.Name, err)
		}

		out, err := e.evalExpression(ctx, condition.Expression, activation, budget)
		if err != nil {
			return false, fmt.Errorf("matchCondition %q: %w", condition.Name, err)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return false, &expressionError{fmt.Errorf("matchCondition %q must return bool, got %T", condition.Name, out.Value())}
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}
