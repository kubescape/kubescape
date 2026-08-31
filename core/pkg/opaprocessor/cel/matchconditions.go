package cel

import (
	"context"
	"errors"
	"fmt"

	celconfig "k8s.io/apiserver/pkg/apis/cel"
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
//
// Every condition is evaluated, even after one has already come back false.
// The apiserver's matcher (webhook/matchconditions matcher.go, which the VAP
// path reuses) works in two separate phases: ForInput first evaluates every
// compiled condition unconditionally against one shared cost budget
// (admission/plugin/cel/condition.go), and only once that finishes does
// Match walk the completed results to pick a verdict, returning not-matched
// at the first false it finds there. Stopping the evaluation loop itself the
// moment a false is seen -- which this function used to do -- looks
// equivalent (the two-condition, no-budget-pressure case indeed produces the
// same verdict either way) but is not: it also stops charging the shared
// budget for whatever conditions come after the false one. A false condition
// followed by an expensive one that would have exhausted the budget is
// exactly the case where the two diverge -- the apiserver still exhausts the
// budget and denies the request under failurePolicy Fail, while stopping
// early here would report a clean not-matched skip instead.
//
// A false condition outranks a condition that errored, whatever order the two
// appear in: the apiserver's Match checks every result for EvalResult==False
// before it even looks at the collected errors, so a false anywhere in the
// gate produces not-matched regardless of what else errored. Only a gate of
// trues and errors, with no false at all, reaches failurePolicy. So an error
// is retained rather than returned immediately, and a false seen anywhere
// (before or after it) discards it at the end.
//
// Cancellation and an exhausted budget are still terminal mid-loop: nothing
// evaluated under an exhausted budget can be trusted, including a false that
// might otherwise have outranked it, so both stop the loop outright rather
// than being retained like a compile/eval error.
//
// The error return is the unknown case. Whether it denies the object or skips
// the policy depends on failurePolicy, so the caller decides (see
// matchConditionsGate).
//
// The gate gets its own budget and its own activation. Its own budget because
// the apiserver's matcher runs on a fresh matchConditions budget and discards
// the remainder, so charging the validations for the gate would exhaust a scan
// where admission is fine. Its own activation because variables memoize per
// activation: sharing one would hand the validations variables the gate already
// paid for, making the policy cheaper offline than at admission.
//
// namespaceObject is deliberately absent from the signature: the gate binds it
// to null, never to the object's real Namespace, even when the scan captured
// one. The apiserver's matcher passes a hardcoded nil namespace to ForInput
// (webhook/matchconditions matcher.go), while the validations that follow get
// the resolved Namespace, so at admission a matchCondition touching
// namespaceObject always evaluates against null and errors into failurePolicy.
// Binding the real namespace here would answer that condition offline instead
// of reproducing the error, which is the scan/admission divergence this package
// exists to avoid. params and variables ARE available to matchConditions at
// admission (the shared CompositedCompiler), so those stay bound.
func (e *Evaluator) matchConditionsHold(ctx context.Context, conditions []MatchCondition, obj map[string]any, params any, variables []Variable) (bool, error) {
	if len(conditions) == 0 {
		return true, nil
	}

	budget := newCostBudget(e.matchConditionsBudgetLimit())
	activation := e.activationFor(ctx, obj, nil, params, variables, budget)

	// The first error we can still recover from, held until the loop ends
	// (whereupon a false condition seen anywhere outranks it).
	var retained error
	sawFalse := false

	for _, condition := range conditions {
		// cel-go only notices a cancelled context every InterruptCheckFrequency
		// steps within one expression, so without this a gate of cheap conditions
		// runs to completion after Ctrl+C (same guard as EvaluateOnObject).
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("matchCondition %q: evaluation stopped: %w", condition.Name, err)
		}

		out, err := e.evalExpression(ctx, condition.Expression, activation, budget)
		if err != nil {
			if isContextError(ctx, err) || errors.Is(err, errOutOfBudget) {
				return false, fmt.Errorf("matchCondition %q: %w", condition.Name, err)
			}
			if retained == nil {
				retained = fmt.Errorf("matchCondition %q: %w", condition.Name, err)
			}
			continue
		}

		matched, ok := out.Value().(bool)
		if !ok {
			if retained == nil {
				retained = &expressionError{fmt.Errorf("matchCondition %q must return bool, got %T", condition.Name, out.Value())}
			}
			continue
		}
		if !matched {
			sawFalse = true
		}
	}

	if sawFalse {
		return false, nil
	}
	if retained != nil {
		return false, retained
	}
	return true, nil
}

// matchConditionsBudgetLimit is the cost budget one object's gate runs on. The
// apiserver bills matchConditions to RuntimeCELCostBudgetMatchConditions, a
// quarter of what it gives the validations, so metering the gate against the
// validations' ceiling would let a gate pass offline that admission cuts off. A
// WithCostBudget override still wins, so tests can reach the exhausted path
// without writing an expensive condition.
func (e *Evaluator) matchConditionsBudgetLimit() int64 {
	if e.costBudget > 0 {
		return e.costBudget
	}
	return celconfig.RuntimeCELCostBudgetMatchConditions
}
