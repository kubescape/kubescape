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
// A false condition outranks a condition that errored, whatever order the two
// appear in. The apiserver's matcher evaluates every condition, collects the
// errors, and still returns not-matched the moment it sees a false one; only a
// gate of trues and errors reaches failurePolicy (webhook/matchconditions
// matcher.go, which the VAP path reuses). So an error is retained rather than
// returned, and a later false discards it. Returning on the first error instead
// would deny an object under failurePolicy Fail that admission simply skips.
//
// A false condition still short-circuits the conditions after it. Evaluating
// them could only add errors that the false already outranks, and the gate's
// budget is discarded either way, so the outcome is identical to the
// apiserver's for less work.
//
// Cancellation and an exhausted budget are the exceptions: they are terminal,
// because no later condition can still produce the false that would outrank
// them. A compile error is not terminal, since the conditions after it are
// unaffected and one of them may yet be false.
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
func (e *Evaluator) matchConditionsHold(ctx context.Context, conditions []MatchCondition, obj, namespaceObject map[string]any, params any, variables []Variable) (bool, error) {
	if len(conditions) == 0 {
		return true, nil
	}

	budget := newCostBudget(e.matchConditionsBudgetLimit())
	activation := e.activationFor(ctx, obj, namespaceObject, params, variables, budget)

	// The first error we can still recover from, held until a false outranks it
	// or the gate runs out of conditions.
	var retained error

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
			return false, nil
		}
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
