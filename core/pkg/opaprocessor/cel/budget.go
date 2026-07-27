package cel

import (
	"errors"
	"fmt"
	"math"

	"github.com/google/cel-go/cel"
)

// errOutOfBudget marks a verdict we could not reach because the policy's shared
// cost budget ran out. Callers match on it with errors.Is; the scanner treats it
// like any other eval failure, an unknown verdict rather than a pass.
var errOutOfBudget = errors.New("out of CEL cost budget")

// costBudget is the cost budget one policy evaluation shares across every
// expression it runs against one object: its variables, its validations and any
// messageExpression. It mirrors the apiserver's RuntimeCELCostBudget accounting
// (pkg/admission/plugin/cel/activation.go Evaluate, condition.go ForInput).
//
// The per-expression limit is a different, already-solved thing: the base env
// bakes cel.CostLimit(PerCallLimit) into every program, so no single expression
// can exceed 1M units offline or at admission. What the base env does NOT give
// us is the ceiling on the SUM. A policy whose expressions each fit inside the
// per-call limit but together run past 10M is accepted offline and rejected at
// live admission, which is exactly the kind of divergence the scan/admission
// guarantee is supposed to rule out.
//
// A nil *costBudget means unmetered, and the methods are nil-safe so call sites
// do not have to branch. That is deliberate rather than lazy: path derivation
// re-runs a validation once per list element against narrowed copies of the
// object (see paths.go), work admission never does. Charging it here would let
// a scan exhaust a budget that admission would not, turning a finding that
// admission accepts into an unknown verdict. Those re-runs stay bounded by the
// per-call limit the base env applies to every program.
type costBudget struct {
	// remaining is what is left of the policy's budget.
	remaining int64
	// pending is cost charged by variables that the expression currently
	// running pulled in. Variables evaluate lazily inside another expression's
	// evaluation, so their cost is collected here and settled by the expression
	// that triggered them, matching the apiserver's compositionContext.
	pending int64
	// spent records that the budget ran out, so the caller can stop instead of
	// evaluating expressions whose result it would have to discard anyway.
	spent bool
}

func newCostBudget(limit int64) *costBudget {
	return &costBudget{remaining: limit}
}

// exhausted reports whether the budget has already run out.
func (b *costBudget) exhausted() bool {
	return b != nil && b.spent
}

// err builds the error handed to every expression that does not get to run.
func (b *costBudget) err() error {
	return fmt.Errorf("%w: no further expressions in this policy were evaluated", errOutOfBudget)
}

// reportDetails records the cost of a variable evaluated lazily inside the
// expression currently running. It does not settle against the budget itself;
// charge does that, so a variable and the expression that pulled it in are
// accounted together and in that order, as the apiserver does.
//
// A variable whose cost the runtime did not report is an error rather than a
// free variable, matching the apiserver's variableAccessor.Callback. The error
// surfaces as the variable's value, so it reaches only the validations that
// actually referenced it.
func (b *costBudget) reportDetails(details *cel.EvalDetails) error {
	if b == nil {
		return nil
	}
	if details == nil {
		return errors.New("unable to get evaluation details")
	}
	actual := details.ActualCost()
	if actual == nil {
		return errors.New("unable to calculate cost")
	}
	cost := int64(math.MaxInt64)
	if *actual <= math.MaxInt64 {
		cost = int64(*actual)
	}
	b.pending += cost
	return nil
}

// charge settles one expression against the budget: first the variables it
// pulled in, then the expression's own cost. It is called even when the
// expression errored, because a failed evaluation still consumed the units, and
// admission charges it the same way.
//
// details comes straight from ContextEval. A nil details or a nil ActualCost
// means the runtime did not report a cost, which we cannot distinguish from an
// expensive expression, so it is treated as a failure rather than as free.
func (b *costBudget) charge(details *cel.EvalDetails) error {
	if b == nil {
		return nil
	}
	if b.spent {
		return b.err()
	}

	pending := b.pending
	b.pending = 0
	if pending > b.remaining {
		b.spent = true
		return b.err()
	}
	b.remaining -= pending

	if details == nil {
		b.spent = true
		return fmt.Errorf("%w: runtime reported no cost details", errOutOfBudget)
	}
	actual := details.ActualCost()
	if actual == nil {
		b.spent = true
		return fmt.Errorf("%w: runtime reported no cost", errOutOfBudget)
	}
	// Bound before converting, then convert once. A cost past MaxInt64 is far
	// beyond any budget anyway, so it is out of budget by definition.
	if *actual > math.MaxInt64 {
		b.spent = true
		return b.err()
	}
	cost := int64(*actual)
	if cost > b.remaining {
		b.spent = true
		return b.err()
	}
	b.remaining -= cost
	return nil
}
