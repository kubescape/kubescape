package cel

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

// Variable is one entry from a VAP's spec.variables. Each is a CEL expression
// that may reference object/params/request and variables declared before it.
type Variable struct {
	Name       string
	Expression string
}

// Validation is one entry from a VAP's spec.validations. Expression must
// evaluate to a bool; false means the resource violates the policy.
type Validation struct {
	Expression string
	// Message is the static violation message. Used as-is when set, and as the
	// fallback when MessageExpression is absent or fails.
	Message string
	// MessageExpression is a CEL expression returning a string, evaluated only
	// when a validation fails. If it errors or returns a non-string, we fall
	// back to Message (and then a default) rather than failing the validation.
	MessageExpression string
}

// ValidationResult is the outcome of one Validation against one object.
//
// Err is reserved for the case where we genuinely do not know the verdict: the
// validation expression failed to compile or evaluate. It is NOT a pass and NOT
// a clean false. A failed messageExpression never lands here (see resolveMessage):
// a real violation with a broken message is still a violation.
type ValidationResult struct {
	Expression string
	Passed     bool
	Message    string
	Err        error
}

// defaultViolationMessage is what we report when a validation fails but neither
// Message nor a working MessageExpression gives us anything, mirroring the
// apiserver's generic "failed expression" fallback.
const defaultViolationMessage = "failed validation"

// Evaluator runs a VAP's variables and validations against scanned objects. The
// CEL env is built once and reused for every object, since compiling the env is
// far more expensive than evaluating against it.
type Evaluator struct {
	env *cel.Env
	// costLimit overrides the per-evaluation CEL cost budget. Zero means "do not
	// override", which leaves the budget the base env already bakes in
	// (apiserver's PerCallLimit). When cost limits are wired up the real value
	// flows through here, so that becomes a value change not a signature one.
	costLimit uint64
}

// Option configures an Evaluator.
type Option func(*Evaluator)

// WithCostLimit overrides the per-evaluation CEL cost budget. Leave it unset to
// keep the base env's default (apiserver's PerCallLimit), which is what gives us
// scan/admission parity.
func WithCostLimit(limit uint64) Option {
	return func(e *Evaluator) { e.costLimit = limit }
}

// NewEvaluator builds an Evaluator over the offline VAP CEL env (see newEnv).
func NewEvaluator(opts ...Option) (*Evaluator, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	e := &Evaluator{env: env}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// EvaluateOnObject evaluates one VAP's variables and validations against a
// single object.
//
//   - obj is the scanned resource, bound to "object".
//   - namespaceObject is the resource's Namespace object (nil for cluster-scoped
//     resources or when the scan does not have it); bound via the stub layer.
//   - params is the resolved paramKind value (nil when the VAP has no paramKind),
//     bound to "params". Once the loader is built these come from the bundle.
//   - variables and validations come from the VAP. Once the loader is built it
//     fills them from real YAML; for now tests fill them by hand. Same structs
//     either way, so the signature does not change when the loader lands.
//
// The activation is built once and reused. Variables are evaluated first, in
// declared order, each written back so later variables and the validations can
// read variables.<name>. Then every validation is evaluated against it, yielding
// one ValidationResult per validation in order.
//
// A variable failure is returned as a top-level error: if a variable cannot be
// resolved, the validations that may depend on it cannot be trusted, so we do
// not produce verdicts for this object. A validation failure, by contrast, is
// captured per-result (see evaluateValidation), since the other validations are
// still meaningful.
func (e *Evaluator) EvaluateOnObject(
	ctx context.Context,
	obj map[string]any,
	namespaceObject map[string]any,
	params any,
	variables []Variable,
	validations []Validation,
) ([]ValidationResult, error) {
	// stubBindings owns request, oldObject and namespaceObject. We add the
	// remaining env-declared variables so every declared variable is bound (an
	// unbound declared variable errors at eval time, see env.go).
	activation := stubBindings(obj, namespaceObject)
	activation["object"] = obj
	activation["params"] = params

	// One inner map bound to "variables". Each evaluated variable is written into
	// this same map, so variables.<name> resolves for both later variables and
	// the validations. It is never rebuilt per variable.
	vars := map[string]any{}
	activation["variables"] = vars

	for _, v := range variables {
		out, err := e.evalExpression(ctx, v.Expression, activation)
		if err != nil {
			return nil, fmt.Errorf("evaluating variable %q: %w", v.Name, err)
		}
		vars[v.Name] = out
	}

	results := make([]ValidationResult, 0, len(validations))
	for _, val := range validations {
		results = append(results, e.evaluateValidation(ctx, val, activation))
	}
	return results, nil
}

// evaluateValidation evaluates one validation against the prepared activation.
// Only a compile/eval failure of the validation expression sets Err; everything
// else resolves to a clean pass or a violation with a message.
func (e *Evaluator) evaluateValidation(ctx context.Context, val Validation, activation map[string]any) ValidationResult {
	res := ValidationResult{Expression: val.Expression}

	out, err := e.evalExpression(ctx, val.Expression, activation)
	if err != nil {
		res.Err = err
		return res
	}

	passed, ok := out.Value().(bool)
	if !ok {
		res.Err = fmt.Errorf("validation expression must return bool, got %T", out.Value())
		return res
	}

	res.Passed = passed
	if !passed {
		res.Message = e.resolveMessage(ctx, val, activation)
	}
	return res
}

// resolveMessage produces the violation message for a failed validation.
//
// A failing messageExpression must NOT turn the violation into an error: a real
// violation with a typo'd message is still a violation. So we fall back, never
// promote to Err. Order: static Message, then messageExpression, then a default.
func (e *Evaluator) resolveMessage(ctx context.Context, val Validation, activation map[string]any) string {
	if val.Message != "" {
		return val.Message
	}
	if val.MessageExpression != "" {
		out, err := e.evalExpression(ctx, val.MessageExpression, activation)
		if err == nil {
			if msg, ok := out.Value().(string); ok && msg != "" {
				return msg
			}
		}
	}
	return defaultViolationMessage
}

// evalExpression compiles and evaluates a single CEL expression against the
// activation. When compile caching is added it wraps the compile step here, and
// when cost reporting is added it surfaces the EvalDetails this currently discards.
func (e *Evaluator) evalExpression(ctx context.Context, expr string, activation map[string]any) (ref.Val, error) {
	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile: %w", issues.Err())
	}

	prog, err := e.program(ast)
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}

	out, _, err := prog.ContextEval(ctx, activation)
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	return out, nil
}

// program instantiates a runnable program from a compiled AST. The cost-limit
// override is only applied when set; otherwise the base env's baked-in
// PerCallLimit stands. InterruptCheckFrequency gets added here later too.
func (e *Evaluator) program(ast *cel.Ast) (cel.Program, error) {
	var opts []cel.ProgramOption
	if e.costLimit > 0 {
		opts = append(opts, cel.CostLimit(e.costLimit))
	}
	return e.env.Program(ast, opts...)
}
