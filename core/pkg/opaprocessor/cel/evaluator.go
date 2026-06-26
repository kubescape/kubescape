package cel

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/lazy"
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
// The activation is built once and reused. Variables are bound LAZILY, matching
// the apiserver (pkg/admission/plugin/cel/composition.go): a variable is
// evaluated only when a validation actually references variables.<name>, the
// result (or its error) is memoized, and a variable error surfaces only to the
// validation(s) that touched it. This is what keeps offline == admission:
//
//   - a variable that errors but is never referenced does not affect the object
//     (at admission it never runs either);
//   - a broken variable referenced by one validation only fails that validation;
//     the rest still get verdicts.
//
// Each validation then yields one ValidationResult, in order. The error return is
// reserved for setup failures; per-validation outcomes (including eval errors)
// live on the result (see evaluateValidation).
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
	activation["variables"] = e.lazyVariables(ctx, variables, activation)

	results := make([]ValidationResult, 0, len(validations))
	for _, val := range validations {
		results = append(results, e.evaluateValidation(ctx, val, activation))
	}
	return results, nil
}

// variablesTypeName is the CEL type name of the lazy variables map. It only
// labels the map value; the env declares "variables" as a dynamic type, so field
// access resolves through the map at runtime rather than against this type.
const variablesTypeName = "kubescape.cel.variables"

// lazyVariables builds the value bound to "variables": a lazy map where each
// variable is evaluated on first access and memoized, mirroring the apiserver's
// composition map. The callback evaluates against the same activation the map is
// part of, so a variable referencing variables.<earlier> triggers that earlier
// variable's callback on demand. An eval/compile failure becomes a CEL error
// value, which propagates only to the validation that referenced the variable.
func (e *Evaluator) lazyVariables(ctx context.Context, variables []Variable, activation map[string]any) *lazy.MapValue {
	lazyVars := lazy.NewMapValue(types.NewObjectType(variablesTypeName))
	for _, v := range variables {
		v := v // capture per iteration for the callback
		lazyVars.Append(v.Name, func(*lazy.MapValue) ref.Val {
			out, err := e.evalExpression(ctx, v.Expression, activation)
			if err != nil {
				return types.NewErr("variable %q: %v", v.Name, err)
			}
			return out
		})
	}
	return lazyVars
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
// Order matches the apiserver (pkg/admission/plugin/policy/validating/
// validator.go): messageExpression first, then the static Message, then a
// "failed expression: <expr>" default. A failing messageExpression must NOT turn
// the violation into an error: a real violation with a typo'd message is still a
// violation, so we fall back rather than promote to Err. A messageExpression
// result that is non-string, empty/whitespace-only, multi-line, or longer than
// the apiserver's limit also falls back, matching what admission would accept.
func (e *Evaluator) resolveMessage(ctx context.Context, val Validation, activation map[string]any) string {
	if val.MessageExpression != "" {
		if msg, ok := e.evalMessageExpression(ctx, val.MessageExpression, activation); ok {
			return msg
		}
	}
	if msg := strings.TrimSpace(val.Message); msg != "" {
		return msg
	}
	return fmt.Sprintf("failed expression: %s", strings.TrimSpace(val.Expression))
}

// evalMessageExpression evaluates a messageExpression and reports whether its
// result is usable. The apiserver rejects (and falls back on) a result that
// errors, is non-string, is empty/whitespace, exceeds the size limit, or spans
// multiple lines; we apply the same guards so the message we report offline is
// one admission would actually use.
func (e *Evaluator) evalMessageExpression(ctx context.Context, expr string, activation map[string]any) (string, bool) {
	out, err := e.evalExpression(ctx, expr, activation)
	if err != nil {
		return "", false
	}
	msg, ok := out.Value().(string)
	if !ok {
		return "", false
	}
	msg = strings.TrimSpace(msg)
	if msg == "" || len(msg) > celconfig.MaxEvaluatedMessageExpressionSizeBytes || strings.ContainsAny(msg, "\n") {
		return "", false
	}
	return msg, true
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
//
// Note for when the cost limit is turned on: this applies a fresh per-expression
// budget. The apiserver instead shares one budget across all of a policy's
// expressions (variables + validations) per evaluation, so that accounting, not
// just the per-call value, is what needs to be matched then.
func (e *Evaluator) program(ast *cel.Ast) (cel.Program, error) {
	var opts []cel.ProgramOption
	if e.costLimit > 0 {
		opts = append(opts, cel.CostLimit(e.costLimit))
	}
	return e.env.Program(ast, opts...)
}
