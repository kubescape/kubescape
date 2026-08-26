package cel

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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
	// Paths are the places in the object this validation looked at, derived
	// from the expression (see paths.go). Only set for a violation, since a
	// passing or unknown verdict has nothing to remediate. Empty is normal: an
	// expression we cannot read a path out of reports none rather than guess.
	Paths []PathHint
}

// expressionError wraps a validation error the CEL expression itself produced
// while running — a runtime evaluation error or a non-bool result — as opposed
// to an offline-only failure such as a compile error, an exhausted cost budget,
// or a cancelled scan. Only the former is a verdict the apiserver can reach, so
// only it is governed by the policy's failurePolicy.
type expressionError struct{ err error }

func (e *expressionError) Error() string { return e.err.Error() }
func (e *expressionError) Unwrap() error { return e.err }

// IsExpressionError reports whether a validation's error was produced by the
// expression itself. Compile errors, budget exhaustion and cancellation return
// false; the scanner leaves those as unknown/skipped verdicts rather than
// letting failurePolicy turn them into a deny.
func IsExpressionError(err error) bool {
	var ee *expressionError
	return errors.As(err, &ee)
}

// isContextError reports whether a validation's evaluation error came from a
// cancelled or expired context rather than from the expression itself. The
// apiserver never reaches a verdict on a request it did not finish evaluating,
// so a context error must stay an unknown/skipped verdict, never an
// expressionError that failurePolicy could turn into a deny.
//
// ContextEval reports an interrupt as an error wrapping context.Cause(ctx)
// (context.Canceled or context.DeadlineExceeded), so errors.Is catches the
// case where the interrupt fired mid-expression. ctx.Err() covers the same
// cancellation once it has landed, including an error a lazy variable surfaced
// whose original cause was flattened into a CEL error value on the way out.
func isContextError(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// Evaluator runs a VAP's variables and validations against scanned objects. The
// CEL env is built once and reused for every object, since compiling the env is
// far more expensive than evaluating against it.
type Evaluator struct {
	env *cel.Env
	// programs caches compiled programs by expression text, so each bundle
	// expression is compiled once per Evaluator rather than once per scanned
	// object (see cache.go).
	programs *programCache
	// plans caches the path plan derived from each expression, so the AST walk
	// behind a violation's remediation paths happens once per expression rather
	// than once per failing object (see paths.go).
	plans *pathPlanCache
	// costBudget overrides the budget one policy evaluation shares across all of
	// its expressions against one object. Zero means the apiserver's
	// RuntimeCELCostBudget, which is what keeps us in step with admission; tests
	// set it low to reach the exhausted path without writing a costly
	// expression. The PER-EXPRESSION limit is not configurable here on purpose:
	// the base env bakes in cel.CostLimit(PerCallLimit) and overriding it would
	// mean scanning under a different ceiling than admission enforces.
	costBudget int64
}

// Option configures an Evaluator.
type Option func(*Evaluator)

// WithCostBudget overrides the shared per-policy-evaluation cost budget. Leave
// it unset to keep the apiserver's RuntimeCELCostBudget, which is what gives us
// scan/admission parity (see budget.go).
func WithCostBudget(budget int64) Option {
	return func(e *Evaluator) { e.costBudget = budget }
}

// budgetLimit is the shared budget a single object's evaluation starts with.
func (e *Evaluator) budgetLimit() int64 {
	if e.costBudget > 0 {
		return e.costBudget
	}
	return celconfig.RuntimeCELCostBudget
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
	// The cache closes over e so compiles pick up option-set state (costLimit);
	// options are applied above, before anything can trigger a compile.
	e.programs = newProgramCache(e.compileProgram)
	e.plans = newPathPlanCache(e.buildPathPlan)
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
//   - failurePolicy is the VAP's spec.failurePolicy. When a validation expression
//     errors, Ignore turns the result into a pass and Fail turns it into a
//     violation. If omitted, eval errors are reported as unknown (Err set).
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
//
// One shared cost budget covers the whole call, matching what admission spends
// on this object (see budget.go). When it runs out we stop evaluating, as the
// apiserver does, but unlike the apiserver we KEEP the verdicts already reached
// instead of collapsing the policy into a single error: the scanner is built to
// report a mixed outcome, and discarding a confirmed violation because a later
// validation ran long would lose real information. The unreached validations
// carry the out-of-budget error, so they read as unknown, never as passing.
//
// A cancelled context stops the loop the same way, and an expression that fails
// to compile stops nothing at all: it never ran, so it costs the policy nothing
// and the validations after it still get their verdicts.
func (e *Evaluator) EvaluateOnObject(
	ctx context.Context,
	obj map[string]any,
	namespaceObject map[string]any,
	params any,
	variables []Variable,
	validations []Validation,
	failurePolicy ...*admissionregistrationv1.FailurePolicyType,
) ([]ValidationResult, error) {
	budget := newCostBudget(e.budgetLimit())
	activation := e.activationFor(ctx, obj, namespaceObject, params, variables, budget)

	var fp *admissionregistrationv1.FailurePolicyType
	if len(failurePolicy) > 0 {
		fp = failurePolicy[0]
	}

	results := make([]ValidationResult, 0, len(validations))
	for _, val := range validations {
		// A cancelled scan stops here rather than partway through whichever
		// expression happens to be long enough for the runtime to notice.
		// InterruptCheckFrequency only makes cel-go check #interrupted every N
		// steps INSIDE one evaluation, so without this an ordinary policy of
		// cheap expressions runs every one of them to completion after Ctrl+C.
		if err := ctx.Err(); err != nil {
			results = append(results, ValidationResult{Expression: val.Expression, Err: fmt.Errorf("evaluation stopped: %w", err)})
			continue
		}
		if budget.exhausted() {
			results = append(results, ValidationResult{Expression: val.Expression, Err: budget.err()})
			continue
		}
		res := e.evaluateValidation(ctx, val, activation, budget, fp)
		if res.Err == nil && !res.Passed {
			res.Paths = e.violationPaths(ctx, val.Expression, obj, namespaceObject, params, variables)
		}
		results = append(results, res)
	}
	return results, nil
}

// activationFor builds the variable bindings one evaluation runs against.
//
// stubBindings owns request, oldObject and namespaceObject. We add the
// remaining env-declared variables so every declared variable is bound (an
// unbound declared variable errors at eval time, see env.go).
//
// Path derivation builds a second activation for the same object with one list
// narrowed, which is why this is separate: the lazy variables memoize against
// the object they were built for, so a modified object needs its own bindings
// rather than a reused map.
//
// budget is the cost budget the variables bound here charge against, and may be
// nil for an unmetered activation (path derivation, see violationPaths).
func (e *Evaluator) activationFor(ctx context.Context, obj, namespaceObject map[string]any, params any, variables []Variable, budget *costBudget) map[string]any {
	activation := stubBindings(obj, namespaceObject)
	activation["object"] = obj
	activation["params"] = params
	activation["variables"] = e.lazyVariables(ctx, variables, activation, budget)
	return activation
}

// violationPaths derives the remediation paths for a validation that just
// failed on an object (see paths.go for how, and why it needs to re-evaluate).
//
// The re-check treats anything other than a clean violation as "not this
// element": an expression that errors or returns a non-bool on the narrowed
// object tells us nothing, and blaming an element on a guess would put a wrong
// path in front of the user.
//
// These re-runs are deliberately UNMETERED by the policy's shared cost budget
// (nil budget). Admission never narrows an object and re-checks it, so charging
// this work would let a scan run out of budget where admission does not, and
// report unknown for a violation admission is happy to reject. Each re-run is
// still capped by the per-expression limit the base env applies to every
// program, and the whole loop only runs for an object that already failed.
func (e *Evaluator) violationPaths(ctx context.Context, expr string, obj, namespaceObject map[string]any, params any, variables []Variable) []PathHint {
	return e.plans.get(expr, variables).resolve(obj, func(narrowed map[string]any) bool {
		out, err := e.evalExpression(ctx, expr, e.activationFor(ctx, narrowed, namespaceObject, params, variables, nil), nil)
		if err != nil {
			return false
		}
		passed, ok := out.Value().(bool)
		return ok && !passed
	})
}

// buildPathPlan compiles an expression - after expanding any `variables.<name>`
// references it makes into the referenced variable's own expression (see
// inlineVariables), so the AST walk sees the object access those variables
// wrap - and reads its path plan off the result. Callers go through the plan
// cache. An expression that will not compile never reached evaluation either,
// so an empty plan (no paths) is the right answer rather than an error to
// propagate.
func (e *Evaluator) buildPathPlan(expr string, variables []Variable) pathPlan {
	ast, issues := e.env.Compile(inlineVariables(expr, variables))
	if issues != nil && issues.Err() != nil {
		return pathPlan{}
	}
	return newPathPlan(ast)
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
// A variable's cost is REPORTED to the budget rather than charged against it
// here: the variable runs inside whichever expression first referenced it, so
// the two are settled together by that expression's charge, which is how the
// apiserver's compositionContext accounts for them. Memoization means a second
// validation reading the same variable pays nothing, offline and at admission
// alike.
func (e *Evaluator) lazyVariables(ctx context.Context, variables []Variable, activation map[string]any, budget *costBudget) *lazy.MapValue {
	lazyVars := lazy.NewMapValue(types.NewObjectType(variablesTypeName))
	for _, v := range variables {
		v := v // capture per iteration for the callback
		lazyVars.Append(v.Name, func(*lazy.MapValue) ref.Val {
			// Compiling first keeps a variable that never ran out of the cost
			// accounting entirely: a compile failure is this variable's error to
			// report, not a missing cost report to complain about.
			prog, err := e.programs.get(v.Expression)
			if err != nil {
				return types.NewErr("variable %q: %v", v.Name, err)
			}
			out, details, evalErr := e.run(ctx, prog, activation)
			if reportErr := budget.reportDetails(details); reportErr != nil {
				return types.NewErr("variable %q: %v", v.Name, reportErr)
			}
			if evalErr != nil {
				if isContextError(ctx, evalErr) {
					return types.WrapErr(fmt.Errorf("variable %q: %w", v.Name, evalErr))
				}
				return types.NewErr("variable %q: %v", v.Name, evalErr)
			}
			return out
		})
	}
	return lazyVars
}

// evaluateValidation evaluates one validation against the prepared activation.
// A compile/eval failure or non-bool result is handled by applyFailurePolicy:
// with no policy it is reported as an error, with Ignore it is a pass, and with
// Fail it is a violation.
func (e *Evaluator) evaluateValidation(ctx context.Context, val Validation, activation map[string]any, budget *costBudget, failurePolicy *admissionregistrationv1.FailurePolicyType) ValidationResult {
	res := ValidationResult{Expression: val.Expression}

	out, err := e.evalExpression(ctx, val.Expression, activation, budget)
	if err != nil {
		return e.applyFailurePolicy(res, val, err, failurePolicy)
	}

	passed, ok := out.Value().(bool)
	if !ok {
		return e.applyFailurePolicy(res, val, &expressionError{fmt.Errorf("validation expression must return bool, got %T", out.Value())}, failurePolicy)
	}

	res.Passed = passed
	if !passed {
		res.Message = e.resolveMessage(ctx, val, activation, budget)
	}
	return res
}

// applyFailurePolicy turns a validation eval/compile/type error into the
// admission-time outcome dictated by spec.failurePolicy. Without a policy the
// result is left as an unknown error (the parity-safe fallback). Ignore turns
// the validation into a pass; Fail keeps the error so the scanner can report a
// deny. Compile errors, budget exhaustion and cancellation are never expression
// errors, so failurePolicy does not turn them into a deny.
func (e *Evaluator) applyFailurePolicy(res ValidationResult, val Validation, evalErr error, failurePolicy *admissionregistrationv1.FailurePolicyType) ValidationResult {
	if failurePolicy == nil {
		res.Err = evalErr
		res.Passed = false
		return res
	}
	if *failurePolicy == admissionregistrationv1.Ignore {
		res.Passed = true
		res.Err = nil
		res.Message = ""
		return res
	}
	res.Passed = false
	res.Err = evalErr
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
//
// A messageExpression draws from the same budget, as it does at admission,
// where it runs on whatever the validations left. Exhausting the budget here
// still only costs the message: the violation stands with its fallback text,
// and the validations that follow report the out-of-budget error instead.
// (The apiserver runs every validation before any messageExpression; we
// interleave them, so the two can differ in WHICH expression first finds the
// budget empty. The set of expressions charged, and therefore whether the
// policy fits, is the same.)
func (e *Evaluator) resolveMessage(ctx context.Context, val Validation, activation map[string]any, budget *costBudget) string {
	if val.MessageExpression != "" {
		if msg, ok := e.evalMessageExpression(ctx, val.MessageExpression, activation, budget); ok {
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
func (e *Evaluator) evalMessageExpression(ctx context.Context, expr string, activation map[string]any, budget *costBudget) (string, bool) {
	out, err := e.evalExpression(ctx, expr, activation, budget)
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

// evalExpression compiles one expression, evaluates it and settles it against
// the budget.
//
// Compiling is a separate step here, and it has to stay one: an expression that
// does not compile never ran, so it spent nothing and must not touch the budget
// at all. Admission works the same way, returning on compilationResult.Error
// before it reaches the accounting (plugin/cel/activation.go Evaluate), which
// leaves the rest of the policy free to evaluate on the untouched budget. Folding
// the two steps together would charge a typo the whole remaining budget and take
// every later validation in the policy down with it.
//
// Once the program does run, the charge happens BEFORE the eval error is
// returned, also on purpose: an expression that ran and then failed still
// consumed the units, and admission charges it the same way (cost first, error
// second). Skipping the charge on error would let a policy spend more offline
// than it can at admission.
func (e *Evaluator) evalExpression(ctx context.Context, expr string, activation map[string]any, budget *costBudget) (ref.Val, error) {
	// Compiled on first use and reused for every later object, so this is a map
	// lookup on all but the first (see cache.go).
	prog, err := e.programs.get(expr)
	if err != nil {
		return nil, err
	}

	out, details, evalErr := e.run(ctx, prog, activation)
	if err := budget.charge(details); err != nil {
		return nil, err
	}
	if evalErr != nil {
		if isContextError(ctx, evalErr) {
			return nil, evalErr
		}
		return nil, &expressionError{evalErr}
	}
	return out, nil
}

// run evaluates one already-compiled program against the activation and hands
// back the raw cost details alongside the result. Callers settle the cost
// themselves: a validation charges it, a variable only reports it (see
// lazyVariables).
//
// Taking a program rather than an expression is what keeps "never compiled" and
// "ran but reported no cost" apart for those callers. Anything that reaches here
// starts evaluating, and cel-go reports the cost tracker to the observer before
// it evaluates a single step, so the details returned are non-nil even when the
// run is cut short by an interrupt or the per-call limit.
func (e *Evaluator) run(ctx context.Context, prog cel.Program, activation map[string]any) (ref.Val, *cel.EvalDetails, error) {
	out, details, err := prog.ContextEval(ctx, activation)
	if err != nil {
		return nil, details, fmt.Errorf("eval: %w", err)
	}
	return out, details, nil
}

// compileProgram compiles one expression into a runnable program. Callers go
// through the program cache, never here directly, so each expression compiles
// once.
//
// Two program options matter here, and only one of them is ours to set:
//
//   - the PER-EXPRESSION cost limit is already in place. MustBaseEnvSet bakes
//     cel.CostLimit(PerCallLimit) in as a library option and cel-go applies it
//     to every env.Program call, so no expression can exceed 1M units offline
//     any more than it can at admission. Setting it again here would be a
//     no-op at best and a parity break at worst, so we do not.
//   - InterruptCheckFrequency is NOT in the base env set; the apiserver adds it
//     in its own compiler (plugin/cel/compile.go). Without it ContextEval only
//     notices a cancelled context between calls, so a comprehension over a long
//     list ignores Ctrl+C until it finishes. With it the runtime checks every
//     CheckFrequency steps, which is what makes an interrupted scan actually
//     stop.
//
// The budget the base env cannot give us is the shared one across a policy's
// expressions; that is accounted at evaluation time instead (see budget.go).
func (e *Evaluator) compileProgram(expr string) (cel.Program, error) {
	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile: %w", issues.Err())
	}

	prog, err := e.env.Program(ast, cel.InterruptCheckFrequency(celconfig.CheckFrequency))
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}
	return prog, nil
}
