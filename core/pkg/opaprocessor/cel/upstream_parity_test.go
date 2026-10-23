package cel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// This file is the harness behind TestUpstreamParity (see
// upstream_parity_cases_test.go for the cases and upstream_parity_decode_test.go
// for the typed-decoding matrix).
//
// The engine here evaluates a ValidatingAdmissionPolicy offline and must keep
// agreeing with what the apiserver's own validator decides for the same
// request. Each case is run twice:
//
//   - through the apiserver's admission plugin components, assembled the way
//     the validating plugin's compilePolicy assembles them (that function is
//     unexported, so the few exported pieces it is made of are wired up here);
//   - through the production path: newVAP, EvaluateVAPGate and
//     EvaluateVAPValidations.
//
// Both results are reduced to a parityOutcome and compared. Error text is
// never compared: the two sides word the same failure differently. A
// difference passes only when the exception registry pins it, with its class,
// its reason and the exact outcome of each side, so that a change on either
// side, and a difference that has gone away, both fail the run.

// parityGate is how a policy's matchConditions treated the request.
type parityGate string

const (
	parityGateMatched parityGate = "matched"
	parityGateSkipped parityGate = "skipped"
	// parityGateError is a gate that reached no verdict: failurePolicy Fail
	// denies the request, Ignore skips the policy (which then reads as
	// parityGateSkipped).
	parityGateError parityGate = "gate-error"
)

// parityVal is the outcome of one validation.
type parityVal string

const (
	parityPass       parityVal = "pass"
	parityDeny       parityVal = "deny"
	parityErrRuntime parityVal = "error:runtime"
	parityErrCompile parityVal = "error:compile"
	parityErrBudget  parityVal = "error:budget"
	parityErrOther   parityVal = "error:other"
)

// parityOutcome is what the two evaluators are compared on.
//
// Error kinds stay apart (runtime, compile, budget) because they follow
// different rules: only a runtime error is governed by failurePolicy on the
// Kubescape side, and the apiserver reports a budget failure for the whole
// policy rather than for one validation.
type parityOutcome struct {
	Gate parityGate
	// GateErr is the kind of a gate that reached no verdict.
	GateErr parityVal
	// Vals holds one entry per validation, in order. It is empty when the gate
	// skipped the policy, or did not reach a verdict.
	Vals []parityVal
	// Msgs holds the message of each denied validation, by index.
	Msgs map[int]string
	// Deny is the effective decision: whether the request is rejected.
	Deny bool
}

func (o parityOutcome) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "gate=%s", o.Gate)
	if o.GateErr != "" {
		fmt.Fprintf(&b, "(%s)", o.GateErr)
	}
	fmt.Fprintf(&b, " vals=%v deny=%t", o.Vals, o.Deny)
	if len(o.Msgs) > 0 {
		idx := make([]int, 0, len(o.Msgs))
		for i := range o.Msgs {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		for _, i := range idx {
			fmt.Fprintf(&b, " msg[%d]=%q", i, o.Msgs[i])
		}
	}
	return b.String()
}

// parityInput says which form of the object each evaluator receives. The
// apiserver decodes a built-in kind into its Go struct before a policy runs
// (see typedDecode); Kubescape reads the manifest as written.
type parityInput int

const (
	// parityRaw gives both sides the manifest as written.
	parityRaw parityInput = iota
	// parityPipeline gives the apiserver the typed-decoded object and
	// Kubescape the raw manifest: what each does for a built-in kind in
	// production.
	parityPipeline
	// parityBothTyped gives both sides the typed-decoded object, which
	// isolates the evaluator from the decoding step.
	parityBothTyped
)

func (m parityInput) String() string {
	switch m {
	case parityPipeline:
		return "pipeline"
	case parityBothTyped:
		return "typed"
	default:
		return "raw"
	}
}

// parityValidation is one spec.validations entry.
type parityValidation struct {
	Expression        string
	Message           string
	MessageExpression string
}

type parityVariable struct{ Name, Expression string }

// parityCase is one equivalent input for both evaluators. Objects are built by
// functions so that no two cases, and no two evaluators, share a map.
type parityCase struct {
	ID       string
	Category string
	Note     string

	// FailurePolicy is nil when the policy omits it, which newVAP defaults to
	// Fail the way the apiserver does.
	FailurePolicy   *admissionregistrationv1.FailurePolicyType
	MatchConditions []string
	Variables       []parityVariable
	Validations     []parityValidation
	// ParamKind declares spec.paramKind. Params is the bound param object, nil
	// for a binding that resolved none.
	ParamKind bool
	Params    func() map[string]any

	Object    func() map[string]any
	Namespace func() map[string]any
	// Resource is the plural the apiserver matched, for kinds the cases use.
	Resource string

	// Operation, OldObject, SubResource, User and DryRun describe the request
	// the apiserver sees; Kubescape models a fresh CREATE of the main resource.
	Operation   admission.Operation
	OldObject   func() map[string]any
	SubResource string
	User        *user.DefaultInfo

	// Budget overrides the cost budget of the validations on both sides. It is
	// not allowed with matchConditions: the apiserver's gate budget is a
	// constant, so the two gates would run on different budgets.
	Budget int64
	Cancel bool

	// Inputs lists the object forms to run; the default is parityRaw.
	Inputs []parityInput
}

// parityRunID names one run of a case.
func parityRunID(c parityCase, in parityInput) string {
	return c.ID + "@" + in.String()
}

func parityFailPolicy(p admissionregistrationv1.FailurePolicyType) *admissionregistrationv1.FailurePolicyType {
	return &p
}

func (c parityCase) policy() *admissionregistrationv1.ValidatingAdmissionPolicy {
	p := &admissionregistrationv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: "parity"}}
	p.Spec.FailurePolicy = c.FailurePolicy
	for i, expr := range c.MatchConditions {
		p.Spec.MatchConditions = append(p.Spec.MatchConditions, admissionregistrationv1.MatchCondition{Name: fmt.Sprintf("m%d", i), Expression: expr})
	}
	for _, v := range c.Variables {
		p.Spec.Variables = append(p.Spec.Variables, admissionregistrationv1.Variable{Name: v.Name, Expression: v.Expression})
	}
	for _, v := range c.Validations {
		p.Spec.Validations = append(p.Spec.Validations, admissionregistrationv1.Validation{
			Expression: v.Expression, Message: v.Message, MessageExpression: v.MessageExpression,
		})
	}
	if c.ParamKind || c.Params != nil {
		p.Spec.ParamKind = &admissionregistrationv1.ParamKind{APIVersion: "v1", Kind: "ConfigMap"}
	}
	return p
}

// parityObject returns the object in the form the evaluator will receive.
func parityObject(t *testing.T, raw map[string]any, typed bool) map[string]any {
	t.Helper()
	if raw == nil || !typed {
		return raw
	}
	return parityTypedDecode(t, raw)
}

// parityTypedDecode runs a built-in kind through the existing typedDecode
// helper. A kind the client-go scheme does not know is a custom resource, which
// the apiserver hands to a policy as written, so it is returned unchanged.
func parityTypedDecode(t *testing.T, raw map[string]any) map[string]any {
	t.Helper()
	apiVersion, _ := raw["apiVersion"].(string)
	kind, _ := raw["kind"].(string)
	gv, err := schema.ParseGroupVersion(apiVersion)
	require.NoError(t, err)
	if !clientgoscheme.Scheme.Recognizes(gv.WithKind(kind)) {
		return raw
	}
	manifest, err := json.Marshal(raw)
	require.NoError(t, err)
	return typedDecode(t, string(manifest))
}

func parityCopy(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return runtime.DeepCopyJSON(m)
}

// parityAllowAll stands in for the apiserver's authorizer, which a real request
// always carries. Every check is allowed, so an expression using authorizer
// has a defined result upstream.
type parityAllowAll struct{}

func (parityAllowAll) Authorize(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionAllow, "", nil
}

// parityContext is the context both sides run under.
func parityContext(c parityCase) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	if c.Cancel {
		cancel()
	}
	return ctx, cancel
}

// parityKubescape runs a case through the production path.
func parityKubescape(t *testing.T, c parityCase, obj, ns, params map[string]any) parityOutcome {
	t.Helper()
	var opts []Option
	if c.Budget > 0 {
		opts = append(opts, WithCostBudget(c.Budget))
	}
	ev, err := NewEvaluator(opts...)
	require.NoError(t, err)
	vap := newVAP(c.policy())
	ctx, cancel := parityContext(c)
	defer cancel()

	var boundParams any
	if params != nil {
		boundParams = params
	}
	compileFails := func(expr string) bool {
		_, err := ev.compileProgram(expr)
		return err != nil
	}
	classify := func(err error, expr string, isExpr bool) parityVal {
		switch {
		case errors.Is(err, errOutOfBudget):
			return parityErrBudget
		case IsExpressionError(err):
			return parityErrRuntime
		case isExpr && compileFails(expr):
			return parityErrCompile
		default:
			return parityErrOther
		}
	}

	out := parityOutcome{Gate: parityGateMatched}
	gate, err := ev.EvaluateVAPGate(ctx, vap, obj, boundParams)
	require.NoError(t, err)
	if !gate.Applicable {
		out.Gate = parityGateSkipped
		return out
	}
	eval := gate
	if len(gate.Results) > 0 {
		out.Gate = parityGateError
		out.GateErr = classify(gate.Results[0].Err, "", false)
		if out.GateErr == parityErrOther {
			for _, cond := range vap.matchConditions {
				if compileFails(cond.Expression) {
					out.GateErr = parityErrCompile
				}
			}
		}
	} else {
		eval, err = ev.EvaluateVAPValidations(ctx, vap, obj, ns, boundParams)
		require.NoError(t, err)
	}

	// The scanner turns a result into a decision this way (see celbased
	// handling in processorhandler.go): a violation denies, and so does an
	// expression error when failurePolicy is Fail.
	for i, res := range eval.Results {
		switch {
		case res.Err != nil:
			if out.Gate == parityGateMatched {
				out.Vals = append(out.Vals, classify(res.Err, res.Expression, true))
			}
			if eval.FailOnError && IsExpressionError(res.Err) {
				out.Deny = true
			}
		case !res.Passed:
			out.Vals = append(out.Vals, parityDeny)
			if out.Msgs == nil {
				out.Msgs = map[int]string{}
			}
			out.Msgs[i] = res.Message
			out.Deny = true
		default:
			if out.Gate == parityGateMatched {
				out.Vals = append(out.Vals, parityPass)
			}
		}
	}
	// An Ignore policy turns a runtime error into a pass inside the evaluator,
	// so there is nothing left to normalize on this side.
	return out
}

// parityUpstream runs a case through the apiserver's admission policy
// components.
func parityUpstream(t *testing.T, c parityCase, obj, old, ns, params map[string]any) parityOutcome {
	t.Helper()
	p := c.policy()
	hasParams := p.Spec.ParamKind != nil
	withAuthorizer := celplugin.OptionalVariableDeclarations{HasParams: hasParams, HasAuthorizer: true}
	withoutAuthorizer := celplugin.OptionalVariableDeclarations{HasParams: hasParams}

	compiler, err := celplugin.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	require.NoError(t, err)
	variables := make([]celplugin.NamedExpressionAccessor, 0, len(p.Spec.Variables))
	for _, v := range p.Spec.Variables {
		variables = append(variables, &validating.Variable{Name: v.Name, Expression: v.Expression})
	}
	compiler.CompileAndStoreVariables(variables, withAuthorizer, environment.StoredExpressions)

	var matcher matchconditions.Matcher
	var gateFilter celplugin.ConditionEvaluator
	if len(p.Spec.MatchConditions) > 0 {
		accessors := make([]celplugin.ExpressionAccessor, len(p.Spec.MatchConditions))
		for i := range p.Spec.MatchConditions {
			accessors[i] = (*matchconditions.MatchCondition)(&p.Spec.MatchConditions[i])
		}
		gateFilter = compiler.CompileCondition(accessors, withAuthorizer, environment.StoredExpressions)
		matcher = matchconditions.NewMatcher(gateFilter, p.Spec.FailurePolicy, "policy", "validate", p.Name)
	}
	validations := make([]celplugin.ExpressionAccessor, len(p.Spec.Validations))
	messages := make([]celplugin.ExpressionAccessor, len(p.Spec.Validations))
	for i, v := range p.Spec.Validations {
		validations[i] = &validating.ValidationCondition{Expression: v.Expression, Message: v.Message}
		if v.MessageExpression != "" {
			messages[i] = &validating.MessageExpressionCondition{MessageExpression: v.MessageExpression}
		}
	}
	// NewValidator dereferences the audit annotation filter, so an empty
	// compiled one stands in for a policy without audit annotations.
	validator := validating.NewValidator(
		compiler.CompileCondition(validations, withAuthorizer, environment.StoredExpressions),
		matcher,
		compiler.CompileCondition(nil, withAuthorizer, environment.StoredExpressions),
		compiler.CompileCondition(messages, withoutAuthorizer, environment.StoredExpressions),
		p.Spec.FailurePolicy, nil)

	subject := &unstructured.Unstructured{Object: obj}
	gvk := subject.GroupVersionKind()
	gvr := schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: c.Resource}
	namespace := subject.GetNamespace()
	var oldObject runtime.Object
	if old != nil {
		oldObject = &unstructured.Unstructured{Object: old}
	}
	op := c.Operation
	if op == "" {
		op = admission.Create
	}
	info := c.User
	if info == nil {
		info = &user.DefaultInfo{}
	}
	attr := admission.NewAttributesRecord(subject, oldObject, gvk, namespace, subject.GetName(), gvr, c.SubResource, op, &metav1.CreateOptions{}, false, info)
	versioned, err := admission.NewVersionedAttributes(attr, gvk, nil)
	require.NoError(t, err)

	var boundParams runtime.Object
	if params != nil {
		boundParams = &unstructured.Unstructured{Object: params}
	}
	var namespaceObject *corev1.Namespace
	if ns != nil {
		namespaceObject = &corev1.Namespace{}
		require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(ns, namespaceObject))
	}
	ctx, cancel := parityContext(c)
	defer cancel()
	budget := int64(celconfig.RuntimeCELCostBudget)
	if c.Budget > 0 {
		budget = c.Budget
	}

	out := parityOutcome{Gate: parityGateMatched}
	if matcher != nil {
		result := matcher.Match(ctx, versioned, boundParams, parityAllowAll{})
		switch {
		case result.Error != nil:
			out.Gate = parityGateError
			out.GateErr = parityErrRuntime
			switch {
			case errors.Is(result.Error, apiservercel.ErrOutOfBudget):
				out.GateErr = parityErrBudget
			case len(gateFilter.CompilationErrors()) > 0:
				out.GateErr = parityErrCompile
			}
		case !result.Matches:
			out.Gate = parityGateSkipped
		}
	}
	result := validator.Validate(ctx, versioned.GetResource(), versioned, boundParams, namespaceObject, budget, parityAllowAll{})
	for _, d := range result.Decisions {
		if d.Action == validating.ActionDeny {
			out.Deny = true
		}
	}
	if out.Gate != parityGateMatched {
		return out
	}

	// A validation that exhausts the cost budget ends the whole policy: the
	// apiserver reports one error decision for it instead of one per validation.
	budgetSpent := false
	filter := compiler.CompileCondition(validations, withAuthorizer, environment.StoredExpressions)
	if _, _, err := filter.ForInput(ctx, versioned, celplugin.CreateAdmissionRequest(versioned.Attributes, metav1.GroupVersionResource(versioned.GetResource()), metav1.GroupVersionKind(versioned.VersionedKind)),
		celplugin.OptionalVariableBindings{VersionedParams: boundParams}, celplugin.CreateNamespaceObject(namespaceObject), budget); err != nil {
		budgetSpent = errors.Is(err, apiservercel.ErrOutOfBudget)
	}
	for i, d := range result.Decisions {
		switch {
		case d.Evaluation == validating.EvalError && d.Action == validating.ActionAdmit:
			// failurePolicy Ignore: the error does not reach the request.
			out.Vals = append(out.Vals, parityPass)
		case d.Evaluation == validating.EvalError:
			kind := parityErrRuntime
			switch {
			case budgetSpent:
				kind = parityErrBudget
			case i < len(validations) && len(compiler.CompileCondition(validations[i:i+1], withAuthorizer, environment.StoredExpressions).CompilationErrors()) > 0:
				kind = parityErrCompile
			}
			out.Vals = append(out.Vals, kind)
		case d.Action == validating.ActionDeny:
			out.Vals = append(out.Vals, parityDeny)
			if out.Msgs == nil {
				out.Msgs = map[int]string{}
			}
			out.Msgs[i] = d.Message
		default:
			out.Vals = append(out.Vals, parityPass)
		}
	}
	return out
}

// parityClass says why a difference is allowed to exist.
type parityClass string

const (
	// parityIntentional is behavior the offline engine chose, with a stated
	// reason in the code.
	parityIntentional parityClass = "intentional"
	// parityInputPipeline is a difference in the object each side is handed,
	// not in how it is evaluated.
	parityInputPipeline parityClass = "input-pipeline"
	// parityCandidateBug is a difference no source comment justifies. It is
	// pinned so the suite stays green and the mismatch stays visible; it is
	// not an endorsement.
	parityCandidateBug parityClass = "candidate-bug"
	// parityUnresolved needs a maintainer to decide.
	parityUnresolved parityClass = "unresolved"
	// parityNotComparable is a request the two sides cannot be given in
	// equivalent form.
	parityNotComparable parityClass = "not-comparable"
)

// parityException pins one known difference. Upstream and Kubescape are the
// exact outcomes of each side, so the entry fails when either one changes.
type parityException struct {
	Class  parityClass
	Reason string
	// Source is the code or upstream behavior the reason rests on.
	Source    string
	Upstream  string
	Kubescape string
	// Accepted is false for a difference that still needs investigation.
	Accepted bool
}

// parityRunnable is a case at one input form.
type parityRunnable struct {
	c  parityCase
	in parityInput
}

func (r parityRunnable) id() string { return parityRunID(r.c, r.in) }

func parityRun(t *testing.T, r parityRunnable) (upstream, kubescape parityOutcome) {
	t.Helper()
	c := r.c
	require.False(t, c.Budget > 0 && len(c.MatchConditions) > 0, "%s: a cost budget override needs a policy without matchConditions", c.ID)
	build := func(f func() map[string]any, typed bool) map[string]any {
		if f == nil {
			return nil
		}
		return parityObject(t, parityCopy(f()), typed)
	}
	upstreamTyped := r.in == parityPipeline || r.in == parityBothTyped
	kubescapeTyped := r.in == parityBothTyped
	upstreamObj := build(c.Object, upstreamTyped)
	// The apiserver decodes the Namespace into its Go struct whatever the
	// object's form, so only Kubescape's copy follows the input form.
	upstreamNS := build(c.Namespace, true)
	kubescapeNS := build(c.Namespace, kubescapeTyped)

	upstream = parityUpstream(t, c, upstreamObj, build(c.OldObject, upstreamTyped), upstreamNS, build(c.Params, false))
	kubescape = parityKubescape(t, c, build(c.Object, kubescapeTyped), kubescapeNS, build(c.Params, false))
	return upstream, kubescape
}

// parityRunnables expands cases into runs.
func parityRunnables(cases []parityCase) []parityRunnable {
	var runs []parityRunnable
	for _, c := range cases {
		inputs := c.Inputs
		if len(inputs) == 0 {
			inputs = []parityInput{parityRaw}
		}
		for _, in := range inputs {
			runs = append(runs, parityRunnable{c: c, in: in})
		}
	}
	return runs
}

// parityCheck compares one run and applies the exception registry.
func parityCheck(t *testing.T, r parityRunnable, seen map[string]bool) {
	t.Helper()
	upstream, kubescape := parityRun(t, r)
	id := r.id()
	exc, known := parityExceptions[id]
	if known {
		seen[id] = true
	}
	same := upstream.String() == kubescape.String()
	describe := func() string {
		return fmt.Sprintf("case %s [%s]\n  upstream:  %s\n  kubescape: %s", id, r.c.Category, upstream, kubescape)
	}
	switch {
	case same && known:
		t.Fatalf("the exception for %s no longer applies: both sides now agree on %s\n  %s", id, upstream, exc.Reason)
	case same:
		return
	case !known:
		t.Fatalf("unrecorded difference\n%s\n  note: %s", describe(), r.c.Note)
	case exc.Upstream != upstream.String() || exc.Kubescape != kubescape.String():
		t.Fatalf("recorded %s difference changed\n%s\n  recorded upstream:  %s\n  recorded kubescape: %s\n  reason: %s",
			exc.Class, describe(), exc.Upstream, exc.Kubescape, exc.Reason)
	case !exc.Accepted:
		t.Logf("tracked %s difference, still to investigate\n%s", exc.Class, describe())
	}
}

// parityAllCases is every case the suite runs.
func parityAllCases() []parityCase {
	var cases []parityCase
	cases = append(cases, parityValidationCases()...)
	cases = append(cases, parityRuntimeCases()...)
	cases = append(cases, parityGateCases()...)
	cases = append(cases, parityFailurePolicyCases()...)
	cases = append(cases, parityVariableCases()...)
	cases = append(cases, parityMessageCases()...)
	cases = append(cases, parityParamCases()...)
	cases = append(cases, parityRequestCases()...)
	cases = append(cases, parityStaticTypingCases()...)
	cases = append(cases, parityBudgetCases()...)
	cases = append(cases, parityDecodeCases()...)
	return cases
}

// variableReference finds the variables a CEL expression reads.
var variableReference = regexp.MustCompile(`variables\.([A-Za-z_][A-Za-z0-9_]*)`)

// parityVariableCycle returns the name of a variable that, directly or through
// others, reads itself. The offline evaluator resolves variables lazily by
// name and recurses until the Go stack overflows on such a policy; that is a
// fatal error, not a failure a test can report, so a case that holds one must
// never be evaluated.
func parityVariableCycle(vars []parityVariable) string {
	reads := make(map[string][]string, len(vars))
	for _, v := range vars {
		for _, m := range variableReference.FindAllStringSubmatch(v.Expression, -1) {
			reads[v.Name] = append(reads[v.Name], m[1])
		}
	}
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var visit func(name string) string
	visit = func(name string) string {
		switch state[name] {
		case visiting:
			return name
		case done:
			return ""
		}
		state[name] = visiting
		for _, next := range reads[name] {
			if cycle := visit(next); cycle != "" {
				return cycle
			}
		}
		state[name] = done
		return ""
	}
	for _, v := range vars {
		if cycle := visit(v.Name); cycle != "" {
			return cycle
		}
	}
	return ""
}

// TestUpstreamParityCasesHaveNoVariableCycle fails a case set that would crash
// the test binary before anything is evaluated.
func TestUpstreamParityCasesHaveNoVariableCycle(t *testing.T) {
	require.Equal(t, "a", parityVariableCycle([]parityVariable{{"a", "variables.a + 1"}}), "the guard must see a self-reference")
	require.Equal(t, "a", parityVariableCycle([]parityVariable{{"a", "variables.b"}, {"b", "variables.a"}}), "the guard must see a mutual reference")
	require.Empty(t, parityVariableCycle([]parityVariable{{"a", "1"}, {"b", "variables.a + 1"}}))
	for _, c := range parityAllCases() {
		require.Emptyf(t, parityVariableCycle(c.Variables), "%s: a variable reads itself, which overflows the stack offline; leave such a policy out of the cases", c.ID)
	}
}

func TestUpstreamParity(t *testing.T) {
	// Checked here as well, so that running only this test cannot reach a case
	// that crashes the process.
	TestUpstreamParityCasesHaveNoVariableCycle(t)
	runs := parityRunnables(parityAllCases())
	seen := make(map[string]bool, len(parityExceptions))
	ids := make(map[string]bool, len(runs))
	for _, r := range runs {
		id := r.id()
		require.False(t, ids[id], "duplicate parity case %s", id)
		ids[id] = true
		t.Run(id, func(t *testing.T) { parityCheck(t, r, seen) })
	}
	for id := range parityExceptions {
		require.True(t, ids[id], "exception %s names no case", id)
	}
}

// TestUpstreamParityExceptionsAreDocumented keeps the registry reviewable: an
// entry without a reason, a source or both outcomes explains nothing.
func TestUpstreamParityExceptionsAreDocumented(t *testing.T) {
	classes := map[parityClass]bool{
		parityIntentional: true, parityInputPipeline: true, parityCandidateBug: true,
		parityUnresolved: true, parityNotComparable: true,
	}
	var tracked []string
	for id, exc := range parityExceptions {
		require.True(t, classes[exc.Class], "%s: unknown class %q", id, exc.Class)
		require.NotEmpty(t, exc.Reason, "%s: reason", id)
		require.NotEmpty(t, exc.Source, "%s: source", id)
		require.NotEmpty(t, exc.Upstream, "%s: upstream outcome", id)
		require.NotEmpty(t, exc.Kubescape, "%s: kubescape outcome", id)
		require.NotEqual(t, exc.Upstream, exc.Kubescape, "%s: both outcomes are the same", id)
		if !exc.Accepted {
			require.Contains(t, []parityClass{parityCandidateBug, parityUnresolved, parityInputPipeline}, exc.Class, "%s: only a candidate, unresolved or pending input-pipeline difference is left open", id)
			tracked = append(tracked, id)
		}
	}
	sort.Strings(tracked)
	t.Logf("%d differences are tracked and not yet accepted: %v", len(tracked), tracked)
}

// TestUpstreamParityAdaptersReportOutcomes pins what each adapter reports for
// inputs whose outcome is obvious, so that two adapters which both reported
// nothing cannot pass the comparison by agreeing.
func TestUpstreamParityAdaptersReportOutcomes(t *testing.T) {
	cases := []struct {
		c    parityCase
		want string
	}{
		{parityNew("pass", parityCatValidation, parityExprs("true")),
			"gate=matched vals=[pass] deny=false"},
		{parityNew("deny", parityCatValidation, parityExprs("false")),
			`gate=matched vals=[deny] deny=true msg[0]="failed expression: false"`},
		{parityNew("static message", parityCatValidation, parityValidations(parityValidation{Expression: "false", Message: "no"})),
			`gate=matched vals=[deny] deny=true msg[0]="no"`},
		{parityNew("runtime error under Fail", parityCatValidation, parityFailure(parityFail), parityExprs("1 / 0 == 1")),
			"gate=matched vals=[error:runtime] deny=true"},
		{parityNew("runtime error under Ignore", parityCatValidation, parityFailure(parityIgnore), parityExprs("1 / 0 == 1")),
			"gate=matched vals=[pass] deny=false"},
		{parityNew("skipped", parityCatGate, parityGateExprs("false"), parityExprs("false")),
			"gate=skipped vals=[] deny=false"},
		{parityNew("gate error under Fail", parityCatGate, parityFailure(parityFail), parityGateExprs("1 / 0 == 1"), parityExprs("false")),
			"gate=gate-error(error:runtime) vals=[] deny=true"},
		{parityNew("gate error under Ignore", parityCatGate, parityFailure(parityIgnore), parityGateExprs("1 / 0 == 1"), parityExprs("false")),
			"gate=skipped vals=[] deny=false"},
		{parityNew("budget", parityCatBudget, parityBudget(1), parityExprs(parityCostly(55))),
			"gate=matched vals=[error:budget] deny=true"},
	}
	for _, tc := range cases {
		t.Run(tc.c.ID, func(t *testing.T) {
			upstream, kubescape := parityRun(t, parityRunnable{c: tc.c, in: parityRaw})
			// Only the budget case may shape its outcome differently: Kubescape
			// reports one entry per validation rather than one for the policy.
			require.Equal(t, tc.want, upstream.String(), "upstream")
			if tc.c.Category != parityCatBudget {
				require.Equal(t, tc.want, kubescape.String(), "kubescape")
			}
		})
	}
}

// TestUpstreamParityProductionEntryPoint checks that the combined entry point
// (EvaluateVAP) gives the result the harness gets by calling the gate and the
// validations separately, so the cases above describe what a scan does.
func TestUpstreamParityProductionEntryPoint(t *testing.T) {
	for _, c := range []parityCase{
		parityNew("pass", parityCatValidation, parityExprs("true")),
		parityNew("deny", parityCatValidation, parityExprs("false", "true")),
		parityNew("error", parityCatValidation, parityExprs("1 / 0 == 1")),
		parityNew("skip", parityCatGate, parityGateExprs("false"), parityExprs("false")),
		parityNew("ignore", parityCatFailure, parityFailure(parityIgnore), parityExprs("1 / 0 == 1")),
		parityNew("typed", parityCatDecode, parityExprs("has(object.status)")),
		parityNew("request", parityCatRequest, parityExprs("request.subResource == ''")),
	} {
		t.Run(c.ID, func(t *testing.T) {
			ev, err := NewEvaluator()
			require.NoError(t, err)
			vap := newVAP(c.policy())
			obj := c.Object()

			whole, err := ev.EvaluateVAP(context.Background(), vap, obj, nil, nil)
			require.NoError(t, err)

			gate, err := ev.EvaluateVAPGate(context.Background(), vap, obj, nil)
			require.NoError(t, err)
			split := gate
			if gate.Applicable && len(gate.Results) == 0 {
				split, err = ev.EvaluateVAPValidations(context.Background(), vap, obj, nil, nil)
				require.NoError(t, err)
			}
			require.Equal(t, split.Applicable, whole.Applicable)
			require.Equal(t, split.FailOnError, whole.FailOnError)
			require.Len(t, whole.Results, len(split.Results))
			for i := range whole.Results {
				require.Equal(t, split.Results[i].Passed, whole.Results[i].Passed, "result %d", i)
				require.Equal(t, split.Results[i].Err == nil, whole.Results[i].Err == nil, "result %d error", i)
				require.Equal(t, split.Results[i].Message, whole.Results[i].Message, "result %d message", i)
			}
		})
	}
}
