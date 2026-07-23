package cel

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types/ref"
)

// PathHint is one place in the scanned object that a failed validation looked
// at. It is deliberately a neutral type: package cel does not depend on the
// report model, so the scanner maps hints onto the report's remediation fields
// at its own boundary.
//
// Path is dotted and object-relative, indexed where the failure was pinned to a
// specific list element: "spec.containers[0].securityContext.readOnlyRootFilesystem".
//
// Value is the literal the expression requires at that path, and is only set
// when the requirement is unambiguous: an equality the policy demands, not one
// of several alternatives. It is empty whenever the expression asks for
// something we cannot turn into a single value a caller could safely write.
type PathHint struct {
	Path  string
	Value string
}

// A ValidatingAdmissionPolicy carries no path information: a validation is an
// expression, a message and a reason, and nothing else. Rego rules hand back
// failedPaths/fixPaths because their author wrote them out by hand; for CEL the
// paths have to be recovered from the expression itself.
//
// That happens in two stages, split because the first is expensive and object
// independent while the second is cheap and object specific:
//
//  1. pathPlan reads the compiled expression once and records which fields it
//     reads (see newPathPlan). Cached per expression.
//  2. resolve turns that plan into concrete hints for one failing object,
//     pinning list indices by re-checking the expression element by element.
//
// Stage 2 only ever runs for an object that already failed, so the extra
// evaluations cost nothing on a clean scan.
//
// The rule running through both stages is that a wrong path is worse than no
// path, because `kubescape fix` writes a hint's value straight into a user's
// YAML. Every place the analysis cannot be sure it drops the value, or the
// path, rather than guess.

// fieldRef is one field an expression reads, with the literal the policy
// requires it to equal, when the expression makes that requirement unambiguous.
type fieldRef struct {
	path  string
	value string
}

// elementPlan describes a validation that iterates a list on the object, which
// is the shape almost every workload policy in the bundle has
// (`object.spec.containers.all(container, ...)`). collection is the list's
// object-relative path and fields are element-relative, so the two are joined
// with an index once we know which element failed.
type elementPlan struct {
	collection string
	fields     []fieldRef
}

// pathPlan is everything one validation expression can say about where it
// failed, independent of any particular object.
type pathPlan struct {
	// direct are fields read straight off the object.
	direct []fieldRef
	// elements is set only when the expression iterates exactly one list on the
	// object AND narrowing that list to one element and re-checking is an exact
	// test of that element (see narrowingIsExact). With no such list there is
	// nothing to index; with more than one we cannot tell which list a failure
	// came from; with a list whose quantifier makes the elements alternatives
	// rather than requirements, blaming one would be a guess. All three fall
	// back to direct paths only.
	elements *elementPlan
}

// scopeGuardFields are object fields a validation reads only to decide whether
// the policy covers this kind at all - every policy in the bundle opens with
// `object.kind != 'Pod' || ...`. They are never what a user has to fix, and
// appliesTo has already made that decision before we get here, so they never
// become a hint (and a disjunct that only tests them is not a real alternative
// to a fix, see siblingHasObjectAlternative).
var scopeGuardFields = map[string]bool{
	"kind":       true,
	"apiVersion": true,
}

// newPathPlan derives the plan for one compiled validation expression.
func newPathPlan(ast *cel.Ast) pathPlan {
	native := ast.NativeRep()
	root := celast.NavigateAST(native)

	// Comprehensions over something other than the object (the bundle iterates
	// params lists and inline kind lists too) tell us nothing about where the
	// object is wrong, so only object-rooted ones count.
	var iterated []celast.NavigableExpr
	ranges := map[string]bool{}
	for _, node := range celast.MatchDescendants(root, celast.KindMatcher(celast.ComprehensionKind)) {
		path, ok := selectPath(node.AsComprehension().IterRange(), "object")
		if !ok {
			continue
		}
		iterated = append(iterated, node)
		ranges[path] = true
	}

	plan := pathPlan{}
	// Exactly one object-rooted list, and only when re-checking a single element
	// against the whole validation is a faithful test of that element. Anything
	// else and we cannot attribute a failure to a specific element without
	// guessing, so we do not try.
	if len(iterated) == 1 && narrowingIsExact(iterated[0]) {
		comprehension := iterated[0].AsComprehension()
		collection, _ := selectPath(comprehension.IterRange(), "object")

		// A field the element predicate reads is element-relative and joined to
		// the pinned index. This includes a collection the predicate iterates in
		// turn (a container's ports, a container's command): we cannot pin the
		// inner index without a second level of re-checking, so that inner
		// collection stays a review path pointing at the offending element's
		// list - which still tells the user the container and the field to look
		// at, unlike the object-level list we index into, which is not a hint
		// because we are about to point at one of its elements instead.
		loopStep := celast.NavigateExpr(native, comprehension.LoopStep())
		plan.elements = &elementPlan{
			collection: collection,
			fields:     fieldsRootedAt(native, loopStep, comprehension.IterVar(), nil),
		}
	}

	// The iterated list itself is not a direct hint: either we are about to
	// point at one of its elements, or we could not tell which list failed and
	// naming them all would just be noise.
	plan.direct = fieldsRootedAt(native, root, "object", ranges)
	return plan
}

// narrowingIsExact reports whether resolve may attribute a failure to a single
// element of an object-rooted comprehension.
//
// resolve narrows the list to one element and re-runs the WHOLE validation. For
// that to be a faithful test of the one element, the element's contribution has
// to be conjunctive with the verdict:
//
//   - `all(e, p)`  fails because some element fails p. Re-run on a singleton is
//     p(e): fails exactly for the offenders. Exact.
//   - `!exists(e, p)` (equivalently `all(e, !p)`) fails because some element
//     satisfies p. Re-run is !p(e): fails exactly for those. Also exact.
//   - bare `exists(e, p)` fails because NO element satisfies p. Re-run is p(e),
//     which fails for every element, so it would blame them all. Not exact.
//   - `!all(e, p)` is the mirror image and equally not exact.
//
// So an `all` under an even number of negations, or an `exists` under an odd
// number, is exact; the other two combinations are not. A ternary between the
// comprehension and the root is not something we reason about, so it is treated
// as not exact.
//
// This is necessary but not sufficient: re-running the WHOLE validation is only
// a test of the element when the comprehension is also the sole reason the
// validation failed. A conjunctive sibling that reads the object
// (`hostNetwork == false && containers.all(...)`) fails on every singleton too,
// which would blame every element. resolve guards that separately, by checking
// the validation passes once the list is emptied before it attributes any
// element (see resolve).
func narrowingIsExact(comprehension celast.NavigableExpr) bool {
	all, ok := quantifierIsAll(comprehension.AsComprehension())
	if !ok {
		return false
	}

	negations := 0
	for node := comprehension; ; {
		parent, ok := node.Parent()
		if !ok {
			break
		}
		if parent.Kind() == celast.CallKind {
			switch parent.AsCall().FunctionName() {
			case operators.LogicalNot:
				negations++
			case operators.Conditional:
				return false
			}
		}
		node = parent
	}

	even := negations%2 == 0
	if all {
		return even
	}
	return !even
}

// quantifierIsAll classifies a comprehension as the all macro (true) or the
// exists macro (false), reporting false in the second return for anything else
// (exists_one, map, filter), which we do not attribute elements from. The two
// macros are told apart by how the standard library expands them: all seeds the
// accumulator true and folds with &&, exists seeds false and folds with ||.
func quantifierIsAll(c celast.ComprehensionExpr) (isAll bool, ok bool) {
	init := c.AccuInit()
	if init.Kind() != celast.LiteralKind {
		return false, false
	}
	seed, isBool := init.AsLiteral().Value().(bool)
	if !isBool {
		return false, false
	}
	step := c.LoopStep()
	if step.Kind() != celast.CallKind {
		return false, false
	}
	switch {
	case seed && step.AsCall().FunctionName() == operators.LogicalAnd:
		return true, true
	case !seed && step.AsCall().FunctionName() == operators.LogicalOr:
		return false, true
	default:
		return false, false
	}
}

// fieldsRootedAt collects the fields an expression reads off a given variable,
// with the value each field is required to hold where that is unambiguous.
//
// Only the longest chain of each read counts: `has(c.securityContext) &&
// c.securityContext.readOnlyRootFilesystem == true` reads two nested paths but
// describes one requirement, and pointing a user at the parent as well as the
// leaf is noise. So chains that another chain extends are dropped. Scope guards
// and the excluded paths (an iterated collection) never become fields.
func fieldsRootedAt(native *celast.AST, root celast.NavigableExpr, ident string, exclude map[string]bool) []fieldRef {
	var refs []fieldRef
	for _, node := range celast.MatchDescendants(root, celast.KindMatcher(celast.SelectKind)) {
		// A select whose parent is a select is the operand of a longer chain;
		// the outermost one carries the full path.
		if parent, ok := node.Parent(); ok && parent.Kind() == celast.SelectKind {
			continue
		}
		path, ok := selectPath(node, ident)
		if !ok || path == "" || scopeGuardFields[path] || exclude[path] {
			continue
		}
		refs = append(refs, fieldRef{path: path, value: requiredValue(native, node, ident)})
	}
	return dedupeRefs(refs)
}

// dedupeRefs drops duplicates and any path another path extends, then orders
// what is left so the same object always produces the same hints.
func dedupeRefs(refs []fieldRef) []fieldRef {
	kept := make(map[string]string, len(refs))
	for _, ref := range refs {
		// Prefer a ref that carries a value: the same field can be read once as
		// a presence test and once as an equality, and the equality is the one
		// that can be fixed.
		if existing, seen := kept[ref.path]; !seen || existing == "" {
			kept[ref.path] = ref.value
		}
	}

	out := make([]fieldRef, 0, len(kept))
	for path, value := range kept {
		extended := false
		for other := range kept {
			if other != path && strings.HasPrefix(other, path+".") {
				extended = true
				break
			}
		}
		if !extended {
			out = append(out, fieldRef{path: path, value: value})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// selectPath renders a chain of field selections rooted at ident as a dotted
// path, reporting false for a chain rooted at anything else. `has(x.y)` is a
// select too (a presence test), so it yields the same path a plain read would.
func selectPath(expr celast.Expr, ident string) (string, bool) {
	var reversed []string
	for expr.Kind() == celast.SelectKind {
		sel := expr.AsSelect()
		reversed = append(reversed, sel.FieldName())
		expr = sel.Operand()
	}
	if expr.Kind() != celast.IdentKind || expr.AsIdent() != ident {
		return "", false
	}

	parts := make([]string, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		parts = append(parts, reversed[i])
	}
	return strings.Join(parts, "."), true
}

// requiredValue returns the literal a field read is compared against, but only
// when the policy genuinely REQUIRES the field to hold that value -
// `container.securityContext.readOnlyRootFilesystem == true` means the fix is
// to set that path to true.
//
// Everything short of a required value yields none, on purpose, because the
// value is written into a user's file:
//   - `!=` says what the field must not be, which is not a value to write.
//   - an equality reached through a negation or a ternary may be inverted by
//     the time it reaches the verdict (see negated).
//   - an equality that is one branch of a disjunction is an ALTERNATIVE, not a
//     requirement: `namespace == 'kube-system' || hostNetwork == false` is
//     satisfied by either, so writing both would move a workload into
//     kube-system to satisfy a host-network policy (see valueIsRequirement).
func requiredValue(native *celast.AST, node celast.NavigableExpr, ident string) string {
	parent, ok := node.Parent()
	if !ok || parent.Kind() != celast.CallKind {
		return ""
	}
	call := parent.AsCall()
	if call.FunctionName() != operators.Equals || len(call.Args()) != 2 {
		return ""
	}

	var literal celast.Expr
	for _, arg := range call.Args() {
		if arg.ID() != node.ID() {
			literal = arg
		}
	}
	if literal == nil || literal.Kind() != celast.LiteralKind {
		return ""
	}
	if negated(parent) || !valueIsRequirement(native, parent, ident) {
		return ""
	}
	value, ok := literalString(literal.AsLiteral())
	if !ok {
		return ""
	}
	return value
}

// negated reports whether a node sits under a logical not or a ternary, either
// of which can flip what its result means for the policy's verdict.
func negated(node celast.NavigableExpr) bool {
	for {
		parent, ok := node.Parent()
		if !ok {
			return false
		}
		if parent.Kind() == celast.CallKind {
			switch parent.AsCall().FunctionName() {
			case operators.LogicalNot, operators.Conditional:
				return true
			}
		}
		node = parent
	}
}

// valueIsRequirement reports whether an equality is a value the policy requires
// rather than one of several alternatives. Walking from the equality up to the
// root (or the enclosing comprehension, which bounds an element predicate):
//
//   - a conjunction (&&) passes a requirement through unchanged.
//   - a disjunction (||) makes its branches alternatives. It is only safe when
//     no OTHER branch offers a competing object field to write: a branch that
//     just tests presence (`!has(x)`) or the resource kind is not a fix a user
//     would make, so `!has(hostNetwork) || hostNetwork == false` stays a
//     requirement while `namespace == 'kube-system' || hostNetwork == false`
//     does not.
//   - crossing out of an element predicate (ident is the loop variable) into the
//     object level does not end the walk: the comprehension is itself a term of
//     the outer expression, so an outer disjunction can still make an element
//     value an alternative. `namespace == 'x' || containers.all(c, c.name == 'v')`
//     must not write name='v' as a fix, exactly as the direct-field case must
//     not. Inside the element predicate a disjunction is disqualifying outright
//     (the exists accumulator is a `||`, and element-level alternatives are not
//     worth reasoning about); once at the object level the sibling check applies.
//   - anything else (a bare function wrapping the boolean, a ternary) is not
//     something we reason about, so the value is dropped.
func valueIsRequirement(native *celast.AST, node celast.NavigableExpr, ident string) bool {
	for {
		parent, ok := node.Parent()
		if !ok {
			return true
		}
		switch parent.Kind() {
		case celast.ComprehensionKind:
			// Leaving the element predicate; judge the rest of the walk as an
			// object-level term, so an outer disjunction is still accounted for.
			ident = "object"
		case celast.CallKind:
			switch parent.AsCall().FunctionName() {
			case operators.LogicalAnd:
			case operators.LogicalOr:
				if ident != "object" {
					return false
				}
				for _, arg := range parent.AsCall().Args() {
					if arg.ID() == node.ID() {
						continue
					}
					if siblingHasObjectAlternative(native, arg) {
						return false
					}
				}
			default:
				return false
			}
		default:
			return false
		}
		node = parent
	}
}

// siblingHasObjectAlternative reports whether a disjunction branch reads a real
// object field as a condition - one that would itself be offered as a competing
// fix. A presence test (`has(...)`, a test-only select) and a scope-guard read
// (object.kind) do not count: neither is a value a user would write to satisfy
// the policy, so a disjunct built only from those leaves the sibling equality a
// genuine requirement.
func siblingHasObjectAlternative(native *celast.AST, branch celast.Expr) bool {
	for _, node := range celast.MatchDescendants(celast.NavigateExpr(native, branch), celast.KindMatcher(celast.SelectKind)) {
		// Only the outermost select of a chain carries the path; an inner link
		// (including every link of a presence test's chain) has a select parent.
		if parent, ok := node.Parent(); ok && parent.Kind() == celast.SelectKind {
			continue
		}
		if node.AsSelect().IsTestOnly() {
			continue // presence test: not a value to write
		}
		path, ok := selectPath(node, "object")
		if !ok || scopeGuardFields[path] {
			continue
		}
		return true
	}
	return false
}

// literalString renders a CEL literal as the string form a YAML fix would
// write. Types with no unambiguous rendering yield false and no hint value.
func literalString(val ref.Val) (string, bool) {
	switch v := val.Value().(type) {
	case bool:
		return strconv.FormatBool(v), true
	case string:
		return v, true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	default:
		return "", false
	}
}

// resolve turns a plan into hints for one object that failed the validation.
//
// violates re-runs the same validation against a modified object and reports
// whether it still fails. That is how a list index gets pinned: for a list
// whose narrowing is exact (see narrowingIsExact), replacing the list with a
// single element and re-checking says whether that element is one of the
// offenders. Elements that pass on their own are not blamed, and if the failure
// came from somewhere else entirely no element is blamed at all.
func (p pathPlan) resolve(obj map[string]any, violates func(map[string]any) bool) []PathHint {
	hints := make([]PathHint, 0, len(p.direct))
	for _, ref := range p.direct {
		hints = append(hints, PathHint{Path: ref.path, Value: ref.value})
	}
	if p.elements == nil || len(p.elements.fields) == 0 {
		return hints
	}

	segments := strings.Split(p.elements.collection, ".")
	list, ok := lookupList(obj, segments)
	if !ok {
		return hints
	}

	// narrowingIsExact establishes the element is conjunctive with the verdict,
	// but re-running the whole validation is only a test of an element when the
	// comprehension is also the reason it failed. Emptying the list makes the
	// comprehension satisfied (all over nothing is vacuously true, and so is the
	// !exists we also attribute); if the validation still fails then, the cause
	// is a sibling reading the object, not any element, so none is blamed.
	if emptied, ok := narrow(obj, segments, []any{}); ok && violates(emptied) {
		return hints
	}

	for i, element := range list {
		candidate, ok := narrow(obj, segments, []any{element})
		if !ok || !violates(candidate) {
			continue
		}
		prefix := p.elements.collection + "[" + strconv.Itoa(i) + "]."
		for _, ref := range p.elements.fields {
			hints = append(hints, PathHint{Path: prefix + ref.path, Value: ref.value})
		}
	}
	return hints
}

// lookupList reads the list at a dotted path, reporting false when the path is
// absent or does not hold a list.
func lookupList(obj map[string]any, segments []string) ([]any, bool) {
	var current any = obj
	for _, segment := range segments {
		parent, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = parent[segment]
		if !ok {
			return nil, false
		}
	}
	list, ok := current.([]any)
	return list, ok
}

// narrow returns a copy of obj with the value at a dotted path replaced,
// reporting false when the path does not run through maps all the way down.
// Only the maps along that path are copied and everything else is shared, so
// narrowing a pod's container list once per container stays cheap. The bool
// keeps a path that does not resolve from silently returning an unchanged copy,
// which resolve would then read as every element violating.
func narrow(obj map[string]any, segments []string, value any) (map[string]any, bool) {
	out := make(map[string]any, len(obj))
	for key, val := range obj {
		out[key] = val
	}
	if len(segments) == 1 {
		out[segments[0]] = value
		return out, true
	}
	child, ok := obj[segments[0]].(map[string]any)
	if !ok {
		return nil, false
	}
	narrowed, ok := narrow(child, segments[1:], value)
	if !ok {
		return nil, false
	}
	out[segments[0]] = narrowed
	return out, true
}

// pathPlanCache memoizes path plans by expression text, for the same reason
// programCache memoizes programs: deriving a plan means compiling the
// expression and walking its AST, and the answer is the same for every object
// the expression runs against. An expression that will not compile has no plan
// and never will, so the empty plan is cached too rather than recompiled per
// failing object.
type pathPlanCache struct {
	build func(expr string) pathPlan

	mu      sync.Mutex
	entries map[string]*pathPlanCacheEntry
}

type pathPlanCacheEntry struct {
	once sync.Once
	plan pathPlan
}

func newPathPlanCache(build func(expr string) pathPlan) *pathPlanCache {
	return &pathPlanCache{
		build:   build,
		entries: make(map[string]*pathPlanCacheEntry),
	}
}

func (c *pathPlanCache) get(expr string) pathPlan {
	c.mu.Lock()
	entry, ok := c.entries[expr]
	if !ok {
		entry = &pathPlanCacheEntry{}
		c.entries[expr] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() { entry.plan = c.build(expr) })
	return entry.plan
}
