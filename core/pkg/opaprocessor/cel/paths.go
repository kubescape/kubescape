package cel

import (
	"regexp"
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
// (`object.spec.containers.all(container, ...)`). fields are element-relative,
// joined to a collection path with an index once we know which element
// failed.
//
// The list itself is usually one fixed path (collection). A validation that
// goes through a variable inlined by inlineVariables can instead iterate a
// ternary that picks the list by the object's kind (`object.kind == 'Pod' ?
// object.spec.containers : ...`) - see objectRootedPaths. Which branch is real
// depends on the object, not the expression, so that shape sets collections
// instead: every candidate path, at most one of which is an actual list on any
// given object (the bundle's matchConstraints already narrowed evaluation to
// one kind). Exactly one of the two is ever set.
type elementPlan struct {
	collection  string
	collections []string
	fields      []fieldRef
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

// inlineVariables textually expands every `variables.<name>` reference in expr
// with that variable's own expression, parenthesized so it composes safely
// with whatever follows it (a field access, a comprehension, ...). Newer bundle
// releases factor object access into a `variables:` block instead of inlining
// it in the validation (`variables.containers.all(...)` rather than
// `object.spec.containers.all(...)`), and the AST walk below only understands
// paths rooted at `object`, so without this expansion those validations would
// derive no path at all (see pathlessPolicies' KNOWN LIMITATION note).
//
// A variable's expression may only reference object/params/request and
// variables declared before it (enforced by the bundle format), so expanding
// left to right - each variable substituting the ones already expanded before
// it is itself substituted into later expressions - reaches a fully
// object-rooted form in one pass; no fixpoint loop is needed.
func inlineVariables(expr string, variables []Variable) string {
	expanded := make(map[string]string, len(variables))
	for _, v := range variables {
		body := maskVariableHasGuards(v.Expression)
		for _, prior := range variables {
			if prior.Name == v.Name {
				break
			}
			if replacement, ok := expanded[prior.Name]; ok {
				body = substituteVariableRef(body, prior.Name, replacement)
			}
		}
		expanded[v.Name] = "(" + body + ")"
	}
	expr = maskVariableHasGuards(expr)
	for _, v := range variables {
		if replacement, ok := expanded[v.Name]; ok {
			expr = substituteVariableRef(expr, v.Name, replacement)
		}
	}
	return expr
}

// variableHasGuardPattern matches `has(variables.<chain>)`: a presence guard
// on a variable reference. CEL's has() macro requires its argument to be a
// literal select chain (has(1+1) is a compile error), so substituting a
// variable's own expression - a ternary, once inlineVariables has expanded it
// - into one, even just at the `variables.<name>` root, stops the whole
// expression compiling. That guard exists only to protect a later, non-has()
// read of the same field against a missing-field error, and that later read
// is exactly the occurrence this file derives a path from - has() itself
// never carries a value. So neutralizing every such guard to the constant
// `true` before substitution costs no derivable path, and keeps a variable
// reference inside `has()` from taking the whole validation's plan down with
// it (see buildPathPlan: a compile failure here yields the empty plan).
var variableHasGuardPattern = regexp.MustCompile(`has\(\s*variables(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*\)`)

func maskVariableHasGuards(expr string) string {
	return variableHasGuardPattern.ReplaceAllLiteralString(expr, "true")
}

// substituteVariableRef replaces every `variables.<name>` reference in expr
// with replacement. \b on both ends keeps a name from matching as a prefix or
// suffix of a longer identifier (`variables.containers2` must not match name
// "containers").
func substituteVariableRef(expr, name, replacement string) string {
	pattern := regexp.MustCompile(`\bvariables\.` + regexp.QuoteMeta(name) + `\b`)
	return pattern.ReplaceAllLiteralString(expr, replacement)
}

// newPathPlan derives the plan for one compiled validation expression.
func newPathPlan(ast *cel.Ast) pathPlan {
	native := ast.NativeRep()
	root := celast.NavigateAST(native)

	// Comprehensions over something other than the object (the bundle iterates
	// params lists and inline kind lists too) tell us nothing about where the
	// object is wrong, so only object-rooted ones count.
	var iterated []celast.NavigableExpr
	var iteratedPaths [][]string
	ranges := map[string]bool{}
	for _, node := range celast.MatchDescendants(root, celast.KindMatcher(celast.ComprehensionKind)) {
		rangeExpr := node.AsComprehension().IterRange()

		// Every object-rooted select inside the range expression is plumbing
		// that decides WHICH list to iterate (a fixed path, a per-kind ternary,
		// a concatenation of several lists, ...), never a value the policy is
		// asking the user to set - so none of them belong in plan.direct,
		// whether or not the shape below resolves to an elementPlan. Without
		// this a range objectRootedPaths cannot fully read (e.g. one that
		// concatenates several lists with `+`) would otherwise leak its
		// constituent paths as spurious direct fields.
		for _, sel := range celast.MatchDescendants(celast.NavigateExpr(native, rangeExpr), celast.KindMatcher(celast.SelectKind)) {
			if parent, ok := sel.Parent(); ok && parent.Kind() == celast.SelectKind {
				continue
			}
			if path, ok := selectPath(sel, "object"); ok {
				ranges[path] = true
			}
		}

		paths, ok := objectRootedPaths(rangeExpr, "object")
		if !ok {
			continue
		}
		iterated = append(iterated, node)
		iteratedPaths = append(iteratedPaths, paths)
	}

	plan := pathPlan{}
	// Exactly one object-rooted list, and only when re-checking a single element
	// against the whole validation is a faithful test of that element. Anything
	// else and we cannot attribute a failure to a specific element without
	// guessing, so we do not try.
	if len(iterated) == 1 && narrowingIsExact(iterated[0]) {
		comprehension := iterated[0].AsComprehension()
		paths := iteratedPaths[0]

		// A field the element predicate reads is element-relative and joined to
		// the pinned index. This includes a collection the predicate iterates in
		// turn (a container's ports, a container's command): we cannot pin the
		// inner index without a second level of re-checking, so that inner
		// collection stays a review path pointing at the offending element's
		// list - which still tells the user the container and the field to look
		// at, unlike the object-level list we index into, which is not a hint
		// because we are about to point at one of its elements instead.
		loopStep := celast.NavigateExpr(native, comprehension.LoopStep())
		elements := &elementPlan{
			fields: fieldsRootedAt(native, loopStep, comprehension.IterVar(), nil),
		}
		if len(paths) == 1 {
			elements.collection = paths[0]
		} else {
			elements.collections = paths
		}
		plan.elements = elements
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
		paths, ok := selectPaths(node, ident)
		if !ok {
			continue
		}
		value := requiredValue(native, node, ident)
		for _, path := range paths {
			if path == "" || scopeGuardFields[path] || exclude[path] {
				continue
			}
			refs = append(refs, fieldRef{path: path, value: value})
		}
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

// objectRootedPaths reads the list of straight ident-rooted paths a
// comprehension's range expression could resolve to at runtime. The common
// case is selectPath's single path; inlineVariables can also hand this a
// ternary chain choosing among several kind-specific lists (the shape the
// bundle's "containers" variable uses: `object.kind == 'Pod' ? object.spec.containers
// : object.kind in [...] ? object.spec.template.spec.containers : ... : []`),
// in which case every true-branch path is returned, in branch order.
//
// ok is false whenever a branch is neither a plain path nor another ternary of
// the same shape: an opaque branch means we cannot enumerate every list the
// range could be, and guessing which ones matter would risk missing the real
// one, so the whole comprehension is left alone (falls back to no element
// attribution) rather than reporting a partial candidate set.
//
// The final else of a kind-dispatch ternary is usually a catch-all that is not
// itself a list on any object (an empty list literal, for a kind none of the
// earlier branches matched); a bare final else that is not a path is treated
// as that catch-all rather than disqualifying the whole chain, since resolve
// only ever uses a candidate that actually is a list on the object it checks.
func objectRootedPaths(expr celast.Expr, ident string) ([]string, bool) {
	if path, ok := selectPath(expr, ident); ok {
		return []string{path}, true
	}
	if expr.Kind() != celast.CallKind {
		return nil, false
	}
	call := expr.AsCall()
	if call.FunctionName() != operators.Conditional || len(call.Args()) != 3 {
		return nil, false
	}

	truePaths, ok := objectRootedPaths(call.Args()[1], ident)
	if !ok {
		return nil, false
	}

	elseBranch := call.Args()[2]
	if elseBranch.Kind() == celast.CallKind && elseBranch.AsCall().FunctionName() == operators.Conditional {
		elsePaths, ok := objectRootedPaths(elseBranch, ident)
		if !ok {
			return nil, false
		}
		return append(truePaths, elsePaths...), true
	}
	if path, ok := selectPath(elseBranch, ident); ok {
		return append(truePaths, path), true
	}
	return truePaths, true
}

// selectPaths generalizes selectPath to a select chain whose base does not
// bottom out at ident directly but at an object-rooted ternary of paths (see
// objectRootedPaths) - the shape inlineVariables leaves behind when a
// variable's own expression picks the right object by kind
// (`(object.kind == 'Pod' ? object.spec.securityContext : ...).runAsUser`).
// Each candidate base contributes one path, base-plus-the-peeled-suffix; a
// plain chain still resolves to its one path, same as selectPath.
//
// The bare base paths are not returned, only the composed ones - a caller
// that (like fieldsRootedAt, walking every select in the tree) also visits
// the base's own select nodes as their own chains gets the bare paths
// separately, and dedupeRefs drops each one once the corresponding composed
// path here makes it a prefix of something more specific. Without that, a
// ternary base half-resolved through a further field select would report the
// object it picks - "spec.securityContext" - as if that whole object were
// the fix, instead of the one field the validation actually reads off it.
func selectPaths(expr celast.Expr, ident string) ([]string, bool) {
	if path, ok := selectPath(expr, ident); ok {
		return []string{path}, true
	}

	var suffix []string
	for expr.Kind() == celast.SelectKind {
		sel := expr.AsSelect()
		suffix = append(suffix, sel.FieldName())
		expr = sel.Operand()
	}
	if len(suffix) == 0 {
		return nil, false
	}
	bases, ok := objectRootedPaths(expr, ident)
	if !ok {
		return nil, false
	}

	for i, j := 0, len(suffix)-1; i < j; i, j = i+1, j-1 {
		suffix[i], suffix[j] = suffix[j], suffix[i]
	}
	tail := strings.Join(suffix, ".")

	paths := make([]string, len(bases))
	for i, base := range bases {
		paths[i] = base + "." + tail
	}
	return paths, true
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
//
// KNOWN IMPRECISION, deliberate: which ELEMENT failed is pinned, which of
// several CONJUNCTIVE FIELDS failed is not. A validation requiring both
// `hostPID == false` and `hostIPC == false` reports both paths even when only
// one of them is actually set, where the Rego equivalent has a separate rule per
// field and names only the failing one.
//
// This is a precision gap, not a soundness one, and the distinction is what
// makes it acceptable to ship: every value emitted here is the value the policy
// REQUIRES at that path (see requiredValue), so applying a redundant one can
// never make the object less compliant - worst case it writes a field that
// already held that value. That is categorically different from the
// alternatives-under-a-disjunction case, where applying the fix could satisfy
// the wrong branch or produce invalid YAML, and which is therefore refused
// outright rather than merely imprecise.
//
// Pinning the field too would mean evaluating each conjunct separately against
// the object, which needs the plan to track which conjunct each field came from
// and whether absence satisfies it (`!has(x) || x == v` vs `has(x) && x == v`
// differ). Worth doing, but as its own change.
func (p pathPlan) resolve(obj map[string]any, violates func(map[string]any) bool) []PathHint {
	hints := make([]PathHint, 0, len(p.direct))
	for _, ref := range p.direct {
		if !objectHasKindSegment(obj, ref.path) {
			continue
		}
		hints = append(hints, PathHint{Path: ref.path, Value: ref.value})
	}
	if p.elements == nil || len(p.elements.fields) == 0 {
		return hints
	}

	collection, segments, list, ok := p.elements.resolveCollection(obj)
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
		prefix := collection + "[" + strconv.Itoa(i) + "]."
		for _, ref := range p.elements.fields {
			hints = append(hints, PathHint{Path: prefix + ref.path, Value: ref.value})
		}
	}
	return hints
}

// resolveCollection picks which candidate list path is a real list on obj. The
// common case (collection set, collections nil) has exactly one candidate;
// collections holds several kind-dependent candidates when the range came from
// a ternary (see objectRootedPaths), of which at most one is ever an actual
// list on a given object - matchConstraints already narrowed evaluation to one
// kind, so the rest simply are not present. ok is false when none resolve.
func (p *elementPlan) resolveCollection(obj map[string]any) (collection string, segments []string, list []any, ok bool) {
	candidates := p.collections
	if len(candidates) == 0 {
		candidates = []string{p.collection}
	}
	for _, candidate := range candidates {
		segs := strings.Split(candidate, ".")
		if l, ok := lookupList(obj, segs); ok {
			return candidate, segs, l, true
		}
	}
	return "", nil, nil, false
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

var kindSegments = map[string]bool{
	"template":    true,
	"jobTemplate": true,
}

// objectHasKindSegment reports whether the kind-dependent prefix of path exists
// on obj. When a variable's inlined ternary contributes paths for several kinds
// (e.g. spec.securityContext for Pod, spec.template.spec.securityContext for
// Deployment, spec.jobTemplate.spec.template.spec.securityContext for CronJob),
// only the one matching obj's kind survives — the same rule resolveCollection
// applies via lookupList for element lists, ported to direct paths.
func objectHasKindSegment(obj map[string]any, path string) bool {
	parts := strings.Split(path, ".")
	if len(parts) < 2 || parts[0] != "spec" || !kindSegments[parts[1]] {
		return true
	}
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return true
	}
	_, exists := spec[parts[1]]
	return exists
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

// pathPlanCache memoizes path plans by expression text plus the variables it
// was expanded against (see inlineVariables), for the same reason programCache
// memoizes programs: deriving a plan means compiling the expression and
// walking its AST, and the answer is the same for every object the expression
// runs against. An expression that will not compile has no plan and never
// will, so the empty plan is cached too rather than recompiled per failing
// object.
type pathPlanCache struct {
	build func(expr string, variables []Variable) pathPlan

	mu      sync.Mutex
	entries map[string]*pathPlanCacheEntry
}

type pathPlanCacheEntry struct {
	once sync.Once
	plan pathPlan
}

func newPathPlanCache(build func(expr string, variables []Variable) pathPlan) *pathPlanCache {
	return &pathPlanCache{
		build:   build,
		entries: make(map[string]*pathPlanCacheEntry),
	}
}

func (c *pathPlanCache) get(expr string, variables []Variable) pathPlan {
	key := planCacheKey(expr, variables)

	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		entry = &pathPlanCacheEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() { entry.plan = c.build(expr, variables) })
	return entry.plan
}

// planCacheKey combines an expression with the variables it may reference into
// one cache key. Two policies can share validation expression text while
// declaring different variables (or the same names with different bodies), so
// the expression text alone is not a safe key once variables are in play.
func planCacheKey(expr string, variables []Variable) string {
	var b strings.Builder
	b.WriteString(expr)
	for _, v := range variables {
		b.WriteByte(0)
		b.WriteString(v.Name)
		b.WriteByte(0)
		b.WriteString(v.Expression)
	}
	return b.String()
}
