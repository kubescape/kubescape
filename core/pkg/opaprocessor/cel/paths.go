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
// when the requirement is an unambiguous equality. It is empty whenever the
// expression asks for something we cannot turn into a single value (a prefix
// check, a range comparison, a plain presence test), because a caller may write
// a non-empty Value straight into the user's YAML.
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

// fieldRef is one field an expression reads, with the literal it is required to
// equal when the expression makes that unambiguous.
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
	// object. With none there is nothing to index; with more than one we cannot
	// tell which list a failure came from, and blaming the wrong one is worse
	// than staying quiet, so both cases fall back to direct paths only.
	elements *elementPlan
}

// scopeGuardFields are object fields a validation reads only to decide whether
// the policy covers this kind at all - every policy in the bundle opens with
// `object.kind != 'Pod' || ...`. They are never what a user has to fix, and
// appliesTo has already made that decision before we get here, so they never
// become a hint.
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
	if len(iterated) == 1 {
		comprehension := iterated[0].AsComprehension()
		collection, _ := selectPath(comprehension.IterRange(), "object")
		plan.elements = &elementPlan{
			collection: collection,
			fields:     fieldsRootedAt(celast.NavigateExpr(native, comprehension.LoopStep()), comprehension.IterVar()),
		}
	}

	for _, ref := range fieldsRootedAt(root, "object") {
		// The iterated list itself is not a hint: either we are about to point
		// at one of its elements, or we could not tell which list failed and
		// naming them all would just be noise.
		if scopeGuardFields[ref.path] || ranges[ref.path] {
			continue
		}
		plan.direct = append(plan.direct, ref)
	}
	return plan
}

// fieldsRootedAt collects the fields an expression reads off a given variable.
//
// Only the longest chain of each read counts: `has(c.securityContext) &&
// c.securityContext.readOnlyRootFilesystem == true` reads two nested paths but
// describes one requirement, and pointing a user at the parent as well as the
// leaf is noise. So chains that another chain extends are dropped.
func fieldsRootedAt(root celast.NavigableExpr, ident string) []fieldRef {
	var refs []fieldRef
	for _, node := range celast.MatchDescendants(root, celast.KindMatcher(celast.SelectKind)) {
		// A select whose parent is a select is the operand of a longer chain;
		// the outermost one carries the full path.
		if parent, ok := node.Parent(); ok && parent.Kind() == celast.SelectKind {
			continue
		}
		path, ok := selectPath(node, ident)
		if !ok || path == "" {
			continue
		}
		refs = append(refs, fieldRef{path: path, value: requiredValue(node)})
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

// requiredValue returns the literal a field read is compared against, when the
// comparison is an equality the field has to satisfy for the policy to pass -
// `container.securityContext.readOnlyRootFilesystem == true` means the fix is
// to set that path to true.
//
// Everything else yields no value, on purpose. `!=` says what the field must
// not be, which is not a value to write. And an equality reached through a
// negation or a ternary may be inverted by the time it reaches the result, so
// the literal there is not necessarily what the policy wants. A caller may
// write a value into a user's file, so anything short of certain is empty.
func requiredValue(node celast.NavigableExpr) string {
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
	if negated(parent) {
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
// whether it still fails. That is how a list index gets pinned: the policy says
// every container must satisfy something, so replacing the list with a single
// container and re-checking says whether that container is one of the offenders.
// Elements that pass on their own are not blamed, and if the failure came from
// somewhere else entirely no element is blamed at all.
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

	for i, element := range list {
		if !violates(narrow(obj, segments, []any{element})) {
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

// narrow returns a copy of obj with the value at a dotted path replaced. Only
// the maps along that path are copied and everything else is shared, so
// narrowing a pod's container list once per container stays cheap.
func narrow(obj map[string]any, segments []string, value any) map[string]any {
	out := make(map[string]any, len(obj))
	for key, val := range obj {
		out[key] = val
	}
	if len(segments) == 1 {
		out[segments[0]] = value
		return out
	}
	child, ok := obj[segments[0]].(map[string]any)
	if !ok {
		return out
	}
	out[segments[0]] = narrow(child, segments[1:], value)
	return out
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
