package cel

import (
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
)

// ReadsNamespaceObjectInValidations reports whether a validation can evaluate
// the Namespace object binding. Message expressions are intentionally absent:
// they only format an already-reached violation. Match conditions are also
// absent because admission always evaluates them with namespaceObject set to
// null. Variables are followed only when a validation references them, matching
// the evaluator's lazy variable semantics.
func (e *Evaluator) ReadsNamespaceObjectInValidations(v *VAP) bool {
	variables := make(map[string]string, len(v.Variables))
	allVariableNames := make([]string, 0, len(v.Variables))
	for _, variable := range v.Variables {
		variables[variable.Name] = variable.Expression
		allVariableNames = append(allVariableNames, variable.Name)
	}

	toVisit := make([]string, 0, len(v.Validations))
	for _, validation := range v.Validations {
		if readsNamespaceObject(e.env, validation.Expression) {
			return true
		}
		toVisit = appendReferencedVariables(toVisit, referencedVariables(e.env, validation.Expression), allVariableNames)
	}

	visited := make(map[string]struct{}, len(toVisit))
	for len(toVisit) > 0 {
		name := toVisit[0]
		toVisit = toVisit[1:]
		if _, seen := visited[name]; seen {
			continue
		}
		visited[name] = struct{}{}
		expression, found := variables[name]
		if !found {
			continue
		}
		if readsNamespaceObject(e.env, expression) {
			return true
		}
		toVisit = appendReferencedVariables(toVisit, referencedVariables(e.env, expression), allVariableNames)
	}
	return false
}

func appendReferencedVariables(toVisit []string, references variableReferences, allVariableNames []string) []string {
	toVisit = append(toVisit, references.names...)
	if references.hasDynamicIndex {
		// lazyVariables resolves dynamic keys at evaluation time. Until that key is
		// known, every declared variable is a possible dependency.
		toVisit = append(toVisit, allVariableNames...)
	}
	return toVisit
}

func readsNamespaceObject(env *cel.Env, expr string) bool {
	if expr == "" {
		return false
	}
	compiled, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return false // a malformed expression is already skipped by evaluation
	}
	root := celast.NavigateAST(compiled.NativeRep())
	for _, node := range celast.MatchDescendants(root, celast.KindMatcher(celast.IdentKind)) {
		if globalIdentifier(node, "namespaceObject") {
			return true
		}
	}
	return false
}

type variableReferences struct {
	names           []string
	hasDynamicIndex bool
}

// referencedVariables returns names referenced through variables.<name> and
// variables["name"]. A dynamic index is recorded separately because the
// runtime lazy map can resolve it to any declared variable. The compiler
// resolves these accesses before this runs, so this follows the same dependency
// shape used by lazyVariables at evaluation.
func referencedVariables(env *cel.Env, expr string) variableReferences {
	if expr == "" {
		return variableReferences{}
	}
	compiled, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return variableReferences{}
	}
	seen := map[string]struct{}{}
	hasDynamicIndex := false
	root := celast.NavigateAST(compiled.NativeRep())
	for _, node := range celast.MatchDescendants(root, celast.KindMatcher(celast.IdentKind)) {
		if !globalIdentifier(node, "variables") {
			continue
		}
		parent, ok := node.Parent()
		if !ok {
			continue
		}
		switch parent.Kind() {
		case celast.SelectKind:
			selection := parent.AsSelect()
			if selection.Operand().ID() == node.ID() {
				seen[selection.FieldName()] = struct{}{}
			}
		case celast.CallKind:
			name, dynamic, indexed := indexedVariableReference(node)
			if !indexed {
				continue
			}
			if dynamic {
				hasDynamicIndex = true
			} else {
				seen[name] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	return variableReferences{names: result, hasDynamicIndex: hasDynamicIndex}
}

// indexedVariableReference follows dyn(...) wrappers around variables. CEL
// represents index operations as calls with the map and key as arguments,
// rather than as a member call, so the identifier can be nested beneath a
// dynamic cast before reaching the index operation.
func indexedVariableReference(node celast.NavigableExpr) (name string, dynamic, indexed bool) {
	receiver := node
	parent, ok := receiver.Parent()
	for ok && parent.Kind() == celast.CallKind {
		call := parent.AsCall()
		args := call.Args()
		if call.FunctionName() == "dyn" && len(args) == 1 && args[0].ID() == receiver.ID() {
			receiver = parent
			parent, ok = receiver.Parent()
			continue
		}
		if call.FunctionName() != "_[_]" || len(args) != 2 || args[0].ID() != receiver.ID() {
			return "", false, false
		}
		if args[1].Kind() != celast.LiteralKind {
			return "", true, true
		}
		key, ok := args[1].AsLiteral().(types.String)
		if !ok {
			return "", true, true
		}
		return string(key), false, true
	}
	return "", false, false
}

// globalIdentifier reports whether node names the activation binding instead
// of a comprehension local. CEL keeps an explicitly global identifier as
// `.name`, which remains global even when an enclosing comprehension shadows
// the unqualified spelling.
func globalIdentifier(node celast.NavigableExpr, name string) bool {
	switch node.AsIdent() {
	case "." + name:
		return true
	case name:
		return !shadowedByComprehension(node, name)
	default:
		return false
	}
}

func shadowedByComprehension(node celast.NavigableExpr, name string) bool {
	child := node
	for {
		parent, ok := child.Parent()
		if !ok {
			return false
		}
		if parent.Kind() == celast.ComprehensionKind {
			c := parent.AsComprehension()
			binds := c.IterVar() == name || (c.HasIterVar2() && c.IterVar2() == name) || c.AccuVar() == name
			outerScope := child.ID() == c.IterRange().ID() || child.ID() == c.AccuInit().ID()
			if binds && !outerScope {
				return true
			}
		}
		child = parent
	}
}
