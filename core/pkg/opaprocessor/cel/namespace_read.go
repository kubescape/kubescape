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
	for _, variable := range v.Variables {
		variables[variable.Name] = variable.Expression
	}

	toVisit := make([]string, 0, len(v.Validations))
	for _, validation := range v.Validations {
		if readsNamespaceObject(e.env, validation.Expression) {
			return true
		}
		toVisit = append(toVisit, referencedVariables(e.env, validation.Expression)...)
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
		toVisit = append(toVisit, referencedVariables(e.env, expression)...)
	}
	return false
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

// referencedVariables returns names referenced through variables.<name> and
// variables["name"]. Dynamic indexes are deliberately excluded because their
// target cannot be known until evaluation. The compiler resolves these accesses
// before this runs, so this follows the same dependency shape used by
// lazyVariables at evaluation.
func referencedVariables(env *cel.Env, expr string) []string {
	if expr == "" {
		return nil
	}
	compiled, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil
	}
	seen := map[string]struct{}{}
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
			call := parent.AsCall()
			args := call.Args()
			if call.FunctionName() != "_[_]" || len(args) != 2 || args[0].ID() != node.ID() {
				continue
			}
			if args[1].Kind() != celast.LiteralKind {
				continue
			}
			key, ok := args[1].AsLiteral().(types.String)
			if ok {
				seen[string(key)] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	return result
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
