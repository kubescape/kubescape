package cel

import (
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
)

// ReadsNamespaceObject reports whether any expression needs the Namespace
// object bound by the scanner. A compiled AST avoids mistaking a message
// string or a comprehension-local variable for the global binding.
func (e *Evaluator) ReadsNamespaceObject(v *VAP) bool {
	env := e.env
	for _, variable := range v.Variables {
		if readsNamespaceObject(env, variable.Expression) {
			return true
		}
	}
	for _, validation := range v.Validations {
		if readsNamespaceObject(env, validation.Expression) || readsNamespaceObject(env, validation.MessageExpression) {
			return true
		}
	}
	for _, condition := range v.matchConditions {
		if readsNamespaceObject(env, condition.Expression) {
			return true
		}
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
		switch node.AsIdent() {
		case ".namespaceObject":
			return true
		case "namespaceObject":
			if !shadowedByComprehension(node, "namespaceObject") {
				return true
			}
		}
	}
	return false
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
