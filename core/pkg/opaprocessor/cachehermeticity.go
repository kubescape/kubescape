package opaprocessor

import (
	"context"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/util"
)

// externalStateBuiltins are builtins whose result can depend on state outside
// the evaluated object and the scan's policy inputs. A verdict that depends on
// them cannot be reused on the strength of the object's own hash. The list
// covers external-state dependencies independently of OPA's Nondeterministic
// flag, so rejection does not depend on that flag alone. Audited against
// OPA v1.22.0.
var externalStateBuiltins = map[string]struct{}{
	// Validate certificates against the current time.
	"crypto.x509.parse_and_verify_certificates":              {},
	"crypto.x509.parse_and_verify_certificates_with_options": {},
	// Resolve "$ref" schemas over HTTP or from the local filesystem. OPA
	// marks both Nondeterministic as of v1.22.0; they stay listed so they
	// are rejected regardless of OPA's flag.
	"json.match_schema":  {},
	"json.verify_schema": {},
	// Kubescape builtins that query an image registry.
	"cosign.verify":         {},
	"cosign.verify_keyless": {},
	"cosign.has_signature":  {},
}

// hermeticCustomBuiltins are the non-OPA builtins known to depend only on
// their arguments. Any other builtin that is not part of OPA's standard set is
// treated as reading external state, so a builtin added later stays out of
// the incremental cache until it is reviewed and listed here.
var hermeticCustomBuiltins = map[string]struct{}{
	// cautils.NormalizeImageName: pure reference parsing.
	"image.parse_normalized_name": {},
}

// standardBuiltinNames is the set of OPA's own builtins, by canonical name.
// ast.DefaultBuiltins does not change when Kubescape registers its builtins,
// unlike ast.Builtins and ast.BuiltinMap.
var standardBuiltinNames = sync.OnceValue(func() map[string]struct{} {
	names := make(map[string]struct{}, len(ast.DefaultBuiltins))
	for _, b := range ast.DefaultBuiltins {
		names[b.Name] = struct{}{}
	}
	return names
})

// hermeticSources memoises regoSourceIsHermetic. Policies repeat the same
// rule and enumerator sources across controls and scopes.
var hermeticSources sync.Map

// hermeticityModuleName is the module name the analysed source is compiled
// under. It must not collide with a rule dependency module name.
const hermeticityModuleName = "kubescape-incremental-cache-analysis"

// evaluatedPackage is the package runRegoOnK8s queries. Every rule in it is
// evaluated, whether or not deny refers to it.
var evaluatedPackage = ast.MustParseRef("data.armo_builtins")

// regoSourceIsHermetic reports whether the Rego source, compiled with the rule
// dependencies exactly as evaluation compiles it, can only produce results
// that depend on its input and the scan's policy inputs. It follows every
// rule the evaluated package can reach through the compiler's dependency
// graph, including library functions and dynamic references, and rejects
// nondeterministic and external-state builtins, builtins it does not
// recognise, and `with` modifiers. A source that fails to compile is not
// hermetic: whatever cannot be proven safe is kept out of the cache.
func regoSourceIsHermetic(source string) bool {
	if memoised, ok := hermeticSources.Load(source); ok {
		return memoised.(bool)
	}

	registerOPABuiltins() // custom builtins must be known for the source to compile

	hermetic := false
	if compiled, _, err := compileWithRuleDependencies(context.Background(), hermeticityModuleName, source, false); err == nil {
		hermetic = compiledModuleIsHermetic(compiled, hermeticityModuleName)
	}

	hermeticSources.Store(source, hermetic)
	return hermetic
}

func compiledModuleIsHermetic(compiled *ast.Compiler, moduleName string) bool {
	if compiled == nil || compiled.Graph == nil {
		return false
	}

	visited := map[util.T]struct{}{}
	var pending []*ast.Rule
	enqueue := func(rule *ast.Rule) {
		// Each else clause is its own node in the graph.
		for r := rule; r != nil; r = r.Else {
			if _, seen := visited[r]; !seen {
				visited[r] = struct{}{}
				pending = append(pending, r)
			}
		}
	}

	for name, module := range compiled.Modules {
		if name == moduleName || module.Package.Path.Equal(evaluatedPackage) {
			for _, rule := range module.Rules {
				enqueue(rule)
			}
		}
	}

	for len(pending) > 0 {
		rule := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		if !ruleBodyIsHermetic(rule) {
			return false
		}
		for dependency := range compiled.Graph.Dependencies(rule) {
			dependent, ok := dependency.(*ast.Rule)
			if !ok {
				return false
			}
			enqueue(dependent)
		}
	}
	return true
}

// ruleBodyIsHermetic inspects one compiled rule (head, body and arguments).
// Calls to other rules are followed by the caller through the dependency
// graph; here every builtin named anywhere in the rule must be hermetic.
func ruleBodyIsHermetic(rule *ast.Rule) bool {
	hermetic := true

	ast.WalkExprs(rule, func(expr *ast.Expr) bool {
		if !hermetic {
			return true
		}
		if len(expr.With) > 0 {
			// with can replace any function or document, so the evaluated
			// program is no longer the one analysed here.
			hermetic = false
			return true
		}
		if expr.IsCall() && !callIsHermetic(expr.Operator()) {
			hermetic = false
		}
		return !hermetic
	})
	if !hermetic {
		return false
	}

	ast.WalkTerms(rule, func(term *ast.Term) bool {
		if !hermetic {
			return true
		}
		switch value := term.Value.(type) {
		case ast.Call:
			if len(value) == 0 {
				hermetic = false
				break
			}
			operator, ok := value[0].Value.(ast.Ref)
			if !ok || !callIsHermetic(operator) {
				hermetic = false
			}
		case ast.Ref:
			// A builtin named outside call position still counts.
			if builtin, ok := ast.BuiltinMap[value.String()]; ok && !builtinIsHermetic(builtin) {
				hermetic = false
			}
		}
		return !hermetic
	})
	return hermetic
}

// callIsHermetic classifies the operator of a call. A call into data is a
// call to a rule, which the dependency graph covers; anything else must be a
// builtin this analysis recognises as hermetic.
func callIsHermetic(operator ast.Ref) bool {
	if operator.HasPrefix(ast.DefaultRootRef) {
		return true
	}
	builtin, ok := ast.BuiltinMap[operator.String()]
	if !ok {
		return false
	}
	return builtinIsHermetic(builtin)
}

// builtinIsHermetic reports whether builtin depends only on its arguments.
// It matches on the canonical name: ast.BuiltinMap also indexes infix
// operators by their symbols.
func builtinIsHermetic(builtin *ast.Builtin) bool {
	if builtin == nil || builtin.Nondeterministic {
		return false
	}
	if _, external := externalStateBuiltins[builtin.Name]; external {
		return false
	}
	if _, standard := standardBuiltinNames()[builtin.Name]; standard {
		return true
	}
	_, allowed := hermeticCustomBuiltins[builtin.Name]
	return allowed
}
