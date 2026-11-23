package cautils

import (
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

const maxTypeCombinations = 128

// expressionType proves a fixed HCL type, retaining the type hints used by
// conditional expressions even when a branch is null or fails to evaluate.
func (c *terraformReferenceChecker) expressionType(expr hcl.Expression, ctx *hcl.EvalContext) (ty cty.Type) {
	expr = unwrapParentheses(expr)
	key := terraformExpressionContext{expr, ctx}
	if cached, exists := c.expressionTypes[key]; exists {
		return cached
	}
	ty = cty.DynamicPseudoType
	c.expressionTypes[key] = ty
	defer func() { c.expressionTypes[key] = ty }()
	if expr == nil {
		return ty
	}
	if syntax, ok := expr.(hclsyntax.Expression); ok && len(expr.Variables()) == 0 && !hasUnavailableTerraformFunctions(syntax, ctx) {
		value, _ := c.expressionValue(expr, ctx)
		return value.Type()
	}
	if traversal, diags := hcl.AbsTraversalForExpr(expr); !diags.HasErrors() {
		root := traversal.RootName()
		scope := terraformVariableScope(root, ctx)
		if scope == nil {
			return ty
		}
		rest := traversal[1:]
		ty = scope.Variables[root].Type()
		moduleScope := scope == c.moduleCtx || (c.moduleCtx == nil && scope.Parent() == nil)
		if moduleScope && len(rest) > 0 && (root == "var" || root == "local") {
			name, valid := terraformObjectSelectionKey(rest[0])
			if !valid {
				return cty.DynamicPseudoType
			}
			if root == "local" {
				if source, exists := c.localExpressions[name.AsString()]; exists {
					return terraformTraversalType(c.expressionType(source, c.moduleCtx), rest[1:])
				}
			} else if variable, exists := c.declaredVariables[name.AsString()]; exists {
				if value, diags := traversal[:2].TraverseAbs(ctx); !diags.HasErrors() {
					return terraformTraversalType(value.Type(), rest[1:])
				}
				return terraformTraversalType(variable.ty.WithoutOptionalAttributesDeep(), rest[1:])
			}
		}
		return terraformTraversalType(ty, rest)
	}
	switch e := expr.(type) {
	case *hclsyntax.UnaryOpExpr:
		return e.Op.Type
	case *hclsyntax.BinaryOpExpr:
		return e.Op.Type
	case *hclsyntax.TemplateExpr, *hclsyntax.TemplateJoinExpr:
		return cty.String
	case *hclsyntax.RelativeTraversalExpr:
		return terraformTraversalType(c.expressionType(e.Source, ctx), e.Traversal)
	case *hclsyntax.IndexExpr:
		collection := c.expressionType(e.Collection, ctx)
		if collection.IsListType() || collection.IsMapType() {
			return collection.ElementType()
		}
		index, diags := c.expressionValue(e.Key, ctx)
		if !diags.HasErrors() && index.IsKnown() && !index.IsNull() && !c.hasUnresolvableVariables(e.Key, ctx) {
			return terraformTraversalType(collection, hcl.Traversal{hcl.TraverseIndex{Key: index}})
		}
	case *hclsyntax.ConditionalExpr:
		left := c.expressionType(e.TrueResult, ctx)
		right := c.expressionType(e.FalseResult, ctx)
		if left == cty.NilType || right == cty.NilType || left.HasDynamicTypes() || right.HasDynamicTypes() {
			return cty.DynamicPseudoType
		}
		common, _ := convert.UnifyUnsafe([]cty.Type{left, right})
		if common != cty.NilType {
			return common
		}
	case *hclsyntax.TupleConsExpr:
		elements := make([]cty.Type, len(e.Exprs))
		for i, element := range e.Exprs {
			elements[i] = c.expressionType(element, ctx)
			if elements[i] == cty.NilType {
				elements[i] = cty.DynamicPseudoType
			}
		}
		return cty.Tuple(elements)
	case *hclsyntax.ObjectConsExpr:
		attributes := map[string]cty.Type{}
		for _, item := range e.Items {
			if c.hasUnresolvableVariables(objectKeyExpr(item.KeyExpr), ctx) {
				return cty.DynamicPseudoType
			}
			key, diags := c.expressionValue(item.KeyExpr, ctx)
			if diags.HasErrors() {
				return cty.DynamicPseudoType
			}
			key, err := convert.Convert(key, cty.String)
			if err != nil || !key.IsKnown() || key.IsNull() {
				return cty.DynamicPseudoType
			}
			value := c.expressionType(item.ValueExpr, ctx)
			if value == cty.NilType {
				value = cty.DynamicPseudoType
			}
			attributes[key.AsString()] = value
		}
		return cty.Object(attributes)
	case *hclsyntax.FunctionCallExpr:
		if e.ExpandFinal {
			return cty.DynamicPseudoType
		}
		if (e.Name == "can" && len(e.Args) == 1) || (e.Name == "contains" && len(e.Args) == 2) {
			return cty.Bool
		}
		if e.Name == "try" || e.Name == "coalesce" {
			result := cty.NilType
			for _, arg := range e.Args {
				constant := len(arg.Variables()) == 0 && !hasUnavailableTerraformFunctions(arg, ctx)
				if constant {
					value, diags := c.expressionValue(arg, ctx)
					if diags.HasErrors() || (e.Name == "coalesce" && (value.IsNull() || (value.Type() == cty.String && value.AsString() == ""))) {
						continue
					}
				}
				candidate := c.expressionType(arg, ctx)
				if candidate != cty.NilType {
					if result != cty.NilType && !result.Equals(candidate) {
						return cty.DynamicPseudoType
					}
					result = candidate
				}
				if e.Name == "try" {
					if call, ok := unwrapParentheses(arg).(*hclsyntax.FunctionCallExpr); ok && call.Name == "can" && len(call.Args) == 1 && !call.ExpandFinal {
						break
					}
					if constant {
						break
					}
				}
			}
			if result != cty.NilType {
				return result
			}
			return cty.DynamicPseudoType
		}
		for scope := ctx; scope != nil; scope = scope.Parent() {
			fn, exists := scope.Functions[e.Name]
			if !exists {
				continue
			}
			params := fn.Params()
			args := make([]cty.Value, len(e.Args))
			for i, arg := range e.Args {
				param := fn.VarParam()
				if i < len(params) {
					param = &params[i]
				}
				if param == nil {
					return cty.DynamicPseudoType
				}
				argumentType := c.expressionType(arg, ctx)
				if argumentType == cty.NilType {
					argumentType = cty.DynamicPseudoType
				}
				args[i] = cty.UnknownVal(argumentType)
				if !c.hasUnresolvableVariables(arg, ctx) {
					if value, diags := c.expressionValue(arg, ctx); !diags.HasErrors() {
						args[i] = value
					}
				}
				if param.Type != cty.DynamicPseudoType {
					converted, err := convert.Convert(args[i], param.Type)
					if err != nil {
						return cty.DynamicPseudoType
					}
					args[i] = converted
				}
			}
			result, err := fn.ReturnTypeForValues(args)
			if err == nil {
				return result
			}
			return cty.DynamicPseudoType
		}
	}
	return cty.DynamicPseudoType
}

func terraformTraversalType(ty cty.Type, traversal hcl.Traversal) cty.Type {
	if ty == cty.NilType || ty == cty.DynamicPseudoType {
		return ty
	}
	value, diags := traversal.TraverseRel(cty.UnknownVal(ty))
	if diags.HasErrors() {
		return cty.DynamicPseudoType
	}
	return value.Type()
}

// provenExpressionValue keeps known inputs and models can() as a non-null Boolean.
func (c *terraformReferenceChecker) provenExpressionValue(expr hcl.Expression, ctx *hcl.EvalContext) cty.Value {
	remaining := 128
	active := map[terraformExpressionContext]bool{}
	var prove func(hcl.Expression, *hcl.EvalContext) cty.Value
	referenceValue := func(traversal hcl.Traversal, scopeCtx *hcl.EvalContext) cty.Value {
		root := traversal.RootName()
		scope := terraformVariableScope(root, scopeCtx)
		moduleScope := scope == c.moduleCtx || (c.moduleCtx == nil && scope != nil && scope.Parent() == nil)
		if moduleScope && (root == "var" || root == "local") && len(traversal) < 2 {
			return cty.NilVal
		}
		if moduleScope && root == "local" {
			name, valid := terraformObjectSelectionKey(traversal[1])
			if !valid {
				return cty.NilVal
			}
			c.recordLocalDependency(name.AsString())
			source, exists := c.localExpressions[name.AsString()]
			if !exists || c.activeLocals[name.AsString()] {
				return cty.NilVal
			}
			stored, storedDiags := traversal[:2].TraverseAbs(scopeCtx)
			current, currentDiags := c.expressionValue(source, c.moduleCtx)
			if storedDiags.HasErrors() || currentDiags.HasErrors() || !current.RawEquals(stored) {
				return cty.NilVal
			}
			value := prove(source, c.moduleCtx)
			if value == cty.NilVal || !value.Type().Equals(stored.Type()) {
				return cty.NilVal
			}
			value, diags := traversal[2:].TraverseRel(value)
			if diags.HasErrors() {
				return cty.NilVal
			}
			return value
		}
		value, diags := traversal.TraverseAbs(scopeCtx)
		if diags.HasErrors() || !value.IsWhollyKnown() {
			return cty.NilVal
		}
		return value
	}
	prove = func(expr hcl.Expression, ctx *hcl.EvalContext) cty.Value {
		expr = unwrapParentheses(expr)
		key := terraformExpressionContext{expr, ctx}
		if expr == nil || remaining == 0 || active[key] {
			return cty.NilVal
		}
		remaining--
		active[key] = true
		defer delete(active, key)
		if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "can" && len(call.Args) == 1 && !call.ExpandFinal && terraformFunctionAvailable("can", ctx) {
			return cty.UnknownVal(cty.Bool).RefineNotNull()
		}
		variables, cached := c.proofVariables[expr]
		if !cached {
			// Traversal lists depend only on the AST, including for repeated local proofs.
			variables = expr.Variables()
			c.proofVariables[expr] = variables
		}
		if len(variables) > 0 {
			if traversal, diags := hcl.AbsTraversalForExpr(expr); !diags.HasErrors() {
				return referenceValue(traversal, ctx)
			}
		}
		fixed := true
		for _, traversal := range variables {
			value := referenceValue(traversal, ctx)
			if value == cty.NilVal || !value.IsWhollyKnown() {
				fixed = false
				break
			}
		}
		if syntax, ok := expr.(hclsyntax.Expression); fixed && ok && !hasUnavailableTerraformFunctions(syntax, ctx) {
			value, diags := c.expressionValue(expr, ctx)
			if !diags.HasErrors() && value.IsWhollyKnown() {
				return value
			}
			return cty.NilVal
		}
		switch e := expr.(type) {
		case *hclsyntax.FunctionCallExpr:
			if e.ExpandFinal || !terraformFunctionAvailable(e.Name, ctx) {
				return cty.NilVal
			}
			if e.Name == "tobool" && len(e.Args) == 1 {
				value := prove(e.Args[0], ctx)
				if value != cty.NilVal && value.Type() == cty.Bool {
					return value
				}
				if conditional, ok := unwrapParentheses(e.Args[0]).(*hclsyntax.ConditionalExpr); ok {
					condition := prove(conditional.Condition, ctx)
					left, right := prove(conditional.TrueResult, ctx), prove(conditional.FalseResult, ctx)
					if condition != cty.NilVal && condition.Type() == cty.Bool && condition.Range().DefinitelyNotNull() && left != cty.NilVal && right != cty.NilVal && left.IsWhollyKnown() && right.IsWhollyKnown() {
						left, leftErr := convert.Convert(left, cty.Bool)
						right, rightErr := convert.Convert(right, cty.Bool)
						if leftErr == nil && rightErr == nil && !left.IsNull() && !right.IsNull() {
							probe := *conditional
							probe.Condition = &hclsyntax.LiteralValueExpr{Val: condition}
							probe.TrueResult = &hclsyntax.LiteralValueExpr{Val: left}
							probe.FalseResult = &hclsyntax.LiteralValueExpr{Val: right}
							result, diags := probe.Value(nil)
							if !diags.HasErrors() {
								return result.RefineNotNull()
							}
						}
					}
				}
			}
			if (e.Name == "contains" && len(e.Args) == 2) || (e.Name == "length" && len(e.Args) == 1) {
				collection := prove(e.Args[0], ctx)
				if collection == cty.NilVal || !collection.IsKnown() || collection.IsNull() || !terraformProofValueSizeIsBounded(collection) {
					return cty.NilVal
				}
				ty := collection.Type()
				if e.Name == "length" || ty.IsTupleType() || ty.IsListType() || ty.IsSetType() {
					probe := *e
					probe.Args = []hclsyntax.Expression{&hclsyntax.LiteralValueExpr{Val: collection}}
					if e.Name == "contains" {
						value := prove(e.Args[1], ctx)
						if value == cty.NilVal || !terraformProofValueSizeIsBounded(value) {
							return cty.NilVal
						}
						probe.Args = append(probe.Args, &hclsyntax.LiteralValueExpr{Val: value})
					}
					result, diags := probe.Value(ctx)
					if !diags.HasErrors() {
						return result.RefineNotNull()
					}
				}
			}
		case *hclsyntax.ConditionalExpr:
			condition, left, right := prove(e.Condition, ctx), prove(e.TrueResult, ctx), prove(e.FalseResult, ctx)
			if condition == cty.NilVal || condition.Type() != cty.Bool || !condition.Range().DefinitelyNotNull() || left == cty.NilVal || right == cty.NilVal || !left.Type().Equals(right.Type()) {
				return cty.NilVal
			}
			if condition.IsKnown() {
				if condition.True() {
					return left
				}
				return right
			}
			if left.RawEquals(right) {
				return left
			}
			if left.Type().HasDynamicTypes() {
				return cty.NilVal
			}
			value := cty.UnknownVal(left.Type())
			if left.Range().DefinitelyNotNull() && right.Range().DefinitelyNotNull() {
				value = value.RefineNotNull()
			}
			return value
		case *hclsyntax.UnaryOpExpr:
			value := prove(e.Val, ctx)
			if e.Op == hclsyntax.OpLogicalNot && value != cty.NilVal && value.Type() == cty.Bool && value.Range().DefinitelyNotNull() {
				probe := *e
				probe.Val = &hclsyntax.LiteralValueExpr{Val: value}
				result, diags := probe.Value(nil)
				if !diags.HasErrors() {
					return result.RefineNotNull()
				}
			}
		case *hclsyntax.BinaryOpExpr:
			comparison := e.Op == hclsyntax.OpLessThan || e.Op == hclsyntax.OpLessThanOrEqual || e.Op == hclsyntax.OpGreaterThan || e.Op == hclsyntax.OpGreaterThanOrEqual
			if !comparison && e.Op != hclsyntax.OpLogicalAnd && e.Op != hclsyntax.OpLogicalOr && e.Op != hclsyntax.OpEqual && e.Op != hclsyntax.OpNotEqual {
				return cty.NilVal
			}
			left, right := prove(e.LHS, ctx), prove(e.RHS, ctx)
			if left != cty.NilVal && right != cty.NilVal && left.Type().Equals(right.Type()) && ((left.Type() == cty.Bool && !comparison) || left.Type() == cty.Number) && left.Range().DefinitelyNotNull() && right.Range().DefinitelyNotNull() {
				probe := *e
				probe.LHS = &hclsyntax.LiteralValueExpr{Val: left}
				probe.RHS = &hclsyntax.LiteralValueExpr{Val: right}
				result, diags := probe.Value(nil)
				if !diags.HasErrors() {
					return result.RefineNotNull()
				}
			}
		case *hclsyntax.TupleConsExpr:
			values := make([]cty.Value, len(e.Exprs))
			for i, element := range e.Exprs {
				values[i] = prove(element, ctx)
				if values[i] == cty.NilVal {
					return cty.NilVal
				}
			}
			return cty.TupleVal(values)
		case *hclsyntax.ObjectConsExpr:
			values := map[string]cty.Value{}
			for _, item := range e.Items {
				key, value := prove(item.KeyExpr, ctx), prove(item.ValueExpr, ctx)
				if key == cty.NilVal || key.Type() != cty.String || !key.IsKnown() || key.IsNull() || value == cty.NilVal {
					return cty.NilVal
				}
				values[key.AsString()] = value
			}
			return cty.ObjectVal(values)
		}
		return cty.NilVal
	}
	return prove(expr, ctx)
}

// Unknown Boolean leaves cannot grow the size checked by bounded functions.
func terraformProofValueSizeIsBounded(value cty.Value) bool {
	if value.IsWhollyKnown() {
		return true
	}
	if !value.IsKnown() {
		return value.Type() == cty.Bool
	}
	if !value.CanIterateElements() {
		return false
	}
	for it := value.ElementIterator(); it.Next(); {
		_, element := it.Element()
		if !terraformProofValueSizeIsBounded(element) {
			return false
		}
	}
	return true
}

// guaranteedCoalesceTypes retains a type contributed by complementary can() branches.
func (c *terraformReferenceChecker) guaranteedCoalesceTypes(args []hclsyntax.Expression, ctx *hcl.EvalContext) []cty.Type {
	type presence struct {
		predicate hcl.Traversal
		ty        cty.Type
		branches  uint8
	}
	sameTraversal := func(left, right hcl.Traversal) bool {
		return slices.EqualFunc(left, right, func(left, right hcl.Traverser) bool {
			switch left := left.(type) {
			case hcl.TraverseRoot:
				right, ok := right.(hcl.TraverseRoot)
				return ok && left.Name == right.Name
			case hcl.TraverseAttr:
				right, ok := right.(hcl.TraverseAttr)
				return ok && left.Name == right.Name
			case hcl.TraverseIndex:
				right, ok := right.(hcl.TraverseIndex)
				return ok && left.Key.RawEquals(right.Key)
			}
			return false
		})
	}
	var groups []presence
	var guaranteed []cty.Type
	for _, arg := range args {
		conditional, ok := unwrapParentheses(arg).(*hclsyntax.ConditionalExpr)
		if !ok {
			continue
		}
		condition := unwrapParentheses(conditional.Condition)
		inverted := false
		for {
			not, ok := condition.(*hclsyntax.UnaryOpExpr)
			if !ok || not.Op != hclsyntax.OpLogicalNot {
				break
			}
			condition = unwrapParentheses(not.Val)
			inverted = !inverted
		}
		call, ok := condition.(*hclsyntax.FunctionCallExpr)
		if !ok || call.Name != "can" || len(call.Args) != 1 || call.ExpandFinal || !terraformFunctionAvailable("can", ctx) {
			continue
		}
		value, diags := c.expressionValue(call, ctx)
		if diags.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.Bool {
			continue
		}
		predicate, diags := hcl.AbsTraversalForExpr(call.Args[0])
		if diags.HasErrors() {
			continue
		}
		left := c.provenExpressionValue(conditional.TrueResult, ctx)
		right := c.provenExpressionValue(conditional.FalseResult, ctx)
		if left == cty.NilVal || right == cty.NilVal || !left.IsWhollyKnown() || !right.IsWhollyKnown() || !left.Type().Equals(right.Type()) {
			continue
		}
		for i, value := range []cty.Value{left, right} {
			ty := terraformCoalesceArgumentType(value)
			if ty == cty.NilType {
				continue
			}
			branch := uint8(1 << i)
			if inverted {
				branch ^= 3
			}
			index := slices.IndexFunc(groups, func(group presence) bool {
				return group.ty.Equals(ty) && sameTraversal(group.predicate, predicate)
			})
			if index == -1 {
				if len(groups) >= maxTypeCombinations {
					return guaranteed
				}
				index = len(groups)
				groups = append(groups, presence{predicate: predicate, ty: ty})
			}
			groups[index].branches |= branch
			if groups[index].branches == 3 && !slices.ContainsFunc(guaranteed, ty.Equals) {
				guaranteed = append(guaranteed, ty)
			}
		}
	}
	return guaranteed
}

func (c *terraformReferenceChecker) coalesceTypesIndependent(args []hclsyntax.Expression, ctx *hcl.EvalContext, selected cty.Type) bool {
	needsTypeCheck := false
	for _, arg := range args {
		_, diags := c.expressionValue(arg, ctx)
		if !diags.HasErrors() && c.hasUnresolvableVariables(arg, ctx) {
			needsTypeCheck = true
			break
		}
	}
	if !needsTypeCheck {
		return true
	}
	observed := []cty.Type{selected}
	possibilities := [][]cty.Type{{selected}}
	for _, arg := range args {
		value, diags := c.expressionValue(arg, ctx)
		if diags.HasErrors() {
			continue
		}
		ty := terraformCoalesceArgumentType(value)
		if ty != cty.NilType {
			observed = append(observed, ty)
		}
		candidates := []cty.Type{ty}
		if c.hasUnresolvableVariables(arg, ctx) {
			candidates = nil
			visits := 0
			if !c.visitCoalesceTypes(arg, ctx, map[terraformExpressionContext]bool{}, func(ty cty.Type) bool {
				visits++
				if visits > maxTypeCombinations {
					return false
				}
				if !slices.ContainsFunc(candidates, ty.Equals) {
					candidates = append(candidates, ty)
				}
				return true
			}) {
				return false
			}
		}
		var next [][]cty.Type
		for _, types := range possibilities {
			for _, candidate := range candidates {
				combination := types
				// Repeating an existing type cannot affect unification.
				if candidate != cty.NilType && !slices.ContainsFunc(types, candidate.Equals) {
					// Bound the size of each combination, including its resolved types.
					if len(types) >= maxTypeCombinations {
						return false
					}
					combination = append(slices.Clone(types), candidate)
				}
				if !slices.ContainsFunc(next, func(other []cty.Type) bool {
					return slices.EqualFunc(other, combination, cty.Type.Equals)
				}) {
					next = append(next, combination)
				}
				// Fail closed rather than enumerate exponentially many type combinations.
				if len(next) > maxTypeCombinations {
					return false
				}
			}
		}
		possibilities = next
	}
	want, _ := convert.UnifyUnsafe(observed)
	guaranteed := c.guaranteedCoalesceTypes(args, ctx)
	checked := false
	for _, types := range possibilities {
		if slices.ContainsFunc(guaranteed, func(ty cty.Type) bool { return !slices.ContainsFunc(types, ty.Equals) }) {
			continue
		}
		checked = true
		got, _ := convert.UnifyUnsafe(types)
		if !got.Equals(want) {
			return false
		}
	}
	return checked
}

func (c *terraformReferenceChecker) visitCoalesceTypes(expr hcl.Expression, ctx *hcl.EvalContext, active map[terraformExpressionContext]bool, visit func(cty.Type) bool) bool {
	expr = unwrapParentheses(expr)
	key := terraformExpressionContext{expr, ctx}
	if active[key] {
		return false
	}
	active[key] = true
	defer delete(active, key)
	if value := c.provenExpressionValue(expr, ctx); value != cty.NilVal {
		if value.IsWhollyKnown() {
			return visit(terraformCoalesceArgumentType(value))
		}
		if value.Type() != cty.String && !value.Type().HasDynamicTypes() && value.Range().DefinitelyNotNull() {
			return visit(value.Type())
		}
	}
	if traversal, diags := hcl.AbsTraversalForExpr(expr); !diags.HasErrors() && len(traversal) == 2 && traversal.RootName() == "local" && terraformVariableScope("local", ctx) == c.moduleCtx {
		if name, valid := terraformObjectSelectionKey(traversal[1]); valid {
			if source, exists := c.localExpressions[name.AsString()]; exists {
				return c.visitCoalesceTypes(source, c.moduleCtx, active, visit)
			}
		}
	}
	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "try" && !call.ExpandFinal {
		for _, arg := range call.Args {
			constant := len(arg.Variables()) == 0 && !hasUnavailableTerraformFunctions(arg, ctx)
			if constant {
				value, diags := c.expressionValue(arg, ctx)
				if diags.HasErrors() {
					continue
				}
				return visit(terraformCoalesceArgumentType(value))
			}
			if !c.visitCoalesceTypes(arg, ctx, active, visit) {
				return false
			}
			if inner, ok := unwrapParentheses(arg).(*hclsyntax.FunctionCallExpr); ok && inner.Name == "can" && len(inner.Args) == 1 && !inner.ExpandFinal {
				return true
			}
		}
		return true
	}
	ty := c.expressionType(expr, ctx)
	if ty == cty.NilType || ty.HasDynamicTypes() {
		return false
	}
	// An unresolved argument may become null, empty, or fail evaluation.
	return visit(cty.NilType) && visit(ty)
}
