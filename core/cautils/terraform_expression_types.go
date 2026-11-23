package cautils

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

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

func (c *terraformReferenceChecker) coalesceTypeIndependent(expr hcl.Expression, ctx *hcl.EvalContext, selected cty.Type, active map[terraformExpressionContext]bool) bool {
	expr = unwrapParentheses(expr)
	key := terraformExpressionContext{expr, ctx}
	if active[key] {
		return false
	}
	active[key] = true
	defer delete(active, key)
	if traversal, diags := hcl.AbsTraversalForExpr(expr); !diags.HasErrors() && len(traversal) == 2 && traversal.RootName() == "local" && terraformVariableScope("local", ctx) == c.moduleCtx {
		if name, valid := terraformObjectSelectionKey(traversal[1]); valid {
			if source, exists := c.localExpressions[name.AsString()]; exists {
				return c.coalesceTypeIndependent(source, c.moduleCtx, selected, active)
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
				if value.IsNull() || (value.Type() == cty.String && value.AsString() == "") {
					return true
				}
			}
			if !c.coalesceTypeIndependent(arg, ctx, selected, active) {
				return false
			}
			if constant {
				return true
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
	common, _ := convert.UnifyUnsafe([]cty.Type{selected, ty})
	return common != cty.NilType && common.Equals(selected)
}
