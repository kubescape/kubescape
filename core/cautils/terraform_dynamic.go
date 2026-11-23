package cautils

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type terraformBlock struct {
	*hclsyntax.Block
	evalCtx   *hcl.EvalContext
	generated bool
}

type terraformBodyConverter struct {
	errs       *[]error
	remaining  int
	exhausted  bool
	references terraformReferenceChecker
}

// reserve bounds the combined generated blocks and values, including nested
// iterations, before they can multiply a small source into a large manifest.
func (c *terraformBodyConverter) reserve(size int, path string) bool {
	if size > c.remaining {
		*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic block expansion exceeds the size limit of %d bytes", path, maxTerraformLocalSize))
		c.remaining = 0
		c.exhausted = true
		return false
	}
	c.remaining -= size
	return true
}

func (c *terraformBodyConverter) blocks(body *hclsyntax.Body, evalCtx *hcl.EvalContext, path string, generated bool) []terraformBlock {
	var blocks []terraformBlock
	for _, block := range body.Blocks {
		if c.exhausted {
			break
		}
		if block.Type != "dynamic" {
			if !generated || c.reserve(terraformElementOverhead, path) {
				blocks = append(blocks, terraformBlock{Block: block, evalCtx: evalCtx, generated: generated})
			}
			continue
		}

		startErrors := len(*c.errs)
		if len(block.Labels) != 1 || block.Labels[0] == "dynamic" {
			*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic requires one nested block type label", path))
			continue
		}
		blockType := block.Labels[0]
		iterator := blockType
		for name, attr := range block.Body.Attributes {
			switch name {
			case "for_each":
			case "iterator":
				traversal, diags := hcl.AbsTraversalForExpr(attr.Expr)
				if diags.HasErrors() || len(traversal) != 1 {
					*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic %q iterator must be a single variable name", path, blockType))
				} else {
					iterator = traversal.RootName()
				}
			default:
				*c.errs = append(*c.errs, fmt.Errorf("%s: unsupported dynamic %q attribute %q", path, blockType, name))
			}
		}
		var content *hclsyntax.Block
		for _, child := range block.Body.Blocks {
			if child.Type != "content" || len(child.Labels) != 0 || content != nil {
				*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic %q requires exactly one unlabeled content block", path, blockType))
			} else {
				content = child
			}
		}
		each := block.Body.Attributes["for_each"]
		if each == nil || content == nil {
			*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic %q requires for_each and content", path, blockType))
			continue
		}
		if len(*c.errs) != startErrors {
			continue
		}
		values, diags := each.Expr.Value(evalCtx)
		if diags.HasErrors() {
			*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic %q for_each: %w", path, blockType, diags))
			continue
		}
		// try() can hide unresolved references behind a known fallback collection.
		if c.references.hasUnresolvableVariables(each.Expr, evalCtx) {
			*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic %q for_each contains unresolved references", path, blockType))
			continue
		}
		if values.IsNull() || !values.IsWhollyKnown() || !values.CanIterateElements() {
			*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic %q for_each must be a known, non-null collection", path, blockType))
			continue
		}
		count := values.LengthInt()
		if count > c.remaining/terraformElementOverhead {
			c.reserve(c.remaining+1, path)
			continue
		}
		c.reserve(count*terraformElementOverhead, path)
		for it := values.ElementIterator(); it.Next(); {
			key, value := it.Element()
			childCtx := evalCtx.NewChild()
			childCtx.Variables = map[string]cty.Value{
				iterator: cty.ObjectVal(map[string]cty.Value{"key": key, "value": value}),
			}
			expanded := *content
			expanded.Type = blockType
			blocks = append(blocks, terraformBlock{Block: &expanded, evalCtx: childCtx, generated: true})
		}
	}
	return blocks
}
