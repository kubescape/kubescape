package cautils

import (
	"fmt"
	"math/big"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// terraformResourceInstances returns one evaluation context for each instance
// of a resource block, following Terraform's count and for_each
// meta-arguments:
//
//   - without either, the resource has one instance, evaluated in evalCtx;
//   - count = N gives N instances, each with count.index bound to 0..N-1;
//   - for_each over a map or object gives one instance per key, and over a set
//     of strings one per element, each with each.key and each.value bound (for
//     a set, each.value is the element itself, as in Terraform).
//
// A count or for_each that cannot be resolved to a known value, has the wrong
// type, or is combined with the other is an error rather than a guess, so the
// caller can keep its fail-closed policy for unresolved values. sourceSize is
// the size of the resource block in bytes; it bounds the number of instances
// so a large count cannot multiply a small block into an unbounded number of
// manifests.
func terraformResourceInstances(count, forEach *hcl.Attribute, evalCtx *hcl.EvalContext, references terraformReferenceChecker, path string, sourceSize int) ([]*hcl.EvalContext, error) {
	switch {
	case count != nil && forEach != nil:
		return nil, fmt.Errorf("%s: count and for_each cannot be used together", path)
	case count != nil:
		return terraformCountInstances(count, evalCtx, references, path, sourceSize)
	case forEach != nil:
		return terraformForEachInstances(forEach, evalCtx, references, path, sourceSize)
	}
	return []*hcl.EvalContext{evalCtx}, nil
}

func terraformCountInstances(count *hcl.Attribute, evalCtx *hcl.EvalContext, references terraformReferenceChecker, path string, sourceSize int) ([]*hcl.EvalContext, error) {
	value, err := terraformMetaArgumentValue(count, evalCtx, references, path, "count")
	if err != nil {
		return nil, err
	}
	number, err := convert.Convert(value, cty.Number)
	if err != nil {
		return nil, fmt.Errorf("%s: count must be a number: %w", path, err)
	}
	n, accuracy := number.AsBigFloat().Int64()
	if accuracy != big.Exact || n < 0 {
		return nil, fmt.Errorf("%s: count must be a whole number of at least 0", path)
	}
	if err := checkTerraformInstanceCount(n, sourceSize, path); err != nil {
		return nil, err
	}
	instances := make([]*hcl.EvalContext, 0, n)
	for i := int64(0); i < n; i++ {
		instances = append(instances, terraformInstanceContext(evalCtx, "count", map[string]cty.Value{
			"index": cty.NumberIntVal(i),
		}))
	}
	return instances, nil
}

func terraformForEachInstances(forEach *hcl.Attribute, evalCtx *hcl.EvalContext, references terraformReferenceChecker, path string, sourceSize int) ([]*hcl.EvalContext, error) {
	value, err := terraformMetaArgumentValue(forEach, evalCtx, references, path, "for_each")
	if err != nil {
		return nil, err
	}
	valueType := value.Type()
	isMap := valueType.IsMapType() || valueType.IsObjectType()
	if !isMap && !valueType.IsSetType() {
		return nil, fmt.Errorf("%s: for_each must be a map or a set of strings, not %s; use toset() for a list", path, valueType.FriendlyName())
	}
	// Terraform refuses a set of anything but strings, such as toset([1, 2]),
	// rather than converting its elements. An empty set has no element type.
	if !isMap && value.LengthInt() > 0 && !valueType.ElementType().Equals(cty.String) {
		return nil, fmt.Errorf("%s: for_each must be a map or a set of strings, not %s", path, valueType.FriendlyName())
	}
	if err := checkTerraformInstanceCount(int64(value.LengthInt()), sourceSize, path); err != nil {
		return nil, err
	}
	instances := make([]*hcl.EvalContext, 0, value.LengthInt())
	for it := value.ElementIterator(); it.Next(); {
		// A set's element is both its key and its value, which the set's
		// iterator already returns.
		key, element := it.Element()
		instances = append(instances, terraformInstanceContext(evalCtx, "each", map[string]cty.Value{
			"key":   key,
			"value": element,
		}))
	}
	return instances, nil
}

// terraformMetaArgumentValue evaluates count or for_each, refusing a value
// that depends on anything the scan cannot resolve: the number of instances
// then isn't known, and guessing it could hide or invent resources.
func terraformMetaArgumentValue(attr *hcl.Attribute, evalCtx *hcl.EvalContext, references terraformReferenceChecker, path, name string) (cty.Value, error) {
	value, diags := attr.Expr.Value(evalCtx)
	if diags.HasErrors() {
		return cty.NilVal, fmt.Errorf("%s: %s: %w", path, name, diags)
	}
	value, _ = value.UnmarkDeep()
	// try() can hide unresolved references behind a known fallback.
	if references.hasUnresolvableVariables(attr.Expr, evalCtx) {
		return cty.NilVal, fmt.Errorf("%s: %s contains unresolved references", path, name)
	}
	if value.IsNull() || !value.IsWhollyKnown() {
		return cty.NilVal, fmt.Errorf("%s: %s must be a known, non-null value", path, name)
	}
	return value, nil
}

// checkTerraformInstanceCount bounds the expansion by the same budget as a
// dynamic block: every instance costs at least the resource's own source plus
// the per-element overhead, and the total must fit in maxTerraformLocalSize.
func checkTerraformInstanceCount(n int64, sourceSize int, path string) error {
	perInstance := int64(sourceSize) + terraformElementOverhead
	if n > int64(maxTerraformLocalSize)/perInstance {
		return fmt.Errorf("%s: count or for_each expansion exceeds the size limit of %d bytes", path, maxTerraformLocalSize)
	}
	return nil
}

func terraformInstanceContext(evalCtx *hcl.EvalContext, name string, attributes map[string]cty.Value) *hcl.EvalContext {
	child := evalCtx.NewChild()
	child.Variables = map[string]cty.Value{name: cty.ObjectVal(attributes)}
	return child
}
