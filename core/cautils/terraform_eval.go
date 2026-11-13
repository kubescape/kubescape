package cautils

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// unboundedTerraformFunctions are the functions available to Terraform expressions
// before size limits are applied; see terraformFunctions.
var unboundedTerraformFunctions = map[string]function.Function{
	"abs":             stdlib.AbsoluteFunc,
	"base64decode":    base64DecodeFunc,
	"base64encode":    base64EncodeFunc,
	"can":             tryfunc.CanFunc,
	"ceil":            stdlib.CeilFunc,
	"chomp":           stdlib.ChompFunc,
	"chunklist":       stdlib.ChunklistFunc,
	"coalesce":        coalesceFunc,
	"coalescelist":    stdlib.CoalesceListFunc,
	"compact":         stdlib.CompactFunc,
	"concat":          stdlib.ConcatFunc,
	"contains":        stdlib.ContainsFunc,
	"csvdecode":       stdlib.CSVDecodeFunc,
	"distinct":        stdlib.DistinctFunc,
	"element":         stdlib.ElementFunc,
	"flatten":         stdlib.FlattenFunc,
	"floor":           stdlib.FloorFunc,
	"format":          stdlib.FormatFunc,
	"formatlist":      stdlib.FormatListFunc,
	"indent":          stdlib.IndentFunc,
	"join":            stdlib.JoinFunc,
	"jsondecode":      stdlib.JSONDecodeFunc,
	"jsonencode":      stdlib.JSONEncodeFunc,
	"keys":            stdlib.KeysFunc,
	"length":          lengthFunc,
	"log":             stdlib.LogFunc,
	"lookup":          lookupFunc,
	"lower":           stdlib.LowerFunc,
	"max":             stdlib.MaxFunc,
	"merge":           stdlib.MergeFunc,
	"min":             stdlib.MinFunc,
	"parseint":        stdlib.ParseIntFunc,
	"pow":             stdlib.PowFunc,
	"range":           stdlib.RangeFunc,
	"regex":           stdlib.RegexFunc,
	"regexall":        stdlib.RegexAllFunc,
	"replace":         replaceFunc,
	"reverse":         stdlib.ReverseListFunc,
	"setintersection": stdlib.SetIntersectionFunc,
	"setsubtract":     stdlib.SetSubtractFunc,
	"setunion":        stdlib.SetUnionFunc,
	"signum":          stdlib.SignumFunc,
	"slice":           stdlib.SliceFunc,
	"sort":            stdlib.SortFunc,
	"split":           stdlib.SplitFunc,
	"strrev":          stdlib.ReverseFunc,
	"substr":          stdlib.SubstrFunc,
	"title":           stdlib.TitleFunc,
	"tobool":          stdlib.MakeToFunc(cty.Bool),
	"tolist":          stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"tomap":           stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType)),
	"tonumber":        stdlib.MakeToFunc(cty.Number),
	"toset":           stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)),
	"tostring":        stdlib.MakeToFunc(cty.String),
	"trim":            stdlib.TrimFunc,
	"trimprefix":      stdlib.TrimPrefixFunc,
	"trimspace":       stdlib.TrimSpaceFunc,
	"trimsuffix":      stdlib.TrimSuffixFunc,
	"try":             tryfunc.TryFunc,
	"upper":           stdlib.UpperFunc,
	"values":          stdlib.ValuesFunc,
	"zipmap":          stdlib.ZipmapFunc,
}

const (
	// maxTerraformLocalSize caps the size of a single resolved local.
	maxTerraformLocalSize = 1 << 20
	// maxTerraformLocalsTotalSize caps the combined size of every local value
	// evaluated for one module, including values rejected for being too large,
	// so that many individually small locals cannot exhaust memory.
	maxTerraformLocalsTotalSize = 16 << 20
)

var coalesceFunc = function.New(&function.Spec{
	VarParam: &function.Parameter{Name: "vals", Type: cty.DynamicPseudoType, AllowNull: true, AllowDynamicType: true},
	Type: func(args []cty.Value) (cty.Type, error) {
		var types []cty.Type
		for _, arg := range args {
			if arg.Type() != cty.DynamicPseudoType {
				types = append(types, arg.Type())
			}
		}
		if len(types) == 0 {
			return cty.DynamicPseudoType, nil
		}
		ty, _ := convert.UnifyUnsafe(types)
		if ty == cty.NilType {
			return cty.NilType, fmt.Errorf("all arguments must have the same type")
		}
		return ty, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for _, arg := range args {
			val, err := convert.Convert(arg, retType)
			if err != nil {
				return cty.UnknownVal(retType), err
			}
			if val.IsNull() || (val.Type() == cty.String && val.AsString() == "") {
				continue
			}
			return val, nil
		}
		return cty.NilVal, fmt.Errorf("no non-null, non-empty-string arguments")
	},
})

var lookupFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "inputMap", Type: cty.DynamicPseudoType},
		{Name: "key", Type: cty.String},
	},
	VarParam: &function.Parameter{Name: "default", Type: cty.DynamicPseudoType, AllowNull: true},
	Type: func(args []cty.Value) (cty.Type, error) {
		if len(args) > 3 {
			return cty.NilType, fmt.Errorf("lookup() takes at most three arguments")
		}
		if len(args) == 3 {
			return stdlib.LookupFunc.ReturnTypeForValues(args)
		}
		return cty.DynamicPseudoType, nil
	},
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		if len(args) == 3 {
			return stdlib.LookupFunc.Call(args)
		}
		ty := args[0].Type()
		key := args[1].AsString()
		switch {
		case ty.IsObjectType() && ty.HasAttribute(key):
			return args[0].GetAttr(key), nil
		case ty.IsMapType() && args[0].HasIndex(args[1]).True():
			return args[0].Index(args[1]), nil
		case ty.IsObjectType() || ty.IsMapType():
			return cty.NilVal, fmt.Errorf("lookup failed to find key %q", key)
		}
		return cty.NilVal, fmt.Errorf("lookup() requires a map as the first argument")
	},
})

var base64EncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.StringVal(base64.StdEncoding.EncodeToString([]byte(args[0].AsString()))), nil
	},
})

var base64DecodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		decoded, err := base64.StdEncoding.DecodeString(args[0].AsString())
		if err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("failed to decode base64 data: %w", err)
		}
		if !utf8.Valid(decoded) {
			return cty.UnknownVal(cty.String), fmt.Errorf("decoded base64 data is not valid UTF-8")
		}
		return cty.StringVal(string(decoded)), nil
	},
})

var lengthFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "value", Type: cty.DynamicPseudoType, AllowDynamicType: true}},
	Type:   function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		if args[0].Type() == cty.String {
			return stdlib.Strlen(args[0])
		}
		return stdlib.Length(args[0])
	},
})

var replaceFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "substr", Type: cty.String},
		{Name: "replace", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		substr := args[1].AsString()
		if len(substr) > 1 && strings.HasPrefix(substr, "/") && strings.HasSuffix(substr, "/") {
			return stdlib.RegexReplace(args[0], cty.StringVal(substr[1:len(substr)-1]), args[2])
		}
		return stdlib.Replace(args[0], args[1], args[2])
	},
})

type terraformVariable struct {
	ty       cty.Type
	defaults *typeexpr.Defaults
}

func newTerraformVariable(typeAttr *hcl.Attribute) terraformVariable {
	if typeAttr == nil {
		return terraformVariable{ty: cty.DynamicPseudoType}
	}
	ty, defaults, diags := typeexpr.TypeConstraintWithDefaults(typeAttr.Expr)
	if diags.HasErrors() {
		return terraformVariable{ty: cty.DynamicPseudoType}
	}
	return terraformVariable{ty: ty, defaults: defaults}
}

func (v terraformVariable) convert(val cty.Value) (cty.Value, error) {
	if v.defaults != nil {
		val = v.defaults.Apply(val)
	}
	return convert.Convert(val, v.ty)
}

func terraformValueSize(val cty.Value, budget int) int {
	if val.IsNull() || !val.IsKnown() {
		return 1
	}
	ty := val.Type()
	switch {
	case ty == cty.String:
		return 1 + len(val.AsString())
	case ty.IsObjectType() || ty.IsMapType() || ty.IsTupleType() || ty.IsListType() || ty.IsSetType():
		// Object and map keys are counted too: they are retained with the
		// value and written out whenever it is serialized.
		keyed := ty.IsObjectType() || ty.IsMapType()
		size := 1
		for it := val.ElementIterator(); it.Next() && size <= budget; {
			key, elem := it.Element()
			if keyed {
				size += 1 + len(key.AsString())
			}
			size += terraformValueSize(elem, budget-size)
		}
		return size
	case ty == cty.Number:
		return terraformNumberSize(val)
	default:
		return 1
	}
}

func newTerraformEvalContext(vars, locals map[string]cty.Value) *hcl.EvalContext {
	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var":   cty.ObjectVal(vars),
			"local": cty.ObjectVal(locals),
		},
		Functions: terraformFunctions,
	}
}

func terraformVarFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var base, auto []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir():
		case name == "terraform.tfvars" || name == "terraform.tfvars.json":
			base = append(base, filepath.Join(dir, name))
		case strings.HasSuffix(name, ".auto.tfvars") || strings.HasSuffix(name, ".auto.tfvars.json"):
			auto = append(auto, filepath.Join(dir, name))
		}
	}
	return append(base, auto...)
}

func applyTerraformVarFiles(parser *hclparse.Parser, dir, workspaceDir string, declared map[string]terraformVariable, values map[string]cty.Value) []error {
	var errs []error
	for _, f := range terraformVarFiles(dir) {
		if workspaceDir != "" && !pathcontainment.IsPathContained(workspaceDir, f) {
			logger.L().Warning("Skipping Terraform variable file outside workspace root", helpers.String("path", f), helpers.String("workspace", workspaceDir))
			continue
		}
		content, err := readTerraformFile(f)
		if err != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", f, err))
			continue
		}
		var file *hcl.File
		var diags hcl.Diagnostics
		if strings.HasSuffix(f, ".json") {
			file, diags = parser.ParseJSON(content, f)
		} else {
			file, diags = parser.ParseHCL(content, f)
		}
		if diags.HasErrors() {
			errs = append(errs, fmt.Errorf("parsing %s: %w", f, diags))
			continue
		}
		attrs, diags := file.Body.JustAttributes()
		if diags.HasErrors() {
			errs = append(errs, fmt.Errorf("parsing %s: %w", f, diags))
			continue
		}
		for name, attr := range attrs {
			variable, ok := declared[name]
			if !ok {
				continue
			}
			val, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				errs = append(errs, fmt.Errorf("%s: variable %q: %w", f, name, diags))
				continue
			}
			val, err = variable.convert(val)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: variable %q: %w", f, name, err))
				continue
			}
			values[name] = val
		}
	}
	return errs
}

func resolveLocals(files []*hcl.File, vars map[string]cty.Value) map[string]cty.Value {
	pending := map[string]hcl.Expression{}
	schema := &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "locals"}}}
	for _, file := range files {
		content, _, _ := file.Body.PartialContent(schema)
		for _, block := range content.Blocks {
			attrs, _ := block.Body.JustAttributes()
			for name, attr := range attrs {
				pending[name] = attr.Expr
			}
		}
	}

	resolved := map[string]cty.Value{}
	budget := maxTerraformLocalsTotalSize
	for len(pending) > 0 {
		var ready []string
		for name, expr := range pending {
			if !referencesPendingLocal(expr, pending) {
				ready = append(ready, name)
			}
		}
		if len(ready) == 0 {
			break
		}
		// Evaluate in a stable order so the locals kept under the budget are deterministic.
		sort.Strings(ready)
		evalCtx := newTerraformEvalContext(vars, resolved)
		for _, name := range ready {
			if budget <= 0 {
				logger.L().Warning("Skipping remaining Terraform locals: total size limit reached",
					helpers.Int("skipped", len(pending)))
				return resolved
			}
			val, diags := pending[name].Value(evalCtx)
			delete(pending, name)
			if diags.HasErrors() {
				continue
			}
			limit := min(maxTerraformLocalSize, budget)
			size := terraformValueSize(val, limit)
			budget -= size
			if size > limit {
				logger.L().Warning("Skipping Terraform local that exceeds the size limit", helpers.String("local", name))
				continue
			}
			resolved[name] = val
		}
	}
	return resolved
}

func referencesPendingLocal(expr hcl.Expression, pending map[string]hcl.Expression) bool {
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != "local" || len(traversal) < 2 {
			continue
		}
		var name string
		switch step := traversal[1].(type) {
		case hcl.TraverseAttr:
			name = step.Name
		case hcl.TraverseIndex:
			if step.Key.Type() == cty.String && step.Key.IsKnown() {
				name = step.Key.AsString()
			}
		}
		if _, ok := pending[name]; ok {
			return true
		}
	}
	return false
}
