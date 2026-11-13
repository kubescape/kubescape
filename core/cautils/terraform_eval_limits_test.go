package cautils

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// The limit used by these tests is small, so that if a bound ever regressed
// the function would only allocate a few kilobytes instead of exhausting
// memory.
const testTerraformFunctionLimit = 1 << 12

func callBoundedTerraformFunction(t *testing.T, name string, args ...cty.Value) (cty.Value, error) {
	t.Helper()
	fn, ok := unboundedTerraformFunctions[name]
	require.True(t, ok, name)
	return boundTerraformFunction(name, fn, terraformFunctionBounds[name], testTerraformFunctionLimit).Call(args)
}

func TestBoundedTerraformFunctions_RejectAmplification(t *testing.T) {
	big := cty.StringVal(strings.Repeat("x", testTerraformFunctionLimit/2))
	tests := []struct {
		name string
		fn   string
		args []cty.Value
	}{
		{"format width", "format", []cty.Value{cty.StringVal("%010000000000d"), cty.NumberIntVal(1)}},
		{"format width on string", "format", []cty.Value{cty.StringVal("%-1000000s"), cty.StringVal("a")}},
		{"format precision", "format", []cty.Value{cty.StringVal("%.1000000f"), cty.NumberIntVal(1)}},
		{"format repeated argument", "format", []cty.Value{cty.StringVal("%[1]s%[1]s%[1]s"), big}},
		{"format huge number", "format", []cty.Value{cty.StringVal("%d"), cty.MustParseNumberVal("1e100000")}},
		{"formatlist width", "formatlist", []cty.Value{cty.StringVal("%0100d"), cty.ListVal(repeatNumbers(100))}},
		{"indent", "indent", []cty.Value{cty.NumberIntVal(1 << 30), cty.StringVal("a\nb")}},
		{"join separator", "join", []cty.Value{big, cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b"), cty.StringVal("c")})}},
		{"replace empty substring", "replace", []cty.Value{cty.StringVal(strings.Repeat("a", 100)), cty.StringVal(""), cty.StringVal(strings.Repeat("b", 100))}},
		{"replace regex expansion", "replace", []cty.Value{cty.StringVal(strings.Repeat("a", 1000)), cty.StringVal("/(a+)/"), cty.StringVal("$1$1$1$1$1")}},
		{"split into characters", "split", []cty.Value{cty.StringVal(""), cty.StringVal(strings.Repeat("a", 1000))}},
		{"regexall empty matches", "regexall", []cty.Value{cty.StringVal(""), cty.StringVal(strings.Repeat("a", 1000))}},
		{"oversized argument", "upper", []cty.Value{cty.StringVal(strings.Repeat("x", testTerraformFunctionLimit+1))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := callBoundedTerraformFunction(t, tt.fn, tt.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "size limit")
			// The call must be refused before it runs, not after its result
			// has already been allocated.
			assert.NotContains(t, err.Error(), "result exceeds")
		})
	}
}

func TestBoundedTerraformFunctions_AllowOrdinaryCalls(t *testing.T) {
	tests := []struct {
		fn   string
		args []cty.Value
		want cty.Value
	}{
		{"format", []cty.Value{cty.StringVal("%s:%05d"), cty.StringVal("nginx"), cty.NumberIntVal(42)}, cty.StringVal("nginx:00042")},
		{"format", []cty.Value{cty.StringVal("%[2]s-%[1]s 100%%"), cty.StringVal("a"), cty.StringVal("b")}, cty.StringVal("b-a 100%")},
		{"formatlist", []cty.Value{cty.StringVal("%s=%d"), cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}), cty.NumberIntVal(1)},
			cty.ListVal([]cty.Value{cty.StringVal("a=1"), cty.StringVal("b=1")})},
		{"indent", []cty.Value{cty.NumberIntVal(2), cty.StringVal("a\nb")}, cty.StringVal("a\n  b")},
		{"join", []cty.Value{cty.StringVal(","), cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})}, cty.StringVal("a,b")},
		{"replace", []cty.Value{cty.StringVal("a-b"), cty.StringVal("-"), cty.StringVal("_")}, cty.StringVal("a_b")},
		{"replace", []cty.Value{cty.StringVal("a1b22"), cty.StringVal("/([0-9]+)/"), cty.StringVal("<$1>")}, cty.StringVal("a<1>b<22>")},
		{"split", []cty.Value{cty.StringVal(","), cty.StringVal("a,b")}, cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})},
		{"regexall", []cty.Value{cty.StringVal("[0-9]"), cty.StringVal("a1b2")}, cty.ListVal([]cty.Value{cty.StringVal("1"), cty.StringVal("2")})},
	}
	for _, tt := range tests {
		t.Run(tt.fn, func(t *testing.T) {
			got, err := callBoundedTerraformFunction(t, tt.fn, tt.args...)
			require.NoError(t, err)
			assert.True(t, got.RawEquals(tt.want), "got %#v", got)
		})
	}
}

func TestBoundedTerraformFunctions_IndentNegativeSpaces(t *testing.T) {
	_, err := callBoundedTerraformFunction(t, "indent", cty.NumberIntVal(-1), cty.StringVal("a\nb"))
	require.Error(t, err)
}

func TestTerraformFunctions_AllBounded(t *testing.T) {
	require.Len(t, terraformFunctions, len(unboundedTerraformFunctions))
	for name := range terraformFunctionBounds {
		assert.Contains(t, unboundedTerraformFunctions, name)
	}
}

// TestTerraformDirectory_GetWorkloads_FormatWidthLimit is the end-to-end case
// from review: a local padding to a width beyond the per-call limit must be
// rejected before the padded string is built. The width is only slightly over
// the limit so a regression cannot exhaust memory.
func TestTerraformDirectory_GetWorkloads_FormatWidthLimit(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"locals.tf": fmt.Sprintf("locals {\n  huge = format(\"%%0%dd\", 1)\n  ok = \"nginx:1.27\"\n}\n", 2*maxTerraformFunctionSize),
		"main.tf": `
resource "kubernetes_pod_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    container {
      name    = "app"
      image   = local.ok
      command = [local.huge]
    }
  }
}
`,
	})

	obj, errs := terraformObject(t, dir)
	container := terraformFirstContainer(t, obj)
	assert.Equal(t, "nginx:1.27", container["image"])
	assert.NotContains(t, container, "command")
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `"command"`)
}

func repeatNumbers(n int) []cty.Value {
	vals := make([]cty.Value, n)
	for i := range vals {
		vals[i] = cty.NumberIntVal(int64(i))
	}
	return vals
}

// evalBoundedTerraformExpr evaluates expr through HCL, as the scanner does, so
// that HCL's own argument conversion and go-cty's return-type calculation are
// exercised, with functions bounded by testTerraformFunctionLimit.
func evalBoundedTerraformExpr(t *testing.T, expr string, locals map[string]cty.Value) (cty.Value, hcl.Diagnostics) {
	t.Helper()
	parsed, diags := hclsyntax.ParseExpression([]byte(expr), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"local": cty.ObjectVal(locals)},
		Functions: boundTerraformFunctions(unboundedTerraformFunctions, testTerraformFunctionLimit),
	}
	return parsed.Value(ctx)
}

func TestBoundedTerraformFunctions_RejectBeforeConversionAndTyping(t *testing.T) {
	bools := make([]cty.Value, testTerraformFunctionLimit*3/4)
	for i := range bools {
		bools[i] = cty.True
	}
	locals := map[string]cty.Value{
		"bools":  cty.TupleVal(bools),
		"bigkey": cty.ObjectVal(map[string]cty.Value{strings.Repeat("k", testTerraformFunctionLimit/2): cty.True}),
	}
	tests := []struct {
		name, expr, want string
	}{
		// HCL would render the number as a decimal string to match upper's
		// string parameter before the function runs.
		{"number to string conversion", "upper(1e100000)", "arguments exceed"},
		{"number to string conversion in a list", `join(",", [1e100000])`, "arguments exceed"},
		// concat computes the full tuple type of its result while type checking.
		{"return type of large tuples", "concat(local.bools, local.bools)", "arguments exceed"},
		// go-cty converts the string to a number and prints every digit.
		{"numeric verb on a string", `format("%d", "1e100000")`, "would exceed"},
		{"binary verb on a string", `format("%b", "1e10000")`, "would exceed"},
		{"numeric verb in formatlist", `formatlist("%x", ["1e100000"])`, "would exceed"},
		// The key is serialized every time the object is formatted.
		{"object keys", `format("%[1]v%[1]v", local.bigkey)`, "would exceed"},
		// go-cty allocates the padding even when there is no newline.
		{"indent without newline", "indent(1048576, \"x\")", "would exceed"},
		// A short string converts to a compact number with a huge exponent;
		// ceil and floor would materialize its integer part.
		{"string converted to a huge number for ceil", `ceil("1e100000")`, "arguments exceed"},
		{"string converted to a huge number for floor", `floor("-1e100000")`, "arguments exceed"},
		{"variadic number conversion", `max(1, "1e100000")`, "arguments exceed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, diags := evalBoundedTerraformExpr(t, tt.expr, locals)
			require.True(t, diags.HasErrors())
			assert.Contains(t, diags.Error(), tt.want)
		})
	}
}

func TestBoundedTerraformFunctions_KeepHCLConversions(t *testing.T) {
	tests := []struct {
		expr string
		want cty.Value
	}{
		{"upper(12)", cty.StringVal("12")},
		{`join(",", [1, true, "a"])`, cty.StringVal("1,true,a")},
		{`format("%d-%s", "42", 7)`, cty.StringVal("42-7")},
		{`indent("2", "a\nb")`, cty.StringVal("a\n  b")},
		{"length([1, 2, 3])", cty.NumberIntVal(3)},
		{"concat([1], [2])", cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)})},
		{`lookup({a = 1}, "a")`, cty.NumberIntVal(1)},
		{"coalesce(null, \"x\")", cty.StringVal("x")},
		{"try(local.missing, \"fallback\")", cty.StringVal("fallback")},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, diags := evalBoundedTerraformExpr(t, tt.expr, map[string]cty.Value{})
			require.False(t, diags.HasErrors(), diags.Error())
			assert.True(t, got.RawEquals(tt.want), "got %#v", got)
		})
	}
}

func TestTerraformValueSize_CountsKeys(t *testing.T) {
	key := strings.Repeat("k", 100)
	obj := cty.ObjectVal(map[string]cty.Value{key: cty.True})
	m := cty.MapVal(map[string]cty.Value{key: cty.True})
	assert.Greater(t, terraformValueSize(obj, maxTerraformLocalSize), len(key))
	assert.Greater(t, terraformValueSize(m, maxTerraformLocalSize), len(key))
}

// TestBoundedTerraformFunctions_CheckConvertedArguments confirms that an
// argument which only becomes oversized once converted to the parameter type
// is refused without invoking the underlying function.
func TestBoundedTerraformFunctions_CheckConvertedArguments(t *testing.T) {
	calls := 0
	spy := function.New(&function.Spec{
		Params: []function.Parameter{{Name: "num", Type: cty.Number}},
		Type:   function.StaticReturnType(cty.Number),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			calls++
			return args[0], nil
		},
	})
	bounded := boundTerraformFunction("spy", spy, nil, testTerraformFunctionLimit)

	_, err := bounded.Call([]cty.Value{cty.StringVal("1e100000")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arguments exceed")
	assert.Zero(t, calls, "the underlying function must not run")

	got, err := bounded.Call([]cty.Value{cty.StringVal("12")})
	require.NoError(t, err)
	assert.True(t, got.RawEquals(cty.NumberIntVal(12)))
	assert.Equal(t, 1, calls)
}
