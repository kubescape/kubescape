package cautils

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
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
