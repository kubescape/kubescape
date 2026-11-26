package cautils

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
)

func TestTerraformTraversalType(t *testing.T) {
	objType := cty.Object(map[string]cty.Type{
		"name":  cty.String,
		"count": cty.Number,
	})

	tests := []struct {
		name      string
		ty        cty.Type
		traversal hcl.Traversal
		want      cty.Type
	}{
		{
			name:      "nil type passes through",
			ty:        cty.NilType,
			traversal: hcl.Traversal{hcl.TraverseAttr{Name: "name"}},
			want:      cty.NilType,
		},
		{
			name:      "dynamic pseudo type passes through",
			ty:        cty.DynamicPseudoType,
			traversal: hcl.Traversal{hcl.TraverseAttr{Name: "name"}},
			want:      cty.DynamicPseudoType,
		},
		{
			name:      "valid object attribute traversal",
			ty:        objType,
			traversal: hcl.Traversal{hcl.TraverseAttr{Name: "name"}},
			want:      cty.String,
		},
		{
			name:      "valid list index traversal",
			ty:        cty.List(cty.Bool),
			traversal: hcl.Traversal{hcl.TraverseIndex{Key: cty.NumberIntVal(0)}},
			want:      cty.Bool,
		},
		{
			name:      "missing object attribute falls back to dynamic",
			ty:        objType,
			traversal: hcl.Traversal{hcl.TraverseAttr{Name: "missing"}},
			want:      cty.DynamicPseudoType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := terraformTraversalType(tt.ty, tt.traversal)
			assert.True(t, got.Equals(tt.want), "got %#v, want %#v", got, tt.want)
		})
	}
}

func TestTerraformProofValueSizeIsBounded(t *testing.T) {
	tests := []struct {
		name  string
		value cty.Value
		want  bool
	}{
		{
			name:  "wholly known scalar is bounded",
			value: cty.StringVal("ok"),
			want:  true,
		},
		{
			name:  "unknown boolean is bounded",
			value: cty.UnknownVal(cty.Bool),
			want:  true,
		},
		{
			name:  "unknown string is unbounded",
			value: cty.UnknownVal(cty.String),
			want:  false,
		},
		{
			name:  "unknown number is unbounded",
			value: cty.UnknownVal(cty.Number),
			want:  false,
		},
		{
			name:  "tuple of known values and unknown bool is bounded",
			value: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.UnknownVal(cty.Bool)}),
			want:  true,
		},
		{
			name:  "tuple containing unknown string is unbounded",
			value: cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.UnknownVal(cty.String)}),
			want:  false,
		},
		{
			name: "nested object with bounded elements is bounded",
			value: cty.ObjectVal(map[string]cty.Value{
				"flag": cty.UnknownVal(cty.Bool),
				"name": cty.StringVal("svc"),
			}),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, terraformProofValueSizeIsBounded(tt.value))
		})
	}
}

func TestTerraformCoalesceTypesInvariant(t *testing.T) {
	strList := cty.List(cty.String)

	tests := []struct {
		name       string
		selected   cty.Type
		observed   []cty.Type
		candidates [][]cty.Type
		want       bool
	}{
		{
			name:     "non-list selected type returns false",
			selected: cty.String,
			observed: []cty.Type{cty.String},
			want:     false,
		},
		{
			name:     "matching list, nil type, and homogeneous tuple candidates",
			selected: strList,
			observed: []cty.Type{strList, cty.NilType},
			candidates: [][]cty.Type{
				{cty.Tuple([]cty.Type{cty.String, cty.String}), cty.EmptyTuple},
			},
			want: true,
		},
		{
			name:     "mismatched element in tuple candidate returns false",
			selected: strList,
			observed: []cty.Type{strList},
			candidates: [][]cty.Type{
				{cty.Tuple([]cty.Type{cty.String, cty.Number})},
			},
			want: false,
		},
		{
			name:     "mismatched observed list type returns false",
			selected: strList,
			observed: []cty.Type{cty.List(cty.Number)},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, terraformCoalesceTypesInvariant(tt.selected, tt.observed, tt.candidates))
		})
	}
}
