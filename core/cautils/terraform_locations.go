package cautils

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/zclconf/go-cty/cty"
)

// SourceLocation is a 1-based line and column in a source file.
type SourceLocation struct {
	Line   int
	Column int
	tree   *terraformSourceNode
}

// terraformSourceNode holds the resource header and the explicitly written
// fields in the same file. The report's artifact URI always names that file.
type terraformSourceNode struct {
	SourceLocation
	file   string
	fields map[string]*terraformSourceNode
	items  []*terraformSourceNode
}

func newTerraformLocation(r hcl.Range) *terraformSourceNode {
	return &terraformSourceNode{SourceLocation: SourceLocation{Line: r.Start.Line, Column: r.Start.Column}, file: r.Filename}
}

// Field resolves a rule path against the Kubernetes shape produced by conversion.
func (loc SourceLocation) Field(path string) (SourceLocation, bool) {
	s := loc.tree
	if s == nil {
		return SourceLocation{}, false
	}
	parts, err := pathparse.ParsePath(path)
	if err != nil || len(parts) == 0 {
		return SourceLocation{}, false
	}
	for _, part := range parts {
		s = s.fields[part.Key]
		if s == nil {
			return SourceLocation{}, false
		}
		if part.Index >= 0 {
			if part.Index >= len(s.items) {
				return SourceLocation{}, false
			}
			s = s.items[part.Index]
			if s == nil {
				return SourceLocation{}, false
			}
		}
	}
	return s.SourceLocation, true
}

func (s *terraformSourceNode) field(key string, r hcl.Range) *terraformSourceNode {
	if s == nil {
		return nil
	}
	if r.Filename != s.file {
		delete(s.fields, key)
		return nil
	}
	if s.fields == nil {
		s.fields = make(map[string]*terraformSourceNode)
	}
	child := newTerraformLocation(r)
	s.fields[key] = child
	return child
}

func (s *terraformSourceNode) item(r hcl.Range) *terraformSourceNode {
	if s == nil {
		return nil
	}
	var child *terraformSourceNode
	if r.Filename == s.file {
		child = newTerraformLocation(r)
	}
	s.items = append(s.items, child)
	return child
}

// Only literal containers have a source position for each child. A computed
// expression still has a position for the attribute that contains it.
func (s *terraformSourceNode) expression(expr hcl.Expression, ctx *hcl.EvalContext) {
	if s == nil || expr.Range().Filename != s.file {
		return
	}
	switch e := unwrapParentheses(expr).(type) {
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			key, diags := item.KeyExpr.Value(ctx)
			if diags.HasErrors() || !key.IsKnown() || key.IsNull() || key.Type() != cty.String {
				continue
			}
			s.field(key.AsString(), item.KeyExpr.Range()).expression(item.ValueExpr, ctx)
		}
	case *hclsyntax.TupleConsExpr:
		for _, elem := range e.Exprs {
			s.item(elem.Range()).expression(elem, ctx)
		}
	}
}

// terraformManifest is a Kubernetes object converted from a Terraform
// resource block, with the source range of that block.
type terraformManifest struct {
	object map[string]interface{}
	source *terraformSourceNode
}

func terraformManifestObjects(manifests []terraformManifest) []map[string]interface{} {
	if manifests == nil {
		return nil
	}
	objects := make([]map[string]interface{}, len(manifests))
	for i, m := range manifests {
		objects[i] = m.object
	}
	return objects
}

func terraformWorkloadPath(file string, index int) string {
	return fmt.Sprintf("%s:%d", file, index)
}

// SourceLocations returns the resource and field locations from the last
// GetWorkloads call, keyed by workload path ("<file>:<index>").
func (td *TerraformDirectory) SourceLocations() map[string]SourceLocation {
	return td.sourceLocations
}
