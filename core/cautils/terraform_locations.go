package cautils

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// SourceLocation is a 1-based line and column in a source file.
type SourceLocation struct {
	Line   int
	Column int
}

// terraformManifest is a Kubernetes object converted from a Terraform
// resource block, with the source range of that block.
type terraformManifest struct {
	object map[string]interface{}
	source hcl.Range
	// incomplete is set when an attribute, count or for_each of the resource
	// could not be resolved, so object is missing what Terraform would set.
	// Such an object is not scanned: a missing field could hide a
	// misconfiguration.
	incomplete bool
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

// recordSourceLocation records the start of the resource block a workload was
// converted from, under the workload's path ("<file>:<index>").
func (td *TerraformDirectory) recordSourceLocation(workloadPath string, source hcl.Range) {
	if source.Start.Line <= 0 {
		return
	}
	if td.sourceLocations == nil {
		td.sourceLocations = map[string]SourceLocation{}
	}
	td.sourceLocations[workloadPath] = SourceLocation{Line: source.Start.Line, Column: source.Start.Column}
}

// SourceLocations returns the start of the Terraform resource block each
// workload of the last GetWorkloads call was converted from, keyed by the
// workload's path ("<file>:<index>"). Terraform files have no YAML node tree,
// so the printers can't resolve a finding's location the way they do for
// manifests. The locations belong to this directory's scan, so scans in the
// same process (e.g. the MCP server) never see or overwrite each other's.
func (td *TerraformDirectory) SourceLocations() map[string]SourceLocation {
	return td.sourceLocations
}
