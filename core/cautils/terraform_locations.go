package cautils

import (
	"fmt"
	"sync"

	"github.com/hashicorp/hcl/v2"
)

// SourceLocation is a 1-based line and column in a source file.
type SourceLocation struct {
	Line   int
	Column int
}

// terraformSourceLocations maps a Terraform workload's path ("<file>:<index>",
// as set by TerraformDirectory.GetWorkloads) to the start of the resource
// block it was converted from. Terraform files have no YAML node tree, so the
// printers can't resolve a finding's location the way they do for manifests.
var terraformSourceLocations sync.Map

// terraformManifest is a Kubernetes object converted from a Terraform
// resource block, with the source range of that block.
type terraformManifest struct {
	object map[string]interface{}
	source hcl.Range
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

func recordTerraformSourceLocation(workloadPath string, source hcl.Range) {
	if source.Start.Line <= 0 {
		terraformSourceLocations.Delete(workloadPath)
		return
	}
	terraformSourceLocations.Store(workloadPath, SourceLocation{Line: source.Start.Line, Column: source.Start.Column})
}

// TerraformSourceLocation returns the start of the Terraform resource block a
// workload was converted from, given the workload's path. It reports false
// for workloads that didn't come from a Terraform file.
func TerraformSourceLocation(workloadPath string) (SourceLocation, bool) {
	v, ok := terraformSourceLocations.Load(workloadPath)
	if !ok {
		return SourceLocation{}, false
	}
	return v.(SourceLocation), true
}
