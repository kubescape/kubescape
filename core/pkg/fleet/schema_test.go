package fleet

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var schemaPath = filepath.Join("..", "..", "..", "docs", "fleet-report.schema.json")

// schemaObject is the part of a schema definition that the Go types decide.
type schemaObject struct {
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
	Enum       []string                   `json:"enum"`
}

// readSchema returns the published schema's root object and its definitions.
func readSchema(t *testing.T) (schemaObject, map[string]schemaObject) {
	t.Helper()
	contents, err := os.ReadFile(schemaPath)
	require.NoError(t, err)
	var root schemaObject
	require.NoError(t, json.Unmarshal(contents, &root))
	var document struct {
		Defs map[string]schemaObject `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(contents, &document))
	return root, document.Defs
}

// jsonFields returns a struct's JSON field names and which of them are always written.
func jsonFields(typ reflect.Type) (names, required []string) {
	for i := range typ.NumField() {
		name, options, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
		if !strings.Contains(options, "omitempty") {
			required = append(required, name)
		}
	}
	return names, required
}

// assertMatchesType fails when a schema object and a Go struct disagree on the fields or on which are required.
func assertMatchesType(t *testing.T, object schemaObject, typ reflect.Type) {
	t.Helper()
	names, required := jsonFields(typ)
	assert.ElementsMatch(t, names, slices.Collect(maps.Keys(object.Properties)), "properties of %s", typ.Name())
	assert.ElementsMatch(t, required, object.Required, "required fields of %s", typ.Name())
}

// TestSchemaMatchesTheGoTypes pins that a field added to or removed from a report type has to be added to or removed from the schema.
func TestSchemaMatchesTheGoTypes(t *testing.T) {
	root, defs := readSchema(t)
	assertMatchesType(t, root, reflect.TypeFor[FleetReport]())

	types := map[string]reflect.Type{
		"FleetMetadata":      reflect.TypeFor[FleetMetadata](),
		"ClusterResult":      reflect.TypeFor[ClusterResult](),
		"ComplianceRollup":   reflect.TypeFor[ComplianceRollup](),
		"FrameworkRollup":    reflect.TypeFor[FrameworkRollup](),
		"ExcludedCluster":    reflect.TypeFor[ExcludedCluster](),
		"FleetControlMatrix": reflect.TypeFor[FleetControlMatrix](),
		"FleetControlRow":    reflect.TypeFor[FleetControlRow](),
		"ControlStatusCell":  reflect.TypeFor[ControlStatusCell](),
		"FleetDivergence":    reflect.TypeFor[FleetDivergence](),
		"ControlDivergence":  reflect.TypeFor[ControlDivergence](),
	}
	for name, typ := range types {
		object, ok := defs[name]
		require.True(t, ok, "%s is missing from the schema", name)
		assertMatchesType(t, object, typ)
	}
}

// TestSchemaListsEveryStatus pins the values the report's status fields can take.
func TestSchemaListsEveryStatus(t *testing.T) {
	_, defs := readSchema(t)

	assert.ElementsMatch(t, []string{string(ClusterScanned), string(ClusterUnreachable), string(ClusterError), string(ClusterCancelled)}, defs["ClusterScanStatus"].Enum)
	assert.ElementsMatch(t, []string{string(CellPassed), string(CellFailed), string(CellSkipped), string(CellNotEvaluated)}, defs["CellStatus"].Enum)
	assert.ElementsMatch(t, []string{string(ExcludedNotScanned), string(ExcludedNotScored), string(ExcludedLowCoverage)}, defs["ExclusionReason"].Enum)
}

// validateAgainstSchema checks a report document against the published schema.
func validateAgainstSchema(t *testing.T, report []byte) error {
	t.Helper()
	contents, err := os.ReadFile(schemaPath)
	require.NoError(t, err)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(contents))
	require.NoError(t, err)
	compiler := jsonschema.NewCompiler()
	require.NoError(t, compiler.AddResource("fleet-report.schema.json", document))
	schema, err := compiler.Compile("fleet-report.schema.json")
	require.NoError(t, err)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(report))
	require.NoError(t, err)
	return schema.Validate(instance)
}

// TestSchemaAcceptsFieldsTheGoldenLeavesOut pins the two optional fields the golden report never writes.
func TestSchemaAcceptsFieldsTheGoldenLeavesOut(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "fleetreport_golden.json"))
	require.NoError(t, err)
	var report FleetReport
	require.NoError(t, json.Unmarshal(golden, &report))
	report.Clusters[0].Attempts = 2
	report.Divergence = BuildDivergence(report.ControlMatrix, "not-in-the-matrix")
	require.True(t, report.Divergence.ReferenceUnavailable)

	contents, err := json.Marshal(report)
	require.NoError(t, err)
	assert.NoError(t, validateAgainstSchema(t, contents))
}

// TestSchemaValidatesReports pins what the schema accepts and rejects, starting from the golden report.
func TestSchemaValidatesReports(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "fleetreport_golden.json"))
	require.NoError(t, err)
	require.NoError(t, validateAgainstSchema(t, golden))

	tests := map[string]struct {
		change func(report map[string]any)
		valid  bool
	}{
		"an unknown field, so new fields stay compatible": {change: func(report map[string]any) { report["addedLater"] = true }, valid: true},
		"no metadata":    {change: func(report map[string]any) { delete(report, "metadata") }},
		"no clusters":    {change: func(report map[string]any) { delete(report, "clusters") }},
		"unknown status": {change: func(report map[string]any) { report["clusters"].([]any)[0].(map[string]any)["status"] = "failed" }},
		"a score that is not a number": {change: func(report map[string]any) {
			report["clusters"].([]any)[0].(map[string]any)["complianceScore"] = "72"
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var report map[string]any
			require.NoError(t, json.Unmarshal(golden, &report))
			tt.change(report)
			changed, err := json.Marshal(report)
			require.NoError(t, err)

			err = validateAgainstSchema(t, changed)

			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
