package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempReport(t *testing.T, r scanReport) string {
	t.Helper()
	data, err := json.Marshal(r)
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "report-*.json")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func makeReport(entries ...resultEntry) scanReport {
	return scanReport{Results: entries}
}

func makeResult(resourceID string, controls ...controlEntry) resultEntry {
	return resultEntry{ResourceID: resourceID, AssociatedControls: controls}
}

func makeControl(id, name, status, severity string) controlEntry {
	return controlEntry{ControlID: id, Name: name, Status: statusInfo{InnerStatus: status}, Severity: severity}
}

func TestCompute_NewFailure(t *testing.T) {
	base := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "passed", "High")))
	head := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed", "High")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Len(t, cs.New, 1)
	assert.Empty(t, cs.Resolved)
	assert.Empty(t, cs.Unchanged)
	assert.Equal(t, "C-001", cs.New[0].ControlID)
	assert.Equal(t, "High", cs.New[0].Severity)
}

func TestCompute_Resolved(t *testing.T) {
	base := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed", "Medium")))
	head := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "passed", "Medium")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Empty(t, cs.New)
	assert.Len(t, cs.Resolved, 1)
	assert.Empty(t, cs.Unchanged)
}

func TestCompute_Unchanged(t *testing.T) {
	base := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed", "Low")))
	head := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed", "Low")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Empty(t, cs.New)
	assert.Empty(t, cs.Resolved)
	assert.Len(t, cs.Unchanged, 1)
}

func TestCompute_NewResourceInHead(t *testing.T) {
	// resource not in base at all but failing in head
	base := makeReport()
	head := makeReport(makeResult("res-new", makeControl("C-002", "Control 2", "failed", "Critical")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Len(t, cs.New, 1)
	assert.Equal(t, "res-new", cs.New[0].ResourceID)
}

func TestCompute_RemovedResourceFromBase(t *testing.T) {
	// resource was failing in base but absent in head
	base := makeReport(makeResult("res-old", makeControl("C-001", "Control 1", "failed", "High")))
	head := makeReport()

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Empty(t, cs.New)
	assert.Len(t, cs.Resolved, 1)
	assert.Equal(t, "absent", cs.Resolved[0].HeadStatus)
}

func TestCompute_MissingFile(t *testing.T) {
	_, err := Compute(filepath.Join(t.TempDir(), "missing.json"), filepath.Join(t.TempDir(), "also-missing.json"))
	assert.Error(t, err)
}

func TestFilterBySeverity(t *testing.T) {
	changes := []ControlChange{
		{ControlID: "C-001", Severity: "Critical"},
		{ControlID: "C-002", Severity: "High"},
		{ControlID: "C-003", Severity: "Medium"},
		{ControlID: "C-004", Severity: "Low"},
	}

	result := FilterBySeverity(changes, "High")
	assert.Len(t, result, 2)
	assert.Equal(t, "Critical", result[0].Severity)
	assert.Equal(t, "High", result[1].Severity)

	result = FilterBySeverity(changes, "")
	assert.Len(t, result, 4)

	result = FilterBySeverity(changes, "Critical")
	assert.Len(t, result, 1)
}
