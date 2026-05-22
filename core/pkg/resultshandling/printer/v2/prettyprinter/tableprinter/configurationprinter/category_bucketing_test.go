package configurationprinter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// failedCtrl is a tiny helper that returns a ControlSummary that the rendering
// code will treat as a failing control belonging to the given category /
// sub-category.
func failedCtrl(id, name, catID, catName, subCatID, subCatName string) reportsummary.ControlSummary {
	cat := &reporthandling.Category{ID: catID, Name: catName}
	if subCatID != "" {
		cat.SubCategory = &reporthandling.SubCategory{ID: subCatID, Name: subCatName}
	}
	return reportsummary.ControlSummary{
		ControlID: id,
		Name:      name,
		Status:    apis.StatusFailed,
		StatusCounters: reportsummary.StatusCounters{
			FailedResources: 1,
		},
		Category: cat,
	}
}

func TestBucketControlsByCategory_UsesControlOwnCategory(t *testing.T) {
	// Two controls whose IDs are NOT in any legacy hardcoded allowlist; the
	// previous implementation dropped both. They carry valid category metadata
	// so the new bucketing function must surface them.
	c270 := failedCtrl("C-0270", "Ensure CPU limits are set", "Cat-5", "Workload", "Cat-7", "Resource management")
	c260 := failedCtrl("C-0260", "Missing network policy", "Cat-4", "Network", "", "")
	sd := reportsummary.SummaryDetails{
		Controls: map[string]reportsummary.ControlSummary{
			"C-0270": c270,
			"C-0260": c260,
		},
	}

	got := bucketControlsByCategory(sd.ListControls())

	if _, ok := got["Cat-7"]; !ok {
		t.Errorf("expected sub-category Cat-7 (resource management) to be bucketed, got keys: %v", keys(got))
	}
	if _, ok := got["Cat-4"]; !ok {
		t.Errorf("expected top-level Cat-4 (network) to be bucketed, got keys: %v", keys(got))
	}
	if got["Cat-7"].CategoryName != "Resource management" {
		t.Errorf("expected sub-category name to be used, got %q", got["Cat-7"].CategoryName)
	}
}

func TestBucketControlsByCategory_NilCategorySkipped(t *testing.T) {
	sd := reportsummary.SummaryDetails{
		Controls: map[string]reportsummary.ControlSummary{
			"C-1": {ControlID: "C-1", Status: apis.StatusFailed},
		},
	}
	got := bucketControlsByCategory(sd.ListControls())
	if len(got) != 0 {
		t.Errorf("expected nil-category controls to be skipped, got %v", got)
	}
}

func TestCategoryRenderOrder_PreservesPreferredAndAppendsExtras(t *testing.T) {
	categories := map[string]CategoryControls{
		"Cat-1":   {},
		"Cat-99":  {},
		"Cat-2":   {},
		"Cat-3":   {},
		"Cat-XYZ": {},
	}
	got := categoryRenderOrder([]string{"Cat-1", "Cat-2", "Cat-3"}, categories)
	want := []string{"Cat-1", "Cat-2", "Cat-3", "Cat-99", "Cat-XYZ"}
	if !equalStrings(got, want) {
		t.Errorf("expected order %v, got %v", want, got)
	}
}

func TestCategoryRenderOrder_SkipsMissingPreferred(t *testing.T) {
	categories := map[string]CategoryControls{
		"Cat-2": {},
		"Cat-7": {},
	}
	got := categoryRenderOrder([]string{"Cat-1", "Cat-2", "Cat-3"}, categories)
	want := []string{"Cat-2", "Cat-7"}
	if !equalStrings(got, want) {
		t.Errorf("expected order %v, got %v", want, got)
	}
}

// End-to-end-ish: render the repo printer against a SummaryDetails that
// reproduces the bug scenario (C-0270 in resource-management, an upstream
// addition past the August-2023 allowlist) and assert the rendered output
// includes the control. Before the fix this fails because the control is
// silently dropped at the rendering layer.
func TestRepoPrinter_RendersControlsBeyondLegacyAllowlist(t *testing.T) {
	ctrls := map[string]reportsummary.ControlSummary{
		"C-0270": failedCtrl("C-0270", "Ensure CPU limits are set", "Cat-5", "Workload", "Cat-7", "Resource management"),
		"C-0260": failedCtrl("C-0260", "Missing network policy", "Cat-4", "Network", "", ""),
		"C-0013": failedCtrl("C-0013", "Non-root containers", "Cat-5", "Workload", "", ""),
	}
	sd := &reportsummary.SummaryDetails{Controls: ctrls}

	var buf bytes.Buffer
	NewRepoPrinter([]string{"/tmp/chart-test"}).PrintCategoriesTables(&buf, sd, nil)
	out := buf.String()

	for _, want := range []string{
		"Ensure CPU limits are set", // C-0270, was previously dropped
		"Missing network policy",    // C-0260
		"Non-root containers",       // C-0013, was already in the legacy allowlist
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected rendered output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestWorkloadPrinter_RendersControlsBeyondLegacyAllowlist(t *testing.T) {
	ctrls := map[string]reportsummary.ControlSummary{
		"C-0270": failedCtrl("C-0270", "Ensure CPU limits are set", "Cat-5", "Workload", "Cat-7", "Resource management"),
		"C-0271": failedCtrl("C-0271", "Ensure memory limits are set", "Cat-5", "Workload", "Cat-7", "Resource management"),
	}
	sd := &reportsummary.SummaryDetails{Controls: ctrls}

	var buf bytes.Buffer
	NewWorkloadPrinter().PrintCategoriesTables(&buf, sd, nil)
	out := buf.String()

	for _, want := range []string{"Ensure CPU limits are set", "Ensure memory limits are set"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected rendered output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestClusterPrinter_RendersControlsInUnknownCategory(t *testing.T) {
	// A control sitting in a brand-new category that isn't part of any
	// preferred-order list. It must still surface in the output.
	ctrls := map[string]reportsummary.ControlSummary{
		"C-9999": failedCtrl("C-9999", "Brand new control", "Cat-NEW", "New category", "", ""),
	}
	sd := &reportsummary.SummaryDetails{Controls: ctrls}

	var buf bytes.Buffer
	NewClusterPrinter().PrintCategoriesTables(&buf, sd, nil)
	out := buf.String()

	if !strings.Contains(out, "Brand new control") {
		t.Errorf("expected unknown-category control to be rendered, got:\n%s", out)
	}
}

func keys(m map[string]CategoryControls) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
