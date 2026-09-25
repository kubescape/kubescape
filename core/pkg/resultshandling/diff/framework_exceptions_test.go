package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameworkScopedExceptions(t *testing.T) {
	tests := []struct {
		name, frameworks, policies string
		mixed                      bool
		want                       string
	}{
		{"single framework", `{"name":"NSA","controls":{"C-0034":{}}}`, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}`, false, "passed"},
		{"partial coverage", `{"name":"NSA","controls":{"C-0034":{}}},{"name":"MITRE","controls":{"C-0034":{}}}`, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}`, false, "failed"},
		{"global", `{"name":"NSA","controls":{"C-0034":{}}},{"name":"MITRE","controls":{"C-0034":{}}}`, `{"controlID":"C-0034","ruleName":"R1"}`, false, "passed"},
		{"unrelated framework", `{"name":"NSA","controls":{"C-0034":{}}},{"name":"MITRE","controls":{"C-0286":{}}}`, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}`, false, "passed"},
		{"mixed rules", `{"name":"NSA","controls":{"C-0034":{}}}`, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}`, true, "failed"},
		{"correlated tuples", `{"name":"MITRE","controls":{"C-0034":{}}}`, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"},{"frameworkName":"MITRE","controlID":"C-0034","ruleName":"R2"}`, false, "failed"},
		{"unnamed framework", `{"name":"","controls":{"C-0034":{}}}`, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}`, false, "failed"},
		{"no framework context", ``, `{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}`, false, "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extra := ""
			if tt.mixed {
				extra = `,{"name":"R2","status":"failed"}`
			}
			data := fmt.Sprintf(`{"results":[{"resourceID":"pod","controls":[{"controlID":"C-0034","status":{"status":"failed"},"rules":[{"name":"R1","status":"failed","exception":[{"actions":["disable"],"posturePolicies":[%s]}]}%s]}]}],"summaryDetails":{"controls":{"C-0034":{}},"frameworks":[%s]}}`, tt.policies, extra, tt.frameworks)
			path := filepath.Join(t.TempDir(), "report.json")
			require.NoError(t, os.WriteFile(path, []byte(data), 0600))
			report, err := loadReport(path)
			require.NoError(t, err)
			control := buildMap(report)[key{resourceID: "pod", controlID: "C-0034"}]
			assert.Equal(t, tt.want, control.Status.InnerStatus)
			if tt.want == "passed" {
				assert.Equal(t, "w/exceptions", control.Status.SubStatus)
			}
			if tt.mixed {
				findings := findingsForControl(key{resourceID: "pod", controlID: "C-0034"}, control, "High", GranularityEvidence)
				require.Len(t, findings, 1)
				assert.Equal(t, "R2", findings[0].fingerprint.ruleName)
			}
			assert.Equal(t, "failed", report.Results[0].AssociatedControls[0].Rules[0].Status, "view must preserve raw evaluation")
			changes, err := Compute(path, path)
			require.NoError(t, err)
			if tt.want == "passed" {
				assert.Empty(t, changes.Unchanged)
			} else {
				require.Len(t, changes.Unchanged, 1)
			}

		})
	}
}

func TestFrameworkScopedExceptionsLegacyWithoutRules(t *testing.T) {
	report := &scanReport{Results: []resultEntry{{ResourceID: "pod", AssociatedControls: []controlEntry{{ControlID: "C-0034", Status: statusInfo{InnerStatus: "skipped", SubStatus: "manualReview"}}}}}}
	assert.Equal(t, report.Results[0].AssociatedControls[0], buildMap(report)[key{resourceID: "pod", controlID: "C-0034"}])
}

func TestFrameworkScopedExceptionsLegacyDiscardedFailure(t *testing.T) {
	// An old report may have already replaced the raw failed rule with passed.
	// Keep it readable; exception metadata cannot recover the discarded outcome.
	path := writeRawReport(t, `{"results":[{"resourceID":"pod","controls":[{"controlID":"C-0034","status":{"status":"passed","subStatus":"w/exceptions"},"rules":[{"name":"R1","status":"passed","subStatus":"w/exceptions","exception":[{"posturePolicies":[{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}]}]}]}]}],"summaryDetails":{"controls":{"C-0034":{}},"frameworks":[{"name":"MITRE","controls":{"C-0034":{}}}]}}`)
	changes, err := Compute(path, path)
	require.NoError(t, err)
	assert.Empty(t, changes.Unchanged)
}

func TestFrameworkScopedExceptionsPreserveIncompleteEvaluation(t *testing.T) {
	for _, status := range []statusInfo{
		{InnerStatus: "skipped"},
		{InnerStatus: "passed", SubStatus: "notEvaluated"},
		{InnerStatus: "unknown"},
	} {
		t.Run(status.InnerStatus+status.SubStatus, func(t *testing.T) {
			path := writeRawReport(t, fmt.Sprintf(`{"results":[{"resourceID":"pod","controls":[{"controlID":"C-0034","status":{"status":%q,"subStatus":%q},"rules":[{"name":"R1","status":"failed","exception":[{"posturePolicies":[{"frameworkName":"NSA","controlID":"C-0034","ruleName":"R1"}]}]}]}]}],"summaryDetails":{"controls":{"C-0034":{}},"frameworks":[{"name":"NSA","controls":{"C-0034":{}}}]}}`, status.InnerStatus, status.SubStatus))
			report, err := loadReport(path)
			require.NoError(t, err)
			assert.Equal(t, status, buildMap(report)[key{resourceID: "pod", controlID: "C-0034"}].Status)
		})
	}
}
