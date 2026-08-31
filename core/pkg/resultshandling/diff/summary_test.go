package diff

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestSummarizeCountsBucketsAndWarnings(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0001", "Forbidden registries", "high"),
			change("pod-b", "C-0002", "Privileged containers", "critical"),
		},
		Resolved: []ControlChange{
			change("pod-a", "C-0003", "HostPath mount", "medium"),
		},
		Unchanged: []ControlChange{
			change("pod-c", "C-0004", "Capabilities", "low"),
		},
		Incomparable: []ControlChange{
			change("pod-d", "C-0005", "Network policy", "medium"),
		},
		Warnings: []string{"scope changed"},
	}

	got := Summarize(cs, "")

	assert.Equal(t, BucketSummary{New: 2, Resolved: 1, Unchanged: 1, Incomparable: 1, Warnings: 1}, got.Total)
	assert.Equal(t, BucketSummary{New: 2, Incomparable: 1, Warnings: 1}, got.Regressions)
	assert.Equal(t, "all", got.Threshold)
	assert.Equal(t, []string{"scope changed"}, got.Warnings)
	assert.Equal(t, 2, got.Buckets["new"].Count)
	assert.Equal(t, 1, got.Buckets["resolved"].Count)
	assert.Equal(t, 1, got.Buckets["unchanged"].Count)
	assert.Equal(t, 1, got.Buckets["incomparable"].Count)
}

func TestSummarizeSeverityBreakdownsAreDeterministic(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0001", "High one", "high"),
			change("pod-b", "C-0002", "Critical one", "critical"),
			change("pod-c", "C-0003", "Unknown one", ""),
			change("pod-d", "C-0004", "Low one", "low"),
			change("pod-e", "C-0005", "Medium one", "medium"),
		},
	}

	got := Summarize(cs, "")

	assert.Equal(t, []SeverityCounter{
		{Severity: "critical", Count: 1},
		{Severity: "high", Count: 1},
		{Severity: "medium", Count: 1},
		{Severity: "low", Count: 1},
		{Severity: "unknown", Count: 1},
	}, got.Buckets["new"].Severities)
	assert.Equal(t, []SeveritySummary{
		{Severity: "critical", Buckets: BucketSummary{New: 1}},
		{Severity: "high", Buckets: BucketSummary{New: 1}},
		{Severity: "medium", Buckets: BucketSummary{New: 1}},
		{Severity: "low", Buckets: BucketSummary{New: 1}},
		{Severity: "unknown", Buckets: BucketSummary{New: 1}},
	}, got.Severities)
}

func TestSummarizeControlAndResourceBreakdowns(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0002", "Privileged containers", "critical"),
			change("pod-a", "C-0002", "Privileged containers", "critical"),
			change("pod-b", "C-0001", "Forbidden registries", "high"),
		},
		Incomparable: []ControlChange{
			change("pod-b", "C-0001", "Forbidden registries", "high"),
			change("pod-c", "C-0003", "HostPath mount", "medium"),
		},
	}

	got := Summarize(cs, "")

	assert.Equal(t, []ControlSummary{
		{
			ControlID:   "C-0001",
			ControlName: "Forbidden registries",
			Severity:    "high",
			Buckets:     BucketSummary{New: 1, Incomparable: 1},
		},
		{
			ControlID:   "C-0002",
			ControlName: "Privileged containers",
			Severity:    "critical",
			Buckets:     BucketSummary{New: 2},
		},
		{
			ControlID:   "C-0003",
			ControlName: "HostPath mount",
			Severity:    "medium",
			Buckets:     BucketSummary{Incomparable: 1},
		},
	}, got.Controls)
	assert.Equal(t, []ResourceSummary{
		{ResourceID: "pod-a", Buckets: BucketSummary{New: 2}},
		{ResourceID: "pod-b", Buckets: BucketSummary{New: 1, Incomparable: 1}},
		{ResourceID: "pod-c", Buckets: BucketSummary{Incomparable: 1}},
	}, got.Resources)
	assert.Equal(t, []ControlCounter{
		{ControlID: "C-0001", ControlName: "Forbidden registries", Severity: "high", Count: 1},
		{ControlID: "C-0002", ControlName: "Privileged containers", Severity: "critical", Count: 2},
	}, got.Buckets["new"].Controls)
	assert.Equal(t, []ResourceCounter{
		{ResourceID: "pod-a", Count: 2},
		{ResourceID: "pod-b", Count: 1},
	}, got.Buckets["new"].Resources)
	assert.Equal(t, []ControlCounter{
		{ControlID: "C-0002", ControlName: "Privileged containers", Severity: "critical", Count: 2},
		{ControlID: "C-0001", ControlName: "Forbidden registries", Severity: "high", Count: 2},
		{ControlID: "C-0003", ControlName: "HostPath mount", Severity: "medium", Count: 1},
	}, got.TopControls)
	assert.Equal(t, []ResourceCounter{
		{ResourceID: "pod-a", Count: 2},
		{ResourceID: "pod-b", Count: 2},
		{ResourceID: "pod-c", Count: 1},
	}, got.TopResources)
}

func TestSummarizeAppliesThresholdToRegressionBucketsOnly(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0001", "Low", "low"),
			change("pod-b", "C-0002", "Medium", "medium"),
			change("pod-c", "C-0003", "High", "high"),
			change("pod-d", "C-0004", "Unknown", ""),
		},
		Resolved: []ControlChange{
			change("pod-e", "C-0005", "Low resolved", "low"),
		},
		Unchanged: []ControlChange{
			change("pod-f", "C-0006", "Low unchanged", "low"),
		},
		Incomparable: []ControlChange{
			change("pod-g", "C-0007", "Medium incomparable", "medium"),
			change("pod-h", "C-0008", "Critical incomparable", "critical"),
		},
	}

	got := Summarize(cs, "high")

	assert.Equal(t, "high", got.Threshold)
	assert.Equal(t, BucketSummary{New: 2, Resolved: 1, Unchanged: 1, Incomparable: 1}, got.Total)
	assert.Equal(t, BucketSummary{New: 2, Incomparable: 1}, got.Regressions)
	assert.Equal(t, 2, got.Buckets["new"].Count)
	assert.Equal(t, []ControlCounter{
		{ControlID: "C-0003", ControlName: "High", Severity: "high", Count: 1},
		{ControlID: "C-0004", ControlName: "Unknown", Count: 1},
	}, got.Buckets["new"].Controls)
	assert.Equal(t, 1, got.Buckets["resolved"].Count)
	assert.Equal(t, 1, got.Buckets["unchanged"].Count)
	assert.Equal(t, 1, got.Buckets["incomparable"].Count)
	assert.Equal(t, []ControlCounter{
		{ControlID: "C-0008", ControlName: "Critical incomparable", Severity: "critical", Count: 1},
		{ControlID: "C-0003", ControlName: "High", Severity: "high", Count: 1},
		{ControlID: "C-0004", ControlName: "Unknown", Count: 1},
	}, got.TopControls)
}

func TestTopRegressionControlsSortByCountSeverityAndID(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0003", "Medium two", "medium"),
			change("pod-b", "C-0003", "Medium two", "medium"),
			change("pod-c", "C-0001", "Critical two", "critical"),
			change("pod-d", "C-0001", "Critical two", "critical"),
			change("pod-e", "C-0002", "High one", "high"),
			change("pod-f", "C-0004", "Unknown one", ""),
		},
		Incomparable: []ControlChange{
			change("pod-g", "C-0002", "High one", "high"),
		},
		Resolved: []ControlChange{
			change("pod-h", "C-0005", "Resolved is not regression", "critical"),
		},
	}

	got := Summarize(cs, "")

	assert.Equal(t, []ControlCounter{
		{ControlID: "C-0001", ControlName: "Critical two", Severity: "critical", Count: 2},
		{ControlID: "C-0002", ControlName: "High one", Severity: "high", Count: 2},
		{ControlID: "C-0003", ControlName: "Medium two", Severity: "medium", Count: 2},
		{ControlID: "C-0004", ControlName: "Unknown one", Count: 1},
	}, got.TopControls)
}

func TestTopRegressionResourcesSortByCountAndID(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-b", "C-0001", "One", "high"),
			change("pod-b", "C-0002", "Two", "high"),
			change("pod-a", "C-0003", "Three", "high"),
		},
		Incomparable: []ControlChange{
			change("pod-a", "C-0004", "Four", "high"),
			change("pod-c", "C-0005", "Five", "high"),
		},
		Resolved: []ControlChange{
			change("pod-z", "C-0006", "Resolved is not regression", "high"),
		},
	}

	got := Summarize(cs, "")

	assert.Equal(t, []ResourceCounter{
		{ResourceID: "pod-a", Count: 2},
		{ResourceID: "pod-b", Count: 2},
		{ResourceID: "pod-c", Count: 1},
	}, got.TopResources)
}

func TestSummarizeNilAndEmptyChangeSets(t *testing.T) {
	nilSummary := Summarize(nil, "")
	emptySummary := Summarize(&ChangeSet{}, "")

	assert.Equal(t, BucketSummary{}, nilSummary.Total)
	assert.Equal(t, BucketSummary{}, emptySummary.Total)
	assert.Equal(t, "all", nilSummary.Threshold)
	assert.Equal(t, "all", emptySummary.Threshold)
	assert.Equal(t, 0, nilSummary.Buckets["new"].Count)
	assert.Equal(t, 0, emptySummary.Buckets["new"].Count)
	assert.Empty(t, nilSummary.Severities)
	assert.Empty(t, emptySummary.Severities)
}

func TestPrintSummaryJSON(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0001", "Forbidden registries", "high"),
		},
		Warnings: []string{"coverage changed"},
	}
	var out bytes.Buffer

	require.NoError(t, PrintSummaryJSON(&out, cs, "medium"))

	var decoded Summary
	require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
	assert.Equal(t, "medium", decoded.Threshold)
	assert.Equal(t, BucketSummary{New: 1, Warnings: 1}, decoded.Total)
	assert.Equal(t, []string{"coverage changed"}, decoded.Warnings)
	assert.Contains(t, out.String(), "\n  \"total\":")
}

func TestPrintSummaryYAML(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0001", "Forbidden registries", "high"),
		},
		Incomparable: []ControlChange{
			change("pod-b", "C-0002", "Privileged containers", "critical"),
		},
	}
	var out bytes.Buffer

	require.NoError(t, PrintSummaryYAML(&out, cs, "high"))

	var decoded Summary
	require.NoError(t, yaml.Unmarshal(out.Bytes(), &decoded))
	assert.Equal(t, "high", decoded.Threshold)
	assert.Equal(t, BucketSummary{New: 1, Incomparable: 1}, decoded.Total)
	assert.Contains(t, out.String(), "regressions:")
	assert.Contains(t, out.String(), "controls:")
}

func TestPrintSummaryCSV(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			change("pod-a", "C-0001", "Forbidden registries", "high"),
			change("pod-a", "C-0001", "Forbidden registries", "high"),
		},
		Resolved: []ControlChange{
			change("pod-b", "C-0002", "Privileged containers", "critical"),
		},
		Warnings: []string{"coverage changed"},
	}
	var out bytes.Buffer

	require.NoError(t, PrintSummaryCSV(&out, cs, "medium"))

	records, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Equal(t, []string{"section", "key", "bucket", "severity", "control_id", "control_name", "resource_id", "count"}, records[0])
	assert.Contains(t, records, []string{"metadata", "threshold", "", "", "", "", "", "medium"})
	assert.Contains(t, records, []string{"metadata", "warnings", "", "", "", "", "", "1"})
	assert.Contains(t, records, []string{"total", "all", "new", "", "", "", "", "2"})
	assert.Contains(t, records, []string{"total", "all", "resolved", "", "", "", "", "1"})
	assert.Contains(t, records, []string{"bucket_control", "", "new", "high", "C-0001", "Forbidden registries", "", "2"})
	assert.Contains(t, records, []string{"bucket_resource", "", "new", "", "", "", "pod-a", "2"})
	assert.Contains(t, records, []string{"top_control", "", "regressions", "high", "C-0001", "Forbidden registries", "", "2"})
	assert.Contains(t, records, []string{"top_resource", "", "regressions", "", "", "", "pod-a", "2"})
	assert.Contains(t, records, []string{"warning", "coverage changed", "", "", "", "", "", ""})
}

func TestSummaryCSVRowsIncludeEmptyBuckets(t *testing.T) {
	rows := summaryCSVRows(Summarize(&ChangeSet{}, ""))

	assert.Contains(t, rows, []string{"bucket", "total", "new", "", "", "", "", "0"})
	assert.Contains(t, rows, []string{"bucket", "total", "resolved", "", "", "", "", "0"})
	assert.Contains(t, rows, []string{"bucket", "total", "unchanged", "", "", "", "", "0"})
	assert.Contains(t, rows, []string{"bucket", "total", "incomparable", "", "", "", "", "0"})
}

func TestSummaryCSVHandlesCommasPipesAndNewlines(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID:  "Deployment/default/api,canary",
				ControlID:   "C-PIPE",
				ControlName: "Name with | pipe\nand newline",
				Severity:    "high",
			},
		},
		Warnings: []string{"warning, with comma\nand newline"},
	}
	var out bytes.Buffer

	require.NoError(t, PrintSummaryCSV(&out, cs, ""))

	records, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	require.NoError(t, err)
	assert.Contains(t, records, []string{"bucket_control", "", "new", "high", "C-PIPE", "Name with | pipe\nand newline", "", "1"})
	assert.Contains(t, records, []string{"bucket_resource", "", "new", "", "", "", "Deployment/default/api,canary", "1"})
	assert.Contains(t, records, []string{"warning", "warning, with comma\nand newline", "", "", "", "", "", ""})
}

func TestSummarizeNormalizesMissingLabels(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			{ResourceID: " ", ControlID: "", ControlName: "Missing identifiers", Severity: ""},
		},
	}

	got := Summarize(cs, "")

	assert.Equal(t, []SeveritySummary{{Severity: "unknown", Buckets: BucketSummary{New: 1}}}, got.Severities)
	assert.Equal(t, []ControlSummary{{ControlID: "unknown", ControlName: "Missing identifiers", Buckets: BucketSummary{New: 1}}}, got.Controls)
	assert.Equal(t, []ResourceSummary{{ResourceID: "unknown", Buckets: BucketSummary{New: 1}}}, got.Resources)
	assert.Equal(t, []ControlCounter{{ControlID: "unknown", ControlName: "Missing identifiers", Count: 1}}, got.TopControls)
	assert.Equal(t, []ResourceCounter{{ResourceID: "unknown", Count: 1}}, got.TopResources)
}

func change(resourceID, controlID, controlName, severity string) ControlChange {
	return ControlChange{
		ResourceID:   resourceID,
		ControlID:    controlID,
		ControlName:  controlName,
		Severity:     severity,
		BaseStatus:   "passed",
		HeadStatus:   "failed",
		RuleName:     "rule",
		EvidenceType: "path",
		Path:         "/spec/containers/0/securityContext",
	}
}
