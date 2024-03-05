package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

func TestAppendFailedPathsIfNotInPaths(t *testing.T) {
	tests := []struct {
		paths         []string
		failedPaths   []string
		expectedPaths []string
	}{
		{
			paths:         []string{"path1", "path2"},
			failedPaths:   []string{"path3", "path1"},
			expectedPaths: []string{"path1", "path2", "path3"},
		},
		{
			paths:         []string{},
			failedPaths:   []string{"path1", "path2"},
			expectedPaths: []string{"path1", "path2"},
		},
		{
			paths:         []string{"path1", "path2"},
			failedPaths:   []string{},
			expectedPaths: []string{"path1", "path2"},
		},
	}

	for _, testcase := range tests {
		updatedPaths := appendFailedPathsIfNotInPaths(testcase.paths, testcase.failedPaths)
		assert.Equal(t, updatedPaths, testcase.expectedPaths)
	}
}

func TestAssistedRemediationPathsToString(t *testing.T) {
	control1 := &resourcesresults.ResourceAssociatedControl{
		ControlID: "control-1",
		Name:      "Control 1",
		Status:    apis.StatusInfo{},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 1",
				Status:    "failed",
				SubStatus: "skipped",
				Paths: []armotypes.PosturePaths{
					{
						FailedPath: "some-path1",
					},
					{
						FailedPath: "random-path1",
					},
				},
			},
		},
	}

	control2 := &resourcesresults.ResourceAssociatedControl{
		ControlID: "control-2",
		Name:      "Control 2",
		Status:    apis.StatusInfo{},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 2",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						FailedPath: "some-path2",
					},
					{
						FailedPath: "random-path2",
					},
				},
			},
		},
	}

	actualPaths := AssistedRemediationPathsToString(control1)
	expectedPaths := []string{"some-path1", "random-path1"}
	assert.Equal(t, expectedPaths, actualPaths)

	actualPaths = AssistedRemediationPathsToString(control2)
	expectedPaths = []string{"some-path2", "random-path2"}
	assert.Equal(t, expectedPaths, actualPaths)
}

func TestReviewPathsToString(t *testing.T) {
	// Create a test case with empty ResourceAssociatedRules
	emptyControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{},
	}

	// Create a test case with one ResourceAssociatedRule and one ReviewPath
	singleRuleControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 1",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						ReviewPath: "review-path1",
					},
				},
			},
		},
	}

	// Create a test case with multiple ResourceAssociatedRules and multiple ReviewPaths
	multipleRulesControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 2",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						ReviewPath: "review-path2",
					},
					{
						ReviewPath: "review-path3",
					},
				},
			},
		},
	}

	// Test case 1: Empty ResourceAssociatedRules
	actualPaths := reviewPathsToString(emptyControl)
	assert.Nil(t, actualPaths)

	// Test case 2: Single ResourceAssociatedRule and one ReviewPath
	expectedPaths := []string{"review-path1"}
	actualPaths = reviewPathsToString(singleRuleControl)
	assert.Equal(t, expectedPaths, actualPaths)

	// Test case 3: Multiple ResourceAssociatedRules and multiple ReviewPaths
	expectedPaths = []string{"review-path2", "review-path3"}
	actualPaths = reviewPathsToString(multipleRulesControl)
	assert.Equal(t, expectedPaths, actualPaths)
}

func TestDeletePathsToString(t *testing.T) {
	// Create a test case with empty ResourceAssociatedRules
	emptyControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{},
	}

	// Create a test case with one ResourceAssociatedRule and one ReviewPath
	singleRuleControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 1",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						DeletePath: "delete-path1",
					},
				},
			},
		},
	}

	// Create a test case with multiple ResourceAssociatedRules and multiple ReviewPaths
	multipleRulesControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 2",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						DeletePath: "delete-path2",
					},
					{
						DeletePath: "delete-path3",
					},
				},
			},
		},
	}

	// Test case 1: Empty ResourceAssociatedRules
	actualPaths := deletePathsToString(emptyControl)
	assert.Nil(t, actualPaths)

	// Test case 2: Single ResourceAssociatedRule and one ReviewPath
	actualPaths = deletePathsToString(singleRuleControl)
	expectedPath := []string{"delete-path1"}
	assert.Equal(t, expectedPath, actualPaths)

	// Test case 3: Multiple ResourceAssociatedRules and multiple ReviewPaths
	actualPaths = deletePathsToString(multipleRulesControl)
	expectedPath = []string{"delete-path2", "delete-path3"}
	assert.Equal(t, expectedPath, actualPaths)
}

func TestFixPathsToString(t *testing.T) {
	// Create a test case with empty ResourceAssociatedRules
	emptyControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{},
	}

	// Create a test case with one ResourceAssociatedRule and one ReviewPath
	singleRuleControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 1",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						FixPath: armotypes.FixPath{
							Path:  "fix-path1",
							Value: "fix-path-value1",
						},
					},
				},
			},
		},
	}

	// Create a test case with multiple ResourceAssociatedRules and multiple ReviewPaths
	multipleRulesControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 2",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						FixPath: armotypes.FixPath{
							Path:  "fix-path2",
							Value: "fix-path-value2",
						},
					},
					{
						FixPath: armotypes.FixPath{
							Path:  "fix-path3",
							Value: "fix-path-value3",
						},
					},
				},
			},
		},
	}

	// Test case 1: Empty ResourceAssociatedRules
	actualPaths := fixPathsToString(emptyControl, false)
	assert.Nil(t, actualPaths)

	// Test case 2: Single ResourceAssociatedRule and one ReviewPath
	actualPaths = fixPathsToString(singleRuleControl, false)
	expectedPath := []string{"fix-path1=fix-path-value1"}
	assert.Equal(t, expectedPath, actualPaths)

	// Test case 3: Multiple ResourceAssociatedRules and multiple ReviewPaths
	actualPaths = fixPathsToString(multipleRulesControl, false)
	expectedPath = []string{"fix-path2=fix-path-value2", "fix-path3=fix-path-value3"}
	assert.Equal(t, expectedPath, actualPaths)
}

func TestFailedPathsToString(t *testing.T) {
	// Create a test case with empty ResourceAssociatedRules
	emptyControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{},
	}

	// Create a test case with one ResourceAssociatedRule and one ReviewPath
	singleRuleControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 1",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						FailedPath: "failed-path1",
					},
				},
			},
		},
	}

	// Create a test case with multiple ResourceAssociatedRules and multiple ReviewPaths
	multipleRulesControl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "Rule 2",
				Status:    "success",
				SubStatus: "passed",
				Paths: []armotypes.PosturePaths{
					{
						FailedPath: "failed-path2",
					},
					{
						FailedPath: "failed-path3",
					},
				},
			},
		},
	}

	// Test case 1: Empty ResourceAssociatedRules
	actualPaths := failedPathsToString(emptyControl)
	assert.Nil(t, actualPaths)

	// Test case 2: Single ResourceAssociatedRule and one ReviewPath
	actualPaths = failedPathsToString(singleRuleControl)
	expectedPath := []string{"failed-path1"}
	assert.Equal(t, expectedPath, actualPaths)

	// Test case 3: Multiple ResourceAssociatedRules and multiple ReviewPaths
	actualPaths = failedPathsToString(multipleRulesControl)
	expectedPath = []string{"failed-path2", "failed-path3"}
	assert.Equal(t, expectedPath, actualPaths)
}

func TestShortFormatResource(t *testing.T) {
	// Create a test case with an empty resourceRows slice
	emptyResourceRows := [][]string{}

	// Create a test case with a single resource row
	singleResourceRow := [][]string{
		{"High", "Control1", "https://example.com/doc1", "Path1"},
	}

	// Create a test case with multiple resource rows
	multipleResourceRows := [][]string{
		{"Medium", "Control2", "https://example.com/doc2", "Path2"},
		{"Low", "Control3", "https://example.com/doc3", "Path3"},
	}

	actualRows := shortFormatResource(emptyResourceRows)
	assert.Empty(t, actualRows)

	actualRows = shortFormatResource(singleResourceRow)
	expectedRows := [][]string{{"Severity             : High\nControl Name         : Control1\nDocs                 : https://example.com/doc1\nAssisted Remediation : Path1"}}
	assert.Equal(t, expectedRows, actualRows)

	actualRows = shortFormatResource(multipleResourceRows)
	expectedRows = [][]string{{"Severity             : Medium\nControl Name         : Control2\nDocs                 : https://example.com/doc2\nAssisted Remediation : Path2"},
		{"Severity             : Low\nControl Name         : Control3\nDocs                 : https://example.com/doc3\nAssisted Remediation : Path3"}}
	assert.Equal(t, expectedRows, actualRows)
}

func TestGenerateResourceHeader(t *testing.T) {
	// Test case 1: Short headers
	shortHeaders := generateResourceHeader(true)
	expectedShortHeaders := []string{"Resources"}
	assert.Equal(t, expectedShortHeaders, shortHeaders)

	// Test case 2: Full headers
	fullHeaders := generateResourceHeader(false)
	expectedFullHeaders := []string{"Severity", "Control name", "Docs", "Assisted remediation"}
	assert.Equal(t, expectedFullHeaders, fullHeaders)
}

func TestGenerateResourceRows_Loop(t *testing.T) {
	tests := []struct {
		name           string
		summaryDetails reportsummary.SummaryDetails
		controls       []resourcesresults.ResourceAssociatedControl
		expectedLen    int
	}{
		{
			name:           "Empty controls",
			summaryDetails: reportsummary.SummaryDetails{},
			controls:       []resourcesresults.ResourceAssociatedControl{},
			expectedLen:    0,
		},
		{
			name:           "2 Failed Controls",
			summaryDetails: reportsummary.SummaryDetails{},
			controls: []resourcesresults.ResourceAssociatedControl{
				resourcesresults.ResourceAssociatedControl{
					ControlID: "control-1",
					Name:      "Control 1",
					Status:    apis.StatusInfo{},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{
							Name:      "Rule 1",
							Status:    "failed",
							SubStatus: "configuration",

							Paths: []armotypes.PosturePaths{
								{
									FailedPath: "some-path1",
								},
								{
									FailedPath: "random-path1",
								},
							},
						},
					},
				},
				resourcesresults.ResourceAssociatedControl{
					ControlID: "control-2",
					Name:      "Control 2",
					Status:    apis.StatusInfo{},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{
							Name:      "Rule 2",
							Status:    "failed",
							SubStatus: "configuration",
							Paths: []armotypes.PosturePaths{
								{
									FailedPath: "some-path2",
								},
								{
									FailedPath: "random-path2",
								},
							},
						},
					},
				},
			},
			expectedLen: 2,
		},
		{
			name:           "One failed control",
			summaryDetails: reportsummary.SummaryDetails{},
			controls: []resourcesresults.ResourceAssociatedControl{
				resourcesresults.ResourceAssociatedControl{
					ControlID: "control-1",
					Name:      "Control 1",
					Status:    apis.StatusInfo{},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{
							Name:      "Rule 1",
							Status:    "passed",
							SubStatus: "configuration",

							Paths: []armotypes.PosturePaths{
								{
									FailedPath: "some-path1",
								},
								{
									FailedPath: "random-path1",
								},
							},
						},
					},
				},
				resourcesresults.ResourceAssociatedControl{
					ControlID: "control-2",
					Name:      "Control 2",
					Status:    apis.StatusInfo{},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{
							Name:      "Rule 2",
							Status:    "failed",
							SubStatus: "configuration",
							Paths: []armotypes.PosturePaths{
								{
									FailedPath: "some-path2",
								},
								{
									FailedPath: "random-path2",
								},
							},
						},
					},
				},
			},
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := generateResourceRows(tt.controls, &tt.summaryDetails)
			assert.Equal(t, tt.expectedLen, len(rows))
		})
	}
}
