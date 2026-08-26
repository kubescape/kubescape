package printer

import (
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
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
		{
			// a bare delete/fix/review path must still be recognized as covering its
			// enriched " (current: <value>)" counterpart in failedPaths
			paths:         []string{"spec.hostNetwork"},
			failedPaths:   []string{"spec.hostNetwork (current: true)"},
			expectedPaths: []string{"spec.hostNetwork"},
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

func TestAssistedRemediationPathsToString_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		control  *resourcesresults.ResourceAssociatedControl
		expected []string
	}{
		{
			name:     "empty control with no rules and no paths",
			control:  &resourcesresults.ResourceAssociatedControl{},
			expected: nil,
		},
		{
			name: "rules with empty path fields",
			control: &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Paths: []armotypes.PosturePaths{
							{},
							{FixPath: armotypes.FixPath{Path: "", Value: "value"}},
						},
					},
				},
			},
			expected: nil,
		},
		{
			name: "duplicate paths across FailedPath and ReviewPath are deduplicated",
			control: &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Paths: []armotypes.PosturePaths{
							{ReviewPath: "shared-path"},
							{FailedPath: "shared-path"},
						},
					},
				},
			},
			expected: []string{"shared-path"},
		},
		{
			name: "mixed valid and empty paths within the same rule",
			control: &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Paths: []armotypes.PosturePaths{
							{},
							{FailedPath: "valid-failed"},
							{FixPath: armotypes.FixPath{Path: "", Value: "value"}},
							{ReviewPath: "valid-review"},
						},
					},
				},
			},
			expected: []string{"valid-review", "valid-failed"},
		},
		{
			name: "all four path types present simultaneously",
			control: &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Paths: []armotypes.PosturePaths{
							{FixPath: armotypes.FixPath{Path: "fix-path", Value: "fix-value"}},
							{DeletePath: "delete-path"},
							{ReviewPath: "review-path"},
							{FailedPath: "failed-path"},
						},
					},
				},
			},
			expected: []string{"fix-path=fix-value", "delete-path", "review-path", "failed-path"},
		},
		{
			name: "nil and missing Paths slices",
			control: &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Name: "rule-with-nil-paths"},
					{
						Name:  "rule-with-nil-paths-explicit",
						Paths: nil,
					},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := AssistedRemediationPathsToString(tt.control)
			assert.Equal(t, tt.expected, actual)
		})
	}
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
	emptyResourceRows := []table.Row{}

	// Create a test case with a single resource row
	singleResourceRow := []table.Row{
		{"High", "Control1", "https://example.com/doc1", "Path1"},
	}

	// Create a test case with multiple resource rows
	multipleResourceRows := []table.Row{
		{"Medium", "Control2", "https://example.com/doc2", "Path2"},
		{"Low", "Control3", "https://example.com/doc3", "Path3"},
	}

	actualRows := shortFormatResource(emptyResourceRows)
	assert.Empty(t, actualRows)

	actualRows = shortFormatResource(singleResourceRow)
	expectedRows := []table.Row{{"Severity             : High\nControl Name         : Control1\nDocs                 : https://example.com/doc1\nAssisted Remediation : Path1"}}
	assert.Equal(t, expectedRows, actualRows)

	actualRows = shortFormatResource(multipleResourceRows)
	expectedRows = []table.Row{{"Severity             : Medium\nControl Name         : Control2\nDocs                 : https://example.com/doc2\nAssisted Remediation : Path2"},
		{"Severity             : Low\nControl Name         : Control3\nDocs                 : https://example.com/doc3\nAssisted Remediation : Path3"}}
	assert.Equal(t, expectedRows, actualRows)
}

func TestGenerateResourceHeader(t *testing.T) {
	// Test case 1: Short headers
	shortHeaders := generateResourceHeader(true)
	expectedShortHeaders := table.Row{"Resources"}
	assert.Equal(t, expectedShortHeaders, shortHeaders)

	// Test case 2: Full headers
	fullHeaders := generateResourceHeader(false)
	expectedFullHeaders := table.Row{"Severity", "Control name", "Docs", "Assisted remediation"}
	assert.Equal(t, expectedFullHeaders, fullHeaders)
}

func TestGenerateResourceRows_Loop(t *testing.T) {
	tests := []struct {
		name                  string
		summaryDetails        reportsummary.SummaryDetails
		controls              []resourcesresults.ResourceAssociatedControl
		resource              workloadinterface.IMetadata
		expectedLen           int
		expectedContainerName string
	}{
		{
			name:           "Empty controls",
			summaryDetails: reportsummary.SummaryDetails{},
			controls:       []resourcesresults.ResourceAssociatedControl{},
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "alpine-container",
							"image": "alpine:latest",
						},
					},
				},
			}),
			expectedLen:           0,
			expectedContainerName: "",
		},
		{
			name:           "2 Failed Controls",
			summaryDetails: reportsummary.SummaryDetails{},
			controls: []resourcesresults.ResourceAssociatedControl{
				{
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
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsNonRoot=true",
								},
								{
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsGroup=1000",
								},
							},
						},
					},
				},
				{
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
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsNonRoot=true",
								},
								{
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsGroup=true",
								},
							},
						},
					},
				},
			},
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "alpine-container",
							"image": "alpine:latest",
						},
					},
				},
			}),
			expectedLen:           2,
			expectedContainerName: "alpine-container",
		},
		{
			name:           "One failed control",
			summaryDetails: reportsummary.SummaryDetails{},
			controls: []resourcesresults.ResourceAssociatedControl{
				{
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
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsNonRoot=true",
								},
								{
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsGroup=true",
								},
							},
						},
					},
				},
				{
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
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsNonRoot=true",
								},
								{
									FailedPath: "spec.template.spec.containers[0].securityContext.runAsGroup=true",
								},
							},
						},
					},
				},
			},
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx-container",
							"image": "nginx:latest",
						},
					},
				},
			}),
			expectedLen:           1,
			expectedContainerName: "nginx-container",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := generateResourceRows(tt.controls, &tt.summaryDetails, tt.resource, true, false, "")
			assert.Equal(t, tt.expectedLen, len(rows))
			//remediation is the last column of the first row
			if len(rows) != 0 {
				remediation := rows[0][3]
				assert.Contains(t, remediation, tt.expectedContainerName)
			}

		})
	}
}

func TestAddContainerNameToAssistedRemediation_OutOfBounds(t *testing.T) {
	tests := []struct {
		name          string
		resource      workloadinterface.IMetadata
		paths         []string
		expectedPaths []string
	}{
		{
			name: "valid container index appends name",
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:latest",
						},
					},
				},
			}),
			paths:         []string{"spec.containers[0].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.containers[0].securityContext.runAsNonRoot (nginx)"},
		},
		{
			name: "out of bounds container index is skipped",
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:latest",
						},
					},
				},
			}),
			paths:         []string{"spec.containers[5].securityContext.readOnlyRootFilesystem"},
			expectedPaths: []string{"spec.containers[5].securityContext.readOnlyRootFilesystem"},
		},
		{
			name: "mixed valid and out of bounds indices",
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:latest",
						},
						map[string]any{
							"name":  "sidecar",
							"image": "sidecar:latest",
						},
					},
				},
			}),
			paths: []string{
				"spec.containers[0].securityContext.runAsNonRoot",
				"spec.containers[10].securityContext.readOnlyRootFilesystem",
				"spec.containers[1].securityContext.allowPrivilegeEscalation",
			},
			expectedPaths: []string{
				"spec.containers[0].securityContext.runAsNonRoot (nginx)",
				"spec.containers[10].securityContext.readOnlyRootFilesystem",
				"spec.containers[1].securityContext.allowPrivilegeEscalation (sidecar)",
			},
		},
		{
			name:          "init and ephemeral container indices append names",
			resource:      privilegedInitAndEphemeralPod(),
			paths:         privilegedInitAndEphemeralPaths(),
			expectedPaths: privilegedInitAndEphemeralNamedPaths(),
		},
		{
			name: "path without container index is unchanged",
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Pod",
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:latest",
						},
					},
				},
			}),
			paths:         []string{"metadata.labels.app"},
			expectedPaths: []string{"metadata.labels.app"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := tt.paths
			addContainerNameToAssistedRemediation(tt.resource, &paths)
			assert.Equal(t, tt.expectedPaths, paths)
		})
	}
}

// TestResourceTable_DoesNotExposeSensitiveData is a regression test ensuring
// that the verbose per-resource table never emits raw Secret data or container
// environment values that may hold sensitive information.
func TestResourceTable_DoesNotExposeSensitiveData(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		resourceObj map[string]any
		paths       []armotypes.PosturePaths
		sensitive   []string
		showSecrets bool
	}{
		{
			name:       "Secret data is not rendered",
			resourceID: "/v1/default/Secret/example-secret",
			resourceObj: map[string]any{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata": map[string]any{
					"name":      "example-secret",
					"namespace": "default",
				},
				"data": map[string]any{
					"password": "PLACEHOLDER_BASE64_001",
					"username": "PLACEHOLDER_BASE64_002",
				},
			},
			paths: []armotypes.PosturePaths{
				{FailedPath: "data.password"},
				{FailedPath: "data.username"},
			},
			sensitive:   []string{"PLACEHOLDER_BASE64_001", "PLACEHOLDER_BASE64_002"},
			showSecrets: false,
		},
		{
			name:       "Pod env value is not rendered",
			resourceID: "/v1/default/Pod/example-pod",
			resourceObj: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name":      "example-pod",
					"namespace": "default",
				},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "app:latest",
							"env": []any{
								map[string]any{
									"name":  "DB_PASSWORD",
									"value": "PLACEHOLDER_VALUE_003",
								},
								map[string]any{
									"name": "SECRET_REF",
									"valueFrom": map[string]any{
										"secretKeyRef": map[string]any{
											"name": "PLACEHOLDER_REF_NAME",
											"key":  "password",
										},
									},
								},
							},
						},
					},
				},
			},
			paths: []armotypes.PosturePaths{
				{FailedPath: "spec.containers[0].env[0].value"},
			},
			sensitive:   []string{"PLACEHOLDER_VALUE_003"},
			showSecrets: false,
		},
		{
			name:       "Secret data is rendered with --show-secrets",
			resourceID: "/v1/default/Secret/example-secret",
			resourceObj: map[string]any{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata": map[string]any{
					"name":      "example-secret",
					"namespace": "default",
				},
				"data": map[string]any{
					"password": "PLACEHOLDER_BASE64_001",
					"username": "PLACEHOLDER_BASE64_002",
				},
			},
			paths: []armotypes.PosturePaths{
				{FailedPath: "data.password"},
				{FailedPath: "data.username"},
			},
			sensitive:   []string{"PLACEHOLDER_BASE64_001", "PLACEHOLDER_BASE64_002"},
			showSecrets: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "resource-table-*.txt")
			assert.NoError(t, err)

			pp := &PrettyPrinter{writer: f, showEvidence: true, showSecrets: tt.showSecrets}
			resource := workloadinterface.NewWorkloadObj(tt.resourceObj)

			session := cautils.NewOPASessionObjMock()
			session.AllResources[tt.resourceID] = resource
			session.ResourcesResult[tt.resourceID] = resourcesresults.Result{
				ResourceID: tt.resourceID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						Name:      "Sensitive data exposure",
						Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name:   "rule-1",
								Status: "failed",
								Paths:  tt.paths,
							},
						},
					},
				},
			}
			session.Report.SummaryDetails = reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ControlID:   "C-0001",
						Name:        "Sensitive data exposure",
						ScoreFactor: 8.0,
					},
				},
			}

			pp.resourceTable(session)

			assert.NoError(t, f.Close())
			out, err := os.ReadFile(f.Name())
			assert.NoError(t, err)

			for _, s := range tt.sensitive {
				if tt.showSecrets {
					assert.Contains(t, string(out), s, "sensitive value %q must appear when --show-secrets is set", s)
				} else {
					assert.NotContains(t, string(out), s, "sensitive value %q must not appear in resource table output", s)
				}
			}
		})
	}
}
func TestAddContainerNameToAssistedRemediation_EdgeCases(t *testing.T) {
	podWithContainerTypes := workloadinterface.NewWorkloadObj(map[string]any{
		"kind": "Pod",
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "app", "image": "app:latest"},
			},
			"initContainers": []any{
				map[string]any{"name": "init", "image": "init:latest"},
			},
			"ephemeralContainers": []any{
				map[string]any{"name": "debug", "image": "debug:latest"},
			},
		},
	})

	tests := []struct {
		name          string
		resource      workloadinterface.IMetadata
		paths         []string
		expectedPaths []string
	}{
		{
			name:          "negative container index is unchanged",
			resource:      podWithContainerTypes,
			paths:         []string{"spec.containers[-1].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.containers[-1].securityContext.runAsNonRoot"},
		},
		{
			name:          "non-numeric container index is unchanged",
			resource:      podWithContainerTypes,
			paths:         []string{"spec.containers[abc].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.containers[abc].securityContext.runAsNonRoot"},
		},
		{
			name:          "missing containers field is unchanged",
			resource:      workloadinterface.NewWorkloadObj(map[string]any{"kind": "Pod", "spec": map[string]any{}}),
			paths:         []string{"spec.containers[0].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.containers[0].securityContext.runAsNonRoot"},
		},
		{
			name:          "init container path appends name",
			resource:      podWithContainerTypes,
			paths:         []string{"spec.initContainers[0].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.initContainers[0].securityContext.runAsNonRoot (init)"},
		},
		{
			name:          "ephemeral container path appends name",
			resource:      podWithContainerTypes,
			paths:         []string{"spec.ephemeralContainers[0].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.ephemeralContainers[0].securityContext.runAsNonRoot (debug)"},
		},
		{
			name:          "out of bounds init container index is unchanged",
			resource:      podWithContainerTypes,
			paths:         []string{"spec.initContainers[5].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.initContainers[5].securityContext.runAsNonRoot"},
		},
		{
			name:          "out of bounds ephemeral container index is unchanged",
			resource:      podWithContainerTypes,
			paths:         []string{"spec.ephemeralContainers[5].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.ephemeralContainers[5].securityContext.runAsNonRoot"},
		},
		{
			name:          "nil resource does not panic",
			resource:      nil,
			paths:         []string{"spec.containers[0].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.containers[0].securityContext.runAsNonRoot"},
		},
		{
			name: "nested template container path appends name",
			resource: workloadinterface.NewWorkloadObj(map[string]any{
				"kind": "Deployment",
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"containers": []any{
								map[string]any{"name": "web", "image": "web:latest"},
							},
						},
					},
				},
			}),
			paths:         []string{"spec.template.spec.containers[0].securityContext.runAsNonRoot"},
			expectedPaths: []string{"spec.template.spec.containers[0].securityContext.runAsNonRoot (web)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := tt.paths
			addContainerNameToAssistedRemediation(tt.resource, &paths)
			assert.Equal(t, tt.expectedPaths, paths)
		})
	}
}
