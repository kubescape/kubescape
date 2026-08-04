package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/kubescape/k8s-interface/workloadinterface"
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
			rows := generateResourceRows(tt.controls, &tt.summaryDetails, tt.resource)
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

func TestAddValueToAssistedRemediation(t *testing.T) {
	simpleControl := &resourcesresults.ResourceAssociatedControl{ControlID: "control-1"}
	credentialControl := &resourcesresults.ResourceAssociatedControl{ControlID: "C-0012"}
	credentialControlC0207 := &resourcesresults.ResourceAssociatedControl{ControlID: "C-0207"}
	controlWithFixPath := &resourcesresults.ResourceAssociatedControl{
		ControlID: "control-1",
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Paths: []armotypes.PosturePaths{
					{
						FixPath: armotypes.FixPath{
							Path:  "spec.containers[0].resources.limits.cpu",
							Value: "YOUR_VALUE",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name          string
		resourceObj   map[string]interface{}
		control       *resourcesresults.ResourceAssociatedControl
		paths         []string
		expectedPaths []string
	}{
		{
			name: "simple path resolves value",
			resourceObj: map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"replicas": 1,
				},
			},
			control:       simpleControl,
			paths:         []string{"spec.replicas"},
			expectedPaths: []string{"spec.replicas=1"},
		},
		{
			name: "path with container index resolves value",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name": "nginx",
							"securityContext": map[string]interface{}{
								"privileged": true,
							},
						},
					},
				},
			},
			control:       simpleControl,
			paths:         []string{"spec.containers[0].securityContext.privileged"},
			expectedPaths: []string{"spec.containers[0].securityContext.privileged=true"},
		},
		{
			name: "path that does not exist is left unchanged",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{},
			},
			control:       simpleControl,
			paths:         []string{"spec.doesNotExist"},
			expectedPaths: []string{"spec.doesNotExist"},
		},
		{
			name: "out of bounds container index is left unchanged",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{"name": "nginx"},
					},
				},
			},
			control:       simpleControl,
			paths:         []string{"spec.containers[5].securityContext.privileged"},
			expectedPaths: []string{"spec.containers[5].securityContext.privileged"},
		},
		{
			name: "path that already has a fixPath value is left unchanged",
			resourceObj: map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"resources": map[string]interface{}{
								"limits": map[string]interface{}{
									"cpu": "500m",
								},
							},
						},
					},
				},
			},
			control:       controlWithFixPath,
			paths:         []string{"spec.containers[0].resources.limits.cpu=YOUR_VALUE"},
			expectedPaths: []string{"spec.containers[0].resources.limits.cpu=YOUR_VALUE"},
		},
		{
			name: "credential-detecting control skips resolution entirely",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"env": []interface{}{
								map[string]interface{}{
									"name":  "DB_PASSWORD",
									"value": "not-a-real-secret-placeholder",
								},
							},
						},
					},
				},
			},
			control:       credentialControl,
			paths:         []string{"spec.containers[0].env[0].value"},
			expectedPaths: []string{"spec.containers[0].env[0].value"},
		},
		{
			name: "C-0207 also skips resolution entirely (same rule family as C-0012)",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"env": []interface{}{
								map[string]interface{}{
									"name":  "API_TOKEN",
									"value": "not-a-real-secret-placeholder",
								},
							},
						},
					},
				},
			},
			control:       credentialControlC0207,
			paths:         []string{"spec.containers[0].env[0].value"},
			expectedPaths: []string{"spec.containers[0].env[0].value"},
		},
		{
			name: "large integer keeps original precision",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"securityContext": map[string]interface{}{
						"runAsUser": 1000660000,
					},
				},
			},
			control:       simpleControl,
			paths:         []string{"spec.securityContext.runAsUser"},
			expectedPaths: []string{"spec.securityContext.runAsUser=1000660000"},
		},
		{
			name: "non-scalar value is left unchanged",
			resourceObj: map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"resources": map[string]interface{}{
								"limits": map[string]interface{}{
									"cpu":    "100m",
									"memory": "128Mi",
								},
							},
						},
					},
				},
			},
			control:       simpleControl,
			paths:         []string{"spec.containers[0].resources"},
			expectedPaths: []string{"spec.containers[0].resources"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := workloadinterface.NewWorkloadObj(tt.resourceObj)
			root, ok := resolveResourceObject(resource)
			assert.True(t, ok)
			paths := tt.paths
			addValueToAssistedRemediation(root, tt.control, &paths)
			assert.Equal(t, tt.expectedPaths, paths)
		})
	}
}

func TestSplitIndex(t *testing.T) {
	tests := []struct {
		name          string
		segment       string
		expectedKey   string
		expectedIndex int
		expectedHas   bool
	}{
		{
			name:          "plain segment has no index",
			segment:       "spec",
			expectedKey:   "spec",
			expectedIndex: 0,
			expectedHas:   false,
		},
		{
			name:          "segment with index",
			segment:       "containers[2]",
			expectedKey:   "containers",
			expectedIndex: 2,
			expectedHas:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, index, hasIndex := splitIndex(tt.segment)
			assert.Equal(t, tt.expectedKey, key)
			assert.Equal(t, tt.expectedIndex, index)
			assert.Equal(t, tt.expectedHas, hasIndex)
		})
	}
}
