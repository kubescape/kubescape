package printer

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	reporthandling "github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testControlID1  = "C-0057"
	testControlID2  = "C-0058"
	testResourceID1 = "apps/v1/Deployment/default/demo"
	testResourceID2 = "apps/v1/Deployment/default/absent"
)

func csvSessionFixture() *cautils.OPASessionObj {
	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]interface{}{},
	}
	lw := localworkload.NewLocalWorkload(obj)

	ac1 := resourcesresults.ResourceAssociatedControl{
		ControlID: testControlID1,
		Name:      "Privileged container",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}

	ac2 := resourcesresults.ResourceAssociatedControl{
		ControlID: testControlID2,
		Name:      "Run as root",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}

	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult[testResourceID1] = resourcesresults.Result{
		ResourceID:         testResourceID1,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac1, ac2},
	}
	session.ResourcesResult[testResourceID2] = resourcesresults.Result{
		ResourceID:         testResourceID2,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac1},
	}
	session.AllResources[testResourceID1] = lw

	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				testControlID1: reportsummary.ControlSummary{
					ControlID:   testControlID1,
					Name:        "Privileged container",
					ScoreFactor: 9.0,
				},
				testControlID2: reportsummary.ControlSummary{
					ControlID:   testControlID2,
					Name:        "Run as root",
					ScoreFactor: 5.0,
				},
			},
		},
	}

	return session
}

func csvSessionFixtureWithPaths() *cautils.OPASessionObj {
	session := csvSessionFixture()

	ac1WithPaths := resourcesresults.ResourceAssociatedControl{
		ControlID: testControlID1,
		Name:      "Privileged container",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Paths: []armotypes.PosturePaths{
					{
						FailedPath: "spec.containers[0].securityContext.privileged",
						FixPath: armotypes.FixPath{
							Path:  "spec.containers[0].securityContext.privileged",
							Value: "false",
						},
					},
					{
						FailedPath: "spec.initContainers[0].securityContext.privileged",
					},
				},
			},
		},
	}

	ac2NoPath := resourcesresults.ResourceAssociatedControl{
		ControlID: testControlID2,
		Name:      "Run as root",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}

	session.ResourcesResult[testResourceID1] = resourcesresults.Result{
		ResourceID:         testResourceID1,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac1WithPaths, ac2NoPath},
	}

	session.ResourceSource = make(map[string]reporthandling.Source)
	session.ResourceSource[testResourceID1] = reporthandling.Source{
		RelativePath: "manifests/deployment.yaml",
		Path:         "/home/user/project/manifests/deployment.yaml",
	}

	session.Report.SummaryDetails.Controls[testControlID1] = reportsummary.ControlSummary{
		ControlID:   testControlID1,
		Name:        "Privileged container",
		ScoreFactor: 9.0,
		Remediation: "remove privilegedContainer: True flag from your pod spec",
	}

	return session
}

// csvSessionFixtureManyRows builds a session with n associated controls on a
// single resource, producing enough CSV row data to overflow the csv.Writer's
// internal buffer mid-loop rather than only at the final Flush.
func csvSessionFixtureManyRows(n int) *cautils.OPASessionObj {
	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]interface{}{},
	}
	lw := localworkload.NewLocalWorkload(obj)

	controls := make([]resourcesresults.ResourceAssociatedControl, 0, n)
	for i := 0; i < n; i++ {
		controls = append(controls, resourcesresults.ResourceAssociatedControl{
			ControlID: fmt.Sprintf("C-%04d", i),
			Name:      fmt.Sprintf("control-%d", i),
			Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		})
	}

	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult[testResourceID1] = resourcesresults.Result{
		ResourceID:         testResourceID1,
		AssociatedControls: controls,
	}
	session.AllResources[testResourceID1] = lw
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{},
		},
	}

	return session
}

// openDevFull opens /dev/full, a device whose Write always fails with
// ENOSPC, to deterministically simulate an underlying I/O write failure.
// Tests using it are skipped on platforms where the device doesn't exist.
func openDevFull(t *testing.T) *os.File {
	t.Helper()
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full not available on this platform")
	}
	f, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestActionPrint_Csv_WriteFailureIsReported(t *testing.T) {
	// A small fixture whose rows all fit comfortably inside the csv.Writer's
	// internal buffer: no row write ever touches the underlying file, so the
	// only write attempt happens on the final Flush.
	cp := NewCsvPrinter()
	cp.writer = openDevFull(t)

	err := cp.ActionPrint(context.TODO(), csvSessionFixture(), nil)
	require.Error(t, err, "ActionPrint must surface a failed flush instead of silently returning nil")
}

func TestActionPrint_Csv_MidLoopWriteFailureIsReported(t *testing.T) {
	// Enough rows to overflow the csv.Writer's internal 4KB buffer mid-loop,
	// forcing a real write to the underlying file (and a resulting error)
	// before the loop even finishes, exercising the early-return path that
	// used to skip the final Flush() entirely.
	cp := NewCsvPrinter()
	cp.writer = openDevFull(t)

	err := cp.ActionPrint(context.TODO(), csvSessionFixtureManyRows(200), nil)
	require.Error(t, err, "ActionPrint must surface a mid-loop write failure instead of silently returning nil")
}

func TestNewCsvPrinter(t *testing.T) {
	cp := NewCsvPrinter()
	assert.NotNil(t, cp)
}

func TestSetWriter_Csv(t *testing.T) {
	cp := NewCsvPrinter()
	assert.NotNil(t, cp)

	cp.SetWriter(context.TODO(), "")
	assert.NotNil(t, cp.writer)
	cp.CloseWriter()
}

func TestScore_Csv(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	cp := NewCsvPrinter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "csvPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer func() {
				_ = f.Close()
			}()

			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			cp.Score(tt.score)

			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestActionPrint_Csv(t *testing.T) {
	session := csvSessionFixture()

	tmpCsv, err := os.CreateTemp("", "csv-regression-*.csv")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpCsv.Name())
	}()

	cp := NewCsvPrinter()
	cp.writer = tmpCsv
	cp.ActionPrint(context.TODO(), session, nil)
	cp.CloseWriter()

	f, err := os.Open(tmpCsv.Name())
	assert.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	assert.NoError(t, err)

	assert.Equal(t, 4, len(records))

	expectedHeader := []string{
		"Control Name",
		"Control ID",
		"Severity",
		"Status",
		"Resource Name",
		"Resource Kind",
		"Resource Namespace",
		"API Version",
		"Failed Paths",
		"Fix Paths",
		"Remediation",
		"Control URL",
		"Source Path",
	}
	assert.Equal(t, expectedHeader, records[0], "Header should match expected")
	assert.Equal(t, 13, len(records[0]), "Header should have 13 columns")

	var failedDemo, passedDemo, failedAbsent bool
	for _, row := range records[1:] {
		require.Equal(t, 13, len(row), "every data row must have 13 columns")
		if row[0] == "Privileged container" && row[1] == testControlID1 && row[3] == "failed" {
			if row[4] == "demo" && row[5] == "Deployment" && row[6] == "default" && row[7] == "apps/v1" {
				failedDemo = true
			} else if row[4] == "" && row[5] == "" && row[6] == "" && row[7] == "" {
				failedAbsent = true
			}
		} else if row[0] == "Run as root" && row[1] == testControlID2 && row[3] == "passed" {
			if row[4] == "demo" {
				passedDemo = true
			}
		}
	}

	assert.True(t, failedDemo, "expected failed control row for demo resource")
	assert.True(t, passedDemo, "expected passed control row for demo resource")
	assert.True(t, failedAbsent, "expected failed control row for absent resource")
}

func TestActionPrint_Csv_WithPaths(t *testing.T) {
	session := csvSessionFixtureWithPaths()

	tmpCsv, err := os.CreateTemp("", "csv-paths-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpCsv.Name())

	cp := NewCsvPrinter()
	cp.writer = tmpCsv
	cp.ActionPrint(context.TODO(), session, nil)
	cp.CloseWriter()

	f, err := os.Open(tmpCsv.Name())
	require.NoError(t, err)
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)
	require.Greater(t, len(records), 1)

	var foundRow []string
	for _, row := range records[1:] {
		if row[1] == testControlID1 && row[4] == "demo" {
			foundRow = row
			break
		}
	}
	require.NotNil(t, foundRow, "should find C-0057 row for demo resource")

	assert.Contains(t, foundRow[8], "spec.containers[0].securityContext.privileged", "Failed Paths column")
	assert.Contains(t, foundRow[8], "spec.initContainers[0].securityContext.privileged", "Failed Paths column second path")
	assert.Contains(t, foundRow[9], "spec.containers[0].securityContext.privileged=false", "Fix Paths column")
	assert.Equal(t, "remove privilegedContainer: True flag from your pod spec", foundRow[10], "Remediation column")
	assert.NotEmpty(t, foundRow[11], "Control URL column should not be empty")
	assert.Equal(t, "manifests/deployment.yaml", foundRow[12], "Source Path column uses RelativePath")
}

func TestActionPrint_Csv_NilSession(t *testing.T) {
	cp := NewCsvPrinter()
	cp.writer = os.Stdout
	cp.ActionPrint(context.TODO(), nil, nil)
}

func TestCsvControlPaths(t *testing.T) {
	makeResult := func(controlID string, rules []resourcesresults.ResourceAssociatedRule) resourcesresults.Result {
		return resourcesresults.Result{
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID:               controlID,
					ResourceAssociatedRules: rules,
				},
			},
		}
	}

	cases := []struct {
		name       string
		result     resourcesresults.Result
		controlID  string
		wantFailed string
		wantFix    string
	}{
		{
			name: "single failed path with fix",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{
							FailedPath: "spec.containers[0].securityContext.privileged",
							FixPath:    armotypes.FixPath{Path: "spec.containers[0].securityContext.privileged", Value: "false"},
						},
					},
				},
			}),
			controlID:  "C-0057",
			wantFailed: "spec.containers[0].securityContext.privileged",
			wantFix:    "spec.containers[0].securityContext.privileged=false",
		},
		{
			name: "multiple failed paths joined by semicolon",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FailedPath: "spec.containers[0].securityContext.privileged"},
						{FailedPath: "spec.initContainers[0].securityContext.privileged"},
					},
				},
			}),
			controlID:  "C-0057",
			wantFailed: "spec.containers[0].securityContext.privileged; spec.initContainers[0].securityContext.privileged",
			wantFix:    "",
		},
		{
			name: "fix path without failed path",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FixPath: armotypes.FixPath{Path: "spec.hostNetwork", Value: "false"}},
					},
				},
			}),
			controlID:  "C-0057",
			wantFailed: "",
			wantFix:    "spec.hostNetwork=false",
		},
		{
			name: "control not in result returns empty strings",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FailedPath: "spec.containers[0].securityContext.privileged"},
					},
				},
			}),
			controlID:  "C-9999",
			wantFailed: "",
			wantFix:    "",
		},
		{
			name:       "result with no rules returns empty strings",
			result:     makeResult("C-0057", nil),
			controlID:  "C-0057",
			wantFailed: "",
			wantFix:    "",
		},
		{
			name: "multiple rules paths concatenated",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FailedPath: "spec.containers[0].securityContext.privileged"},
					},
				},
				{
					Paths: []armotypes.PosturePaths{
						{FailedPath: "spec.containers[1].securityContext.privileged"},
					},
				},
			}),
			controlID:  "C-0057",
			wantFailed: "spec.containers[0].securityContext.privileged; spec.containers[1].securityContext.privileged",
			wantFix:    "",
		},
		{
			name: "empty result returns empty strings",
			result: resourcesresults.Result{
				AssociatedControls: nil,
			},
			controlID:  "C-0057",
			wantFailed: "",
			wantFix:    "",
		},
		{
			name: "fix path with empty value emits bare path without equals",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FixPath: armotypes.FixPath{Path: "spec.automountServiceAccountToken", Value: ""}},
					},
				},
			}),
			controlID:  "C-0057",
			wantFailed: "",
			wantFix:    "spec.automountServiceAccountToken",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotFailed, gotFix := csvControlPaths(tc.result, tc.controlID)
			assert.Equal(t, tc.wantFailed, gotFailed, "failed paths mismatch")
			assert.Equal(t, tc.wantFix, gotFix, "fix paths mismatch")
		})
	}
}

func TestCsvSourcePath(t *testing.T) {
	cases := []struct {
		name string
		src  reporthandling.Source
		want string
	}{
		{
			name: "relative path preferred over absolute",
			src:  reporthandling.Source{RelativePath: "manifests/deploy.yaml", Path: "/abs/path/deploy.yaml"},
			want: "manifests/deploy.yaml",
		},
		{
			name: "absolute path used when relative is empty",
			src:  reporthandling.Source{RelativePath: "", Path: "/abs/path/deploy.yaml"},
			want: "/abs/path/deploy.yaml",
		},
		{
			name: "both empty returns empty string",
			src:  reporthandling.Source{},
			want: "",
		},
		{
			name: "only relative path set",
			src:  reporthandling.Source{RelativePath: "k8s/namespace.yaml"},
			want: "k8s/namespace.yaml",
		},
		{
			name: "helm template path with relative",
			src:  reporthandling.Source{RelativePath: "templates/deployment.yaml", HelmTemplateLine: 12},
			want: "templates/deployment.yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, csvSourcePath(tc.src))
		})
	}
}
