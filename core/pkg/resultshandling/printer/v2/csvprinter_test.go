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
						ReviewPath: "spec.containers[0].securityContext.privileged",
						FixPath: armotypes.FixPath{
							Path:  "spec.containers[0].securityContext.privileged",
							Value: "false",
						},
					},
					{
						ReviewPath: "spec.initContainers[0].securityContext.privileged",
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
	cp := NewCsvPrinter(false)
	cp.writer = openDevFull(t)

	err := cp.ActionPrint(context.TODO(), csvSessionFixture(), nil)
	require.Error(t, err, "ActionPrint must surface a failed flush instead of silently returning nil")
}

func TestActionPrint_Csv_MidLoopWriteFailureIsReported(t *testing.T) {
	// Enough rows to overflow the csv.Writer's internal 4KB buffer mid-loop,
	// forcing a real write to the underlying file (and a resulting error)
	// before the loop even finishes, exercising the early-return path that
	// used to skip the final Flush() entirely.
	cp := NewCsvPrinter(false)
	cp.writer = openDevFull(t)

	err := cp.ActionPrint(context.TODO(), csvSessionFixtureManyRows(200), nil)
	require.Error(t, err, "ActionPrint must surface a mid-loop write failure instead of silently returning nil")
}

func TestNewCsvPrinter(t *testing.T) {
	cp := NewCsvPrinter(false)
	assert.NotNil(t, cp)
}

func TestSetWriter_Csv(t *testing.T) {
	cp := NewCsvPrinter(false)
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

	cp := NewCsvPrinter(false)
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

	cp := NewCsvPrinter(false)
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

	cp := NewCsvPrinter(false)
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

// TestActionPrint_Csv_MissingAllResourcesEntryFailsClosed is a regression
// test: when a resource's ResourcesResult entry has no corresponding
// AllResources entry (a partial/degraded collection, or ordering the
// printer has no control over), resKind in ActionPrint stays "". Before the
// kind == "" fail-closed check in csvControlPaths, this resource's fix
// values were written to the CSV unredacted regardless of --show-secrets,
// since the Secret-kind check in isSensitivePath never got a chance to
// fire.
func TestActionPrint_Csv_MissingAllResourcesEntryFailsClosed(t *testing.T) {
	const missingResourceID = "v1/Secret/default/orphaned"
	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult[missingResourceID] = resourcesresults.Result{
		ResourceID: missingResourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0012",
				Name:      "Credentials in env var",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Paths: []armotypes.PosturePaths{
							{FixPath: armotypes.FixPath{Path: "data.password", Value: "s3cr3t-plaintext-password"}},
						},
					},
				},
			},
		},
	}
	// Deliberately no session.AllResources[missingResourceID] entry.
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				"C-0012": reportsummary.ControlSummary{ControlID: "C-0012", Name: "Credentials in env var", ScoreFactor: 8.0},
			},
		},
	}

	tmpCsv, err := os.CreateTemp("", "csv-missing-resource-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpCsv.Name())

	cp := NewCsvPrinter(false)
	cp.writer = tmpCsv
	require.NoError(t, cp.ActionPrint(context.TODO(), session, nil))
	require.NoError(t, cp.CloseWriter())

	f, err := os.Open(tmpCsv.Name())
	require.NoError(t, err)
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)

	var foundRow []string
	for _, row := range records[1:] {
		if row[1] == "C-0012" {
			foundRow = row
			break
		}
	}
	require.NotNil(t, foundRow, "should find the C-0012 row even though the resource is unresolved")
	assert.Empty(t, foundRow[5], "Resource Kind column is empty: the AllResources lookup missed")
	assert.NotContains(t, foundRow[9], "s3cr3t-plaintext-password", "Fix Paths column must not leak the value when kind is unresolved")
	assert.Contains(t, foundRow[9], "[redacted]", "Fix Paths column must fail closed to redacted")
}

func TestActionPrint_Csv_NilSession(t *testing.T) {
	cp := NewCsvPrinter(false)
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
		kind       string
		wantFailed string
		wantFix    string
	}{
		{
			name: "single failed path with fix",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{
							ReviewPath: "spec.containers[0].securityContext.privileged",
							FixPath:    armotypes.FixPath{Path: "spec.containers[0].securityContext.privileged", Value: "false"},
						},
					},
				},
			}),
			controlID:  "C-0057",
			kind:       "Deployment",
			wantFailed: "spec.containers[0].securityContext.privileged",
			wantFix:    "spec.containers[0].securityContext.privileged=false",
		},
		{
			name: "multiple failed paths joined by semicolon",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{ReviewPath: "spec.containers[0].securityContext.privileged"},
						{ReviewPath: "spec.initContainers[0].securityContext.privileged"},
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
			kind:       "Deployment",
			wantFailed: "",
			wantFix:    "spec.hostNetwork=false",
		},
		{
			name: "control not in result returns empty strings",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{ReviewPath: "spec.containers[0].securityContext.privileged"},
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
						{ReviewPath: "spec.containers[0].securityContext.privileged"},
					},
				},
				{
					Paths: []armotypes.PosturePaths{
						{ReviewPath: "spec.containers[1].securityContext.privileged"},
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
			// kind: "Pod" matters here: automountServiceAccountToken is a
			// secret-shaped field name ("...Token"), but it's an allowlisted
			// safe field on a Pod spec (see matchesSafeField) -- an empty
			// kind would fall through to the generic name-pattern check and
			// wrongly redact a boolean toggle that never holds a secret.
			name: "fix path with empty value emits bare path without equals",
			result: makeResult("C-0057", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FixPath: armotypes.FixPath{Path: "spec.automountServiceAccountToken", Value: ""}},
					},
				},
			}),
			controlID:  "C-0057",
			kind:       "Pod",
			wantFailed: "",
			wantFix:    "spec.automountServiceAccountToken",
		},
		{
			name: "sensitive Secret.data fix path is redacted by default",
			result: makeResult("C-0012", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FixPath: armotypes.FixPath{Path: "data.password", Value: "s3cr3t-plaintext-password"}},
					},
				},
			}),
			controlID:  "C-0012",
			kind:       "Secret",
			wantFailed: "",
			wantFix:    "data.password=[redacted]",
		},
		{
			// Regression: an unresolved kind ("" -- the caller's
			// AllResources lookup missed) must redact regardless of
			// whether the field name itself looks credential-shaped.
			// isSensitivePath("", "data.customKey") is false on its own --
			// the Secret.data/stringData check requires kind == "Secret" to
			// fire, and "customKey" matches none of the generic
			// secretFieldPatterns -- so without the explicit kind == ""
			// fail-closed check, this exact case would leak.
			name: "unresolved kind fails closed even for a non-pattern-matching field name",
			result: makeResult("C-0012", []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FixPath: armotypes.FixPath{Path: "data.customKey", Value: "s3cr3t-plaintext-value"}},
					},
				},
			}),
			controlID:  "C-0012",
			kind:       "",
			wantFailed: "",
			wantFix:    "data.customKey=[redacted]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotFailed, gotFix := csvControlPaths(tc.result, tc.controlID, tc.kind, false)
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

func TestActionPrint_Csv_UnevaluatedControlsIncluded(t *testing.T) {
	session := csvSessionFixture()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     66.0,
		EvaluatedControls: 2,
		TotalControls:     3,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID:   "C-0099",
				MissingGVRs: []string{"apps/v1/daemonsets"},
			},
		},
	}

	tmpCsv, err := os.CreateTemp("", "csv-unevaluated-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpCsv.Name())

	cp := NewCsvPrinter(false)
	cp.writer = tmpCsv
	err = cp.ActionPrint(context.TODO(), session, nil)
	require.NoError(t, err)
	require.NoError(t, cp.CloseWriter())

	f, err := os.Open(tmpCsv.Name())
	require.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	require.NoError(t, err)

	var foundUnevaluated bool
	for _, row := range records[1:] {
		require.Equal(t, 13, len(row), "every row must have 13 columns")
		if row[1] == "C-0099" {
			foundUnevaluated = true
			assert.Equal(t, "C-0099", row[0], "name should fallback to control ID when not in summary")
			assert.Equal(t, "not evaluated", row[3], "status must be 'not evaluated'")
			assert.Equal(t, "", row[4], "resource name must be empty")
			assert.Equal(t, "", row[5], "resource kind must be empty")
			assert.Equal(t, "", row[6], "resource namespace must be empty")
			assert.Equal(t, "", row[7], "api version must be empty")
			assert.Equal(t, "", row[8], "failed paths must be empty")
			assert.Equal(t, "", row[9], "fix paths must be empty")
			assert.Equal(t, "missing: apps/v1/daemonsets", row[10], "remediation should contain skip reason")
			assert.Contains(t, row[11], "c-0099", "control URL should link to control")
			assert.Equal(t, "", row[12], "source path must be empty")
		}
	}
	assert.True(t, foundUnevaluated, "expected unevaluated control C-0099 in CSV output")
}

func TestActionPrint_Csv_UnevaluatedControlsNotDuplicated(t *testing.T) {
	session := csvSessionFixture()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     50.0,
		EvaluatedControls: 1,
		TotalControls:     2,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID: "C-0099",
				Reason:    "evaluation timed out",
			},
			{
				ControlID: "C-0099",
				Reason:    "evaluation timed out",
			},
		},
	}

	tmpCsv, err := os.CreateTemp("", "csv-dup-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpCsv.Name())

	cp := NewCsvPrinter(false)
	cp.writer = tmpCsv
	err = cp.ActionPrint(context.TODO(), session, nil)
	require.NoError(t, err)
	require.NoError(t, cp.CloseWriter())

	f, err := os.Open(tmpCsv.Name())
	require.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	require.NoError(t, err)

	unevaluatedCount := 0
	for _, row := range records[1:] {
		if row[1] == "C-0099" && row[3] == "not evaluated" {
			unevaluatedCount++
		}
	}
	assert.Equal(t, 1, unevaluatedCount, "unevaluated control should only be emitted once as not evaluated even if duplicated in input")
}

func TestActionPrint_Csv_PreserveUnevaluatedDiagnosticWhenResourceRowsExist(t *testing.T) {
	session := csvSessionFixture()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     50.0,
		EvaluatedControls: 1,
		TotalControls:     2,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID: testControlID1,
				Reason:    "evaluation timed out",
			},
		},
	}

	tmpCsv, err := os.CreateTemp("", "csv-preserve-diag-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpCsv.Name())

	cp := NewCsvPrinter(false)
	cp.writer = tmpCsv
	err = cp.ActionPrint(context.TODO(), session, nil)
	require.NoError(t, err)
	require.NoError(t, cp.CloseWriter())

	f, err := os.Open(tmpCsv.Name())
	require.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	require.NoError(t, err)

	var resourceRows [][]string
	var diagRows [][]string
	for _, row := range records[1:] {
		if row[1] == testControlID1 {
			if row[3] == "not evaluated" {
				diagRows = append(diagRows, row)
			} else {
				resourceRows = append(resourceRows, row)
			}
		}
	}

	// Resource rows from earlier scopes are retained
	assert.Len(t, resourceRows, 2, "resource result rows should be retained")
	var foundDemo bool
	for _, row := range resourceRows {
		assert.Equal(t, "failed", row[3])
		if row[4] == "demo" {
			foundDemo = true
		}
	}
	assert.True(t, foundDemo, "resource demo should be present in resource rows")

	// Diagnostic row for timeout is preserved alongside existing results
	require.Len(t, diagRows, 1, "exactly one control-level not-evaluated diagnostic row should be emitted alongside results")
	diag := diagRows[0]
	assert.Equal(t, "Privileged container", diag[0], "control name should come from summary")
	assert.Equal(t, testControlID1, diag[1])
	assert.Equal(t, "Critical", diag[2], "severity should match control score factor")
	assert.Equal(t, "not evaluated", diag[3])
	assert.Empty(t, diag[4], "resource name should be empty on diagnostic row")
	assert.Empty(t, diag[5], "resource kind should be empty on diagnostic row")
	assert.Empty(t, diag[6], "resource namespace should be empty on diagnostic row")
	assert.Empty(t, diag[7], "api version should be empty on diagnostic row")
	assert.Empty(t, diag[8], "failed paths should be empty on diagnostic row")
	assert.Empty(t, diag[9], "fix paths should be empty on diagnostic row")
	assert.Equal(t, "evaluation timed out", diag[10], "remediation should contain timeout reason")
	assert.Contains(t, diag[11], "c-0057")
	assert.Empty(t, diag[12], "source path should be empty on diagnostic row")
}

func TestActionPrint_Csv_SkippedControlFromSummaryIncluded(t *testing.T) {
	session := csvSessionFixture()
	skippedStatus := &apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusIrrelevant,
		InnerInfo:   "no matching resources",
	}
	ctrlSkipped := &reportsummary.ControlSummary{
		ControlID:   "C-0070",
		Name:        "Host IPC",
		ScoreFactor: 6.0,
		StatusInfo:  *skippedStatus,
	}
	session.Report.SummaryDetails.Controls["C-0070"] = *ctrlSkipped

	tmpCsv, err := os.CreateTemp("", "csv-skipped-summary-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpCsv.Name())

	cp := NewCsvPrinter(false)
	cp.writer = tmpCsv
	err = cp.ActionPrint(context.TODO(), session, nil)
	require.NoError(t, err)
	require.NoError(t, cp.CloseWriter())

	f, err := os.Open(tmpCsv.Name())
	require.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	require.NoError(t, err)

	var foundSkipped bool
	for _, row := range records[1:] {
		if row[1] == "C-0070" {
			foundSkipped = true
			assert.Equal(t, "Host IPC", row[0])
			assert.Equal(t, "not evaluated", row[3])
			assert.Equal(t, "Medium", row[2])
			assert.Equal(t, "irrelevant: no matching resources", row[10])
		}
	}
	assert.True(t, foundSkipped, "expected skipped control C-0070 in CSV output")
}
