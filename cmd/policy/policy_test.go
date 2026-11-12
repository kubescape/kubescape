package policy

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()

	root := &cobra.Command{Use: "kubescape"}
	root.AddCommand(GetPolicyCmd())

	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func TestPolicyInit_ScaffoldsRuleThatPassesTest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")

	out, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	assert.Contains(t, out, "wrote")
	assert.Contains(t, out, "raw.rego")
	assert.Contains(t, out, "expected.json")

	out, err = runCmd(t, "policy", "test", dir)
	require.NoError(t, err)
	assert.Contains(t, out, "2/2 cases passed")
}

func TestPolicyInit_HonoursKindFlag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-pods")

	_, err := runCmd(t, "policy", "init", dir, "--kind", "Pod")
	require.NoError(t, err)

	metadata, err := os.ReadFile(filepath.Join(dir, "rule.metadata.json"))
	require.NoError(t, err)
	assert.Contains(t, string(metadata), `"Pod"`)

	_, err = runCmd(t, "policy", "test", dir)
	require.NoError(t, err)
}

func TestPolicyInit_RejectsUnsupportedKind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "check-service")

	_, err := runCmd(t, "policy", "init", dir, "--kind", "Service")
	require.ErrorContains(t, err, "unsupported kind")
}

func TestPolicyTestUpdate_RewritesExpectations(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	expected := filepath.Join(dir, "test", "flagged", "expected.json")
	require.NoError(t, os.WriteFile(expected, []byte("[]\n"), 0o600))

	_, err = runCmd(t, "policy", "test", dir)
	require.Error(t, err)

	out, err := runCmd(t, "policy", "test", dir, "--update")
	require.NoError(t, err)
	assert.Contains(t, out, "UPDATED")
	assert.Contains(t, out, "1 case(s) updated")

	_, err = runCmd(t, "policy", "test", dir)
	require.NoError(t, err)
}

func TestPolicyTestUpdate_IsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	out, err := runCmd(t, "policy", "test", dir, "--update")
	require.NoError(t, err)
	assert.Contains(t, out, "UNCHANGED")
	assert.Contains(t, out, "0 case(s) updated")
}

func TestPolicyTest_RunSelectsMatchingCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	// Break the case --run leaves out, so the first run only passes if it is skipped.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "expected.json"), []byte("[]\n"), 0o600))

	out, err := runCmd(t, "policy", "test", dir, "--run", "^no-privileged-containers/clean$")
	require.NoError(t, err, out)
	assert.Contains(t, out, "PASS no-privileged-containers/clean")
	assert.NotContains(t, out, "flagged")
	assert.Contains(t, out, "1/1 cases passed")

	out, err = runCmd(t, "policy", "test", dir, "--run", "flagged")
	require.ErrorContains(t, err, "1 test case(s) failed")
	assert.Contains(t, out, "FAIL no-privileged-containers/flagged")
	assert.NotContains(t, out, "/clean")
}

func TestPolicyTestUpdate_RunRewritesOnlyMatchingCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	flagged := filepath.Join(dir, "test", "flagged", "expected.json")
	clean := filepath.Join(dir, "test", "clean", "expected.json")
	require.NoError(t, os.WriteFile(flagged, []byte("[]\n"), 0o600))
	require.NoError(t, os.WriteFile(clean, []byte("not json\n"), 0o600))

	out, err := runCmd(t, "policy", "test", dir, "--update", "--run", "/flagged$")
	require.NoError(t, err, out)
	assert.Contains(t, out, "UPDATED no-privileged-containers/flagged")
	assert.NotContains(t, out, "/clean")
	assert.Contains(t, out, "1 case(s) updated")

	got, err := os.ReadFile(clean)
	require.NoError(t, err)
	assert.Equal(t, "not json\n", string(got), "a case --run does not select must be left untouched")

	_, err = runCmd(t, "policy", "test", dir, "--run", "/flagged$")
	require.NoError(t, err)
}

func TestPolicyTest_RunWithoutMatchesReturnsError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	for _, args := range [][]string{
		{"policy", "test", dir, "--run", "no-such-case"},
		{"policy", "test", dir, "--run", "no-such-case", "--update"},
	} {
		t.Run(strings.Join(args[3:], " "), func(t *testing.T) {
			out, err := runCmd(t, args...)
			require.ErrorContains(t, err, `match --run "no-such-case"`)
			assert.NotContains(t, out, "Usage:")
			assert.NotContains(t, out, "cases passed")
			assert.NotContains(t, out, "case(s) updated")
		})
	}
}

func TestPolicyTest_RejectsInvalidRunPattern(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	out, err := runCmd(t, "policy", "test", dir, "--run", "flagged(")
	require.ErrorContains(t, err, "invalid --run pattern")
	assert.Contains(t, out, "Usage:")
}

// junitReport is the subset of a JUnit XML report the command tests check.
type junitReport struct {
	Tests    int `xml:"tests,attr"`
	Failures int `xml:"failures,attr"`
	Errors   int `xml:"errors,attr"`
	Suites   []struct {
		Name  string `xml:"name,attr"`
		Cases []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Failure   *struct {
				Text string `xml:",chardata"`
			} `xml:"failure"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func readJUnitReport(t *testing.T, path string) junitReport {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var report junitReport
	require.NoError(t, xml.Unmarshal(data, &report))
	return report
}

func TestPolicyTest_JUnitReportRecordsEveryCase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "expected.json"), []byte("[]\n"), 0o600))
	// The report directory does not exist yet: the command creates it.
	reportPath := filepath.Join(t.TempDir(), "reports", "policy.xml")

	out, err := runCmd(t, "policy", "test", dir, "--junit-report", reportPath)
	require.ErrorContains(t, err, "1 test case(s) failed", "a failing case must still fail the command")
	assert.Contains(t, out, "1/2 cases passed")

	report := readJUnitReport(t, reportPath)
	assert.Equal(t, 2, report.Tests)
	assert.Equal(t, 1, report.Failures)
	assert.Equal(t, 0, report.Errors)
	require.Len(t, report.Suites, 1)
	suite := report.Suites[0]
	assert.Equal(t, "no-privileged-containers", suite.Name)
	require.Len(t, suite.Cases, 2)

	byName := map[string]int{}
	for i, c := range suite.Cases {
		assert.Equal(t, "no-privileged-containers", c.ClassName)
		byName[c.Name] = i
	}
	require.Contains(t, byName, "clean")
	require.Contains(t, byName, "flagged")
	assert.Nil(t, suite.Cases[byName["clean"]].Failure)
	require.NotNil(t, suite.Cases[byName["flagged"]].Failure)
	assert.NotEmpty(t, suite.Cases[byName["flagged"]].Failure.Text, "the failure must carry the diff policy test prints")

	info, err := os.Stat(reportPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestPolicyTest_JUnitReportRecordsCasesThatCannotBeEvaluated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "input", "resource.yaml"), []byte("bad: [yaml\n"), 0o600))
	reportPath := filepath.Join(t.TempDir(), "policy.xml")

	_, err = runCmd(t, "policy", "test", dir, "--junit-report", reportPath)
	require.ErrorContains(t, err, "1 test case(s) failed")

	report := readJUnitReport(t, reportPath)
	assert.Equal(t, 2, report.Tests)
	assert.Equal(t, 0, report.Failures)
	assert.Equal(t, 1, report.Errors)
	require.Len(t, report.Suites, 1)
	for _, c := range report.Suites[0].Cases {
		if c.Name == "flagged" {
			require.NotNil(t, c.Error)
			assert.Contains(t, c.Error.Message, "load input")
			assert.Nil(t, c.Failure)
		}
	}
}

func TestPolicyTest_JUnitReportOnPassingRunCoversSelectedCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	reportPath := filepath.Join(t.TempDir(), "policy.xml")
	// A stale report from an earlier run is replaced, not appended to.
	require.NoError(t, os.WriteFile(reportPath, []byte("stale"), 0o600))

	out, err := runCmd(t, "policy", "test", dir, "--run", "/clean$", "--junit-report", reportPath)
	require.NoError(t, err, out)

	report := readJUnitReport(t, reportPath)
	assert.Equal(t, 1, report.Tests)
	assert.Equal(t, 0, report.Failures)
	assert.Equal(t, 0, report.Errors)
	require.Len(t, report.Suites, 1)
	require.Len(t, report.Suites[0].Cases, 1)
	assert.Equal(t, "clean", report.Suites[0].Cases[0].Name)
}

func TestPolicyTest_JUnitReportInvalidUse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	flagged := filepath.Join(dir, "test", "flagged", "expected.json")
	require.NoError(t, os.WriteFile(flagged, []byte("[]\n"), 0o600))
	reportPath := filepath.Join(t.TempDir(), "policy.xml")

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "empty path",
			args:    []string{"policy", "test", dir, "--junit-report", ""},
			wantErr: "--junit-report requires a file path",
		},
		{
			name:    "whitespace path",
			args:    []string{"policy", "test", dir, "--junit-report", "  "},
			wantErr: "--junit-report requires a file path",
		},
		{
			name:    "with --update",
			args:    []string{"policy", "test", dir, "--update", "--junit-report", reportPath},
			wantErr: "--junit-report cannot be used with --update",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runCmd(t, tt.args...)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Contains(t, out, "Usage:")
			assert.NotContains(t, out, "cases passed")
			assert.NotContains(t, out, "case(s) updated")
		})
	}

	got, err := os.ReadFile(flagged)
	require.NoError(t, err)
	assert.Equal(t, "[]\n", string(got), "a rejected invocation must not rewrite fixtures")
	assert.NoFileExists(t, reportPath)
}

func TestPolicyTest_JUnitReportNotWrittenWithoutRules(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "policy.xml")

	_, err := runCmd(t, "policy", "test", t.TempDir(), "--junit-report", reportPath)
	require.ErrorContains(t, err, "no rule directories")
	assert.NoFileExists(t, reportPath)
}

func TestPolicyTest_ReportsMissingRules(t *testing.T) {
	_, err := runCmd(t, "policy", "test", t.TempDir())
	require.ErrorContains(t, err, "no rule directories")
}

func TestPolicy_RuntimeFailuresDoNotPrintUsage(t *testing.T) {
	scaffold := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "no-privileged-containers")
		_, err := runCmd(t, "policy", "init", dir)
		require.NoError(t, err)
		return dir
	}

	tests := []struct {
		name    string
		args    func(t *testing.T) []string
		wantErr string
	}{
		{
			name: "test with a failing case",
			args: func(t *testing.T) []string {
				dir := scaffold(t)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "expected.json"), []byte("[]\n"), 0o600))
				return []string{"policy", "test", dir}
			},
			wantErr: "1 test case(s) failed",
		},
		{
			name: "test --update with a case that cannot be evaluated",
			args: func(t *testing.T) []string {
				dir := scaffold(t)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "input", "resource.yaml"), []byte("bad: [yaml\n"), 0o600))
				return []string{"policy", "test", dir, "--update"}
			},
			wantErr: "1 test case(s) could not be evaluated",
		},
		{
			name: "test without rules",
			args: func(t *testing.T) []string {
				return []string{"policy", "test", t.TempDir()}
			},
			wantErr: "no rule directories",
		},
		{
			name: "test with a JUnit report that cannot be written",
			args: func(t *testing.T) []string {
				// A directory cannot be replaced by the report file.
				return []string{"policy", "test", scaffold(t), "--junit-report", t.TempDir()}
			},
			wantErr: "write JUnit report",
		},
		{
			name: "init over an existing rule",
			args: func(t *testing.T) []string {
				return []string{"policy", "init", scaffold(t)}
			},
			wantErr: "--force",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runCmd(t, tt.args(t)...)
			require.ErrorContains(t, err, tt.wantErr)
			assert.NotContains(t, out, "Usage:")
		})
	}
}

func TestPolicy_ArgumentErrorsPrintUsage(t *testing.T) {
	for _, args := range [][]string{
		{"policy", "test"},
		{"policy", "init"},
		{"policy", "init", "one", "two"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, err := runCmd(t, args...)
			require.Error(t, err)
			assert.Contains(t, out, "Usage:")
		})
	}
}
