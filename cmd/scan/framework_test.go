package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFrameworkCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	cmd := getFrameworkCmd(mockKubescape, &scanInfo)

	// Verify the command name and short description
	assert.Equal(t, "framework <framework names list> [`<glob pattern>`/`-`] [flags]", cmd.Use)
	assert.Equal(t, fmt.Sprintf("The framework you wish to use. Run '%[1]s list frameworks' for the list of supported frameworks", cautils.ExecName()), cmd.Short)
	assert.Equal(t, frameworkExample, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "requires at least one framework name"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"nsa,mitre"})
	assert.Nil(t, err)

	err = cmd.Args(&cobra.Command{}, []string{"nsa,mitre,"})
	expectedErrorMessage = "usage: <framework-0>,<framework-1>"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage = "bad argument: accound ID must be a valid UUID"
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func TestGetFrameworkCmdWithNonExistentFramework(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	// Call the GetFrameworkCmd function
	cmd := getFrameworkCmd(mockKubescape, &scanInfo)

	// Run the command with a non-existent framework argument
	err := cmd.RunE(&cobra.Command{}, []string{"framework", "nsa,mitre"})

	// Check that there is an error and the error message is as expected
	expectedErrorMessage := "bad argument: accound ID must be a valid UUID"
	assert.Error(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func TestGetFrameworkCmd_RunERejectsStdinMixedWithOtherInputs(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getFrameworkCmd(&mocks.MockIKubescape{}, &scanInfo)

	err := cmd.RunE(cmd, []string{"nsa", "-", "manifests/app.yaml"})

	assert.EqualError(t, err, "usage: stdin input '-' cannot be combined with other input paths")
}

// Regression: a --custom-rules control carried no base score, so it summarized
// as "Unknown" severity, which enforceSeverityThresholds counts as exceeding
// every threshold. Any failing custom rule then failed a
// --severity-threshold critical scan.
func Test_enforceSeverityThresholds_FailingCustomRuleDoesNotTripEveryThreshold(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "no-root.rego"), []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "root user found" }`), 0o600))

	summaryDetails := summarizeCustomRules(t, dir)

	// The custom control failed on one resource.
	control := summaryDetails.Controls["custom-no-root"]
	control.StatusCounters = reportsummary.StatusCounters{FailedResources: 1}
	summaryDetails.Controls["custom-no-root"] = control

	assert.NoError(t, enforceSeverityThresholds(summaryDetails, &cautils.ScanInfo{FailThresholdSeverity: apis.SeverityCriticalString}))
	assert.NoError(t, enforceSeverityThresholds(summaryDetails, &cautils.ScanInfo{FailThresholdSeverity: apis.SeverityHighString}))

	// The rule's severity is still enforceable: it lands in the Medium bucket,
	// not in the unbucketed one the gate fails closed on.
	assert.Equal(t, apis.SeverityMediumString, apis.ControlSeverityToString(control.GetScoreFactor()))
	assert.Zero(t, countFailedResourcesWithUnbucketedSeverity(summaryDetails))
}

// summarizeCustomRules loads the custom rules under dir the way a scan does,
// so the summary carries whatever severity LoadCustomRules assigned.
func summarizeCustomRules(t *testing.T, dir string) *reportsummary.SummaryDetails {
	t.Helper()

	customFramework, err := getter.LoadCustomRules(dir)
	require.NoError(t, err)
	require.NotNil(t, customFramework)

	frameworks := []reporthandling.Framework{*customFramework}
	policies := cautils.NewPolicies()
	policies.Set(frameworks, nil, reporthandling.ScopeFile)

	summaryDetails := &reportsummary.SummaryDetails{}
	opaprocessor.ConvertFrameworksToSummaryDetails(summaryDetails, frameworks, policies)
	require.Contains(t, summaryDetails.Controls, "custom-no-root")

	return summaryDetails
}
