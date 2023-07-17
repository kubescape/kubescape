package opaprocessor

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func TestConvertFrameworksToPolicies(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()
	policies := ConvertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, "", &cautils.ScanInfo{InputPatterns: []string{""}})
	assert.Equal(t, 2, len(policies.Frameworks))
	assert.Equal(t, 3, len(policies.Controls))
}
func TestInitializeSummaryDetails(t *testing.T) {
	fw0 := mocks.MockFramework_0006_0013()
	fw1 := mocks.MockFramework_0044()

	summaryDetails := reportsummary.SummaryDetails{}
	frameworks := []reporthandling.Framework{*fw0, *fw1}
	policies := ConvertFrameworksToPolicies([]reporthandling.Framework{*fw0, *fw1}, "", &cautils.ScanInfo{InputPatterns: []string{""}})
	ConvertFrameworksToSummaryDetails(&summaryDetails, frameworks, policies)
	assert.Equal(t, 2, len(summaryDetails.Frameworks))
	// assert.Equal(t, 3, len(summaryDetails.Controls))
}

func TestParseIntEnvVar(t *testing.T) {
	testCases := []struct {
		expectedErr  string
		name         string
		varName      string
		varValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "Variable does not exist",
			varName:      "DOES_NOT_EXIST",
			varValue:     "",
			defaultValue: 123,
			expected:     123,
			expectedErr:  "",
		},
		{
			name:         "Variable exists and is a valid integer",
			varName:      "MY_VAR",
			varValue:     "456",
			defaultValue: 123,
			expected:     456,
			expectedErr:  "",
		},
		{
			name:         "Variable exists but is not a valid integer",
			varName:      "MY_VAR",
			varValue:     "not_an_integer",
			defaultValue: 123,
			expected:     123,
			expectedErr:  "failed to parse MY_VAR env var as int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.varValue != "" {
				os.Setenv(tc.varName, tc.varValue)
			} else {
				os.Unsetenv(tc.varName)
			}

			actual, err := parseIntEnvVar(tc.varName, tc.defaultValue)
			if tc.expectedErr != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.Nil(t, err)
			}

			assert.Equalf(t, tc.expected, actual, "unexpected result")
		})
	}
}
