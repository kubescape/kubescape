package utils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
)

func TestGetColor(t *testing.T) {
	type args struct {
		severity int
	}
	type expected struct {
		colorFunc     func(...string) string
		coloredString string
	}

	tests := []struct {
		name        string
		testMessage string
		args        args
		expected    expected
	}{
		{
			name:        "Critical severity",
			testMessage: "Critical",
			args:        args{severity: apis.SeverityCritical},
			expected:    expected{colorFunc: gchalk.WithAnsi256(1).Bold, coloredString: gchalk.WithAnsi256(1).Bold("Critical")},
		},
		{
			name:        "High severity",
			testMessage: "High",
			args:        args{severity: apis.SeverityHigh},
			expected:    expected{colorFunc: gchalk.WithAnsi256(196).Bold, coloredString: gchalk.WithAnsi256(196).Bold("High")},
		},
		{
			name:        "Medium severity",
			testMessage: "Medium",
			args:        args{severity: apis.SeverityMedium},
			expected:    expected{colorFunc: gchalk.WithAnsi256(166).Bold, coloredString: gchalk.WithAnsi256(166).Bold("Medium")},
		},
		{
			name:        "Low severity",
			testMessage: "Low",
			args:        args{severity: apis.SeverityLow},
			expected:    expected{colorFunc: gchalk.WithAnsi256(220).Bold, coloredString: gchalk.WithAnsi256(220).Bold("Low")},
		},
		{
			name:        "Default case",
			testMessage: "Unknown",
			args:        args{severity: 10}, // Invalid severity
			expected:    expected{colorFunc: gchalk.WithAnsi256(16).Bold, coloredString: gchalk.WithAnsi256(16).Bold("Unknown")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			colorFunc := GetColor(tt.args.severity)
			coloredString := colorFunc(tt.testMessage) // Call the colorFunc with the same input string

			assert.Equal(t, tt.expected.coloredString, coloredString)
		})
	}
}

func TestImageSeverityToInt(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected int
	}{
		{
			name:     "Critical severity",
			severity: apis.SeverityCriticalString,
			expected: 5,
		},
		{
			name:     "High severity",
			severity: apis.SeverityHighString,
			expected: 4,
		},
		{
			name:     "Medium severity",
			severity: apis.SeverityMediumString,
			expected: 3,
		},
		{
			name:     "Low severity",
			severity: apis.SeverityLowString,
			expected: 2,
		},
		{
			name:     "Negligible severity",
			severity: apis.SeverityNegligibleString,
			expected: 1,
		},
		{
			name:     "Super critical severity",
			severity: "7",
			expected: 0,
		},
		{
			name:     "Negative severity",
			severity: "-7",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ImageSeverityToInt(tt.severity))
		})
	}
}

func TestPrintInfo(t *testing.T) {
	tests := []struct {
		name            string
		infoToPrintInfo []InfoStars
		expected        string
	}{
		{
			name: "Critical info",
			infoToPrintInfo: []InfoStars{
				InfoStars{
					Stars: "5",
					Info:  "Critical Info",
				},
			},
			expected: "🚨 5 Critical Info\n",
		},
		{
			name: "Medium and high info",
			infoToPrintInfo: []InfoStars{
				InfoStars{
					Stars: "3",
					Info:  "Medium Info",
				},
				InfoStars{
					Stars: "4",
					Info:  "High Info",
				},
			},
			expected: "🚨 3 Medium Info\n🚨 4 High Info\n",
		},
		{
			name: "Negligible and low info",
			infoToPrintInfo: []InfoStars{
				InfoStars{
					Stars: "1",
					Info:  "Negligible Info",
				},
				InfoStars{
					Stars: "2",
					Info:  "Low Info",
				},
			},
			expected: "🚨 1 Negligible Info\n🚨 2 Low Info\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			PrintInfo(f, tt.infoToPrintInfo)

			// Read the contents of the temporary file
			f.Seek(0, 0)
			got, err := ioutil.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.expected, string(got))
		})
	}
}

func TestGetColorStatus(t *testing.T) {
	type expected struct {
		colorFunc     func(...string) string
		coloredString string
	}

	tests := []struct {
		name        string
		testMessage string
		status      apis.ScanningStatus
		expected    expected
	}{
		{
			name:        "Status passed",
			testMessage: "Passed",
			status:      apis.StatusPassed,
			expected:    expected{colorFunc: gchalk.WithGreen().Bold, coloredString: gchalk.WithGreen().Bold("Passed")},
		},
		{
			name:        "Status skipped",
			testMessage: "Skipped",
			status:      apis.StatusSkipped,
			expected:    expected{colorFunc: gchalk.WithCyan().Bold, coloredString: gchalk.WithCyan().Bold("Skipped")},
		},
		{
			name:        "Status failed",
			testMessage: "Failed",
			status:      apis.StatusFailed,
			expected:    expected{colorFunc: gchalk.WithRed().Bold, coloredString: gchalk.WithRed().Bold("Failed")},
		},
		{
			name:        "Status unknown",
			testMessage: "Unknown",
			status:      apis.StatusUnknown,
			expected:    expected{colorFunc: gchalk.WithWhite().Bold, coloredString: gchalk.WithWhite().Bold("Unknown")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			colorFunc := GetStatusColor(tt.status)
			coloredString := colorFunc(tt.testMessage) // Call the colorFunc with the same input string

			assert.Equal(t, tt.expected.coloredString, coloredString)
		})
	}
}

func TestGetStatusIcon(t *testing.T) {
	tests := []struct {
		name     string
		status   apis.ScanningStatus
		expected string
	}{
		{
			name:     "Status unknown",
			status:   apis.StatusUnknown,
			expected: "⚠️",
		},
		{
			name:     "Status skipped",
			status:   apis.StatusSkipped,
			expected: "⚠️",
		},
		{
			name:     "Status failed",
			status:   apis.StatusFailed,
			expected: "❌",
		},
		{
			name:     "Status passed",
			status:   apis.StatusPassed,
			expected: "✅",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetStatusIcon(tt.status))
		})
	}
}

func TestGetColorForVulnerabilitySeverity(t *testing.T) {
	type expected struct {
		colorFunc     func(...string) string
		coloredString string
	}

	tests := []struct {
		name        string
		testMessage string
		severity    string
		expected    expected
	}{
		{
			name:        "Critical severity",
			testMessage: "Critical",
			severity:    apis.SeverityCriticalString,
			expected:    expected{colorFunc: gchalk.WithAnsi256(1).Bold, coloredString: gchalk.WithAnsi256(1).Bold("Critical")},
		},
		{
			name:        "High severity",
			testMessage: "High",
			severity:    apis.SeverityHighString,
			expected:    expected{colorFunc: gchalk.WithAnsi256(196).Bold, coloredString: gchalk.WithAnsi256(196).Bold("High")},
		},
		{
			name:        "Medium severity",
			testMessage: "Medium",
			severity:    apis.SeverityMediumString,
			expected:    expected{colorFunc: gchalk.WithAnsi256(166).Bold, coloredString: gchalk.WithAnsi256(166).Bold("Medium")},
		},
		{
			name:        "Low severity",
			testMessage: "Low",
			severity:    apis.SeverityLowString,
			expected:    expected{colorFunc: gchalk.WithAnsi256(220).Bold, coloredString: gchalk.WithAnsi256(220).Bold("Low")},
		},
		{
			name:        "Unknown case",
			testMessage: "Unknown",
			severity:    apis.SeverityUnknownString,
			expected:    expected{colorFunc: gchalk.WithAnsi256(30).Bold, coloredString: gchalk.WithAnsi256(30).Bold("Unknown")},
		},
		{
			name:        "Default case",
			testMessage: "Default",
			severity:    "",
			expected:    expected{colorFunc: gchalk.WithAnsi256(7).Bold, coloredString: gchalk.WithAnsi256(7).Bold("Default")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			colorFunc := GetColorForVulnerabilitySeverity(tt.severity)
			coloredString := colorFunc(tt.testMessage) // Call the colorFunc with the same input string

			assert.Equal(t, tt.expected.coloredString, coloredString)
		})
	}
}
