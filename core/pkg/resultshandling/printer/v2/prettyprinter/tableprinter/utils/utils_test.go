package utils

import (
	"io"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruncateName(t *testing.T) {
	t.Run("short name is unchanged", func(t *testing.T) {
		assert.Equal(t, "short", TruncateName("short", 50))
	})

	t.Run("ASCII name longer than max is truncated with ellipsis", func(t *testing.T) {
		name := strings.Repeat("a", 60)
		got := TruncateName(name, 50)
		assert.Equal(t, strings.Repeat("a", 50)+"...", got)
	})

	t.Run("name exactly at max length is unchanged", func(t *testing.T) {
		name := strings.Repeat("a", 50)
		assert.Equal(t, name, TruncateName(name, 50))
	})

	// Regression: byte-index slicing (name[:50]) can split a multi-byte
	// UTF-8 rune in half, producing invalid UTF-8. Truncating by rune count
	// must never do that.
	t.Run("multi-byte UTF-8 name is truncated on a rune boundary", func(t *testing.T) {
		name := strings.Repeat("héllo-世界-", 10) // multi-byte runes throughout, > 50 bytes and > 50 runes
		require.Greater(t, len([]byte(name)), 50)
		require.Greater(t, len([]rune(name)), 50)

		got := TruncateName(name, 50)

		require.True(t, utf8.ValidString(got), "truncated name must be valid UTF-8")
		require.True(t, strings.HasSuffix(got, "..."))
		require.Equal(t, 50, len([]rune(strings.TrimSuffix(got, "..."))), "must truncate by rune count, not byte count")
	})
}

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
				{
					Stars: "5",
					Info:  "Critical Info",
				},
			},
			expected: "\n🚨 5 Critical Info\n",
		},
		{
			name: "Medium and high info",
			infoToPrintInfo: []InfoStars{
				{
					Stars: "3",
					Info:  "Medium Info",
				},
				{
					Stars: "4",
					Info:  "High Info",
				},
			},
			expected: "\n🚨 3 Medium Info\n🚨 4 High Info\n",
		},
		{
			name: "Negligible and low info",
			infoToPrintInfo: []InfoStars{
				{
					Stars: "1",
					Info:  "Negligible Info",
				},
				{
					Stars: "2",
					Info:  "Low Info",
				},
			},
			expected: "\n🚨 1 Negligible Info\n🚨 2 Low Info\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			PrintInfo(f, tt.infoToPrintInfo)

			f.Seek(0, 0)
			got, err := io.ReadAll(f)
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

func TestCheckShortTerminalWidth(t *testing.T) {
	tests := []struct {
		name    string
		rows    []table.Row
		headers table.Row
		// We can't predict the exact result since it depends on terminal size
		// but we can test it doesn't panic with various inputs
		shouldNotPanic bool
	}{
		{
			name: "Normal string rows",
			rows: []table.Row{
				{"cell1", "cell2", "cell3"},
				{"longer cell 1", "longer cell 2", "longer cell 3"},
			},
			headers:        table.Row{"Header1", "Header2", "Header3"},
			shouldNotPanic: true,
		},
		{
			name: "Rows with non-string values (map)",
			rows: []table.Row{
				{"cell1", map[string]any{"key": "value"}, "cell3"},
				{"cell4", "cell5", "cell6"},
			},
			headers:        table.Row{"Header1", "Header2", "Header3"},
			shouldNotPanic: true,
		},
		{
			name: "Headers with non-string values",
			rows: []table.Row{
				{"cell1", "cell2", "cell3"},
			},
			headers:        table.Row{"Header1", map[string]any{"key": "value"}, "Header3"},
			shouldNotPanic: true,
		},
		{
			name: "Both rows and headers with non-string values",
			rows: []table.Row{
				{map[string]any{"key": "value"}, "cell2", 123},
			},
			headers:        table.Row{[]string{"a", "b"}, "Header2", true},
			shouldNotPanic: true,
		},
		{
			name:           "Empty rows",
			rows:           []table.Row{},
			headers:        table.Row{"Header1", "Header2"},
			shouldNotPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if tt.shouldNotPanic {
						t.Errorf("CheckShortTerminalWidth() panicked when it shouldn't: %v", r)
					}
				}
			}()
			// Call the function - we just want to ensure it doesn't panic
			_ = CheckShortTerminalWidth(tt.rows, tt.headers)
		})
	}
}
