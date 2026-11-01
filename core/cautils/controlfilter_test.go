package cautils

import (
	"os"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureFilterWarnings redirects the global logger output to a temporary file.
// The logger is global, so callers must not run in parallel.
func captureFilterWarnings(t *testing.T) func() string {
	t.Helper()
	logFile, err := os.CreateTemp(t.TempDir(), "controlfilter-log-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })
	log := logger.L()
	previousWriter, previousLevel := log.GetWriter(), log.GetLevel()
	log.SetWriter(logFile)
	require.NoError(t, log.SetLevel("warning"))
	t.Cleanup(func() {
		log.SetWriter(previousWriter)
		_ = log.SetLevel(previousLevel)
	})
	return func() string {
		t.Helper()
		output, err := os.ReadFile(logFile.Name())
		require.NoError(t, err)
		return string(output)
	}
}

func TestSplitCommaList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "whitespace only",
			input:    "    ",
			expected: []string{},
		},
		{
			name:     "only commas and spaces",
			input:    " , , ,  ",
			expected: []string{},
		},
		{
			name:     "single token",
			input:    "C-0001",
			expected: []string{"C-0001"},
		},
		{
			name:     "multiple tokens comma separated",
			input:    "C-0001,C-0002,C-0003",
			expected: []string{"C-0001", "C-0002", "C-0003"},
		},
		{
			name:     "tokens with surrounding spaces and trailing/leading commas",
			input:    " , C-0001 ,  C-0002,  CIS-1.1.1 , ",
			expected: []string{"C-0001", "C-0002", "CIS-1.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCommaList(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestControlIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		control  *reporthandling.Control
		expected []string
	}{
		{
			name: "both ControlID and Control_ID present",
			control: &reporthandling.Control{
				ControlID:  "C-0286",
				Control_ID: "CIS-3.1.1",
			},
			expected: []string{"c-0286", "cis-3.1.1"},
		},
		{
			name: "only ControlID present",
			control: &reporthandling.Control{
				ControlID: "C-0012",
			},
			expected: []string{"c-0012"},
		},
		{
			name: "only Control_ID present",
			control: &reporthandling.Control{
				Control_ID: "CIS-1.2.3",
			},
			expected: []string{"cis-1.2.3"},
		},
		{
			name: "both IDs are identical case-insensitively",
			control: &reporthandling.Control{
				ControlID:  "C-0012",
				Control_ID: "c-0012",
			},
			expected: []string{"c-0012"},
		},
		{
			name: "whitespace in IDs is trimmed and lowercased",
			control: &reporthandling.Control{
				ControlID:  "  C-0012  ",
				Control_ID: " CIS-5.2.1 ",
			},
			expected: []string{"c-0012", "cis-5.2.1"},
		},
		{
			name:     "empty control",
			control:  &reporthandling.Control{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ControlIdentifiers(tt.control)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestControlMatchesAny(t *testing.T) {
	control := &reporthandling.Control{
		ControlID:  "C-0286",
		Control_ID: "CIS-3.1.1",
	}

	tests := []struct {
		name     string
		set      map[string]struct{}
		expected bool
	}{
		{
			name: "matches by lowercase ControlID",
			set: map[string]struct{}{
				"c-0286": {},
			},
			expected: true,
		},
		{
			name: "matches by lowercase Control_ID",
			set: map[string]struct{}{
				"cis-3.1.1": {},
			},
			expected: true,
		},
		{
			name: "does not match unrelated control",
			set: map[string]struct{}{
				"c-0001": {},
			},
			expected: false,
		},
		{
			name:     "empty set",
			set:      map[string]struct{}{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ControlMatchesAny(control, tt.set)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func sampleFrameworks() []reporthandling.Framework {
	return []reporthandling.Framework{
		{
			PortalBase: armotypes.PortalBase{Name: "nsa"},
			Controls: []reporthandling.Control{
				{
					ControlID:  "C-0001",
					Control_ID: "CIS-1.1",
					PortalBase: armotypes.PortalBase{Name: "Control One"},
				},
				{
					ControlID:  "C-0002",
					Control_ID: "CIS-1.2",
					PortalBase: armotypes.PortalBase{Name: "Control Two"},
				},
				{
					ControlID:  "C-0003",
					Control_ID: "CIS-1.3",
					PortalBase: armotypes.PortalBase{Name: "Control Three"},
				},
			},
		},
		{
			PortalBase: armotypes.PortalBase{Name: "mitre"},
			Controls: []reporthandling.Control{
				{
					ControlID:  "C-0002",
					Control_ID: "CIS-1.2",
					PortalBase: armotypes.PortalBase{Name: "Control Two"},
				},
				{
					ControlID:  "C-0004",
					Control_ID: "CIS-1.4",
					PortalBase: armotypes.PortalBase{Name: "Control Four"},
				},
			},
		},
	}
}

func TestFilterFrameworkControls_EmptyFilters(t *testing.T) {
	frameworks := sampleFrameworks()

	filtered, err := FilterFrameworkControls(frameworks, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, frameworks, filtered, "empty filters must return original slice without error")

	filtered, err = FilterFrameworkControls(frameworks, []string{}, []string{})
	require.NoError(t, err)
	assert.Equal(t, frameworks, filtered, "empty slices must return original slice without error")
}

func TestFilterFrameworkControls_IncludeWhitelist(t *testing.T) {
	frameworks := sampleFrameworks()

	filtered, err := FilterFrameworkControls(frameworks, nil, []string{"c-0001", "C-0004"})
	require.NoError(t, err)
	require.Len(t, filtered, 2)

	// Framework 1 (nsa) should keep only C-0001
	require.Len(t, filtered[0].Controls, 1)
	assert.Equal(t, "C-0001", filtered[0].Controls[0].ControlID)

	// Framework 2 (mitre) should keep only C-0004
	require.Len(t, filtered[1].Controls, 1)
	assert.Equal(t, "C-0004", filtered[1].Controls[0].ControlID)
}

func TestFilterFrameworkControls_SkipBlacklist(t *testing.T) {
	frameworks := sampleFrameworks()

	filtered, err := FilterFrameworkControls(frameworks, []string{"C-0002"}, nil)
	require.NoError(t, err)
	require.Len(t, filtered, 2)

	// Framework 1 (nsa) has C-0001 and C-0003
	require.Len(t, filtered[0].Controls, 2)
	assert.Equal(t, "C-0001", filtered[0].Controls[0].ControlID)
	assert.Equal(t, "C-0003", filtered[0].Controls[1].ControlID)

	// Framework 2 (mitre) has only C-0004 remaining
	require.Len(t, filtered[1].Controls, 1)
	assert.Equal(t, "C-0004", filtered[1].Controls[0].ControlID)
}

func TestFilterFrameworkControls_SkipWinsOverInclude(t *testing.T) {
	frameworks := sampleFrameworks()

	// C-0002 is both included and skipped -> skip must take precedence
	filtered, err := FilterFrameworkControls(frameworks, []string{"C-0002"}, []string{"C-0001", "C-0002"})
	require.NoError(t, err)
	require.Len(t, filtered, 2)

	// Framework 1 (nsa) retains only C-0001
	require.Len(t, filtered[0].Controls, 1)
	assert.Equal(t, "C-0001", filtered[0].Controls[0].ControlID)

	// Framework 2 (mitre) retains nothing
	require.Len(t, filtered[1].Controls, 0)
}

func TestFilterFrameworkControls_MatchesSectionNumber(t *testing.T) {
	frameworks := sampleFrameworks()

	// Matching by CIS-1.3 (Control_ID)
	filtered, err := FilterFrameworkControls(frameworks, nil, []string{"cis-1.3"})
	require.NoError(t, err)
	require.Len(t, filtered, 2)

	require.Len(t, filtered[0].Controls, 1)
	assert.Equal(t, "C-0003", filtered[0].Controls[0].ControlID)
	assert.Equal(t, "CIS-1.3", filtered[0].Controls[0].Control_ID)

	require.Len(t, filtered[1].Controls, 0)
}

func TestFilterFrameworkControls_UnknownControlsWarning(t *testing.T) {
	readWarnings := captureFilterWarnings(t)
	frameworks := sampleFrameworks()

	// Skip control that does not exist and include control that does not exist alongside a valid one
	filtered, err := FilterFrameworkControls(frameworks, []string{"C-9999"}, []string{"C-0001", "C-8888"})
	require.NoError(t, err)
	require.Len(t, filtered, 2)

	require.Len(t, filtered[0].Controls, 1)
	assert.Equal(t, "C-0001", filtered[0].Controls[0].ControlID)

	warnings := readWarnings()
	assert.Contains(t, warnings, "skip control not found in loaded policies")
	assert.Contains(t, strings.ToLower(warnings), "c-9999")
	assert.Contains(t, warnings, "include control not found in loaded policies")
	assert.Contains(t, strings.ToLower(warnings), "c-8888")
	assert.Equal(t, 1, strings.Count(warnings, "skip control not found in loaded policies"), "one warning for unknown skip control")
	assert.Equal(t, 1, strings.Count(warnings, "include control not found in loaded policies"), "one warning for unknown include control")
}

func TestFilterFrameworkControls_ErrIncludeControlsNoMatch(t *testing.T) {
	frameworks := sampleFrameworks()

	// None of the included controls match any loaded framework
	filtered, err := FilterFrameworkControls(frameworks, nil, []string{"C-9999", "C-8888"})
	assert.Nil(t, filtered)
	assert.ErrorIs(t, err, ErrIncludeControlsNoMatch)
}

func TestFilterFrameworkControls_ErrNoControlsAfterFilter(t *testing.T) {
	frameworks := sampleFrameworks()

	// Skip every control in the frameworks
	allIDs := []string{"C-0001", "C-0002", "C-0003", "C-0004"}
	filtered, err := FilterFrameworkControls(frameworks, allIDs, nil)
	assert.Nil(t, filtered)
	assert.ErrorIs(t, err, ErrNoControlsAfterFilter)

	// Include one control but also skip it
	filtered, err = FilterFrameworkControls(frameworks, []string{"C-0001"}, []string{"C-0001"})
	assert.Nil(t, filtered)
	assert.ErrorIs(t, err, ErrNoControlsAfterFilter)
}

func TestFilterFrameworkControls_Immutability(t *testing.T) {
	frameworks := sampleFrameworks()

	// Snapshot original controls to verify no aliasing or in-place overwriting
	originalControls0 := make([]reporthandling.Control, len(frameworks[0].Controls))
	copy(originalControls0, frameworks[0].Controls)
	originalControls1 := make([]reporthandling.Control, len(frameworks[1].Controls))
	copy(originalControls1, frameworks[1].Controls)

	filtered, err := FilterFrameworkControls(frameworks, nil, []string{"C-0001"})
	require.NoError(t, err)
	require.Len(t, filtered, 2)
	require.Len(t, filtered[0].Controls, 1)

	// Check them after filtering to ensure filtering did not mutate or overwrite the original backing arrays
	assert.Equal(t, originalControls0, frameworks[0].Controls, "original framework 0 controls must not be modified during filtering")
	assert.Equal(t, originalControls1, frameworks[1].Controls, "original framework 1 controls must not be modified during filtering")

	// Mutate a retained result element and verify the original remains unchanged
	filtered[0].Controls[0].ControlID = "C-MUTATED"
	filtered[0].Controls[0].Name = "Mutated Name"
	assert.Equal(t, originalControls0[0].ControlID, frameworks[0].Controls[0].ControlID, "original control ID must remain unchanged when mutating retained result element")
	assert.Equal(t, originalControls0[0].Name, frameworks[0].Controls[0].Name, "original control name must remain unchanged when mutating retained result element")
	assert.Equal(t, originalControls0, frameworks[0].Controls, "original framework 0 controls must remain completely unchanged")

	// Modifying the filtered controls slice must not affect original framework controls slice
	filtered[0].Controls = append(filtered[0].Controls, reporthandling.Control{ControlID: "C-APPENDED"})
	assert.Equal(t, originalControls0, frameworks[0].Controls, "original framework controls must not be mutated by append")
}

func TestEffectiveControlIDs(t *testing.T) {
	frameworks := sampleFrameworks()

	t.Run("valid filter returns set of control IDs", func(t *testing.T) {
		ids := EffectiveControlIDs(frameworks, "C-0002", "C-0001, C-0002, C-0004")
		expected := map[string]struct{}{
			"C-0001": {},
			"C-0004": {},
		}
		assert.Equal(t, expected, ids)
	})

	t.Run("no match error returns nil", func(t *testing.T) {
		ids := EffectiveControlIDs(frameworks, "", "C-9999")
		assert.Nil(t, ids)
	})

	t.Run("all excluded returns nil", func(t *testing.T) {
		ids := EffectiveControlIDs(frameworks, "C-0001,C-0002,C-0003,C-0004", "")
		assert.Nil(t, ids)
	})
}
