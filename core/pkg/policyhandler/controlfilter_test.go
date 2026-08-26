package policyhandler

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testControl(id, name string) reporthandling.Control {
	return reporthandling.Control{
		ControlID:  id,
		PortalBase: armotypes.PortalBase{Name: name},
	}
}

func testPolicies() []reporthandling.Framework {
	return []reporthandling.Framework{
		{
			PortalBase: armotypes.PortalBase{Name: "NSA"},
			Controls: []reporthandling.Control{
				testControl("C-0016", "Allow privilege escalation"),
				testControl("C-0017", "Immutable container filesystem"),
			},
		},
		{
			PortalBase: armotypes.PortalBase{Name: "MITRE"},
			Controls: []reporthandling.Control{
				testControl("C-0016", "Allow privilege escalation"),
				testControl("C-0035", "Cluster-admin binding"),
			},
		},
	}
}

func controlIDs(policies []reporthandling.Framework) []string {
	var ids []string
	for _, framework := range policies {
		for _, control := range framework.Controls {
			ids = append(ids, control.ControlID)
		}
	}
	return ids
}

func TestExcludeControls(t *testing.T) {
	tests := []struct {
		name          string
		exclusions    []string
		wantIDs       []string
		wantExcluded  int
		wantUnmatched []string
	}{
		{
			name:         "by control ID across every framework",
			exclusions:   []string{"C-0016"},
			wantIDs:      []string{"C-0017", "C-0035"},
			wantExcluded: 2,
		},
		{
			name:         "control ID is case-insensitive",
			exclusions:   []string{"c-0035"},
			wantIDs:      []string{"C-0016", "C-0017", "C-0016"},
			wantExcluded: 1,
		},
		{
			name:         "a control ID is trimmed",
			exclusions:   []string{"  C-0035  "},
			wantIDs:      []string{"C-0016", "C-0017", "C-0016"},
			wantExcluded: 1,
		},
		{
			name:          "a control name is not an identifier",
			exclusions:    []string{"Immutable container filesystem"},
			wantIDs:       []string{"C-0016", "C-0017", "C-0016", "C-0035"},
			wantExcluded:  0,
			wantUnmatched: []string{"Immutable container filesystem"},
		},
		{
			name:         "several identifiers at once",
			exclusions:   []string{"C-0016", "C-0035"},
			wantIDs:      []string{"C-0017"},
			wantExcluded: 3,
		},
		{
			name:         "a repeated identifier is applied once",
			exclusions:   []string{"C-0035", "c-0035"},
			wantIDs:      []string{"C-0016", "C-0017", "C-0016"},
			wantExcluded: 1,
		},
		{
			name:          "an identifier matching nothing is reported",
			exclusions:    []string{"C-9999"},
			wantIDs:       []string{"C-0016", "C-0017", "C-0016", "C-0035"},
			wantExcluded:  0,
			wantUnmatched: []string{"C-9999"},
		},
		{
			name:          "unmatched identifiers keep the order they were given",
			exclusions:    []string{"C-9999", "C-0016", "C-8888"},
			wantIDs:       []string{"C-0017", "C-0035"},
			wantExcluded:  2,
			wantUnmatched: []string{"C-9999", "C-8888"},
		},
		{
			name:         "no exclusions leaves the policies alone",
			exclusions:   nil,
			wantIDs:      []string{"C-0016", "C-0017", "C-0016", "C-0035"},
			wantExcluded: 0,
		},
		{
			name:         "blank identifiers carry no rule",
			exclusions:   []string{"", "   "},
			wantIDs:      []string{"C-0016", "C-0017", "C-0016", "C-0035"},
			wantExcluded: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := excludeControls(testPolicies(), tt.exclusions)
			require.NoError(t, err)

			assert.Equal(t, tt.wantIDs, controlIDs(result.policies))
			assert.Equal(t, tt.wantExcluded, result.excluded)
			assert.Equal(t, tt.wantUnmatched, nonEmpty(result.unmatched))
		})
	}
}

func nonEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return values
}

// A control's CIS section number lives in the legacy "id" field.
func TestExcludeControlsMatchesCISSectionNumber(t *testing.T) {
	policies := []reporthandling.Framework{{
		Controls: []reporthandling.Control{
			{ControlID: "C-0286", Control_ID: "CIS-3.1.1", PortalBase: armotypes.PortalBase{Name: "Client certificate authentication"}},
			testControl("C-0002", "kept"),
		},
	}}

	result, err := excludeControls(policies, []string{"cis-3.1.1"})
	require.NoError(t, err)

	assert.Equal(t, 1, result.excluded)
	assert.Equal(t, []string{"C-0002"}, controlIDs(result.policies))
}

func TestExcludeControlsRejectsAnEmptyScan(t *testing.T) {
	result, err := excludeControls(testPolicies(), []string{"C-0016", "C-0017", "C-0035"})

	require.ErrorIs(t, err, errAllControlsExcluded)
	assert.Nil(t, result.policies)
}

// The frameworks handed to excludeControls are the ones held in the policy cache, so a
// long-lived process must not see one scan's exclusions in the next scan.
func TestExcludeControlsLeavesTheInputUntouched(t *testing.T) {
	policies := testPolicies()

	result, err := excludeControls(policies, []string{"C-0016"})
	require.NoError(t, err)

	assert.Equal(t, []string{"C-0016", "C-0017", "C-0016", "C-0035"}, controlIDs(policies))
	assert.Equal(t, []string{"C-0017", "C-0035"}, controlIDs(result.policies))
}

func TestQuoteIdentifiersKeepsSplitValuesApart(t *testing.T) {
	assert.Equal(t, `"alpha", "beta"`, quoteIdentifiers([]string{"alpha", "beta"}))
	assert.Equal(t, `"alpha, beta"`, quoteIdentifiers([]string{"alpha, beta"}))
	assert.Empty(t, quoteIdentifiers(nil))
}

func TestExcludeControlsMarksEveryAliasOfAMatchedControl(t *testing.T) {
	policies := []reporthandling.Framework{{
		Controls: []reporthandling.Control{
			{ControlID: "C-0286", Control_ID: "CIS-3.1.1", PortalBase: armotypes.PortalBase{Name: "Client certificate authentication"}},
			testControl("C-0002", "kept"),
		},
	}}

	result, err := excludeControls(policies, []string{"C-0286", "CIS-3.1.1"})
	require.NoError(t, err)

	assert.Equal(t, 1, result.excluded)
	assert.Equal(t, []string{"C-0002"}, controlIDs(result.policies))
	assert.Empty(t, result.unmatched)
}
