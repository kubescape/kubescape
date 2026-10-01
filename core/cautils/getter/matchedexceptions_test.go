package getter

import (
	"context"
	stdjson "encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilterMatchedExceptionsScopes keeps uncovered tuples and preserves all
// policies within the same source, including conflicting primary actions.
func TestFilterMatchedExceptionsScopes(t *testing.T) {
	primary := armotypes.PostureExceptionPolicy{PortalBase: armotypes.PortalBase{Name: "primary"}, PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001", FrameworkName: "NSA"}}, Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}}
	secondary := armotypes.PostureExceptionPolicy{PortalBase: armotypes.PortalBase{Name: "crd", Attributes: map[string]any{secondaryExceptionSourceAttribute: true}}, PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001", FrameworkName: "NSA"}, {ControlID: "C-0001", FrameworkName: "MITRE"}}, Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}}
	for _, tc := range []struct {
		name    string
		primary armotypes.PostureExceptionPolicy
		want    []armotypes.PosturePolicy
	}{
		{"matching framework", primary, secondary.PosturePolicies[1:]},
		{"different control", armotypes.PostureExceptionPolicy{PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0002"}}}, secondary.PosturePolicies},
		{"different rule", armotypes.PostureExceptionPolicy{PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001", RuleName: "another-rule"}}}, secondary.PosturePolicies},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []armotypes.PostureExceptionPolicy{tc.primary, secondary}
			before, err := stdjson.Marshal(in)
			require.NoError(t, err)
			got := FilterMatchedExceptions(in)
			require.Len(t, got, 2)
			assert.Equal(t, tc.want, got[1].PosturePolicies)
			after, err := stdjson.Marshal(in)
			require.NoError(t, err)
			assert.JSONEq(t, string(before), string(after))
		})
	}
	secondary2 := secondary
	secondary2.Name = "other-crd"
	assert.Equal(t, []armotypes.PostureExceptionPolicy{secondary, secondary2}, FilterMatchedExceptions([]armotypes.PostureExceptionPolicy{secondary, secondary2}))
	primary2 := primary
	primary2.Actions = []armotypes.PostureExceptionPolicyActions{armotypes.Disable}
	assert.Equal(t, []armotypes.PostureExceptionPolicy{primary, primary2}, FilterMatchedExceptions([]armotypes.PostureExceptionPolicy{primary, primary2}))
	// A saved secondary becomes primary when loaded through the primary source.
	merged, err := NewMergedExceptionsGetter(
		&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{secondary}},
		&exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{secondary2}},
	).GetExceptions(context.Background(), "cluster-a")
	require.NoError(t, err)
	require.Len(t, merged, 2) // scope-less policies are left for runtime matching
	assert.NotContains(t, merged[0].Attributes, secondaryExceptionSourceAttribute)
	assert.Contains(t, secondary.Attributes, secondaryExceptionSourceAttribute, "the caller's saved policy is unchanged")
	got := FilterMatchedExceptions(merged)
	require.Len(t, got, 1)
	assert.Equal(t, "crd", got[0].Name)
}
