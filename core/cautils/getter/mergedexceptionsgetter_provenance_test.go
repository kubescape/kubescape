package getter

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMergedExceptionsGetter_NormalizesPrimaryProvenance ensures a saved CRD
// becomes primary regardless of whether the secondary source returns policies.
func TestMergedExceptionsGetter_NormalizesPrimaryProvenance(t *testing.T) {
	saved := armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Name: "saved-crd",
			Attributes: map[string]any{
				secondaryExceptionSourceAttribute: true,
				"description":                     "preserved metadata",
			},
		},
		PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001"}},
		Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
	}
	fresh := armotypes.PostureExceptionPolicy{
		PortalBase:      armotypes.PortalBase{Name: "fresh-primary"},
		PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0001"}},
		Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
	}
	data, err := stdjson.Marshal([]armotypes.PostureExceptionPolicy{saved, fresh})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "exceptions.json")
	require.NoError(t, os.WriteFile(path, data, 0600))

	for _, source := range []string{"file", "reused policies"} {
		for _, tc := range []struct {
			name      string
			secondary IExceptionsGetter
		}{
			{name: "nil secondary"},
			{name: "empty secondary", secondary: &exceptionsGetterStub{}},
			{name: "failed secondary", secondary: &exceptionsGetterStub{err: errors.New("CRD access denied")}},
			{name: "unrelated secondary", secondary: &exceptionsGetterStub{exceptions: []armotypes.PostureExceptionPolicy{
				{PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0002"}}},
			}}},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				var primary IExceptionsGetter = NewLoadPolicy([]string{path})
				var original []armotypes.PostureExceptionPolicy
				if source == "reused policies" {
					require.NoError(t, stdjson.Unmarshal(data, &original))
					primary = &exceptionsGetterStub{exceptions: original}
				}
				merged := NewMergedExceptionsGetter(primary, tc.secondary)
				for range 2 {
					got, err := merged.GetExceptions(context.Background(), "cluster-a")
					require.NoError(t, err)
					require.GreaterOrEqual(t, len(got), 2)
					assert.NotContains(t, got[0].Attributes, secondaryExceptionSourceAttribute)
					assert.Equal(t, "preserved metadata", got[0].Attributes["description"])
					matched := FilterMatchedExceptions(exceptions.FilterExceptionsByFrameworks(got, nil, "C-0001", "test-rule"))
					require.Len(t, matched, 2, "both primary actions must survive post-match filtering")
					rule := resourcesresults.ResourceAssociatedRule{Name: "test-rule", Status: apis.StatusFailed, Exception: matched}
					assert.True(t, rule.GetStatus(nil).IsPassed(), "the saved primary Disable must still suppress the finding")
				}
				if original != nil {
					after, err := stdjson.Marshal(original)
					require.NoError(t, err)
					assert.JSONEq(t, string(data), string(after), "normalization must not mutate a reusable source slice or its attribute maps")
				}
				after, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, data, after, "normalization must not rewrite the source file")
			})
		}
	}
}
