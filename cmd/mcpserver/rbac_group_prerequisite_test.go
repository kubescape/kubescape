package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRBACGroupImpersonationRequiresAuthorizedUsername(t *testing.T) {
	cases := []struct {
		name              string
		identityResources []string
		identityNames     []string
		groupNames        []string
		wantAdmin         bool
	}{
		{name: "unrestricted groups alone"},
		{name: "system masters alone", groupNames: []string{"system:masters"}},
		{name: "privileged group alone", groupNames: []string{"privileged"}},
		{name: "groups and named user", identityResources: []string{"users"}, identityNames: []string{"alice"}, groupNames: []string{"system:masters"}, wantAdmin: true},
		{name: "groups and uncollected SA", identityResources: []string{"serviceaccounts"}, identityNames: []string{"deleted-worker"}, groupNames: []string{"system:masters"}, wantAdmin: true},
		{name: "empty user restriction", identityResources: []string{"users"}, identityNames: []string{""}, groupNames: []string{"system:masters"}},
		{name: "SA-form users grant", identityResources: []string{"users"}, identityNames: []string{"system:serviceaccount:prod:worker"}, groupNames: []string{"system:masters"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := []map[string]any{unstructuredPolicyRule([]string{""}, []string{"groups"}, []string{"impersonate"}, tc.groupNames)}
			if len(tc.identityResources) > 0 {
				rules = append(rules, unstructuredPolicyRule([]string{""}, tc.identityResources, []string{"impersonate"}, tc.identityNames))
			}
			objects := []runtime.Object{
				unstructuredServiceAccount("prod", "caller"),
				unstructuredClusterRole("impersonator", rules...),
				unstructuredClusterRoleBinding("grant", "impersonator", "prod", "caller"),
				unstructuredClusterRole("power", unstructuredPolicyRule([]string{"*"}, []string{"*"}, []string{"*"}, nil)),
			}
			groupBinding := unstructuredClusterRoleBinding("group-power", "power", "", "")
			groupBinding.Object["subjects"] = []any{map[string]any{"kind": "Group", "name": "privileged"}}
			objects = append(objects, groupBinding)
			ksServer := newRBACEscalationTestServer(t, objects...)
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
				"subject_kind": "ServiceAccount", "namespace": "prod", "name": "caller",
			}))
			require.False(t, result.IsError)
			var output struct {
				Admin   bool             `json:"cluster_admin_equivalent"`
				Reached []map[string]any `json:"reached"`
			}
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &output))
			require.Equal(t, tc.wantAdmin, output.Admin)
			if !tc.wantAdmin {
				require.Empty(t, output.Reached)
			}
		})
	}
}

func TestRBACGroupImpersonationDoesNotChangeDirectGroupPermissions(t *testing.T) {
	// Analyzing a Group as the starting compromised identity is different
	// from claiming that another identity can impersonate that group.
	admin := unstructuredClusterRole("power", unstructuredPolicyRule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binding := unstructuredClusterRoleBinding("group-power", "power", "", "")
	binding.Object["subjects"] = []any{map[string]any{"kind": "Group", "name": "operators"}}
	ksServer := newRBACEscalationTestServer(t, admin, binding)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "Group", "name": "operators",
	}))
	require.False(t, result.IsError)
	var output map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &output))
	require.Equal(t, true, output["cluster_admin_equivalent"])
}
