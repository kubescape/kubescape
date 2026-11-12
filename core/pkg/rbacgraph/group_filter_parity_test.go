package rbacgraph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters/impersonation"
	"k8s.io/apiserver/pkg/endpoints/request"
)

// Run the upstream impersonation filter, rather than assuming that a group
// authorization alone is a valid request. Only its RBAC decision is stubbed.
func groupImpersonationFilterStatus(t *testing.T, rules []ScopedRule, username string) int {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	codec := serializer.NewCodecFactory(scheme)
	authz := authorizer.AuthorizerFunc(func(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		for _, sr := range rules {
			if sr.Namespace != "" && sr.Namespace != a.GetNamespace() {
				continue
			}
			if ruleGrants(sr.Rule, a.GetAPIGroup(), a.GetResource(), a.GetVerb()) &&
				(len(sr.Rule.ResourceNames) == 0 || resourceNameMatches(sr.Rule.ResourceNames, a.GetName())) {
				return authorizer.DecisionAllow, "fixture grant", nil
			}
		}
		return authorizer.DecisionDeny, "no fixture grant", nil
	})
	handler := impersonation.WithImpersonation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual, ok := request.UserFrom(r.Context())
		require.True(t, ok)
		require.Equal(t, username, actual.GetName())
		require.Contains(t, actual.GetGroups(), "system:masters")
		w.WriteHeader(http.StatusNoContent)
	}), authz, codec)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/prod/pods", nil)
	req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{Name: "caller", Groups: []string{user.AllAuthenticated}}))
	if username != "" {
		req.Header.Set(authenticationv1.ImpersonateUserHeader, username)
	}
	req.Header.Set(authenticationv1.ImpersonateGroupHeader, "system:masters")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response.Code
}

func TestGroupPrerequisiteMatchesUpstreamImpersonationFilter(t *testing.T) {
	identityGrant := func(resource, scope string, names ...string) ScopedRule {
		return ScopedRule{Namespace: scope, Rule: rule([]string{""}, []string{resource}, []string{"impersonate"}, names)}
	}
	groupGrant := ScopedRule{Rule: rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"})}
	cases := []struct {
		name     string
		username string
		grants   []ScopedRule
		status   int
	}{
		{name: "group header alone", status: http.StatusBadRequest},
		{name: "own username still needs authorization", username: "caller", status: http.StatusForbidden},
		{name: "another username needs authorization", username: "alice", status: http.StatusForbidden},
		{name: "unrestricted users", username: "alice", grants: []ScopedRule{identityGrant("users", "")}, status: http.StatusNoContent},
		{name: "literal user restriction", username: "alice", grants: []ScopedRule{identityGrant("users", "", "alice")}, status: http.StatusNoContent},
		{name: "anonymous is a user", username: user.Anonymous, grants: []ScopedRule{identityGrant("users", "", user.Anonymous)}, status: http.StatusNoContent},
		{name: "literal asterisk username", username: "*", grants: []ScopedRule{identityGrant("users", "", "*")}, status: http.StatusNoContent},
		{name: "namespace cannot authorize users", username: "alice", grants: []ScopedRule{identityGrant("users", "prod", "alice")}, status: http.StatusForbidden},
		{name: "SA username is not users", username: "system:serviceaccount:prod:worker", grants: []ScopedRule{identityGrant("users", "", "system:serviceaccount:prod:worker")}, status: http.StatusForbidden},
		{name: "namespaced SA permission", username: "system:serviceaccount:prod:worker", grants: []ScopedRule{identityGrant("serviceaccounts", "prod", "worker")}, status: http.StatusNoContent},
		{name: "cluster-wide SA permission", username: "system:serviceaccount:prod:worker", grants: []ScopedRule{identityGrant("serviceaccounts", "", "worker")}, status: http.StatusNoContent},
		{name: "empty user restriction", username: "alice", grants: []ScopedRule{identityGrant("users", "", "")}, status: http.StatusForbidden},
		{name: "token create does not impersonate", username: "system:serviceaccount:prod:worker", grants: []ScopedRule{{Rule: rule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}, []string{"worker"})}}, status: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := append([]ScopedRule{groupGrant}, tc.grants...)
			status := groupImpersonationFilterStatus(t, rules, tc.username)
			require.Equal(t, tc.status, status)
			roles := []rbacv1.ClusterRole{clusterRole("groups", groupGrant.Rule)}
			clusterBindings := []rbacv1.ClusterRoleBinding{clusterRoleBinding("groups", "groups", saSubject("prod", "caller"))}
			var namespacedRoles []rbacv1.Role
			var bindings []rbacv1.RoleBinding
			for _, grant := range tc.grants {
				if grant.Namespace == "" {
					roles = append(roles, clusterRole("identity", grant.Rule))
					clusterBindings = append(clusterBindings, clusterRoleBinding("identity", "identity", saSubject("prod", "caller")))
				} else {
					namespacedRoles = append(namespacedRoles, role(grant.Namespace, "identity", grant.Rule))
					bindings = append(bindings, roleBinding(grant.Namespace, "identity", "Role", "identity", saSubject("prod", "caller")))
				}
			}
			graph := NewIndex(namespacedRoles, roles, bindings, clusterBindings, nil).AnalyzeEscalation(sa("prod", "caller"))
			require.Equal(t, status == http.StatusNoContent, graph.ClusterAdmin)
			require.False(t, graph.Truncated)
		})
	}
}
