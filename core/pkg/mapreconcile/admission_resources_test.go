package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admissionregistration/v1alpha1"
)

// TestMatches_PolicyExemptResourcesAreNeverMutated covers the resources the
// apiserver never runs an API-defined policy against: the admission policy
// resources and their bindings (so a policy cannot rewrite its own
// configuration), and the non-persisted review resources kube-apiserver
// excludes from every policy. A catch-all policy therefore never mutates them.
func TestMatches_PolicyExemptResourcesAreNeverMutated(t *testing.T) {
	everything := &admission.MatchResources{
		ResourceRules: []admission.NamedRuleWithOperations{
			rule([]string{"*"}, []string{"*"}, []string{"*", "*/*"}, admission.OperationAll),
		},
	}
	idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate-everything", everything)},
		[]admission.MutatingAdmissionPolicyBinding{binding("mutate-everything-binding", "mutate-everything", nil)})
	require.Empty(t, errs)

	request := func(group, resource, subresource string, operation admission.OperationType) ObjectInfo {
		return ObjectInfo{
			Group:         group,
			Version:       "v1",
			Resource:      resource,
			Subresource:   subresource,
			Name:          "some-object",
			Operation:     operation,
			ClusterScoped: true,
		}
	}

	for _, resource := range []string{
		"validatingadmissionpolicies",
		"validatingadmissionpolicybindings",
		"mutatingadmissionpolicies",
		"mutatingadmissionpolicybindings",
	} {
		assert.Empty(t, idx.Matches(request("admissionregistration.k8s.io", resource, "", admission.Update)), "%s is never admitted by an API-defined policy", resource)
		assert.Empty(t, idx.Matches(request("admissionregistration.k8s.io", resource, "status", admission.Update)), "%s/status is never admitted by an API-defined policy", resource)
	}

	for group, resources := range map[string][]string{
		"authentication.k8s.io": {"selfsubjectreviews", "tokenreviews"},
		"authorization.k8s.io":  {"localsubjectaccessreviews", "selfsubjectaccessreviews", "selfsubjectrulesreviews", "subjectaccessreviews"},
	} {
		for _, resource := range resources {
			assert.Empty(t, idx.Matches(request(group, resource, "", admission.Create)), "%s.%s is excluded from every policy", resource, group)
		}
	}

	// Webhook configurations are exempt from webhooks only, not from policies.
	assert.Len(t, idx.Matches(request("admissionregistration.k8s.io", "validatingwebhookconfigurations", "", admission.Update)), 1)
	assert.Len(t, idx.Matches(request("admissionregistration.k8s.io", "mutatingwebhookconfigurations", "", admission.Update)), 1)
}
