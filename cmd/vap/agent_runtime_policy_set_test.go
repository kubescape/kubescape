package vap

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

func TestAgentRuntimePolicySetIsAvailableToVAPCommands(t *testing.T) {
	policies := []struct {
		controlID   string
		name        string
		takesParams bool
	}{
		{"C-0297", "kubescape-c-0297-agent-sandbox-runtime-isolation", true},
		{"C-0309", "kubescape-c-0309-agent-sandbox-token-automount", false},
		{"C-0311", "kubescape-c-0311-agent-sandbox-container-limits", false},
		{"C-0312", "kubescape-c-0312-agent-sandbox-image-digests", false},
		{"C-0313", "kubescape-c-0313-agent-sandbox-image-registries", true},
		{"C-0314", "kubescape-c-0314-agent-sandbox-managed-networking", false},
	}

	var listed []policyListEntry
	require.NoError(t, json.Unmarshal([]byte(listOutput(t, formatJSON, true)), &listed))
	listedByControl := make(map[string]policyListEntry, len(listed))
	for _, policy := range listed {
		listedByControl[policy.ControlID] = policy
	}

	deployed, err := deployLibrary("", 0)
	require.NoError(t, err)

	for _, policy := range policies {
		t.Run(policy.controlID, func(t *testing.T) {
			entry, ok := listedByControl[policy.controlID]
			require.True(t, ok, "policy must appear in vap list-policies --controls-only")
			assert.Equal(t, policy.name, entry.Policy)
			assert.Equal(t, policy.takesParams, entry.TakesParams)

			assert.Contains(t, deployed, "name: "+policy.name,
				"vap deploy-library must include the same policy that the CLI lists")

			resolved, err := resolvePolicyName("", policy.controlID)
			require.NoError(t, err)
			assert.Equal(t, policy.name, resolved)

			parameterReference := ""
			if policy.takesParams {
				parameterReference = "basic-control-configuration"
			}
			bindingYAML, err := createPolicyBinding(
				"agent-runtime-"+policy.controlID[2:],
				resolved,
				[]admissionv1.ValidationAction{admissionv1.Warn, admissionv1.Audit},
				parameterReference,
				nil,
				nil,
				nil,
			)
			require.NoError(t, err)

			var binding admissionv1.ValidatingAdmissionPolicyBinding
			require.NoError(t, yaml.Unmarshal([]byte(bindingYAML), &binding))
			assert.Equal(t, policy.name, binding.Spec.PolicyName)
			assert.Equal(t, []admissionv1.ValidationAction{admissionv1.Warn, admissionv1.Audit}, binding.Spec.ValidationActions)
			if policy.takesParams {
				require.NotNil(t, binding.Spec.ParamRef)
				assert.Equal(t, parameterReference, binding.Spec.ParamRef.Name)
			} else {
				assert.Nil(t, binding.Spec.ParamRef)
			}
		})
	}
}
