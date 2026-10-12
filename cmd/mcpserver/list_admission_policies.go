package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
)

// admissionPolicyEntry mirrors the JSON shape of `kubescape vap list-policies
// --format json`, so both surfaces describe a policy identically.
type admissionPolicyEntry struct {
	Policy           string   `json:"policy"`
	ControlID        string   `json:"controlID,omitempty"`
	TakesParams      bool     `json:"takesParams"`
	FailurePolicy    string   `json:"failurePolicy,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	DuplicateName    bool     `json:"duplicateName,omitempty"`
	DuplicateControl bool     `json:"duplicateControl,omitempty"`
}

// ListAdmissionPolicies lists the ValidatingAdmissionPolicies in the CEL
// admission policy library embedded in this binary. It reads the same catalog
// as `kubescape vap list-policies` and never touches a cluster.
func (ksServer *KubescapeMcpserver) ListAdmissionPolicies(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return listAdmissionPolicies(cel.ListPolicies)
}

func listAdmissionPolicies(list func() ([]cel.PolicyInfo, error)) ([]byte, error) {
	policies, err := list()
	if err != nil {
		return nil, fmt.Errorf("read embedded policy library: %w", err)
	}
	entries := make([]admissionPolicyEntry, 0, len(policies))
	for _, policy := range policies {
		entries = append(entries, admissionPolicyEntry{
			Policy:           policy.PolicyName,
			ControlID:        policy.ControlID,
			TakesParams:      policy.TakesParams,
			FailurePolicy:    policy.FailurePolicy,
			Resources:        policy.Resources,
			DuplicateName:    policy.DuplicateName,
			DuplicateControl: policy.DuplicateControl,
		})
	}
	return json.Marshal(entries)
}
