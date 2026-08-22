package getter

import (
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
)

// convertSecurityExceptionToPosturePolicy converts a single posture entry from a
// SecurityException or ClusterSecurityException CRD spec into an
// armotypes.PostureExceptionPolicy that the existing scan-time exception flow
// (opaprocessor.updateResults) can consume without modification.
//
// This is part of the in-cluster SecurityException CRD support (kubescape/kubescape#1982).
func convertSecurityExceptionToPosturePolicy(
	name string,
	controlID string,
	frameworkName string,
	action string,
	expiresAt string,
	reason string,
	resources []map[string]string,
) (armotypes.PostureExceptionPolicy, error) {

	// map CRD action → armotypes action
	var actions []armotypes.PostureExceptionPolicyActions
	switch action {
	case "ignore":
		actions = []armotypes.PostureExceptionPolicyActions{armotypes.Disable}
	case "alert_only", "":
		actions = []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}
	default:
		return armotypes.PostureExceptionPolicy{}, fmt.Errorf("unknown action %q: must be ignore or alert_only", action)
	}

	// parse expiresAt → ExpirationDate
	var expirationDate *time.Time
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return armotypes.PostureExceptionPolicy{}, fmt.Errorf("invalid expiresAt %q: %w", expiresAt, err)
		}
		expirationDate = &t
	}

	// build resource designators
	var designators []identifiers.PortalDesignator
	for _, res := range resources {
		if len(res) == 0 {
			continue
		}
		designators = append(designators, identifiers.PortalDesignator{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     res,
		})
	}

	// optional reason
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}

	policy := armotypes.PostureExceptionPolicy{
		PolicyType: string(armotypes.PostureExceptionPolicyType),
		Actions:    actions,
		Resources:  designators,
		PosturePolicies: []armotypes.PosturePolicy{
			{
				ControlID:     controlID,
				FrameworkName: frameworkName,
			},
		},
		ExpirationDate: expirationDate,
		Reason:         reasonPtr,
	}
	policy.Name = fmt.Sprintf("%s/%s", name, controlID)

	return policy, nil
}
