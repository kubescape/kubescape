package vapreconcile

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Collect lists ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding
// resources from the live cluster. Both resource types are cluster-scoped so no
// namespace selector is needed.
func Collect(ctx context.Context, k8s *k8sinterface.KubernetesApi) ([]unstructured.Unstructured, []unstructured.Unstructured, error) {
	groupVersion := "admissionregistration.k8s.io/v1"
	version := "v1"

	resources, err := k8s.DiscoveryClient.ServerResourcesForGroupVersion(groupVersion)
	if err != nil || !hasVAPResources(resources) {
		groupVersion = "admissionregistration.k8s.io/v1beta1"
		resources, err = k8s.DiscoveryClient.ServerResourcesForGroupVersion(groupVersion)
		if err != nil || !hasVAPResources(resources) {
			logger.L().Ctx(ctx).Warning("ValidatingAdmissionPolicies are not supported on this cluster, skipping VAP reconciliation")
			return nil, nil, nil
		}
		version = "v1beta1"
	}

	vapGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  version,
		Resource: "validatingadmissionpolicies",
	}
	vapbGVR := schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  version,
		Resource: "validatingadmissionpolicybindings",
	}

	vapList, err := k8s.DynamicClient.Resource(vapGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list ValidatingAdmissionPolicies: %w", err)
	}

	vapbList, err := k8s.DynamicClient.Resource(vapbGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list ValidatingAdmissionPolicyBindings: %w", err)
	}

	return vapList.Items, vapbList.Items, nil
}

func hasVAPResources(resources *metav1.APIResourceList) bool {
	if resources == nil {
		return false
	}
	hasVAP := false
	hasVAPB := false
	for i := range resources.APIResources {
		if resources.APIResources[i].Name == "validatingadmissionpolicies" {
			hasVAP = true
		}
		if resources.APIResources[i].Name == "validatingadmissionpolicybindings" {
			hasVAPB = true
		}
	}
	return hasVAP && hasVAPB
}

// BuildIndex builds a map of controlId -> VAPEnforcementStatus by reading the
// controlId label that cel-admission-library stamps on every VAP, then joining
// bindings back via spec.policyName to determine the enforcement mode.
func BuildIndex(policies, bindings []unstructured.Unstructured) map[string]*reportsummary.VAPEnforcementStatus {
	// map policyName -> controlId so we can join bindings
	policyNameToControlID := make(map[string]string, len(policies))
	index := make(map[string]*reportsummary.VAPEnforcementStatus, len(policies))

	for i := range policies {
		vap := &policies[i]
		labels := vap.GetLabels()
		controlID, ok := labels["controlId"]
		if !ok || controlID == "" {
			continue
		}
		policyNameToControlID[vap.GetName()] = controlID
		index[controlID] = &reportsummary.VAPEnforcementStatus{
			PolicyName: vap.GetName(),
			Bound:      false,
		}
	}

	seenActions := make(map[string]map[string]struct{})

	for i := range bindings {
		vapb := &bindings[i]
		spec, ok := vapb.Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		policyName, _ := spec["policyName"].(string)
		controlID, ok := policyNameToControlID[policyName]
		if !ok {
			continue
		}

		status, ok := index[controlID]
		if !ok {
			continue
		}
		status.Bound = true

		if seenActions[controlID] == nil {
			seenActions[controlID] = make(map[string]struct{})
		}
		if actionsRaw, ok := spec["validationActions"].([]any); ok {
			for _, a := range actionsRaw {
				if s, ok := a.(string); ok {
					if _, dup := seenActions[controlID][s]; !dup {
						seenActions[controlID][s] = struct{}{}
						status.Actions = append(status.Actions, s)
					}
				}
			}
		}
	}

	return index
}

// EnrichSummary attaches VAPEnforcementStatus to each ControlSummary whose
// controlId appears in the index.
func EnrichSummary(controls reportsummary.ControlSummaries, index map[string]*reportsummary.VAPEnforcementStatus) {
	for controlID, status := range index {
		if cs, ok := controls[controlID]; ok {
			cs.VAPEnforcement = status
			controls[controlID] = cs
		}
	}
}
