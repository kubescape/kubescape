package vapreconcile

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

// Collect lists ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding
// resources from the live cluster. Both resource types are cluster-scoped so no
// namespace selector is needed.
func Collect(ctx context.Context, k8s *k8sinterface.KubernetesApi) ([]unstructured.Unstructured, []unstructured.Unstructured, error) {
	groupVersion := "admissionregistration.k8s.io/v1"
	version := "v1"

	resources, err := k8s.DiscoveryClient.ServerResourcesForGroupVersion(groupVersion)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, err
	}
	if err != nil || !hasVAPResources(resources) {
		groupVersion = "admissionregistration.k8s.io/v1beta1"
		resources, err = k8s.DiscoveryClient.ServerResourcesForGroupVersion(groupVersion)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, err
		}
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
const (
	vapGroup           = "admissionregistration.k8s.io"
	vapResource        = "validatingadmissionpolicies"
	vapBindingResource = "validatingadmissionpolicybindings"
)

// vapVersions lists the served versions of the VAP API in preference order:
// v1 since Kubernetes 1.30, v1beta1 since 1.28, v1alpha1 since 1.26.
var vapVersions = []string{"v1", "v1beta1", "v1alpha1"}

// ErrUnsupported reports a cluster that serves no version of the VAP API, so
// there is no enforcement state to reconcile.
var ErrUnsupported = errors.New("cluster does not serve ValidatingAdmissionPolicy resources")

// Collect lists ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding
// resources from the live cluster, using whichever version of the API the
// cluster serves. Both resource types are cluster-scoped so no namespace
// selector is needed. Clusters without the API return ErrUnsupported.
func Collect(ctx context.Context, k8s *k8sinterface.KubernetesApi) ([]unstructured.Unstructured, []unstructured.Unstructured, error) {
	version, err := resolveVersion(k8s.DiscoveryClient)
	if err != nil {
		return nil, nil, err
	}

	policies, err := list(ctx, k8s.DynamicClient, version, vapResource)
	if err != nil {
		return nil, nil, err
	}
	bindings, err := list(ctx, k8s.DynamicClient, version, vapBindingResource)
	if err != nil {
		return nil, nil, err
	}

	return policies, bindings, nil
}

// resolveVersion returns the first VAP version the cluster both advertises and
// serves both resources for. Without a discovery client the newest version is
// assumed, which is what the API server routing did before discovery existed.
func resolveVersion(client discovery.DiscoveryInterface) (string, error) {
	if client == nil {
		return vapVersions[0], nil
	}

	for _, version := range vapVersions {
		gv := schema.GroupVersion{Group: vapGroup, Version: version}
		resources, err := client.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return "", fmt.Errorf("failed to discover %s: %w", gv.String(), err)
		}
		if serves(resources, vapResource, vapBindingResource) {
			return version, nil
		}
	}

	return "", ErrUnsupported
}

// serves reports whether the API resource list carries every named resource.
func serves(resources *metav1.APIResourceList, names ...string) bool {
	if resources == nil {
		return false
	}

	served := make(map[string]struct{}, len(resources.APIResources))
	for _, resource := range resources.APIResources {
		served[resource.Name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := served[name]; !ok {
			return false
		}
	}

	return true
}

// list pulls every object of one cluster-scoped VAP resource. A resource that
// discovery advertised but the API server does not route is reported as
// unsupported rather than as a scan failure.
func list(ctx context.Context, client dynamic.Interface, version, resource string) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{Group: vapGroup, Version: version, Resource: resource}
	listed, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrUnsupported
		}
		return nil, fmt.Errorf("failed to list %s: %w", gvr.String(), err)
	}

	return listed.Items, nil
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
