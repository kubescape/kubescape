package vapreconcile

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

const (
	vapGroup           = "admissionregistration.k8s.io"
	vapResource        = "validatingadmissionpolicies"
	vapBindingResource = "validatingadmissionpolicybindings"

	// controlIDLabel is the label cel-admission-library stamps a control's
	// policy with. Policies without it are not addressable by control.
	controlIDLabel = "controlId"
)

func isDiscoveryMissingError(err error) bool {
	if apierrors.IsNotFound(err) {
		return true
	}
	var discoveryErr *discovery.ErrGroupDiscoveryFailed
	if errors.As(err, &discoveryErr) {
		return true
	}
	var noMatchErr *meta.NoResourceMatchError
	return errors.As(err, &noMatchErr)
}

// vapVersions lists the served versions of the VAP API in preference order:
// v1 since Kubernetes 1.30, v1beta1 since 1.28, v1alpha1 since 1.26.
var vapVersions = []string{"v1", "v1beta1", "v1alpha1"}

// ErrUnsupported reports a cluster that serves no version of the VAP API, so
// there is no enforcement state to reconcile.
var ErrUnsupported = errors.New("cluster does not serve ValidatingAdmissionPolicy resources")

// ErrForbidden reports credentials that may not list the VAP API. Enforcement
// state enriches a scan rather than feeding it, so being denied it leaves the
// scan intact.
var ErrForbidden = errors.New("not permitted to list ValidatingAdmissionPolicy resources")

// Collect lists ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding
// resources from the live cluster, using whichever version of the API the
// cluster serves. Both resource types are cluster-scoped so no namespace
// selector is needed. A cluster without the API returns ErrUnsupported, and
// credentials that may not list it ErrForbidden.
func Collect(ctx context.Context, k8s *k8sinterface.KubernetesApi) ([]unstructured.Unstructured, []unstructured.Unstructured, error) {
	version, err := resolveVersion(k8s.DiscoveryClient)
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			return nil, nil, nil
		}
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
// A discovery error on one version does not stop the remaining ones from being
// probed: an unreachable v1 must not hide a v1beta1 the cluster does serve.
func resolveVersion(client discovery.DiscoveryInterface) (string, error) {
	if client == nil {
		return vapVersions[0], nil
	}

	// A version we could not ask about is not a version the cluster fails to
	// serve, so keep probing and only report the error if nothing answers.
	var probeErr error
	for _, version := range vapVersions {
		gv := schema.GroupVersion{Group: vapGroup, Version: version}
		resources, err := client.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			if isDiscoveryMissingError(err) {
				continue
			}
			if !apierrors.IsNotFound(err) && probeErr == nil {
				probeErr = fmt.Errorf("failed to discover %s: %w", gv.String(), err)
			}
			continue
		}
		if serves(resources, vapResource, vapBindingResource) {
			return version, nil
		}
	}

	if probeErr != nil {
		return "", probeErr
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
// unsupported, and one the credentials may not read as forbidden; neither is a
// scan failure.
func list(ctx context.Context, client dynamic.Interface, version, resource string) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{Group: vapGroup, Version: version, Resource: resource}

	var items []unstructured.Unstructured
	listFunc := func(opts metav1.ListOptions) (string, error) {
		listed, err := client.Resource(gvr).List(ctx, opts)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return "", ErrUnsupported
			}
			if apierrors.IsForbidden(err) {
				return "", fmt.Errorf("%w: %s", ErrForbidden, gvr.String())
			}
			return "", fmt.Errorf("failed to list %s: %w", gvr.String(), err)
		}
		items = append(items, listed.Items...)
		return listed.GetContinue(), nil
	}

	if err := getter.ListWithPagination(ctx, listFunc); err != nil {
		return nil, err
	}
	return items, nil
}

// BuildIndex builds a map of controlId -> VAPEnforcementStatus by reading the
// controlId label that cel-admission-library stamps on every VAP, then joining
// bindings back via spec.policyName to determine the enforcement mode.
//
// More than one policy can carry the same control: an upgrade that renames the
// library policy leaves the old one behind, and a hand-written policy can stamp
// the same label. Enforcement is resolved per policy and only then reduced to
// the control, so a binding is credited to the policy it names rather than to
// whichever policy the listing ended on. Names are sorted so the reported
// policy does not move between scans.
func BuildIndex(policies, bindings []unstructured.Unstructured) map[string]*reportsummary.VAPEnforcementStatus {
	controlByPolicy := make(map[string]string, len(policies))
	policiesByControl := make(map[string][]string, len(policies))

	for i := range policies {
		name := policies[i].GetName()
		controlID := policies[i].GetLabels()[controlIDLabel]
		if name == "" || controlID == "" {
			continue
		}
		if _, seen := controlByPolicy[name]; seen {
			continue // a repeated name is the same policy listed twice
		}
		controlByPolicy[name] = controlID
		policiesByControl[controlID] = append(policiesByControl[controlID], name)
	}

	// Presence in this map is what binds a policy: a binding declaring no
	// action still binds the policy it names.
	actionsByPolicy := make(map[string][]string, len(bindings))
	for i := range bindings {
		spec, ok := bindings[i].Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		policyName, _ := spec["policyName"].(string)
		if _, known := controlByPolicy[policyName]; !known {
			continue
		}
		actions := actionsByPolicy[policyName]
		for _, action := range bindingActions(spec) {
			if !slices.Contains(actions, action) {
				actions = append(actions, action)
			}
		}
		actionsByPolicy[policyName] = actions
	}

	index := make(map[string]*reportsummary.VAPEnforcementStatus, len(policiesByControl))
	for controlID, names := range policiesByControl {
		slices.Sort(names)
		status := &reportsummary.VAPEnforcementStatus{PolicyName: names[0]}
		for _, name := range names {
			actions, bound := actionsByPolicy[name]
			if !bound {
				continue
			}
			if !status.Bound {
				// The name has to be a bound policy, or the status reads as
				// enforced by a policy nothing binds.
				status.Bound = true
				status.PolicyName = name
			}
			for _, action := range actions {
				if !slices.Contains(status.Actions, action) {
					status.Actions = append(status.Actions, action)
				}
			}
		}
		index[controlID] = status
	}

	return index
}

// bindingActions reads a binding's spec.validationActions. An entry that is not
// a string is dropped rather than failing the whole binding: the rest of its
// actions still describe how the policy is enforced.
func bindingActions(spec map[string]any) []string {
	raw, ok := spec["validationActions"].([]any)
	if !ok {
		return nil
	}
	actions := make([]string, 0, len(raw))
	for _, entry := range raw {
		if action, ok := entry.(string); ok {
			actions = append(actions, action)
		}
	}
	return actions
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

// GenerateValidatingAdmissionPolicy creates a ValidatingAdmissionPolicy manifest
func GenerateValidatingAdmissionPolicy(name, celExpr string, paramSchema map[string]interface{}, apiVersion string, targetResource string) *unstructured.Unstructured {
	if apiVersion == "" {
		apiVersion = "v1"
	}
	vap := &unstructured.Unstructured{}
	vap.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "admissionregistration.k8s.io",
		Version: apiVersion,
		Kind:    "ValidatingAdmissionPolicy",
	})
	vap.SetName(name)

	// Add spec with CEL expression and parameter schema linkage
	spec := map[string]interface{}{
		"validations": []interface{}{
			map[string]interface{}{
				"expression": celExpr,
			},
		},
		"matchConstraints": map[string]interface{}{
			"resourceRules": []interface{}{
				map[string]interface{}{
					"apiGroups":   []interface{}{"*"},
					"apiVersions": []interface{}{"*"},
					"operations":  []interface{}{"CREATE", "UPDATE"},
					"resources":   []interface{}{targetResource},
				},
			},
		},
	}
	if len(paramSchema) > 0 {
		spec["paramKind"] = map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
		}
	}
	vap.Object["spec"] = spec
	return vap
}

// GenerateValidatingAdmissionPolicyBinding creates a ValidatingAdmissionPolicyBinding manifest
func GenerateValidatingAdmissionPolicyBinding(name, policyName, apiVersion, paramRefName string) *unstructured.Unstructured {
	if apiVersion == "" {
		apiVersion = "v1"
	}
	vapb := &unstructured.Unstructured{}
	vapb.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "admissionregistration.k8s.io",
		Version: apiVersion,
		Kind:    "ValidatingAdmissionPolicyBinding",
	})
	vapb.SetName(name)

	spec := map[string]interface{}{
		"policyName":        policyName,
		"validationActions": []interface{}{"Deny"},
	}
	if paramRefName != "" {
		spec["paramRef"] = map[string]interface{}{
			"name":                    paramRefName,
			"parameterNotFoundAction": "Deny",
		}
	}
	vapb.Object["spec"] = spec
	return vapb
}
