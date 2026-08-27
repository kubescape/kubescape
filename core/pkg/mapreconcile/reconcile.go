// Package mapreconcile discovers a live cluster's MutatingAdmissionPolicy and
// MutatingAdmissionPolicyBinding objects (admissionregistration.k8s.io
// /v1alpha1, stable since Kubernetes 1.32) and reports which ones would match
// a given resource -- surfacing implicit, in-cluster mutation that never
// appears in the manifest a user applied.
//
// This package does not evaluate the CEL expressions a Mutation declares: it
// reports that a policy's mutation *would run* against a matching resource,
// and what its raw expression is, not what the mutated object would look
// like. Actually computing the patched value would require the same
// apiserver-grade CEL/ApplyConfiguration machinery admission control itself
// uses; reporting the match and the expression verbatim is honest about that
// boundary rather than guessing at an evaluated result.
package mapreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

const (
	mapGroup           = "admissionregistration.k8s.io"
	mapResource        = "mutatingadmissionpolicies"
	mapBindingResource = "mutatingadmissionpolicybindings"
)

// mapVersions lists the served versions of the MutatingAdmissionPolicy API in
// preference order, mirroring vapVersions: newest first. The type was
// introduced as v1alpha1 in Kubernetes 1.32; live verification against a
// cluster that has since graduated it straight to v1 (skipping v1beta1
// entirely, unlike ValidatingAdmissionPolicy's path) confirmed a
// single-version list is not future-proof, so every version the API has ever
// been served under is probed here rather than assuming v1alpha1 forever. The
// vendored v1alpha1 Go types still decode a v1-served object correctly: only
// the GVR used to list it differs between versions, not the JSON shape.
var mapVersions = []string{"v1", "v1beta1", "v1alpha1"}

// ErrUnsupported reports a cluster that serves no version of the
// MutatingAdmissionPolicy API, so there is nothing to reconcile.
var ErrUnsupported = errors.New("cluster does not serve MutatingAdmissionPolicy resources")

// ErrForbidden reports credentials that may not list the API. This enriches a
// scan/query rather than feeding it, so being denied it should not be treated
// as a hard failure by callers.
var ErrForbidden = errors.New("not permitted to list MutatingAdmissionPolicy resources")

// ErrDiscoveryRequired reports that resolveVersion was given no discovery
// client to confirm which version a cluster actually serves. Unlike
// vapreconcile (whose VAP version has graduated the same v1alpha1 -> v1beta1
// -> v1 path on every cluster observed), live verification against a real
// cluster found MutatingAdmissionPolicy version support varies: one cluster
// served it directly under v1 with v1beta1 never having existed at all.
// Guessing mapVersions[0] without confirmation risks a wrong (and possibly
// failing) version against an older cluster, so an absent discovery client is
// treated as a real error here rather than a silent assumption.
var ErrDiscoveryRequired = errors.New("a discovery client is required to determine which MutatingAdmissionPolicy version a cluster serves")

// resolveVersion returns the first MutatingAdmissionPolicy version the
// cluster both advertises and serves both resources for. A discovery error on
// one version does not stop the remaining ones from being probed, mirroring
// vapreconcile.resolveVersion.
func resolveVersion(client discovery.DiscoveryInterface) (string, error) {
	if client == nil {
		return "", ErrDiscoveryRequired
	}

	var probeErr error
	for _, version := range mapVersions {
		gv := schema.GroupVersion{Group: mapGroup, Version: version}
		resources, err := client.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			if !apierrors.IsNotFound(err) && probeErr == nil {
				probeErr = fmt.Errorf("failed to discover %s: %w", gv.String(), err)
			}
			continue
		}
		if serves(resources, mapResource, mapBindingResource) {
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

// list pulls every object of one cluster-scoped resource under the resolved
// MutatingAdmissionPolicy API version.
func list(ctx context.Context, client dynamic.Interface, version, resource string) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{Group: mapGroup, Version: version, Resource: resource}

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

// Collect lists MutatingAdmissionPolicy and MutatingAdmissionPolicyBinding
// objects from the live cluster and decodes them into their typed shape. Both
// resource types are cluster-scoped. An object that fails to decode is
// skipped, with its error appended to decodeErrs, rather than one malformed
// object hiding every other policy from the caller -- dropping a policy here
// can hide a real, currently-running mutation, so the caller must be able to
// see that something was dropped rather than have it disappear silently.
func Collect(ctx context.Context, k8s *k8sinterface.KubernetesApi) (policies []admissionregistrationv1alpha1.MutatingAdmissionPolicy, bindings []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding, decodeErrs []error, err error) {
	version, err := resolveVersion(k8s.DiscoveryClient)
	if err != nil {
		return nil, nil, nil, err
	}

	rawPolicies, err := list(ctx, k8s.DynamicClient, version, mapResource)
	if err != nil {
		return nil, nil, nil, err
	}
	rawBindings, err := list(ctx, k8s.DynamicClient, version, mapBindingResource)
	if err != nil {
		return nil, nil, nil, err
	}

	for i := range rawPolicies {
		var p admissionregistrationv1alpha1.MutatingAdmissionPolicy
		if decErr := decode(rawPolicies[i].Object, &p); decErr != nil {
			decodeErrs = append(decodeErrs, fmt.Errorf("MutatingAdmissionPolicy %s: %w", rawPolicies[i].GetName(), decErr))
			continue
		}
		policies = append(policies, p)
	}
	for i := range rawBindings {
		var b admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding
		if decErr := decode(rawBindings[i].Object, &b); decErr != nil {
			decodeErrs = append(decodeErrs, fmt.Errorf("MutatingAdmissionPolicyBinding %s: %w", rawBindings[i].GetName(), decErr))
			continue
		}
		bindings = append(bindings, b)
	}

	return policies, bindings, decodeErrs, nil
}

// decode converts an unstructured object's generic map into its typed shape
// via a JSON round-trip, the same pattern core/pkg/networkpolicy's adapter
// uses to bridge a dynamic client's generic representation and a concrete
// Kubernetes API type.
func decode(obj map[string]any, out any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
