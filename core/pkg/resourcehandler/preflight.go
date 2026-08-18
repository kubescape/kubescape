package resourcehandler

import (
	"context"
	"errors"
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GVRCheck is the preflight result for a single resource type the scan needs to list.
// Errored is set when the SelfSubjectAccessReview request itself could not be
// completed (timeout, API failure, ...), which is not the same as the API
// server answering that "list" is denied — Allowed stays false in both cases,
// so callers must check Errored before treating a check as a real denial.
type GVRCheck struct {
	GVR              string
	Allowed          bool
	Errored          bool
	Reason           string
	AffectedControls []string
}

// PreflightResult is the outcome of checking whether the current credentials
// can list every resource type the requested policies depend on.
type PreflightResult struct {
	Checks            []GVRCheck
	DiscoveryFailures []cautils.PartialGVRPull
}

// Denied returns the checks the API server answered with "not allowed", in
// the order they were checked. Checks whose request itself failed are
// excluded — see Errored.
func (r *PreflightResult) Denied() []GVRCheck {
	var denied []GVRCheck
	for _, c := range r.Checks {
		if !c.Allowed && !c.Errored {
			denied = append(denied, c)
		}
	}
	return denied
}

// Errored returns the checks whose SelfSubjectAccessReview request itself
// failed, so no access decision was obtained.
func (r *PreflightResult) Errored() []GVRCheck {
	var errored []GVRCheck
	for _, c := range r.Checks {
		if c.Errored {
			errored = append(errored, c)
		}
	}
	return errored
}

// ErrPreflightNotSupported is returned by resource handlers that cannot
// evaluate RBAC access, such as file-based scans with no API server to ask.
var ErrPreflightNotSupported = errors.New("dry-run RBAC preflight is only supported for cluster scans")

// Preflight resolves the resource types the given policies require and
// checks, via SelfSubjectAccessReview, whether the current credentials can
// list each one, without collecting any resources. Kubescape lists every
// resource type with a single cluster-wide LIST (namespace filtering happens
// against the returned items, not via a namespaced list call), so a
// cluster-wide "list" access review is the same check the real collection
// would need to pass, regardless of --include-namespaces/--exclude-namespaces.
func (k8sHandler *K8sResourceHandler) Preflight(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (*PreflightResult, error) {
	resolver, discoveryFailures := newDiscoveryResourceResolver(k8sHandler.k8s.DiscoveryClient)

	resourceToControl := make(map[string][]string)
	scanningScope := cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)
	queryableResources, _ := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope, resolver)
	setKSResourceMap(sessionObj.Policies, resourceToControl, resolver)

	result := &PreflightResult{DiscoveryFailures: discoveryFailures}
	seen := make(map[string]struct{}, len(queryableResources))
	for _, qr := range queryableResources {
		if _, ok := seen[qr.GroupVersionResourceTriplet]; ok {
			continue
		}
		seen[qr.GroupVersionResourceTriplet] = struct{}{}

		result.Checks = append(result.Checks, k8sHandler.checkListAccess(ctx, qr.GroupVersionResourceTriplet, resourceToControl[qr.GroupVersionResourceTriplet]))
	}

	sort.Slice(result.Checks, func(i, j int) bool { return result.Checks[i].GVR < result.Checks[j].GVR })
	return result, nil
}

func (k8sHandler *K8sResourceHandler) checkListAccess(ctx context.Context, gvrTriplet string, affectedControls []string) GVRCheck {
	group, version, resource := k8sinterface.StringToResourceGroup(gvrTriplet)
	check := GVRCheck{GVR: gvrTriplet, AffectedControls: affectedControls}

	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "list",
				Group:    group,
				Version:  version,
				Resource: resource,
			},
		},
	}

	resp, err := k8sHandler.k8s.KubernetesClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		check.Errored = true
		check.Reason = err.Error()
		return check
	}

	check.Allowed = resp.Status.Allowed
	check.Reason = resp.Status.Reason
	return check
}
