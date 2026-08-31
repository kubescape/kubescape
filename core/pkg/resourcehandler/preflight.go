package resourcehandler

import (
	"context"
	"errors"
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVRCheck is the preflight result for a single resource type the scan needs to list.
// Errored is set when no access decision was obtained: the
// SelfSubjectAccessReview request itself could not be completed (timeout, API
// failure, ...), or the API server answered without one of its authorizers
// reaching a verdict. Neither is the same as the API server answering that
// "list" is denied — Allowed stays false in all of these cases, so callers must
// check Errored before treating a check as a real denial.
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

// Errored returns the checks for which no access decision was obtained, whether
// the request failed or an authorizer never reached a verdict.
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
// resource type at the scope collection will address it: namespaced when
// --include-namespaces names the namespaces a namespaced resource is collected
// from, cluster-wide otherwise. That is the same check the real collection
// would need to pass.
//
// --include-kinds/--exclude-kinds are honored too: they decide which resource
// types get listed at all, so reviewing access to an excluded kind would fail
// the dry-run over a listing that never happens.
func (k8sHandler *K8sResourceHandler) Preflight(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (*PreflightResult, error) {
	resolver, discoveryFailures := newDiscoveryResourceResolver(k8sHandler.k8s.DiscoveryClient)

	resourceToControl := make(map[string][]string)
	scanningScope := cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)
	queryableResources, _ := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope, resolver)
	filterQueryableResourcesByKind(queryableResources, scanInfo)
	setKSResourceMap(sessionObj.Policies, resourceToControl, resolver)

	globalFieldSelectors := getFieldSelectorFromScanInfo(scanInfo)

	result := &PreflightResult{DiscoveryFailures: discoveryFailures}
	seen := make(map[string]struct{}, len(queryableResources))
	for _, qr := range queryableResources {
		// An access review for a resource Kubescape serves itself is always
		// denied, which would fail the dry-run over a resource the scan never
		// asks the API server for.
		if isExternalResource(qr.GroupVersionResourceTriplet) {
			continue
		}
		if _, ok := seen[qr.GroupVersionResourceTriplet]; ok {
			continue
		}
		seen[qr.GroupVersionResourceTriplet] = struct{}{}

		apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(qr.GroupVersionResourceTriplet)
		gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
		namespaces := globalFieldSelectors.GetNamespaceScopedQueries(&gvr, qr.Namespaced)

		result.Checks = append(result.Checks, k8sHandler.checkListAccess(ctx, qr.GroupVersionResourceTriplet, namespaces, resourceToControl[qr.GroupVersionResourceTriplet]))
	}

	sort.Slice(result.Checks, func(i, j int) bool { return result.Checks[i].GVR < result.Checks[j].GVR })
	return result, nil
}

// checkListAccess reviews "list" access to gvrTriplet. namespaces are the
// namespaces collection will address the resource in; an empty slice reviews
// cluster scope. Every namespace must be allowed for the check to pass, since
// collection queries all of them, and the first one that is not decides the
// reported outcome.
func (k8sHandler *K8sResourceHandler) checkListAccess(ctx context.Context, gvrTriplet string, namespaces []string, affectedControls []string) GVRCheck {
	group, version, resource := k8sinterface.StringToResourceGroup(gvrTriplet)

	scopes := namespaces
	if len(scopes) == 0 {
		scopes = []string{""}
	}

	check := GVRCheck{GVR: gvrTriplet, AffectedControls: affectedControls}
	for _, namespace := range scopes {
		ssar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "list",
					Group:     group,
					Version:   version,
					Resource:  resource,
					Namespace: namespace,
				},
			},
		}

		check = GVRCheck{GVR: gvrTriplet, AffectedControls: affectedControls}
		resp, err := k8sHandler.k8s.KubernetesClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
		if err != nil {
			check.Errored = true
			check.Reason = err.Error()
			return check
		}

		applyAccessReviewStatus(&check, resp.Status)
		if !check.Allowed {
			return check
		}
	}

	return check
}

// applyAccessReviewStatus records the API server's access decision on the check.
//
// Allowed=false with Denied=false means no authorizer had an opinion, which is a
// real denial only when they all actually reached one. An EvaluationError says
// one of them did not: a webhook authorizer that times out or errors produces
// exactly this shape, and reporting it as a denial fails the dry-run over access
// the credentials may well have. An explicit Denied, or no opinion with every
// authorizer reporting cleanly, stays the denial it is.
func applyAccessReviewStatus(check *GVRCheck, status authorizationv1.SubjectAccessReviewStatus) {
	check.Allowed = status.Allowed
	check.Reason = status.Reason
	if status.Allowed || status.Denied || status.EvaluationError == "" {
		return
	}
	check.Errored = true
	check.Reason = status.EvaluationError
	if status.Reason != "" {
		check.Reason = status.Reason + ": " + status.EvaluationError
	}
}
