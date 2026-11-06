package core

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

// eventsAccessReviewTimeout bounds the permission check so that a slow or
// unreachable API server cannot hold up the scan; a check that times out
// disables the events like any other failed check.
var eventsAccessReviewTimeout = 10 * time.Second

// newSecurityExceptionEventRecorder returns the ExceptionMatched event recorder
// for a live cluster scan and the function that shuts it down, or nil for both
// when not connected to a cluster or not allowed to create events.
func newSecurityExceptionEventRecorder(ctx context.Context) (record.EventRecorder, func()) {
	if !k8sinterface.IsConnectedToCluster() {
		return nil, nil
	}

	k8s := getKubernetesApi()
	if k8s == nil || k8s.KubernetesClient == nil {
		return nil, nil
	}

	return newSecurityExceptionEventRecorderWithClient(ctx, k8s.KubernetesClient)
}

// newSecurityExceptionEventRecorderWithClient returns nil when the scanning
// identity may not create and patch Events. ExceptionMatched events go to the namespace of
// the excepted resource, so the check is cluster-wide. Without it, every event
// would be rejected and logged by the broadcaster. The operator chart only grants
// these permissions when risk acceptance is enabled.
func newSecurityExceptionEventRecorderWithClient(ctx context.Context, k8sClient kubernetes.Interface) (record.EventRecorder, func()) {
	if k8sClient == nil {
		return nil, nil
	}

	allowed, reason, err := canWriteEvents(ctx, k8sClient)
	if err != nil {
		logger.L().Ctx(ctx).Warning("ExceptionMatched events disabled: could not verify permission to write events",
			helpers.Error(err))
		return nil, nil
	}
	if !allowed {
		logger.L().Ctx(ctx).Info("ExceptionMatched events disabled: the scanning identity cannot create and patch events",
			helpers.String("reason", reason))
		return nil, nil
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: k8sClient.CoreV1().Events("")})
	return broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "kubescape"}), broadcaster.Shutdown
}

// eventVerbs are the verbs the event broadcaster uses: it creates new events
// and patches existing ones to aggregate repeats.
var eventVerbs = []string{"create", "patch"}

// canWriteEvents reports whether the current identity may create and patch core
// Events in every namespace, with the authorizer's reason when it may not. An
// error means the review could not reach a decision (the request failed, or an
// authorizer reported an evaluation error without allowing or denying); the
// caller treats that as not allowed, since the events are optional and an
// emitter that fails on every write is worse than none.
func canWriteEvents(ctx context.Context, k8sClient kubernetes.Interface) (bool, string, error) {
	reviewCtx, cancel := context.WithTimeout(ctx, eventsAccessReviewTimeout)
	defer cancel()
	for _, verb := range eventVerbs {
		allowed, reason, err := reviewEventAccess(reviewCtx, k8sClient, verb)
		if err != nil || !allowed {
			return false, reason, err
		}
	}
	return true, "", nil
}

// reviewEventAccess runs one cluster-wide SelfSubjectAccessReview for verb on
// core events. Allowed=false with Denied=false and an EvaluationError means an
// authorizer (typically a webhook) failed rather than denied, so it is returned
// as an error, as applyAccessReviewStatus does for the scan preflight.
func reviewEventAccess(ctx context.Context, k8sClient kubernetes.Interface, verb string) (bool, string, error) {
	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     verb,
				Version:  "v1",
				Resource: "events",
			},
		},
	}
	resp, err := k8sClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		return false, "", fmt.Errorf("%s events: %w", verb, err)
	}
	status := resp.Status
	if status.Allowed {
		return true, "", nil
	}
	if !status.Denied && status.EvaluationError != "" {
		msg := status.EvaluationError
		if status.Reason != "" {
			msg = status.Reason + ": " + msg
		}
		return false, "", fmt.Errorf("%s events: %s", verb, msg)
	}
	reason := status.Reason
	if reason == "" {
		reason = "not allowed"
	}
	return false, verb + " events: " + reason, nil
}
