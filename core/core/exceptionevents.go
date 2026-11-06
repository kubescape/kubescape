package core

import (
	"context"

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
// identity may not create Events. ExceptionMatched events go to the namespace of
// the excepted resource, so the check is cluster-wide. Without it, every event
// would be rejected and logged by the broadcaster. The operator chart only grants
// this permission when risk acceptance is enabled.
func newSecurityExceptionEventRecorderWithClient(ctx context.Context, k8sClient kubernetes.Interface) (record.EventRecorder, func()) {
	if k8sClient == nil {
		return nil, nil
	}

	allowed, reason, err := canCreateEvents(ctx, k8sClient)
	if err != nil {
		logger.L().Ctx(ctx).Warning("ExceptionMatched events disabled: could not verify permission to create events",
			helpers.Error(err))
		return nil, nil
	}
	if !allowed {
		logger.L().Ctx(ctx).Info("ExceptionMatched events disabled: the scanning identity cannot create events",
			helpers.String("reason", reason))
		return nil, nil
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: k8sClient.CoreV1().Events("")})
	return broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "kubescape"}), broadcaster.Shutdown
}

// canCreateEvents reports whether the current identity may create core Events
// in every namespace, with the authorizer's reason when it may not. The caller
// treats a review that cannot be completed as not allowed: the events are
// optional, and an emitter that fails on every write is worse than none.
func canCreateEvents(ctx context.Context, k8sClient kubernetes.Interface) (bool, string, error) {
	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "create",
				Version:  "v1",
				Resource: "events",
			},
		},
	}
	resp, err := k8sClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		return false, "", err
	}
	if !resp.Status.Allowed {
		if resp.Status.Reason != "" {
			return false, resp.Status.Reason, nil
		}
		return false, "not allowed", nil
	}
	return true, "", nil
}
