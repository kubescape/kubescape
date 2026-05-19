package core

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

func newSecurityExceptionEventRecorder() record.EventRecorder {
	if !k8sinterface.IsConnectedToCluster() {
		return nil
	}

	k8s := getKubernetesApi()
	if k8s == nil || k8s.KubernetesClient == nil {
		return nil
	}

	return newSecurityExceptionEventRecorderWithClient(k8s.KubernetesClient)
}

func newSecurityExceptionEventRecorderWithClient(k8sClient kubernetes.Interface) record.EventRecorder {
	if k8sClient == nil {
		return nil
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: k8sClient.CoreV1().Events("")})
	return broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "kubescape"})
}
