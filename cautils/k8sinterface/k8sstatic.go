package k8sinterface

import (
	"context"

	"kube-escape/cautils/cautils"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func IsAttached(labels map[string]string) *bool {
	return IsLabel(labels, cautils.ArmoAttach)
}

func IsAgentCompatibleLabel(labels map[string]string) *bool {
	return IsLabel(labels, cautils.ArmoCompatibleLabel)
}
func IsAgentCompatibleAnnotation(annotations map[string]string) *bool {
	return IsLabel(annotations, cautils.ArmoCompatibleAnnotation)
}
func SetAgentCompatibleLabel(labels map[string]string, val bool) {
	SetLabel(labels, cautils.ArmoCompatibleLabel, val)
}
func SetAgentCompatibleAnnotation(annotations map[string]string, val bool) {
	SetLabel(annotations, cautils.ArmoCompatibleAnnotation, val)
}
func IsLabel(labels map[string]string, key string) *bool {
	if labels == nil || len(labels) == 0 {
		return nil
	}
	var k bool
	if l, ok := labels[key]; ok {
		if l == "true" {
			k = true
		} else if l == "false" {
			k = false
		}
		return &k
	}
	return nil
}
func SetLabel(labels map[string]string, key string, val bool) {
	if labels == nil {
		return
	}
	v := ""
	if val {
		v = "true"
	} else {
		v = "false"
	}
	labels[key] = v
}
func (k8sAPI *KubernetesApi) ListAttachedPods(namespace string) ([]corev1.Pod, error) {
	return k8sAPI.ListPods(namespace, map[string]string{cautils.ArmoAttach: cautils.BoolToString(true)})
}

func (k8sAPI *KubernetesApi) ListPods(namespace string, podLabels map[string]string) ([]corev1.Pod, error) {
	listOptions := metav1.ListOptions{}
	if podLabels != nil && len(podLabels) > 0 {
		set := labels.Set(podLabels)
		listOptions.LabelSelector = set.AsSelector().String()
	}
	pods, err := k8sAPI.KubernetesClient.CoreV1().Pods(namespace).List(context.Background(), listOptions)
	if err != nil {
		return []corev1.Pod{}, err
	}
	return pods.Items, nil
}
