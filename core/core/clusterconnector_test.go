package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func readyPod(name string) v1.Pod {
	return v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": "operator"},
		},
		Status: v1.PodStatus{
			Phase:      v1.PodRunning,
			Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionTrue}},
		},
	}
}

func notReadyPod(name string) v1.Pod {
	return v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": "operator"},
		},
		Status: v1.PodStatus{
			Phase:      v1.PodRunning,
			Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionFalse}},
		},
	}
}

func Test_isPodReady(t *testing.T) {
	terminating := readyPod("terminating")
	deletionTimestamp := metav1.NewTime(time.Unix(0, 0))
	terminating.DeletionTimestamp = &deletionTimestamp

	testCases := []struct {
		name string
		pod  v1.Pod
		want bool
	}{
		{
			name: "running and ready",
			pod:  readyPod("p"),
			want: true,
		},
		{
			name: "running but ready condition is false",
			pod:  notReadyPod("p"),
			want: false,
		},
		{
			name: "running with no ready condition at all",
			pod:  v1.Pod{Status: v1.PodStatus{Phase: v1.PodRunning}},
			want: false,
		},
		{
			name: "pending with ready condition true",
			pod: v1.Pod{Status: v1.PodStatus{
				Phase:      v1.PodPending,
				Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: v1.ConditionTrue}},
			}},
			want: false,
		},
		{
			name: "terminating pod stays running and ready but must not be selected",
			pod:  terminating,
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isPodReady(&tc.pod))
		})
	}
}

func Test_getOperatorPod(t *testing.T) {
	notReadyErr := func(count int) error {
		return fmt.Errorf("found %d Kubescape Operator pod(s) in namespace %q, but none are running and ready", count, kubescapeNamespace)
	}

	testCases := []struct {
		name         string
		pods         []v1.Pod
		expectedErr  error
		expectedName string
	}{
		{
			name:        "no operator pod exists",
			pods:        nil,
			expectedErr: errOperatorNotFound,
		},
		{
			name:         "single ready pod is returned",
			pods:         []v1.Pod{readyPod("first")},
			expectedName: "first",
		},
		{
			name:        "single not-ready pod is reported, not handed to the caller",
			pods:        []v1.Pod{notReadyPod("first")},
			expectedErr: notReadyErr(1),
		},
		{
			name:         "multiple pods, the ready one is selected even when it sorts after the not-ready one",
			pods:         []v1.Pod{notReadyPod("aaa-not-ready"), readyPod("zzz-ready")},
			expectedName: "zzz-ready",
		},
		{
			name:        "multiple pods, none ready",
			pods:        []v1.Pod{notReadyPod("first"), notReadyPod("second")},
			expectedErr: notReadyErr(2),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewClientset(),
				Context:          context.Background(),
			}

			for i := range tc.pods {
				_, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &tc.pods[i], metav1.CreateOptions{})
				assert.NoError(t, err)
			}

			pod, err := getOperatorPod(&k8sClient, kubescapeNamespace)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedName, pod.Name)
		})
	}
}

func Test_getOperatorPod_nilClient(t *testing.T) {
	_, err := getOperatorPod(nil, kubescapeNamespace)
	assert.EqualError(t, err, "kubernetes client is not initialised")

	_, err = getOperatorPod(&k8sinterface.KubernetesApi{}, kubescapeNamespace)
	assert.EqualError(t, err, "kubernetes client is not initialised")
}
