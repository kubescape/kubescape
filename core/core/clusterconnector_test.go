package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_getOperatorPod(t *testing.T) {
	testCases := []struct {
		name                                  string
		createOperatorPod                     bool
		createAnotherOperatorPodWithSameLabel bool
		expectedError                         error
	}{
		{
			name:                                  "test error no operator exist",
			createOperatorPod:                     false,
			createAnotherOperatorPodWithSameLabel: false,
			expectedError:                         fmt.Errorf("Could not find the Kubescape Operator chart, please validate that the Kubescape Operator helm chart is installed and running -> https://github.com/kubescape/helm-charts"),
		},
		{
			name:                                  "test error several operators exist",
			createOperatorPod:                     true,
			createAnotherOperatorPodWithSameLabel: true,
			expectedError:                         fmt.Errorf("Could not find the Kubescape Operator chart, please validate that the Kubescape Operator helm chart is installed and running -> https://github.com/kubescape/helm-charts"),
		},
		{
			name:                                  "test no error",
			createOperatorPod:                     true,
			createAnotherOperatorPodWithSameLabel: false,
			expectedError:                         nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewSimpleClientset(),
				Context:          context.TODO(),
			}

			var createdOperatorPod *v1.Pod
			if tc.createOperatorPod {
				operatorPod := v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "first",
						Labels: map[string]string{
							"app": "operator",
						},
					},
				}
				var err error
				createdOperatorPod, err = k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
				assert.Equal(t, nil, err)
			}
			if tc.createAnotherOperatorPodWithSameLabel {
				operatorPod := v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "second",
						Labels: map[string]string{
							"app": "operator",
						},
					},
				}
				_, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
				assert.Equal(t, nil, err)
			}

			pod, err := getOperatorPod(&k8sClient, kubescapeNamespace)
			assert.Equal(t, err, tc.expectedError)
			if tc.expectedError == nil {
				assert.Equal(t, pod, createdOperatorPod)
			}
		})
	}
}
