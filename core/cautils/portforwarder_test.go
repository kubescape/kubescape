package cautils

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type FakeCachedDiscoveryClient struct {
	discovery.DiscoveryInterface
	Groups             []*metav1.APIGroup
	Resources          []*metav1.APIResourceList
	PreferredResources []*metav1.APIResourceList
	Invalidations      int
}

func Test_getPortForwardingPort(t *testing.T) {
	testCases := []struct {
		name          string
		createNewPort bool
		port          string
		expectedPort  string
	}{
		{
			name:         "test default port",
			port:         "",
			expectedPort: DefaultPortForwardPortValue,
		},
		{
			name:          "test set port",
			createNewPort: true,
			port:          "1234",
			expectedPort:  "1234",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.createNewPort {
				t.Setenv(DefaultPortForwardPortEnv, tc.port)
			}
			assert.Equal(t, tc.expectedPort, getPortForwardingPort())
		})
	}
}

func Test_CreatePortForwarder(t *testing.T) {
	testCases := []struct {
		name          string
		expectedError error
	}{
		{
			name: "test creation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewSimpleClientset(),
				K8SConfig: &rest.Config{
					Host: "any",
				},
				Context: context.TODO(),
			}

			operatorPod := v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "first",
					Labels: map[string]string{
						"app": "operator",
					},
				},
			}
			createdOperatorPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
			assert.Equal(t, nil, err)

			_, err = CreatePortForwarder(&k8sClient, createdOperatorPod, "1234", "any")
			assert.Equal(t, nil, err)

		})
	}
}

func Test_GetPortForwardLocalhost(t *testing.T) {
	testCases := []struct {
		name   string
		port   string
		result string
	}{
		{
			name:   "test creation",
			port:   "1234",
			result: "localhost",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewSimpleClientset(),
				K8SConfig: &rest.Config{
					Host: "any",
				},
				Context: context.TODO(),
			}

			operatorPod := v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "first",
					Labels: map[string]string{
						"app": "operator",
					},
				},
			}
			createdOperatorPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
			assert.Equal(t, nil, err)

			t.Setenv(DefaultPortForwardPortEnv, tc.port)
			pf, err := CreatePortForwarder(&k8sClient, createdOperatorPod, "1234", "any")
			assert.Equal(t, nil, err)

			result := pf.GetPortForwardLocalhost()
			assert.Equal(t, tc.result+":"+getPortForwardingPort(), result)
		})
	}
}
