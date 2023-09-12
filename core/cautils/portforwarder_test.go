package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
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

// func Test_CreatePortForwarder(t *testing.T) {
// 	testCases := []struct {
// 		name          string
// 		expectedError error
// 	}{
// 		{
// 			name: "test default port",
// 		},
// 		{
// 			name: "test set port",
// 		},
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			fakeClientset := fake.NewSimpleClientset()
// 			config := &rest.Config{
// 				Host:            fakeClientset.RESTClient().Get().URL().String(),
// 				APIPath:         "/api",
// 				BearerToken:     "your-token",                         // Replace with an appropriate token
// 				TLSClientConfig: rest.TLSClientConfig{Insecure: true}, // For testing purposes only
// 			}

// 			k8sClient := k8sinterface.KubernetesApi{
// 				KubernetesClient: fake.NewSimpleClientset(),
// 				Context:          context.TODO(),
// 			}

// 			operatorPod := v1.Pod{
// 				ObjectMeta: metav1.ObjectMeta{
// 					Name: "first",
// 					Labels: map[string]string{
// 						"app": "operator",
// 					},
// 				},
// 			}
// 			createdOperatorPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
// 			assert.Equal(t, nil, err)

// 			_, err = CreatePortForwarder(&k8sClient, createdOperatorPod, "1234", "any")
// 			assert.Equal(t, nil, err)

// 		})
// 	}
// }
