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

func Test_splitHostAndBasePath(t *testing.T) {
	testCases := []struct {
		name         string
		host         string
		wantHost     string
		wantBasePath string
		wantErr      bool
	}{
		{
			name:     "https scheme is stripped",
			host:     "https://1.2.3.4:6443",
			wantHost: "1.2.3.4:6443",
		},
		{
			name:     "http scheme is stripped",
			host:     "http://1.2.3.4:6443",
			wantHost: "1.2.3.4:6443",
		},
		{
			name:     "host without scheme is returned unchanged",
			host:     "1.2.3.4:6443",
			wantHost: "1.2.3.4:6443",
		},
		{
			name:     "empty host is returned unchanged",
			host:     "",
			wantHost: "",
		},
		{
			name:     "hostname starting with 'h' is preserved after https scheme",
			host:     "https://hello-cluster.example.com:6443",
			wantHost: "hello-cluster.example.com:6443",
		},
		{
			name:     "hostname starting with 't' is preserved after https scheme",
			host:     "https://test.example.com:6443",
			wantHost: "test.example.com:6443",
		},
		{
			name:     "hostname starting with 'p' is preserved after https scheme",
			host:     "https://prod.example.com",
			wantHost: "prod.example.com",
		},
		{
			name:     "hostname starting with 's' is preserved after https scheme",
			host:     "https://staging.example.com",
			wantHost: "staging.example.com",
		},
		{
			name:     "kubernetes.docker.internal is preserved",
			host:     "https://kubernetes.docker.internal:6443",
			wantHost: "kubernetes.docker.internal:6443",
		},
		{
			name:         "host with base path preserves path",
			host:         "https://proxy.example.com/k8s",
			wantHost:     "proxy.example.com",
			wantBasePath: "/k8s",
		},
		{
			name:         "host with port and base path preserves both",
			host:         "https://proxy.example.com:6443/k8s",
			wantHost:     "proxy.example.com:6443",
			wantBasePath: "/k8s",
		},
		{
			name:         "trailing slash on base path is trimmed",
			host:         "https://proxy.example.com/k8s/",
			wantHost:     "proxy.example.com",
			wantBasePath: "/k8s",
		},
		{
			name:         "multi-segment base path is preserved",
			host:         "https://proxy.example.com/api/v1/k8s",
			wantHost:     "proxy.example.com",
			wantBasePath: "/api/v1/k8s",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotBasePath, err := splitHostAndBasePath(tc.host)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantHost, gotHost)
			assert.Equal(t, tc.wantBasePath, gotBasePath)
		})
	}
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
				KubernetesClient: fake.NewClientset(),
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
				KubernetesClient: fake.NewClientset(),
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
