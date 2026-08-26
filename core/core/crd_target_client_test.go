package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/dynamic"
	restclient "k8s.io/client-go/rest"
)

func TestCRDPolicyGettersUseScanTargetClient(t *testing.T) {
	var globalRequests atomic.Int64
	globalServer := newCRDPolicyAPIServer(t, "global", &globalRequests)
	defer globalServer.Close()

	var targetRequests atomic.Int64
	targetServer := newCRDPolicyAPIServer(t, "target", &targetRequests)
	defer targetServer.Close()

	previousConfig := k8sinterface.K8SConfig
	previousConnected := k8sinterface.IsConnectedToCluster()
	k8sinterface.K8SConfig = &restclient.Config{Host: globalServer.URL}
	k8sinterface.SetConnectedToCluster(true)
	t.Cleanup(func() {
		k8sinterface.K8SConfig = previousConfig
		k8sinterface.SetConnectedToCluster(previousConnected)
	})

	targetConfig := &restclient.Config{Host: targetServer.URL}
	targetDynamic, err := dynamic.NewForConfig(targetConfig)
	require.NoError(t, err)
	target := &k8sinterface.KubernetesApi{
		DynamicClient: targetDynamic,
		K8SConfig:     targetConfig,
	}

	controlInputsGetter, fromCache, err := getConfigInputsGetterForTarget(
		context.Background(), "", "", nil, true, false, target,
	)
	require.NoError(t, err)
	assert.False(t, fromCache)
	controlInputs, err := controlInputsGetter.GetControlsInputs(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, []string{"target"}, controlInputs["source"])

	exceptionsPath := filepath.Join(t.TempDir(), "exceptions.json")
	require.NoError(t, os.WriteFile(exceptionsPath, []byte("[]"), 0o600))
	exceptionsGetter, exceptionsFromCache, err := getExceptionsGetterForTarget(
		context.Background(), exceptionsPath, "", nil, false, target,
	)
	require.NoError(t, err)
	assert.False(t, exceptionsFromCache)
	exceptions, err := exceptionsGetter.GetExceptions(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, exceptions, 1)
	assert.Equal(t, "target-exception/C-0001", exceptions[0].Name)
	require.Len(t, exceptions[0].Resources, 1)
	assert.Equal(t, "target-ns", exceptions[0].Resources[0].Attributes["namespace"])

	assert.Zero(t, globalRequests.Load(), "CRD policy reads must not consult the process-global API server")
	assert.Positive(t, targetRequests.Load())
}

func newCRDPolicyAPIServer(t *testing.T, source string, requests *atomic.Int64) *httptest.Server {
	t.Helper()

	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Errorf("encode fake Kubernetes API response: %v", err)
		}
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/api":
			writeJSON(w, map[string]any{
				"apiVersion": "v1",
				"kind":       "APIVersions",
				"versions":   []string{"v1"},
			})
		case "/apis":
			writeJSON(w, map[string]any{
				"apiVersion": "v1",
				"kind":       "APIGroupList",
				"groups":     []any{},
			})
		case "/api/v1":
			writeJSON(w, map[string]any{
				"apiVersion":   "v1",
				"kind":         "APIResourceList",
				"groupVersion": "v1",
				"resources": []map[string]any{{
					"name":         "namespaces",
					"singularName": "namespace",
					"namespaced":   false,
					"kind":         "Namespace",
					"verbs":        []string{"get", "list"},
				}},
			})
		case "/api/v1/namespaces":
			writeJSON(w, map[string]any{
				"apiVersion": "v1",
				"kind":       "NamespaceList",
				"items": []map[string]any{{
					"apiVersion": "v1",
					"kind":       "Namespace",
					"metadata": map[string]any{
						"name":   source + "-ns",
						"labels": map[string]string{"source": source},
					},
				}},
			})
		case "/apis/kubescape.io/v1/controlinputs/default":
			writeJSON(w, map[string]any{
				"apiVersion": "kubescape.io/v1",
				"kind":       "ControlInput",
				"metadata":   map[string]any{"name": "default"},
				"spec": map[string]any{
					"controls": map[string]any{"source": []string{source}},
				},
			})
		case "/apis/kubescape.io/v1beta1/securityexceptions":
			writeJSON(w, map[string]any{
				"apiVersion": "kubescape.io/v1beta1",
				"kind":       "SecurityExceptionList",
				"items":      []any{},
			})
		case "/apis/kubescape.io/v1beta1/clustersecurityexceptions":
			writeJSON(w, map[string]any{
				"apiVersion": "kubescape.io/v1beta1",
				"kind":       "ClusterSecurityExceptionList",
				"items": []map[string]any{{
					"apiVersion": "kubescape.io/v1beta1",
					"kind":       "ClusterSecurityException",
					"metadata": map[string]any{
						"name": source + "-exception",
					},
					"spec": map[string]any{
						"match": map[string]any{
							"namespaceSelector": map[string]any{
								"matchLabels": map[string]string{"source": source},
							},
						},
						"posture": []map[string]any{{
							"controlID": "C-0001",
							"action":    "ignore",
						}},
					},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}
