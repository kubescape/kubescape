package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
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
		context.Background(), exceptionsPath, "", nil, true, false, target,
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

// TestExceptionsGetterReadsCRDsOnlyWhenAsked pins that no exceptions source
// reaches for the cluster in the current kube-context on its own: the
// SecurityException CRDs are merged only for a caller that asks for them.
func TestExceptionsGetterReadsCRDsOnlyWhenAsked(t *testing.T) {
	var crdReads atomic.Int64
	withGlobalClusterAPI(t, "global", &crdReads)

	originalStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	t.Cleanup(func() { getter.DefaultLocalStore = originalStore })
	require.NoError(t, os.WriteFile(getter.GetDefaultPath(cautils.LocalExceptionsFilename), []byte("[]"), 0o600))

	exceptionsPath := filepath.Join(t.TempDir(), "exceptions.json")
	require.NoError(t, os.WriteFile(exceptionsPath, []byte("[]"), 0o600))

	ctx := context.Background()
	sources := map[string]func(useCRD bool) (getter.IExceptionsGetter, bool, error){
		"exceptions file": func(useCRD bool) (getter.IExceptionsGetter, bool, error) {
			return getExceptionsGetter(ctx, exceptionsPath, "", nil, useCRD, false)
		},
		"air-gapped cache": func(useCRD bool) (getter.IExceptionsGetter, bool, error) {
			return getExceptionsGetter(ctx, "", "", nil, useCRD, true)
		},
		"release": func(useCRD bool) (getter.IExceptionsGetter, bool, error) {
			return getReleasedExceptionsGetter(ctx, &releasedExceptionsGetterStub{}, useCRD)
		},
		"release cache fallback": func(useCRD bool) (getter.IExceptionsGetter, bool, error) {
			return getReleasedExceptionsGetter(ctx, &releasedExceptionsGetterStub{fallback: true}, useCRD)
		},
	}

	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			crdReads.Store(0)
			exceptionsGetter, _, err := source(false)
			require.NoError(t, err)
			exceptions, err := exceptionsGetter.GetExceptions(ctx, "")
			require.NoError(t, err)
			assert.Empty(t, exceptions)
			assert.Zero(t, crdReads.Load(), "the cluster must not be asked for SecurityException CRDs")

			exceptionsGetter, _, err = source(true)
			require.NoError(t, err)
			exceptions, err = exceptionsGetter.GetExceptions(ctx, "")
			require.NoError(t, err)
			require.Len(t, exceptions, 1)
			assert.Equal(t, "global-exception/C-0001", exceptions[0].Name)
			assert.Positive(t, crdReads.Load())
		})
	}
}

// TestFileScanIgnoresClusterSecurityExceptions pins #4124: a scan of local
// files must report the same result whichever cluster the current kube-context
// points at, so it neither reads nor applies that cluster's SecurityException
// CRDs.
func TestFileScanIgnoresClusterSecurityExceptions(t *testing.T) {
	var crdReads atomic.Int64
	// The cluster excepts C-0001 for every workload in the "global-ns" namespace.
	withGlobalClusterAPI(t, "global", &crdReads)

	originalStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	t.Cleanup(func() { getter.DefaultLocalStore = originalStore })

	dir := t.TempDir()
	writeFile := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	manifestPath := writeFile("pod.yaml", `apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: global-ns
`)

	rule := reporthandling.PolicyRule{
		Rule: `package armo_builtins

import rego.v1

deny contains message if {
	resource := input[_]
	resource.kind == "Pod"
	message := {
		"alertMessage": "pod is not allowed",
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [resource]}
	}
}
`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"Pod"},
		}},
	}
	rule.Name = "deny-pods"
	control := reporthandling.Control{ControlID: "C-0001", BaseScore: 7, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "deny-pods"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "file-scan-probe"
	frameworkBytes, err := json.Marshal(framework)
	require.NoError(t, err)

	scanInfo := &cautils.ScanInfo{
		UseFrom:        []string{writeFile("framework.json", string(frameworkBytes))},
		ControlsInputs: writeFile("controls-inputs.json", `{}`),
		UseExceptions:  writeFile("exceptions.json", `[]`),
		AttackTracks:   writeFile("attack-tracks.json", `[]`),
		InputPatterns:  []string{manifestPath},
		Local:          true,
		FrameworkScan:  true,
		ScanType:       cautils.ScanTypeFramework,
	}
	scanInfo.Submit.SetBool(false)

	results, err := NewKubescape(context.Background()).Scan(scanInfo, []cautils.PolicyIdentifier{{
		Identifier: framework.Name,
		Kind:       apisv1.KindFramework,
	}})
	require.NoError(t, err)
	require.NotNil(t, results)
	data := results.GetData()
	require.NotNil(t, data)

	summary, ok := data.Report.SummaryDetails.Controls[control.ControlID]
	require.True(t, ok)
	assert.Equal(t, apis.StatusFailed, summary.GetStatus().Status())
	assert.Equal(t, 1, summary.StatusCounters.FailedResources)
	assert.Empty(t, data.Exceptions)
	assert.Zero(t, crdReads.Load(), "a file scan must not ask the cluster for SecurityException CRDs")
}

// TestDownloadExceptionsLeavesClusterSecurityExceptionsOut pins that the
// downloaded exceptions, which later scans of any target load, hold the
// selected source only and not the SecurityException CRDs of the cluster in
// the current kube-context.
func TestDownloadExceptionsLeavesClusterSecurityExceptionsOut(t *testing.T) {
	var crdReads atomic.Int64
	withGlobalClusterAPI(t, "global", &crdReads)
	withTenantConfig(t, &fakeTenantConfig{})

	want := []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{Name: "from-source"}}}
	sourcePath := filepath.Join(t.TempDir(), "source.json")
	require.NoError(t, getter.SaveInFile(want, sourcePath))

	// Keep the real getter and the CRD choice downloadExceptions makes, with a
	// local file standing in for the release it would otherwise fetch.
	original := exceptionsGetterFunc
	exceptionsGetterFunc = func(ctx context.Context, _ string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy, useCRD bool, airGapped bool) (getter.IExceptionsGetter, bool, error) {
		return getExceptionsGetter(ctx, sourcePath, accountID, downloadReleasedPolicy, useCRD, airGapped)
	}
	t.Cleanup(func() { exceptionsGetterFunc = original })

	dir := t.TempDir()
	files, err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: dir})
	require.NoError(t, err)
	require.Len(t, files, 1)

	var got []armotypes.PostureExceptionPolicy
	readJSONFile(t, files[0], &got)
	assert.Equal(t, want, got)
	assert.Zero(t, crdReads.Load(), "a download must not ask the cluster for SecurityException CRDs")
}

// withGlobalClusterAPI points the process-global Kubernetes configuration at a
// fake API server, the way a reachable current kube-context does, and counts
// the requests it receives for kubescape.io SecurityException resources.
func withGlobalClusterAPI(t *testing.T, source string, crdReads *atomic.Int64) {
	t.Helper()

	api := newCRDPolicyAPIServer(t, source, new(atomic.Int64))
	t.Cleanup(api.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "securityexceptions") {
			crdReads.Add(1)
		}
		api.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	previousConfig := k8sinterface.K8SConfig
	previousConnected := k8sinterface.IsConnectedToCluster()
	k8sinterface.K8SConfig = &restclient.Config{Host: server.URL}
	k8sinterface.SetConnectedToCluster(true)
	t.Cleanup(func() {
		k8sinterface.K8SConfig = previousConfig
		k8sinterface.SetConnectedToCluster(previousConnected)
	})
}

// TestConfigInputsGetterOnlyAbortsWhenTheScanIsStopped pins that a ControlInput read that timed out connecting falls back instead of aborting the scan.
func TestConfigInputsGetterOnlyAbortsWhenTheScanIsStopped(t *testing.T) {
	dialTimeout := &url.Error{Op: "Get", URL: "https://10.255.255.1/apis/kubescape.io/v1/controlinputs/default", Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}}
	target := &k8sinterface.KubernetesApi{DynamicClient: failingDynamicClient(dialTimeout)}

	t.Run("cluster timed out", func(t *testing.T) {
		g, _, err := getConfigInputsGetterForTarget(context.Background(), "", "", nil, true, false, target)
		require.NoError(t, err)
		require.NotNil(t, g)
		_, isCRD := g.(*getter.CRDControlInputs)
		assert.False(t, isCRD)
	})

	t.Run("scan stopped", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		target := &k8sinterface.KubernetesApi{DynamicClient: failingDynamicClient(context.Canceled)}
		g, _, err := getConfigInputsGetterForTarget(ctx, "", "", nil, true, false, target)
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, g)
	})
}

// failingDynamicClient returns a dynamic client whose every get fails with err.
func failingDynamicClient(err error) dynamic.Interface {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("get", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
	return client
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
