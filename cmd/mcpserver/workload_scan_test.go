package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
)

// --- request building (no scan) -------------------------------------------

func TestBuildWorkloadScanRequest_InvalidIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		workload string
		wantErr  string
	}{
		{name: "empty identifier", workload: ""},
		{name: "missing kind", workload: "nginx"},
		{name: "too many segments", workload: "cluster/default/Deployment/nginx"},
		{name: "empty segment", workload: "default//nginx"},
		{name: "bad api version", workload: "Deployment.vX.apps/nginx", wantErr: "is not a valid API version"},
		{name: "missing api version", workload: "Deployment.apps/nginx", wantErr: "is not a valid API version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildWorkloadScanRequest(tt.workload, "", "", "")
			require.Error(t, err)
			assert.True(t, errors.Is(err, cautils.ErrInvalidWorkloadIdentifier),
				"expected ErrInvalidWorkloadIdentifier, got %v", err)
			if tt.wantErr != "" {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuildWorkloadScanRequest_ScanObject(t *testing.T) {
	tests := []struct {
		name          string
		workload      string
		namespace     string
		wantNamespace string
		wantKind      string
		wantName      string
		wantAPIVer    string
	}{
		{
			name:          "bare kind and name leaves apiVersion unset for discovery and defaults namespace to default",
			workload:      "Deployment/nginx",
			wantNamespace: "default",
			wantKind:      "Deployment",
			wantName:      "nginx",
		},
		{
			name:          "namespace from the identifier",
			workload:      "default/Deployment/nginx",
			wantNamespace: "default",
			wantKind:      "Deployment",
			wantName:      "nginx",
		},
		{
			name:          "explicit namespace when identifier has none",
			workload:      "Deployment/nginx",
			namespace:     "b",
			wantNamespace: "b",
			wantKind:      "Deployment",
			wantName:      "nginx",
		},
		{
			name:          "dotted kind resolves to a group/version apiVersion",
			workload:      "Deployment.v1.apps/nginx",
			wantNamespace: "default",
			wantKind:      "Deployment",
			wantName:      "nginx",
			wantAPIVer:    "apps/v1",
		},
		{
			name:          "bare short name preserves raw kind",
			workload:      "deploy/nginx",
			wantNamespace: "default",
			wantKind:      "deploy",
			wantName:      "nginx",
		},
		{
			name:          "bare CRD kind preserves casing",
			workload:      "Deploy/crd-deploy",
			wantNamespace: "default",
			wantKind:      "Deploy",
			wantName:      "crd-deploy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildWorkloadScanRequest(tt.workload, tt.namespace, "", "")
			require.NoError(t, err)
			require.NotNil(t, req.scanObject)
			assert.Equal(t, tt.wantNamespace, req.scanObject.GetNamespace())
			assert.Equal(t, tt.wantKind, req.scanObject.GetKind())
			assert.Equal(t, tt.wantName, req.scanObject.GetName())
			assert.Equal(t, tt.wantAPIVer, req.scanObject.GetApiVersion())
			assert.Equal(t, tt.wantNamespace, req.namespace)
		})
	}
}

// TestBuildWorkloadScanRequest_NamespacePrecedence pins the namespace resolution rules.
// An omitted namespace defaults to "default" for cluster scans, and remains unconstrained for file scans.
func TestBuildWorkloadScanRequest_NamespacePrecedence(t *testing.T) {
	tests := []struct {
		name          string
		workload      string
		namespace     string
		path          string
		want          string
		wantDefaulted bool
	}{
		{
			name:          "omitted, identifier has none defaults to default",
			workload:      "Deployment/nginx",
			want:          "default",
			wantDefaulted: true,
		},
		{
			name:          "file scan: omitted, identifier has none leaves namespace empty",
			workload:      "Deployment/nginx",
			path:          "testdata/deployment.yaml",
			want:          "",
			wantDefaulted: false,
		},
		{
			name:          "omitted, identifier supplies one",
			workload:      "default/Deployment/nginx",
			want:          "default",
			wantDefaulted: false,
		},
		{
			name:          "matching explicit and identifier",
			workload:      "default/Deployment/nginx",
			namespace:     "default",
			want:          "default",
			wantDefaulted: false,
		},
		{
			name:          "explicit namespace when identifier has none",
			workload:      "Deployment/nginx",
			namespace:     "b",
			want:          "b",
			wantDefaulted: false,
		},
		{
			name:          "wildcard with no identifier namespace stays cluster-wide",
			workload:      "Deployment/nginx",
			namespace:     "*",
			want:          "",
			wantDefaulted: false,
		},
		{
			name:          "identifier wildcard with no namespace argument stays cluster-wide",
			workload:      "*/Deployment/nginx",
			namespace:     "",
			want:          "",
			wantDefaulted: false,
		},
		{
			name:          "explicit namespace is trimmed",
			workload:      "Deployment/nginx",
			namespace:     "  default  ",
			want:          "default",
			wantDefaulted: false,
		},
		{
			name:          "whitespace-only namespace reads as omitted",
			workload:      "default/Deployment/nginx",
			namespace:     "   ",
			want:          "default",
			wantDefaulted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildWorkloadScanRequest(tt.workload, tt.namespace, tt.path, "")
			require.NoError(t, err)
			require.NotNil(t, req.scanObject)
			assert.Equal(t, tt.want, req.scanObject.GetNamespace(),
				"the scan object's namespace is what both resource handlers match on")
			if tt.path == "" {
				assert.Equal(t, tt.want, req.namespace)
			} else {
				assert.Equal(t, "", req.namespace, "file scan request leaves collection namespace empty")
			}
			assert.Equal(t, tt.wantDefaulted, req.namespaceDefaulted)
		})
	}
}

func TestBuildWorkloadScanRequest_NamespaceConflict(t *testing.T) {
	tests := []struct {
		name      string
		workload  string
		namespace string
		wantErr   string
	}{
		{
			name:      "explicit differs from identifier",
			workload:  "a/Deployment/nginx",
			namespace: "b",
			wantErr:   "conflicting namespaces",
		},
		{
			name:      "wildcard differs from identifier namespace",
			workload:  "default/Deployment/nginx",
			namespace: "*",
			wantErr:   "conflicting namespaces",
		},
		{
			name:      "identifier wildcard differs from explicit namespace",
			workload:  "*/Deployment/nginx",
			namespace: "prod",
			wantErr:   "conflicting namespaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildWorkloadScanRequest(tt.workload, tt.namespace, "", "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.True(t, errors.Is(err, cautils.ErrInvalidWorkloadIdentifier))
		})
	}
}

func TestBuildWorkloadScanRequest_Frameworks(t *testing.T) {
	t.Run("defaults to the workload control set", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("Deployment/nginx", "", "", "")
		require.NoError(t, err)
		got := make([]string, 0, len(req.policyIdentifiers))
		for _, pi := range req.policyIdentifiers {
			got = append(got, pi.Identifier)
		}
		assert.Equal(t, workloadScanFrameworks, got)
	})

	t.Run("an explicit framework replaces the default", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("Deployment/nginx", "", "", "  nsa  ")
		require.NoError(t, err)
		require.Len(t, req.policyIdentifiers, 1)
		assert.Equal(t, "nsa", req.policyIdentifiers[0].Identifier)
	})
}

// TestBuildScanInfo_WorkloadTimeout pins the budget a single-workload scan
// gets. The namespace-derived budgets do not apply: a workload scan's cost is
// the control set it loads, not the resources a namespace would exclude, and
// the 10s a namespaced scan would otherwise receive is under the measured cost
// of loading the default workload control set.
func TestBuildScanInfo_WorkloadTimeout(t *testing.T) {
	tests := []struct {
		namespace     string
		wantNamespace string
	}{
		{namespace: "", wantNamespace: "default"},
		{namespace: "*", wantNamespace: ""},
		{namespace: "default", wantNamespace: "default"},
	}
	for _, tt := range tests {
		t.Run("namespace="+tt.namespace, func(t *testing.T) {
			req, err := buildWorkloadScanRequest("Deployment/nginx", tt.namespace, "", "")
			require.NoError(t, err)
			scanInfo := buildScanInfo(req)
			assert.Equal(t, workloadScanTimeout, scanInfo.ScanTimeout,
				"a workload scan's budget must not be derived from its namespace")
			require.NotNil(t, scanInfo.ScanObject)
			assert.Equal(t, "nginx", scanInfo.ScanObject.GetName(),
				"the scan object must reach ScanInfo, which is what drives single-resource collection")
			assert.Equal(t, tt.wantNamespace, scanInfo.ScanObject.GetNamespace())
		})
	}
}

func TestMCPStringArg(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		got, toolErr := mcpStringArg(map[string]any{}, "path")
		assert.Nil(t, toolErr)
		assert.Equal(t, "", got)
	})

	t.Run("null is absent, not a type error", func(t *testing.T) {
		got, toolErr := mcpStringArg(map[string]any{"path": nil}, "path")
		assert.Nil(t, toolErr, "a null optional argument must not refuse the call")
		assert.Equal(t, "", got)
	})

	t.Run("trimmed", func(t *testing.T) {
		got, toolErr := mcpStringArg(map[string]any{"path": "  ./x  "}, "path")
		assert.Nil(t, toolErr)
		assert.Equal(t, "./x", got)
	})

	t.Run("wrong type is reported", func(t *testing.T) {
		_, toolErr := mcpStringArg(map[string]any{"path": 42}, "path")
		require.NotNil(t, toolErr)
		assert.Contains(t, toolResultText(t, toolErr), "path argument must be a string")
	})
}

// TestBuildScanInfo_NonWorkloadTimeoutsUnchanged guards the existing scans
// against the workload branch leaking into them.
func TestBuildScanInfo_NonWorkloadTimeoutsUnchanged(t *testing.T) {
	tests := []struct {
		namespace           string
		wantComplianceScore bool
		want                time.Duration
	}{
		{namespace: "default", want: 10 * time.Second},
		{namespace: "default", wantComplianceScore: true, want: 30 * time.Second},
		{namespace: "", want: 60 * time.Second},
		{namespace: "*", want: 60 * time.Second},
		{namespace: "", wantComplianceScore: true, want: 120 * time.Second},
	}
	for _, tt := range tests {
		scanInfo := buildScanInfo(scanRequest{namespace: tt.namespace, wantComplianceScore: tt.wantComplianceScore})
		assert.Equal(t, tt.want, scanInfo.ScanTimeout,
			"namespace=%q complianceScore=%v", tt.namespace, tt.wantComplianceScore)
		assert.Nil(t, scanInfo.ScanObject)
	}
}

func TestBuildWorkloadScanRequest_HandlerSelection(t *testing.T) {
	t.Run("no path scans the live cluster", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("default/Deployment/nginx", "", "", "")
		require.NoError(t, err)
		assert.Nil(t, req.rsrcHandler, "a nil handler is what makes executeScan build a cluster client")
		assert.Empty(t, req.inputPatterns)
		assert.Equal(t, "default", req.namespace)
	})

	t.Run("a path switches to the file handler and drops the collection namespace", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("default/Deployment/nginx", "", "testdata/deployment.yaml", "")
		require.NoError(t, err)
		require.NotNil(t, req.rsrcHandler)
		assert.Equal(t, []string{"testdata/deployment.yaml"}, req.inputPatterns)
		assert.Empty(t, req.namespace, "the file handler has no namespace collection filter")
		assert.Equal(t, "default", req.scanObject.GetNamespace(),
			"the namespace must survive on the scan object, which is what matches the manifests")
	})
}

// --- resolution against local manifests -----------------------------------
//
// These run the real collect-policies → collect-resources pipeline through
// FileResourceHandler, so they exercise ScanObject resolution without a
// cluster. They pass an explicit framework to keep the policy set small; the
// default set is asserted separately above.

func newWorkloadScanTestServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	return &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
	}
}

func TestRunWorkloadScan_ResolvesFromFile(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// File scan with omitted namespace resolves cleanly and does not default namespace
	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "", "testdata/deployment.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)
	assert.NotContains(t, string(respBytes), `"warning":`)
	assert.NotContains(t, string(respBytes), `"namespace_defaulted": true`)

	respBytesExplicit, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "default", "testdata/deployment.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytesExplicit), `"total_failed":`)
	assert.NotContains(t, string(respBytesExplicit), `"warning":`)
	assert.NotContains(t, string(respBytesExplicit), `"namespace_defaulted": true`)
}

func TestRunWorkloadScan_CaseInsensitiveAndShortName(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// Lowercase kind
	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "deployment/nginx", "", "testdata/deployment.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)

	// Registered kubectl short name
	respBytes, err = ksServer.RunWorkloadScan(context.Background(), "deploy/nginx", "", "testdata/deployment.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)
}

func TestRunWorkloadScan_CRDDeploy(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// CRD with kind: Deploy matched via exact PascalCase kind
	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "Deploy/crd-deploy", "", "testdata/crd-deploy.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)

	// CRD with kind: Deploy matched via lowercase alias kind in pass 1
	respBytes, err = ksServer.RunWorkloadScan(context.Background(), "deploy/crd-deploy", "", "testdata/crd-deploy.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)
}

func TestRunWorkloadScan_NotFoundInFile(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	_, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/absent", "", "testdata/deployment.yaml", "nsa")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "not found")
	assert.True(t, errors.Is(err, resourcehandler.ErrResourceNotFound), "expected ErrResourceNotFound sentinel in error chain")
}

func TestRunWorkloadScan_AmbiguousInFile(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// Two Deployments named nginx in different namespaces: without a namespace,
	// file resolution does not restrict to "default", matching both and reporting ambiguity.
	_, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "", "testdata/two-workloads.yaml", "nsa")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "more than one")
	assert.True(t, errors.Is(err, resourcehandler.ErrAmbiguousResource), "expected ErrAmbiguousResource sentinel in error chain")

	// Explicit wildcard "*" also matches both across namespaces
	_, err = ksServer.RunWorkloadScan(context.Background(), "*/Deployment/nginx", "", "testdata/two-workloads.yaml", "nsa")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "more than one")
	assert.True(t, errors.Is(err, resourcehandler.ErrAmbiguousResource), "expected ErrAmbiguousResource sentinel in error chain")

	// Also verify passing namespace: "*" parameter directly
	_, err = ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "*", "testdata/two-workloads.yaml", "nsa")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "more than one")
	assert.True(t, errors.Is(err, resourcehandler.ErrAmbiguousResource), "expected ErrAmbiguousResource sentinel in error chain")
}

func TestRunWorkloadScan_NamespaceDisambiguates(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// The same file that is ambiguous above resolves cleanly once the namespace
	// picks one of the two.
	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "staging/Deployment/nginx", "", "testdata/two-workloads.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)
}

func TestRunWorkloadScan_InvalidIdentifierDoesNotScan(t *testing.T) {
	// No policy getter is configured: reaching the scan would fail differently,
	// so this also proves the identifier is rejected before any work starts.
	ksServer := &KubescapeMcpserver{}

	_, err := ksServer.RunWorkloadScan(context.Background(), "nginx", "", "testdata/deployment.yaml", "nsa")
	require.Error(t, err)
	assert.True(t, errors.Is(err, cautils.ErrInvalidWorkloadIdentifier))
}

// --- resolution against live cluster ---------------------------------------
//
// These run the real collect-policies -> collect-resources pipeline with an
// empty path, forcing executeScan to construct K8sResourceHandler from
// ksServer.k8sClient instead of FileResourceHandler.

var (
	sharedLiveClusterPolicyGetter     getter.IPolicyGetter
	sharedLiveClusterPolicyGetterErr  error
	sharedLiveClusterPolicyFallback   bool
	sharedLiveClusterPolicyGetterOnce sync.Once
	initMockResourcesOnce             sync.Once
)

func initMockResources() {
	initMockResourcesOnce.Do(func() {
		k8sinterface.InitializeMapResourcesMock()
	})
}

func getSharedLiveClusterPolicyGetter(t *testing.T) getter.IPolicyGetter {
	t.Helper()
	sharedLiveClusterPolicyGetterOnce.Do(func() {
		drp := getter.NewDownloadReleasedPolicy()
		sharedLiveClusterPolicyFallback, sharedLiveClusterPolicyGetterErr = drp.SetRegoObjectsWithFallback()
		if sharedLiveClusterPolicyGetterErr != nil {
			return
		}
		if sharedLiveClusterPolicyFallback {
			paths := make([]string, 0, len(getter.NativeFrameworks)+4)
			for _, fw := range getter.NativeFrameworks {
				paths = append(paths, getter.GetDefaultPath(fw+".json"))
			}
			paths = append(paths,
				getter.GetDefaultPath("allcontrols.json"),
				getter.GetDefaultPath("c-0017.json"),
				filepath.Join("..", "..", "core", "cautils", "getter", "testdata", "NSA.json"),
				filepath.Join("..", "..", "core", "cautils", "getter", "testdata", "MITRE.json"),
			)
			sharedLiveClusterPolicyGetter = getter.NewLoadPolicy(paths)
		} else {
			sharedLiveClusterPolicyGetter = drp
		}
	})
	if sharedLiveClusterPolicyGetterErr != nil {
		t.Skipf("failed to initialize policy getter from network/disk fallback: %v", sharedLiveClusterPolicyGetterErr)
	}
	if sharedLiveClusterPolicyFallback {
		t.Log("using fallback policy store for live-cluster test")
	}
	return sharedLiveClusterPolicyGetter
}

func newLiveClusterWorkloadScanTestServer(t *testing.T, objects ...runtime.Object) *KubescapeMcpserver {
	t.Helper()
	initMockResources()

	listKinds := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}:                                             "DeploymentList",
		{Group: "apps", Version: "v1", Resource: "replicasets"}:                                             "ReplicaSetList",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}:                                              "DaemonSetList",
		{Group: "apps", Version: "v1", Resource: "statefulsets"}:                                            "StatefulSetList",
		{Group: "batch", Version: "v1", Resource: "jobs"}:                                                   "JobList",
		{Group: "batch", Version: "v1", Resource: "cronjobs"}:                                               "CronJobList",
		{Group: "", Version: "v1", Resource: "pods"}:                                                        "PodList",
		{Group: "", Version: "v1", Resource: "nodes"}:                                                       "NodeList",
		{Group: "", Version: "v1", Resource: "namespaces"}:                                                  "NamespaceList",
		{Group: "", Version: "v1", Resource: "services"}:                                                    "ServiceList",
		{Group: "", Version: "v1", Resource: "serviceaccounts"}:                                             "ServiceAccountList",
		{Group: "", Version: "v1", Resource: "configmaps"}:                                                  "ConfigMapList",
		{Group: "", Version: "v1", Resource: "endpoints"}:                                                   "EndpointsList",
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}:                            "NetworkPolicyList",
		{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}:                                  "IngressList",
		{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}:                                  "PodDisruptionBudgetList",
		{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}:                              "PodSecurityPolicyList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}:                              "RoleList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}:                       "RoleBindingList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}:                       "ClusterRoleList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}:                "ClusterRoleBindingList",
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}: "ValidatingWebhookConfigurationList",
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}:   "MutatingWebhookConfigurationList",
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)

	dummyNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
	}
	k8sClient := kubernetesfake.NewSimpleClientset(dummyNode)

	discovery := k8sClient.Discovery().(*discoveryfake.FakeDiscovery)
	discovery.FakedServerVersion = &version.Info{
		GitVersion: "v1.28.0",
		Major:      "1",
		Minor:      "28",
	}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "apps/v1",
			APIResources: []metav1.APIResource{
				{Name: "deployments", Kind: "Deployment", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "replicasets", Kind: "ReplicaSet", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "daemonsets", Kind: "DaemonSet", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "statefulsets", Kind: "StatefulSet", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "batch/v1",
			APIResources: []metav1.APIResource{
				{Name: "jobs", Kind: "Job", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "cronjobs", Kind: "CronJob", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "nodes", Kind: "Node", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
				{Name: "namespaces", Kind: "Namespace", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
				{Name: "services", Kind: "Service", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "configmaps", Kind: "ConfigMap", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "endpoints", Kind: "Endpoints", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "networkpolicies", Kind: "NetworkPolicy", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "ingresses", Kind: "Ingress", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "policy/v1",
			APIResources: []metav1.APIResource{
				{Name: "poddisruptionbudgets", Kind: "PodDisruptionBudget", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "policy/v1beta1",
			APIResources: []metav1.APIResource{
				{Name: "podsecuritypolicies", Kind: "PodSecurityPolicy", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "rbac.authorization.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "roles", Kind: "Role", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "rolebindings", Kind: "RoleBinding", Namespaced: true, Verbs: []string{"get", "list", "watch"}},
				{Name: "clusterroles", Kind: "ClusterRole", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
				{Name: "clusterrolebindings", Kind: "ClusterRoleBinding", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "admissionregistration.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
				{Name: "mutatingwebhookconfigurations", Kind: "MutatingWebhookConfiguration", Namespaced: false, Verbs: []string{"get", "list", "watch"}},
			},
		},
	}

	ksServer := &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
		k8sClient: &k8sinterface.KubernetesApi{
			DynamicClient:    dyn,
			KubernetesClient: k8sClient,
			DiscoveryClient:  discovery,
		},
	}
	return ksServer
}

func TestRunWorkloadScan_LiveClusterPath(t *testing.T) {
	deploy := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"matchLabels": map[string]any{"app": "nginx"},
			},
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{"app": "nginx"},
				},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:latest",
						},
					},
				},
			},
		},
	}}

	ksServer := newLiveClusterWorkloadScanTestServer(t, deploy)

	// path is empty and namespace omitted: forces executeScan to construct NewK8sResourceHandler
	// and defaults namespace to default with warning
	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "", "", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"warning":`)
	assert.Contains(t, string(respBytes), `"namespace_defaulted": true`)

	var resp struct {
		FrameworkName   string `json:"framework_name"`
		TotalControls   int    `json:"total_controls"`
		TotalFailed     int    `json:"total_failed"`
		ReturnedFailed  int    `json:"returned_failed"`
		Truncated       bool   `json:"truncated"`
		FailedResources []any  `json:"failed_resources"`
	}
	err = json.Unmarshal(respBytes, &resp)
	require.NoError(t, err)

	assert.Greater(t, resp.TotalControls, 0)
	assert.GreaterOrEqual(t, resp.TotalFailed, 0)
	assert.LessOrEqual(t, resp.ReturnedFailed, resp.TotalFailed)
	assert.False(t, resp.Truncated)

	if resp.ReturnedFailed > 0 {
		firstFailed, ok := resp.FailedResources[0].(map[string]any)
		require.True(t, ok, "expected failed resource entry to be an object")
		resourceID, _ := firstFailed["resourceID"].(string)
		assert.Contains(t, resourceID, "Deployment")
		assert.Contains(t, resourceID, "nginx")

		if rawRes, ok := firstFailed["rawResource"].(map[string]any); ok {
			if obj, ok := rawRes["object"].(map[string]any); ok {
				assert.Equal(t, "Deployment", obj["kind"])
				if meta, ok := obj["metadata"].(map[string]any); ok {
					assert.Equal(t, "nginx", meta["name"])
				}
			}
		}
	}
}

func TestRunWorkloadScan_LiveClusterPath_NotFound(t *testing.T) {
	// Empty cluster (no objects seeded)
	ksServer := newLiveClusterWorkloadScanTestServer(t)

	// Omitted namespace: defaults to default and wraps hint
	_, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/absent", "", "", "nsa")
	require.Error(t, err)
	assert.True(t, errors.Is(err, resourcehandler.ErrResourceNotFound), "expected ErrResourceNotFound sentinel in error chain")
	var hinted interface{ Hint() string }
	require.True(t, errors.As(err, &hinted))
	assert.Equal(t, mcpNamespaceDefaultedHint, hinted.Hint())

	// Explicit namespace: no hint wrapped
	_, errExplicit := ksServer.RunWorkloadScan(context.Background(), "Deployment/absent", "default", "", "nsa")
	require.Error(t, errExplicit)
	assert.True(t, errors.Is(errExplicit, resourcehandler.ErrResourceNotFound))
	assert.False(t, errors.As(errExplicit, &hinted))
}

// --- tool dispatch --------------------------------------------------------

// stubWorkloadScan replaces the scan seam with a recorder so CallTool argument
// mapping can be asserted without running a scan, and restores it afterwards.
// It returns a pointer to the recorded arguments.
func stubWorkloadScan(t *testing.T) *struct{ workload, namespace, path, framework string } {
	t.Helper()
	got := &struct{ workload, namespace, path, framework string }{}
	orig := workloadScanFn
	t.Cleanup(func() { workloadScanFn = orig })
	workloadScanFn = func(_ *KubescapeMcpserver, _ context.Context, workload, namespace, path, framework string) ([]byte, error) {
		got.workload, got.namespace, got.path, got.framework = workload, namespace, path, framework
		return []byte(`{"total_failed":0}`), nil
	}
	return got
}

func newWorkloadToolServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	require.NotPanics(t, func() { createWorkloadScanningTools(ksServer) })
	return ksServer
}

func TestCallTool_ScanWorkload_ArgumentErrors(t *testing.T) {
	tests := []struct {
		name      string
		arguments map[string]any
		wantErr   string
	}{
		{
			name:      "missing workload",
			arguments: map[string]any{},
			wantErr:   "workload argument is required",
		},
		{
			name:      "blank workload",
			arguments: map[string]any{"workload": "   "},
			wantErr:   "workload argument is required",
		},
		{
			name:      "non-string workload",
			arguments: map[string]any{"workload": 42},
			wantErr:   "workload argument must be a string",
		},
		{
			name:      "non-string namespace",
			arguments: map[string]any{"workload": "Deployment/nginx", "namespace": 7},
			wantErr:   "namespace argument must be a string",
		},
		{
			name:      "non-string path",
			arguments: map[string]any{"workload": "Deployment/nginx", "path": true},
			wantErr:   "path argument must be a string",
		},
		{
			name:      "non-string framework",
			arguments: map[string]any{"workload": "Deployment/nginx", "framework": []any{"nsa"}},
			wantErr:   "framework argument must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubWorkloadScan(t)
			ksServer := newWorkloadToolServer(t)

			res, err := ksServer.CallTool(context.Background(), "scan_workload", tt.arguments)
			require.NoError(t, err, "argument problems are reported as tool errors, not Go errors")
			require.NotNil(t, res)
			assert.True(t, res.IsError, "expected a tool error result")
			assert.Contains(t, toolResultText(t, res), tt.wantErr)
		})
	}
}

func TestCallTool_ScanWorkload_ForwardsArguments(t *testing.T) {
	tests := []struct {
		name          string
		arguments     map[string]any
		wantWorkload  string
		wantNamespace string
		wantPath      string
		wantFramework string
	}{
		{
			name:         "workload only",
			arguments:    map[string]any{"workload": "Deployment/nginx"},
			wantWorkload: "Deployment/nginx",
		},
		{
			// "*" is forwarded verbatim, not folded into "": the wildcard has to
			// stay distinguishable from an omitted argument until
			// buildWorkloadScanRequest can weigh it against the identifier's
			// namespace. The resolution itself is asserted in
			// TestBuildWorkloadScanRequest_NamespacePrecedence.
			name:          "wildcard namespace survives dispatch",
			arguments:     map[string]any{"workload": "Deployment/nginx", "namespace": "*"},
			wantWorkload:  "Deployment/nginx",
			wantNamespace: "*",
		},
		{
			name:          "all arguments forwarded and trimmed",
			arguments:     map[string]any{"workload": "  Deployment/nginx  ", "namespace": "  default  ", "path": "  ./manifests  ", "framework": " nsa "},
			wantWorkload:  "Deployment/nginx",
			wantNamespace: "default",
			wantPath:      "./manifests",
			wantFramework: "nsa",
		},
		{
			// Clients commonly send null for an optional parameter they are not
			// setting; that must read as absent rather than refusing the call.
			name:         "null optional arguments are treated as absent",
			arguments:    map[string]any{"workload": "Deployment/nginx", "namespace": nil, "path": nil, "framework": nil},
			wantWorkload: "Deployment/nginx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stubWorkloadScan(t)
			ksServer := newWorkloadToolServer(t)

			res, err := ksServer.CallTool(context.Background(), "scan_workload", tt.arguments)
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.False(t, res.IsError, "unexpected tool error: %s", toolResultText(t, res))

			assert.Equal(t, tt.wantWorkload, got.workload)
			assert.Equal(t, tt.wantNamespace, got.namespace)
			assert.Equal(t, tt.wantPath, got.path)
			assert.Equal(t, tt.wantFramework, got.framework)
		})
	}
}

// TestCallTool_ScanWorkload_ScanFailureIsToolError asserts a failing scan comes
// back as a structured tool error the agent can read, not a transport-level Go error.
func TestCallTool_ScanWorkload_ScanFailureIsToolError(t *testing.T) {
	orig := workloadScanFn
	t.Cleanup(func() { workloadScanFn = orig })
	workloadScanFn = func(_ *KubescapeMcpserver, _ context.Context, _, ns, _, _ string) ([]byte, error) {
		baseErr := fmt.Errorf("resource nginx was not found: %w", resourcehandler.ErrResourceNotFound)
		if ns == "" {
			return nil, &defaultedNamespaceError{err: baseErr, hint: mcpNamespaceDefaultedHint}
		}
		return nil, baseErr
	}
	ksServer := newWorkloadToolServer(t)

	// Omitted namespace: defaulted to default, includes hint
	res, err := ksServer.CallTool(context.Background(), "scan_workload", map[string]any{"workload": "Deployment/nginx"})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.IsError)
	text := toolResultText(t, res)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(text), &toolErr))
	assert.Equal(t, ErrCodeResourceNotFound, toolErr.Code)
	assert.Contains(t, toolErr.Message, "was not found", "the underlying reason must survive to the caller")
	assert.Contains(t, toolErr.Message, mcpNamespaceDefaultedHint)
	assert.Equal(t, mcpNamespaceDefaultedHint, toolErr.Details["hint"])

	// Explicit namespace: no defaulted hint
	resExplicit, err := ksServer.CallTool(context.Background(), "scan_workload", map[string]any{"workload": "Deployment/nginx", "namespace": "default"})
	require.NoError(t, err)
	require.NotNil(t, resExplicit)
	assert.True(t, resExplicit.IsError)
	textExplicit := toolResultText(t, resExplicit)
	var toolErrExplicit ToolError
	require.NoError(t, json.Unmarshal([]byte(textExplicit), &toolErrExplicit))
	assert.Equal(t, ErrCodeResourceNotFound, toolErrExplicit.Code)
	assert.NotContains(t, toolErrExplicit.Message, mcpNamespaceDefaultedHint)
	assert.Nil(t, toolErrExplicit.Details["hint"])
}

func TestCreateWorkloadScanningTools_RegistersScanWorkload(t *testing.T) {
	ksServer := newWorkloadToolServer(t)

	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	require.NoError(t, err)
	raw, err := json.Marshal(ksServer.s.HandleMessage(context.Background(), message))
	require.NoError(t, err)

	var listed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Properties map[string]any `json:"properties"`
					Required   []string       `json:"required"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &listed))

	var found bool
	for _, tool := range listed.Result.Tools {
		if tool.Name != "scan_workload" {
			continue
		}
		found = true
		for _, prop := range []string{"workload", "namespace", "path", "framework"} {
			assert.Contains(t, tool.InputSchema.Properties, prop)
		}
		assert.Contains(t, tool.InputSchema.Required, "workload")
		assert.NotContains(t, tool.InputSchema.Required, "namespace",
			"namespace must stay optional so an agent can search all namespaces")
	}
	assert.True(t, found, "scan_workload was not registered")
}
