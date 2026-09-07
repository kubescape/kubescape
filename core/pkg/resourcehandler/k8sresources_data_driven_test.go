package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func scanObject(apiVersion, kind, namespace, name string) *objectsenvelopes.ScanObject {
	return objectsenvelopes.NewScanObject(map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	})
}

func unstructuredResource(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	}}
}

func unstructuredResourceWithParent(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"ownerReferences": []any{
				map[string]any{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
					"name":       "parent-deploy",
				},
			},
		},
	}}
}

func TestFindScanObjectResourceDataDriven(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	deploymentGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	replicaSetGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	listKinds := map[schema.GroupVersionResource]string{
		deploymentGVR: "DeploymentList",
		replicaSetGVR: "ReplicaSetList",
		// Secrets are registered so the fake client is genuinely able to serve
		// them. Without this the client cannot list secrets at all and the
		// "no API calls were issued" assertion below would hold even for an
		// implementation that fetches the Secret before rejecting it.
		secretGVR: "SecretList",
	}

	tests := []struct {
		name             string
		request          *objectsenvelopes.ScanObject
		objects          []runtime.Object
		wantName         string
		wantError        string
		wantNil          bool
		wantNoAPIActions bool
		listForbidden    bool
		selector         IFieldSelector
	}{
		{name: "nil request is not a single-resource scan", request: nil, wantNil: true},
		{
			name:     "deployment is returned as a workload",
			request:  scanObject("apps/v1", "Deployment", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			wantName: "checkout",
		},
		{
			name:          "deployment is returned via get when list is forbidden",
			request:       scanObject("apps/v1", "Deployment", "shop", "checkout"),
			objects:       []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			wantName:      "checkout",
			listForbidden: true,
		},
		{
			name:      "workload with parent cannot be scanned",
			request:   scanObject("apps/v1", "ReplicaSet", "shop", "checkout-rs"),
			objects:   []runtime.Object{unstructuredResourceWithParent("apps/v1", "ReplicaSet", "shop", "checkout-rs")},
			wantError: "has a parent and cannot be scanned",
		},
		{
			// When namespace is omitted, cluster-wide list is used; pullSingleResourceInto
			// filters out workloads with parents, returning not found rather than parent error.
			name:      "workload with parent and omitted namespace reports not found",
			request:   scanObject("apps/v1", "ReplicaSet", "", "checkout-rs"),
			objects:   []runtime.Object{unstructuredResourceWithParent("apps/v1", "ReplicaSet", "shop", "checkout-rs")},
			wantError: "was not found",
		},
		{
			name:      "missing deployment reports the requested identity",
			request:   scanObject("apps/v1", "Deployment", "shop", "missing"),
			wantError: "was not found",
		},
		{
			name:    "ambiguous result is rejected",
			request: scanObject("apps/v1", "Deployment", "", "checkout"),
			objects: []runtime.Object{
				unstructuredResource("apps/v1", "Deployment", "shop", "checkout"),
				unstructuredResource("apps/v1", "Deployment", "staging", "checkout"),
			},
			wantError: "more than one resource found",
		},
		{
			name:      "unknown kind returns discovery mapping error",
			request:   scanObject("example.com/v1", "UnknownKind", "shop", "object"),
			wantError: "resource not found",
		},
		{
			name:      "unknown kind without apiVersion explains required identity",
			request:   scanObject("", "UnknownKind", "shop", "object"),
			wantError: "apiVersion is required to resolve non-built-in resource",
		},
		{
			// Defense in depth: a Secret is not a useful single-resource scan
			// target, so it must be rejected before retrieval rather than
			// fetched and then sanitized downstream. Rejecting early also
			// avoids the need for Secret-reading RBAC permissions.
			name:             "secret is rejected before API retrieval",
			request:          scanObject("v1", "Secret", "shop", "db-creds"),
			objects:          []runtime.Object{unstructuredResource("v1", "Secret", "shop", "db-creds")},
			wantError:        "scanning Secret resources via single resource scan is not supported",
			wantNoAPIActions: true,
		},
		{
			name:             "secret is rejected via the legacy no-apiVersion path",
			request:          scanObject("", "Secret", "shop", "db-creds"),
			objects:          []runtime.Object{unstructuredResource("v1", "Secret", "shop", "db-creds")},
			wantError:        "scanning Secret resources via single resource scan is not supported",
			wantNoAPIActions: true,
		},
		{
			name:             "workload in excluded namespace is rejected without API call",
			request:          scanObject("apps/v1", "Deployment", "dev", "checkout"),
			objects:          []runtime.Object{unstructuredResource("apps/v1", "Deployment", "dev", "checkout")},
			selector:         NewExcludeSelector("dev"),
			wantError:        "was not found",
			wantNoAPIActions: true,
		},
		{
			name:     "workload in non-excluded namespace is returned via get",
			request:  scanObject("apps/v1", "Deployment", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			selector: NewExcludeSelector("dev"),
			wantName: "checkout",
		},
		{
			name:     "workload in included namespace is returned via get",
			request:  scanObject("apps/v1", "Deployment", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			selector: NewIncludeSelector("shop,staging"),
			wantName: "checkout",
		},
		{
			name:             "workload not in included namespace is rejected without API call",
			request:          scanObject("apps/v1", "Deployment", "dev", "checkout"),
			objects:          []runtime.Object{unstructuredResource("apps/v1", "Deployment", "dev", "checkout")},
			selector:         NewIncludeSelector("shop"),
			wantError:        "was not found",
			wantNoAPIActions: true,
		},
		{
			name:          "workload in included namespace is returned via get when list is forbidden",
			request:       scanObject("apps/v1", "Deployment", "shop", "checkout"),
			objects:       []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			selector:      NewIncludeSelector("shop"),
			wantName:      "checkout",
			listForbidden: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, test.objects...)
			if test.listForbidden {
				dynamicClient.PrependReactor("list", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "", errors.New("cannot list resource"))
				})
			}
			handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: dynamicClient}}
			resolver, discoveryFailures := newDiscoveryResourceResolver(nil)
			require.Empty(t, discoveryFailures)

			selector := test.selector
			if selector == nil {
				selector = &EmptySelector{}
			}
			workload, err := handler.findScanObjectResource(context.Background(), test.request, selector, resolver)
			if test.wantNoAPIActions {
				// Defense in depth: the rejection must happen before the live
				// API pull, so no Kubernetes API/RBAC operation is issued for a
				// Secret at all. Fetching first and refusing afterwards would
				// still pass the error assertion below, so the absence of
				// client actions is what actually pins the ordering.
				assert.Empty(t, dynamicClient.Actions(), "expected the request to be rejected before any API call")
			}
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				assert.Nil(t, workload)
				return
			}
			require.NoError(t, err)
			if test.wantNil {
				assert.Nil(t, workload)
				return
			}
			require.NotNil(t, workload)
			assert.Equal(t, test.wantName, workload.GetName())
		})
	}
}

func TestPullWorkerNodesNumberDataDriven(t *testing.T) {
	controlPlaneTaint := corev1.Taint{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}
	masterTaint := corev1.Taint{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule}
	customTaint := corev1.Taint{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}
	tests := []struct {
		name      string
		nodes     []corev1.Node
		listError error
		want      int
	}{
		{name: "empty cluster", want: 0},
		{
			name: "workers with custom taints count but control-plane nodes do not",
			nodes: []corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "worker-plain"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "worker-gpu"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{customTaint}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "control-plane"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{controlPlaneTaint}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "legacy-master"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{masterTaint}}},
			},
			want: 2,
		},
		{name: "API error is propagated", listError: errors.New("nodes forbidden")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects := make([]runtime.Object, 0, len(test.nodes))
			for i := range test.nodes {
				objects = append(objects, &test.nodes[i])
			}
			client := kubernetesfake.NewClientset(objects...)
			if test.listError != nil {
				client.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, test.listError
				})
			}
			handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{KubernetesClient: client}}

			got, err := handler.pullWorkerNodesNumber(context.Background())
			if test.listError != nil {
				require.ErrorIs(t, err, test.listError)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestClusterAPIServerInfoDataDriven(t *testing.T) {
	tests := []struct {
		name        string
		serverInfo  *version.Info
		serverError error
		wantVersion string
	}{
		{name: "server version is returned", serverInfo: &version.Info{GitVersion: "v1.35.2"}, wantVersion: "v1.35.2"},
		{name: "discovery error returns nil", serverError: errors.New("discovery unavailable")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := &k8stesting.Fake{}
			if test.serverError != nil {
				fakeClient.PrependReactor("get", "version", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, test.serverError
				})
			}
			discovery := &discoveryfake.FakeDiscovery{Fake: fakeClient, FakedServerVersion: test.serverInfo}
			handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DiscoveryClient: discovery}}

			info := handler.GetClusterAPIServerInfo(context.Background())
			if test.serverError != nil {
				assert.Nil(t, info)
				return
			}
			require.NotNil(t, info)
			assert.Equal(t, test.wantVersion, info.GitVersion)
		})
	}
}
