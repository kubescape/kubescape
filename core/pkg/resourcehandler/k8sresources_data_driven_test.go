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
	"k8s.io/client-go/discovery"
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

func clusterTrustBundleDiscovery() *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "certificates.k8s.io/v1",
			APIResources: []metav1.APIResource{{Name: "clustertrustbundles", Kind: "ClusterTrustBundle", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "certificates.k8s.io/v1beta1",
			APIResources: []metav1.APIResource{{Name: "clustertrustbundles", Kind: "ClusterTrustBundle", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}}},
		},
	}
	return discovery
}

func apiServiceDiscovery() *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "apiregistration.k8s.io/v1",
			APIResources: []metav1.APIResource{{Name: "apiservices", Kind: "APIService", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}}},
		},
	}
	return discovery
}

func ipAddressDiscovery() *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{{Name: "ipaddresses", Kind: "IPAddress", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}}},
		},
	}
	return discovery
}

func eventDiscovery() *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{{Name: "events", Kind: "Event", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "events.k8s.io/v1",
			APIResources: []metav1.APIResource{{Name: "events", Kind: "Event", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "events.k8s.io/v1beta1",
			APIResources: []metav1.APIResource{{Name: "events", Kind: "Event", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
	}
	return discovery
}

func customCRDDiscoveryNamespaced(group, version, kind, resource string, namespaced bool) *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: group + "/" + version,
			APIResources: []metav1.APIResource{{Name: resource, Kind: kind, Namespaced: namespaced, Verbs: metav1.Verbs{"get", "list"}}},
		},
	}
	return discovery
}

func customCRDDiscovery(group, version, kind, resource string) *discoveryfake.FakeDiscovery {
	return customCRDDiscoveryNamespaced(group, version, kind, resource, false)
}

func TestFindScanObjectResourceDataDriven(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	deploymentGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	daemonSetGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
	replicaSetGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	clusterRoleGVR := schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}
	clusterTrustBundleV1GVR := schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1", Resource: "clustertrustbundles"}
	clusterTrustBundleV1Beta1GVR := schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "clustertrustbundles"}
	csrGVR := schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests"}
	apiServiceGVR := schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}
	ipAddressGVR := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ipaddresses"}
	eventGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "events"}
	groupedEventV1GVR := schema.GroupVersionResource{Group: "events.k8s.io", Version: "v1", Resource: "events"}
	groupedEventV1Beta1GVR := schema.GroupVersionResource{Group: "events.k8s.io", Version: "v1beta1", Resource: "events"}
	crdClusterTrustBundleGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "clustertrustbundles"}
	crdAPIServiceGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "apiservices"}
	crdIPAddressGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "ipaddresses"}
	crdEventGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "events"}
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	listKinds := map[schema.GroupVersionResource]string{
		deploymentGVR:                "DeploymentList",
		daemonSetGVR:                 "DaemonSetList",
		replicaSetGVR:                "ReplicaSetList",
		clusterRoleGVR:               "ClusterRoleList",
		clusterTrustBundleV1GVR:      "ClusterTrustBundleList",
		clusterTrustBundleV1Beta1GVR: "ClusterTrustBundleList",
		csrGVR:                       "CertificateSigningRequestList",
		apiServiceGVR:                "APIServiceList",
		ipAddressGVR:                 "IPAddressList",
		eventGVR:                     "EventList",
		groupedEventV1GVR:            "EventList",
		groupedEventV1Beta1GVR:       "EventList",
		crdClusterTrustBundleGVR:     "ClusterTrustBundleList",
		crdAPIServiceGVR:             "APIServiceList",
		crdIPAddressGVR:              "IPAddressList",
		crdEventGVR:                  "EventList",
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
		discovery        discovery.DiscoveryInterface
	}{
		{name: "nil request is not a single-resource scan", request: nil, wantNil: true},
		{
			name:     "deployment is returned as a workload",
			request:  scanObject("apps/v1", "Deployment", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			wantName: "checkout",
		},
		{
			name:     "clusterrole with path segment name system:discovery is returned as a workload",
			request:  scanObject("rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:discovery"),
			objects:  []runtime.Object{unstructuredResource("rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:discovery")},
			wantName: "system:discovery",
		},
		{
			name:      "clustertrustbundle v1 with signer-linked name example.com:foo:abc is returned as a workload",
			request:   scanObject("certificates.k8s.io/v1", "ClusterTrustBundle", "", "example.com:foo:abc"),
			objects:   []runtime.Object{unstructuredResource("certificates.k8s.io/v1", "ClusterTrustBundle", "", "example.com:foo:abc")},
			discovery: clusterTrustBundleDiscovery(),
			wantName:  "example.com:foo:abc",
		},
		{
			name:      "clustertrustbundle v1beta1 with signer-linked name example.com:foo:abc is returned as a workload",
			request:   scanObject("certificates.k8s.io/v1beta1", "ClusterTrustBundle", "", "example.com:foo:abc"),
			objects:   []runtime.Object{unstructuredResource("certificates.k8s.io/v1beta1", "ClusterTrustBundle", "", "example.com:foo:abc")},
			discovery: clusterTrustBundleDiscovery(),
			wantName:  "example.com:foo:abc",
		},
		{
			name:     "certificatesigningrequest with path segment name client:alice is returned as a workload",
			request:  scanObject("certificates.k8s.io/v1", "CertificateSigningRequest", "", "client:alice"),
			objects:  []runtime.Object{unstructuredResource("certificates.k8s.io/v1", "CertificateSigningRequest", "", "client:alice")},
			wantName: "client:alice",
		},
		{
			name:      "apiservice with trailing dot name v1. is returned as a workload",
			request:   scanObject("apiregistration.k8s.io/v1", "APIService", "", "v1."),
			objects:   []runtime.Object{unstructuredResource("apiregistration.k8s.io/v1", "APIService", "", "v1.")},
			discovery: apiServiceDiscovery(),
			wantName:  "v1.",
		},
		{
			name:      "ipaddress with IPv6 name 2001:db8::1 is returned as a workload",
			request:   scanObject("networking.k8s.io/v1", "IPAddress", "", "2001:db8::1"),
			objects:   []runtime.Object{unstructuredResource("networking.k8s.io/v1", "IPAddress", "", "2001:db8::1")},
			discovery: ipAddressDiscovery(),
			wantName:  "2001:db8::1",
		},
		{
			name:      "core/v1 event with path segment name event:legacy is returned as a workload",
			request:   scanObject("v1", "Event", "default", "event:legacy"),
			objects:   []runtime.Object{unstructuredResource("v1", "Event", "default", "event:legacy")},
			discovery: eventDiscovery(),
			wantName:  "event:legacy",
		},
		{
			name:      "bare event with path segment name event:legacy is returned as a workload",
			request:   scanObject("", "Event", "default", "event:legacy"),
			objects:   []runtime.Object{unstructuredResource("v1", "Event", "default", "event:legacy")},
			discovery: eventDiscovery(),
			wantName:  "event:legacy",
		},
		{
			name:      "events.k8s.io/v1 event with path segment name event:legacy is returned as a workload",
			request:   scanObject("events.k8s.io/v1", "Event", "default", "event:legacy"),
			objects:   []runtime.Object{unstructuredResource("events.k8s.io/v1", "Event", "default", "event:legacy")},
			discovery: eventDiscovery(),
			wantName:  "event:legacy",
		},
		{
			name:      "events.k8s.io/v1beta1 event with path segment name event:legacy is returned as a workload",
			request:   scanObject("events.k8s.io/v1beta1", "Event", "default", "event:legacy"),
			objects:   []runtime.Object{unstructuredResource("events.k8s.io/v1beta1", "Event", "default", "event:legacy")},
			discovery: eventDiscovery(),
			wantName:  "event:legacy",
		},
		{
			name:      "crd event with custom group and standard name my-event is returned as a workload",
			request:   scanObject("example.com/v1", "Event", "default", "my-event"),
			objects:   []runtime.Object{unstructuredResource("example.com/v1", "Event", "default", "my-event")},
			discovery: customCRDDiscoveryNamespaced("example.com", "v1", "Event", "events", true),
			wantName:  "my-event",
		},
		{
			name:      "crd clustertrustbundle with custom group and standard name my-bundle is returned as a workload",
			request:   scanObject("example.com/v1", "ClusterTrustBundle", "", "my-bundle"),
			objects:   []runtime.Object{unstructuredResource("example.com/v1", "ClusterTrustBundle", "", "my-bundle")},
			discovery: customCRDDiscovery("example.com", "v1", "ClusterTrustBundle", "clustertrustbundles"),
			wantName:  "my-bundle",
		},
		{
			name:      "crd apiservice with custom group and standard name my-api is returned as a workload",
			request:   scanObject("example.com/v1", "APIService", "", "my-api"),
			objects:   []runtime.Object{unstructuredResource("example.com/v1", "APIService", "", "my-api")},
			discovery: customCRDDiscovery("example.com", "v1", "APIService", "apiservices"),
			wantName:  "my-api",
		},
		{
			name:      "crd ipaddress with custom group and standard name my-address is returned as a workload",
			request:   scanObject("example.com/v1", "IPAddress", "", "my-address"),
			objects:   []runtime.Object{unstructuredResource("example.com/v1", "IPAddress", "", "my-address")},
			discovery: customCRDDiscovery("example.com", "v1", "IPAddress", "ipaddresses"),
			wantName:  "my-address",
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
			name:     "deployment with lowercase kind resolves cleanly without apiVersion",
			request:  scanObject("", "deployment", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			wantName: "checkout",
		},
		{
			name:     "deployment with short name deploy resolves cleanly without apiVersion",
			request:  scanObject("", "deploy", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			wantName: "checkout",
		},
		{
			name:     "deployment with uppercase short name DEPLOY resolves cleanly without apiVersion",
			request:  scanObject("", "DEPLOY", "shop", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout")},
			wantName: "checkout",
		},
		{
			name:     "daemonset with lowercase kind resolves cleanly without apiVersion",
			request:  scanObject("", "daemonset", "kube-system", "fluentd"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "DaemonSet", "kube-system", "fluentd")},
			wantName: "fluentd",
		},
		{
			name:     "daemonset with short name ds resolves cleanly without apiVersion",
			request:  scanObject("", "ds", "kube-system", "fluentd"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "DaemonSet", "kube-system", "fluentd")},
			wantName: "fluentd",
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
		{
			name:      "workload queried with default namespace does not find workload in staging",
			request:   scanObject("apps/v1", "Deployment", "default", "checkout"),
			objects:   []runtime.Object{unstructuredResource("apps/v1", "Deployment", "staging", "checkout")},
			wantError: "was not found",
		},
		{
			name:     "cluster-wide query with empty namespace finds single workload across namespaces",
			request:  scanObject("apps/v1", "Deployment", "", "checkout"),
			objects:  []runtime.Object{unstructuredResource("apps/v1", "Deployment", "staging", "checkout")},
			wantName: "checkout",
		},
		{
			name:      "cluster-wide query with empty namespace fails when duplicates exist across namespaces",
			request:   scanObject("apps/v1", "Deployment", "", "checkout"),
			objects:   []runtime.Object{unstructuredResource("apps/v1", "Deployment", "shop", "checkout"), unstructuredResource("apps/v1", "Deployment", "staging", "checkout")},
			wantError: "more than one resource found",
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
			resolver, discoveryFailures := newDiscoveryResourceResolver(test.discovery)
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
