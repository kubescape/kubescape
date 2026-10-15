package namespaceselector_test

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/exposure"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestNamespaceManifestMatchesBothSecurityModels(t *testing.T) {
	// These are pre-apply manifests: the namespace has no labels because the
	// API server adds its immutable name label only when the object is served.
	const manifests = `
- apiVersion: v1
  kind: Namespace
  metadata:
    name: trusted
- apiVersion: v1
  kind: Service
  metadata:
    namespace: trusted
    name: backend
  spec:
    ports: [{port: 80}]
- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    namespace: app
    name: allow-trusted
  spec:
    podSelector: {}
    ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: trusted
- apiVersion: gateway.networking.k8s.io/v1
  kind: Gateway
  metadata:
    namespace: gateway
    name: public
  spec:
    listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              kubernetes.io/metadata.name: trusted
- apiVersion: gateway.networking.k8s.io/v1
  kind: HTTPRoute
  metadata:
    namespace: trusted
    name: web
  spec:
    parentRefs: [{name: public, namespace: gateway}]
    rules:
    - backendRefs: [{name: backend, port: 80}]
`
	var objects []map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(manifests), &objects))
	resources := make(map[string]workloadinterface.IMetadata)
	for _, object := range objects {
		resource := workloadinterface.NewWorkloadObj(object)
		resources[resource.GetID()] = resource
	}
	policies, namespaces, errs := networkpolicy.FromResources(resources)
	require.Empty(t, errs)
	np, errs := networkpolicy.NewIndex(policies, namespaces)
	require.Empty(t, errs)
	verdict, _, _ := np.Reaches(networkpolicy.Endpoint{Namespace: "trusted", Name: "client"},
		networkpolicy.Endpoint{Namespace: "app", Name: "server"}, &networkpolicy.PortSpec{Port: 80})
	require.Equal(t, networkpolicy.Allowed, verdict)

	services, ingresses, exposureNamespaces, errs := exposure.FromResources(resources)
	require.Empty(t, errs)
	routes, gateways, errs := exposure.FromUnstructuredGatewayAPI(resources)
	require.Empty(t, errs)
	public := exposure.NewIndex(services, ingresses, routes, gateways, exposureNamespaces)
	paths, unclear := public.ServiceExposure(exposure.ServiceRef{Namespace: "trusted", Name: "backend"})
	require.False(t, unclear)
	require.Len(t, paths, 1)
	require.Equal(t, exposure.ExposureHTTPRoute, paths[0].Kind)
	require.Equal(t, "trusted/web", paths[0].Source)
	// The same resource snapshot remains suitable for another analysis.
	for _, resource := range resources {
		if resource.GetKind() == "Namespace" {
			require.NotContains(t, resource.GetObject()["metadata"], "labels")
		}
	}
}
