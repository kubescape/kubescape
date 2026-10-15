package exposure

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGatewayNamespaceNameSelector(t *testing.T) {
	for _, tc := range []struct {
		name        string
		namespace   string
		namespaces  []NamespaceInfo
		extraLabels map[string]string
		wantPaths   int
		wantKnown   bool
	}{
		{name: "manifest namespace without automatic label", namespace: "trusted", namespaces: []NamespaceInfo{{Name: "trusted"}}, wantPaths: 1, wantKnown: true},
		{name: "matching uncollected namespace", namespace: "trusted", wantPaths: 1, wantKnown: true},
		{name: "different uncollected namespace", namespace: "other", wantKnown: true},
		{name: "different known namespace", namespace: "other", namespaces: []NamespaceInfo{{Name: "other"}}, wantKnown: true},
		{name: "inconsistent automatic label", namespace: "other", namespaces: []NamespaceInfo{{Name: "other", Labels: map[string]string{corev1.LabelMetadataName: "trusted"}}}, wantKnown: true},
		{name: "custom label remains unknown", namespace: "trusted", extraLabels: map[string]string{"team": "platform"}, wantPaths: 1},
		{name: "name mismatch resolves conjunction", namespace: "other", extraLabels: map[string]string{"team": "platform"}, wantKnown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			labels := map[string]string{corev1.LabelMetadataName: "trusted"}
			for k, v := range tc.extraLabels {
				labels[k] = v
			}
			from := fromSelector
			l := listener{Protocol: "HTTP", Port: 80, AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{
				From: &from, Selector: &metav1.LabelSelector{MatchLabels: labels},
			}}}
			g := gateway{Namespace: "gateway", Name: "public", Listeners: []listener{l}}
			gatewayNS := "gateway"
			route := gatewayRoute{Kind: "HTTPRoute", Namespace: tc.namespace, Name: "app", ParentRefs: []parentRef{{Name: "public", Namespace: &gatewayNS}},
				Rules: []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "backend"}}}},
			}
			idx := NewIndex([]corev1.Service{svc(tc.namespace, "backend", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{g}, tc.namespaces)
			_, known := idx.gatewayAdmitsRouteNamespace(l, tc.namespace, "gateway")
			require.Equal(t, tc.wantKnown, known)
			paths, unclear := idx.ServiceExposure(ref(tc.namespace, "backend"))
			require.False(t, unclear)
			require.Len(t, paths, tc.wantPaths)
		})
	}
}

func TestNamespaceSelectorsDoNotModifySnapshot(t *testing.T) {
	labels := map[string]string{"team": "platform"}
	ns := NamespaceInfo{Name: "trusted", Labels: labels}
	from := fromSelector
	l := listener{AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{From: &from, Selector: &metav1.LabelSelector{
		MatchLabels: map[string]string{corev1.LabelMetadataName: "trusted", "team": "platform"},
	}}}}
	idx := NewIndex(nil, nil, nil, nil, []NamespaceInfo{ns})
	for i := 0; i < 3; i++ {
		match, known := idx.gatewayAdmitsRouteNamespace(l, "trusted", "gateway")
		require.True(t, known)
		require.True(t, match)
	}
	require.Equal(t, map[string]string{"team": "platform"}, labels)
}
