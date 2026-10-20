package exposure

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func strp(s string) *string { return &s }

func grantFor(ns string, from []referenceGrantFrom, to []referenceGrantTo) referenceGrant {
	return referenceGrant{Namespace: ns, Name: "g", From: from, To: to}
}

func fromRoute(kind, ns string) referenceGrantFrom {
	return referenceGrantFrom{Group: gatewayAPIGroup, Kind: kind, Namespace: ns}
}

func toService(name *string) referenceGrantTo {
	return referenceGrantTo{Group: "", Kind: "Service", Name: name}
}

func TestReferenceGrantPermitsService(t *testing.T) {
	target := ref("prod", "app")
	httpFrom := routeReferrer{Kind: "HTTPRoute", Namespace: "edge"}

	for _, tc := range []struct {
		name  string
		grant referenceGrant
		from  routeReferrer
		want  bool
	}{
		{"matching, omitted name covers all", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(nil)}), httpFrom, true},
		{"empty name covers all", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(strp(""))}), httpFrom, true},
		{"named match", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(strp("app"))}), httpFrom, true},
		{"named mismatch", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(strp("other"))}), httpFrom, false},
		{"source namespace mismatch", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "other")}, []referenceGrantTo{toService(nil)}), httpFrom, false},
		{"source kind mismatch", grantFor("prod", []referenceGrantFrom{fromRoute("GRPCRoute", "edge")}, []referenceGrantTo{toService(nil)}), httpFrom, false},
		{"source group mismatch", grantFor("prod", []referenceGrantFrom{{Group: "example.io", Kind: "HTTPRoute", Namespace: "edge"}}, []referenceGrantTo{toService(nil)}), httpFrom, false},
		{"empty source group is core, not Gateway API", grantFor("prod", []referenceGrantFrom{{Group: "", Kind: "HTTPRoute", Namespace: "edge"}}, []referenceGrantTo{toService(nil)}), httpFrom, false},
		{"target kind mismatch", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{{Group: "", Kind: "Secret"}}), httpFrom, false},
		{"target group mismatch", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{{Group: "example.io", Kind: "Service"}}), httpFrom, false},
		{"grant in another namespace", grantFor("elsewhere", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(nil)}), httpFrom, false},
		{"multiple from entries are alternatives", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "x"), fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(nil)}), httpFrom, true},
		{"multiple to entries are alternatives", grantFor("prod", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(strp("x")), toService(strp("app"))}), httpFrom, true},
		{"GRPCRoute source", grantFor("prod", []referenceGrantFrom{fromRoute("GRPCRoute", "edge")}, []referenceGrantTo{toService(nil)}), routeReferrer{Kind: "GRPCRoute", Namespace: "edge"}, true},
		{"no entries", grantFor("prod", nil, nil), httpFrom, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.grant.permitsService(tc.from, target))
		})
	}
}

func TestFromUnstructuredReferenceGrants(t *testing.T) {
	obj := func(apiVersion string, spec map[string]any) workloadinterface.IMetadata {
		return unstructuredResource(map[string]any{
			"apiVersion": apiVersion, "kind": "ReferenceGrant",
			"metadata": map[string]any{"name": "g", "namespace": "prod"},
			"spec":     spec,
		})
	}
	valid := map[string]any{
		"from": []any{map[string]any{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "edge"}},
		"to":   []any{map[string]any{"group": "", "kind": "Service"}},
	}

	for _, version := range []string{"gateway.networking.k8s.io/v1", "gateway.networking.k8s.io/v1beta1"} {
		grants, errs := FromUnstructuredReferenceGrants(map[string]workloadinterface.IMetadata{"a": obj(version, valid)})
		require.Empty(t, errs, version)
		require.Len(t, grants, 1, version)
		require.True(t, grants[0].permitsService(routeReferrer{Kind: "HTTPRoute", Namespace: "edge"}, ref("prod", "app")))
	}

	t.Run("omitted group reads as core", func(t *testing.T) {
		grants, errs := FromUnstructuredReferenceGrants(map[string]workloadinterface.IMetadata{"a": obj("gateway.networking.k8s.io/v1", map[string]any{
			"from": []any{map[string]any{"kind": "HTTPRoute", "namespace": "edge"}},
			"to":   []any{map[string]any{"kind": "Service"}},
		})})
		require.Empty(t, errs)
		require.Equal(t, "", grants[0].From[0].Group)
		require.False(t, grants[0].permitsService(routeReferrer{Kind: "HTTPRoute", Namespace: "edge"}, ref("prod", "app")), "an empty from group is the core group, which holds no routes")
	})

	t.Run("ignores other kinds", func(t *testing.T) {
		grants, errs := FromUnstructuredReferenceGrants(map[string]workloadinterface.IMetadata{"a": unstructuredResource(map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "s"}})})
		require.Empty(t, grants)
		require.Empty(t, errs)
	})

	for name, spec := range map[string]map[string]any{
		"no from":      {"to": valid["to"]},
		"no to":        {"from": valid["from"]},
		"from no kind": {"from": []any{map[string]any{"namespace": "edge"}}, "to": valid["to"]},
		"from no ns":   {"from": []any{map[string]any{"kind": "HTTPRoute"}}, "to": valid["to"]},
		"to no kind":   {"from": valid["from"], "to": []any{map[string]any{"name": "x"}}},
		"wrong types":  {"from": "nope", "to": 3},
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			grants, errs := FromUnstructuredReferenceGrants(map[string]workloadinterface.IMetadata{"a": obj("gateway.networking.k8s.io/v1", spec)})
			require.Empty(t, grants)
			require.Len(t, errs, 1)
			opt, optErrs := ReferenceGrantsOption(map[string]workloadinterface.IMetadata{"a": obj("gateway.networking.k8s.io/v1", spec)})
			require.Nil(t, opt, "a grant that cannot be read leaves authorization undetermined")
			require.NotEmpty(t, optErrs)
		})
	}

	t.Run("no namespace", func(t *testing.T) {
		_, errs := FromUnstructuredReferenceGrants(map[string]workloadinterface.IMetadata{"a": unstructuredResource(map[string]any{
			"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrant", "metadata": map[string]any{"name": "g"}, "spec": valid})})
		require.Len(t, errs, 1)
	})

	t.Run("a good grant beside a bad one is kept but the option is withheld", func(t *testing.T) {
		in := map[string]workloadinterface.IMetadata{"a": obj("gateway.networking.k8s.io/v1", valid), "b": obj("gateway.networking.k8s.io/v1", map[string]any{})}
		grants, errs := FromUnstructuredReferenceGrants(in)
		require.Len(t, grants, 1)
		require.Len(t, errs, 1)
		opt, _ := ReferenceGrantsOption(in)
		require.Nil(t, opt)
	})

	t.Run("empty listing is a real answer", func(t *testing.T) {
		opt, errs := ReferenceGrantsOption(map[string]workloadinterface.IMetadata{})
		require.Empty(t, errs)
		require.NotNil(t, opt)
	})
}

// crossNSRoute builds a route in "edge" with one backendRef into "prod".
func crossNSRoute(t *testing.T, kind string, mutate func(backend map[string]any, rule map[string]any)) gatewayRoute {
	t.Helper()
	backend := map[string]any{"name": "app", "namespace": "prod", "port": 80}
	rule := map[string]any{"backendRefs": []any{backend}}
	if mutate != nil {
		mutate(backend, rule)
	}
	r, err := decodeGatewayRoute(kind, map[string]any{
		"metadata": map[string]any{"name": "r", "namespace": "edge"},
		"spec":     map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}, "hostnames": []any{"a.example.com"}, "rules": []any{rule}},
	})
	require.NoError(t, err)
	return r
}

func appService() corev1.Service {
	s := svc("prod", "app", corev1.ServiceTypeClusterIP)
	s.Spec.Ports = []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}}
	return s
}

var edgeGateway = gateway{Namespace: "edge", Name: "gw", Listeners: []listener{{Name: "http"}}}

func allowFrom(kind, ns string) referenceGrant {
	return grantFor("prod", []referenceGrantFrom{fromRoute(kind, ns)}, []referenceGrantTo{toService(nil)})
}

func TestServiceExposure_ReferenceGrantAuthorization(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		route := crossNSRoute(t, kind, nil)
		idxWith := func(grants ...referenceGrant) *Index {
			return NewIndex([]corev1.Service{appService()}, nil, []gatewayRoute{route}, []gateway{edgeGateway}, nil, WithReferenceGrants(grants))
		}

		t.Run(kind+"/authorized by a matching grant", func(t *testing.T) {
			paths, unclear := idxWith(allowFrom(kind, "edge")).ServiceExposure(ref("prod", "app"))
			require.False(t, unclear)
			require.Len(t, paths, 1)
			require.Equal(t, routeExposureKind(kind), paths[0].Kind)
			require.Equal(t, "edge/r", paths[0].Source)
			require.Equal(t, "a.example.com", paths[0].Host)
		})
		t.Run(kind+"/no grants collected is a definite no", func(t *testing.T) {
			paths, unclear := idxWith().ServiceExposure(ref("prod", "app"))
			require.Empty(t, paths)
			require.False(t, unclear)
		})
		t.Run(kind+"/grant for the other route kind does not authorize", func(t *testing.T) {
			other := map[string]string{"HTTPRoute": "GRPCRoute", "GRPCRoute": "HTTPRoute"}[kind]
			paths, unclear := idxWith(allowFrom(other, "edge")).ServiceExposure(ref("prod", "app"))
			require.Empty(t, paths)
			require.False(t, unclear)
		})
		t.Run(kind+"/multiple grants add up", func(t *testing.T) {
			paths, _ := idxWith(allowFrom(kind, "nowhere"), allowFrom(kind, "edge")).ServiceExposure(ref("prod", "app"))
			require.Len(t, paths, 1)
		})
		t.Run(kind+"/grants not supplied stays unclear", func(t *testing.T) {
			idx := NewIndex([]corev1.Service{appService()}, nil, []gatewayRoute{route}, []gateway{edgeGateway}, nil)
			paths, unclear := idx.ServiceExposure(ref("prod", "app"))
			require.Empty(t, paths)
			require.True(t, unclear)
		})
	}
}

func TestServiceExposure_ReferenceGrantKeepsOtherChecks(t *testing.T) {
	grant := allowFrom("HTTPRoute", "edge")
	query := func(t *testing.T, route gatewayRoute, gw gateway, opts ...Option) ([]ExposurePath, bool) {
		t.Helper()
		idx := NewIndex([]corev1.Service{appService()}, nil, []gatewayRoute{route}, []gateway{gw}, nil, opts...)
		return idx.ServiceExposure(ref("prod", "app"))
	}

	t.Run("same namespace needs no grant", func(t *testing.T) {
		r := crossNSRoute(t, "HTTPRoute", func(b, _ map[string]any) { delete(b, "namespace") })
		r.Namespace = "prod"
		gw := gateway{Namespace: "prod", Name: "gw", Listeners: []listener{{Name: "http"}}}
		paths, unclear := query(t, r, gw, WithReferenceGrants(nil))
		require.Len(t, paths, 1)
		require.False(t, unclear)
	})
	t.Run("explicit own namespace needs no grant", func(t *testing.T) {
		r := crossNSRoute(t, "HTTPRoute", func(b, _ map[string]any) { b["namespace"] = "prod" })
		r.Namespace = "prod"
		gw := gateway{Namespace: "prod", Name: "gw", Listeners: []listener{{Name: "http"}}}
		paths, _ := query(t, r, gw, WithReferenceGrants(nil))
		require.Len(t, paths, 1)
	})
	t.Run("existing target Service authorizes nothing", func(t *testing.T) {
		paths, unclear := query(t, crossNSRoute(t, "HTTPRoute", nil), edgeGateway, WithReferenceGrants(nil))
		require.Empty(t, paths)
		require.False(t, unclear)
	})
	t.Run("missing target Service", func(t *testing.T) {
		idx := NewIndex(nil, nil, []gatewayRoute{crossNSRoute(t, "HTTPRoute", nil)}, []gateway{edgeGateway}, nil, WithReferenceGrants([]referenceGrant{grant}))
		paths, unclear := idx.ServiceExposure(ref("prod", "app"))
		require.Empty(t, paths)
		require.False(t, unclear)
	})
	t.Run("zero weight", func(t *testing.T) {
		r := crossNSRoute(t, "HTTPRoute", func(b, _ map[string]any) { b["weight"] = 0 })
		paths, unclear := query(t, r, edgeGateway, WithReferenceGrants([]referenceGrant{grant}))
		require.Empty(t, paths)
		require.False(t, unclear)
		paths, unclear = query(t, r, edgeGateway)
		require.Empty(t, paths)
		require.False(t, unclear, "a zero-weight backend is not uncertain exposure either")
	})
	t.Run("port mismatch", func(t *testing.T) {
		r := crossNSRoute(t, "HTTPRoute", func(b, _ map[string]any) { b["port"] = 9999 })
		paths, unclear := query(t, r, edgeGateway, WithReferenceGrants([]referenceGrant{grant}))
		require.Empty(t, paths)
		require.False(t, unclear)
	})
	t.Run("route not admitted by the gateway", func(t *testing.T) {
		same := fromSame
		gw := gateway{Namespace: "infra", Name: "gw", Listeners: []listener{{Name: "http", AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{From: &same}}}}}
		r := crossNSRoute(t, "HTTPRoute", nil)
		r.ParentRefs = []parentRef{{Name: "gw", Namespace: strp("infra")}}
		paths, unclear := query(t, r, gw, WithReferenceGrants([]referenceGrant{grant}))
		require.Empty(t, paths, "a grant authorizes the backend reference, not the route's attachment")
		require.False(t, unclear)
		paths, unclear = query(t, r, gw)
		require.Empty(t, paths)
		require.False(t, unclear, "an unadmitted route stays irrelevant even when grants are unknown")
	})
	t.Run("non-Service backend kind", func(t *testing.T) {
		r := crossNSRoute(t, "HTTPRoute", func(b, _ map[string]any) { b["kind"] = "ServiceImport"; b["group"] = "multicluster.x-k8s.io" })
		paths, unclear := query(t, r, edgeGateway, WithReferenceGrants([]referenceGrant{grant}))
		require.Empty(t, paths)
		require.False(t, unclear)
	})
	t.Run("existing callers without grants", func(t *testing.T) {
		_, unclear := query(t, crossNSRoute(t, "HTTPRoute", nil), edgeGateway)
		require.True(t, unclear)
	})
}

func TestRequestMirrorCrossNamespaceReferenceGrant(t *testing.T) {
	mirrorTo := map[string]any{"name": "app", "namespace": "prod", "port": 80}
	build := func(t *testing.T, onBackend bool) gatewayRoute {
		t.Helper()
		return crossNSRoute(t, "HTTPRoute", func(backend, rule map[string]any) {
			// Primary backend stays in the route's namespace; only the mirror crosses.
			backend["name"], backend["port"] = "primary", 80
			delete(backend, "namespace")
			if onBackend {
				backend["filters"] = []any{mirrorFilter(mirrorTo, nil)}
			} else {
				rule["filters"] = []any{mirrorFilter(mirrorTo, nil)}
			}
		})
	}
	for _, onBackend := range []bool{false, true} {
		r := build(t, onBackend)
		mk := func(opts ...Option) *Index {
			return NewIndex([]corev1.Service{appService()}, nil, []gatewayRoute{r}, []gateway{edgeGateway}, nil, opts...)
		}
		t.Run("authorized", func(t *testing.T) {
			paths, unclear := mk(WithReferenceGrants([]referenceGrant{allowFrom("HTTPRoute", "edge")})).ServiceExposure(ref("prod", "app"))
			require.Len(t, paths, 1)
			require.False(t, unclear)
		})
		t.Run("unauthorized", func(t *testing.T) {
			paths, unclear := mk(WithReferenceGrants(nil)).ServiceExposure(ref("prod", "app"))
			require.Empty(t, paths)
			require.False(t, unclear)
		})
		t.Run("unknown", func(t *testing.T) {
			paths, unclear := mk().ServiceExposure(ref("prod", "app"))
			require.Empty(t, paths)
			require.True(t, unclear)
		})
	}

	t.Run("backend-scoped mirror whose cross-namespace parent is unauthorized", func(t *testing.T) {
		// The primary backend is itself a cross-namespace reference to a Service
		// in "other" that no grant allows, so it receives no requests and its
		// mirror filter never runs -- even though the mirror target is authorized.
		other := svc("other", "primary", corev1.ServiceTypeClusterIP)
		other.Spec.Ports = []corev1.ServicePort{{Port: 80}}
		r := crossNSRoute(t, "HTTPRoute", func(backend, _ map[string]any) {
			backend["name"], backend["namespace"], backend["port"] = "primary", "other", 80
			backend["filters"] = []any{mirrorFilter(mirrorTo, nil)}
		})
		grants := []referenceGrant{allowFrom("HTTPRoute", "edge")} // prod only; nothing in "other"
		idx := NewIndex([]corev1.Service{appService(), other}, nil, []gatewayRoute{r}, []gateway{edgeGateway}, nil, WithReferenceGrants(grants))
		paths, unclear := idx.ServiceExposure(ref("prod", "app"))
		require.Empty(t, paths)
		require.False(t, unclear)

		grants = append(grants, grantFor("other", []referenceGrantFrom{fromRoute("HTTPRoute", "edge")}, []referenceGrantTo{toService(nil)}))
		idx = NewIndex([]corev1.Service{appService(), other}, nil, []gatewayRoute{r}, []gateway{edgeGateway}, nil, WithReferenceGrants(grants))
		paths, _ = idx.ServiceExposure(ref("prod", "app"))
		require.Len(t, paths, 1, "once the parent is authorized its mirror is active again")
	})
}
