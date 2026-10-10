package exposure

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestServiceExposure_BackendWeight(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, crossNamespace := range []bool{false, true} {
			for _, tc := range []struct {
				name   string
				weight any
				want   bool
			}{
				{"omitted", nil, true}, {"zero", 0, false}, {"positive", 5, true},
			} {
				ns := "ns"
				if crossNamespace {
					ns = "other"
				}
				t.Run(kind+"/"+ns+"/"+tc.name, func(t *testing.T) {
					backend := map[string]any{"name": "app", "namespace": "ns", "port": 80}
					if tc.weight != nil {
						backend["weight"] = tc.weight
					}
					route, err := decodeGatewayRoute(kind, map[string]any{
						"metadata": map[string]any{"name": "route", "namespace": ns},
						"spec": map[string]any{
							"parentRefs": []any{map[string]any{"name": "gw"}},
							"rules":      []any{map[string]any{"backendRefs": []any{backend, map[string]any{"name": "active", "port": 80, "weight": 1}}}},
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{{Namespace: ns, Name: "gw", Listeners: []listener{{Name: "http"}}}}, nil)
					paths, unclear := idx.ServiceExposure(ref("ns", "app"))
					if crossNamespace {
						if len(paths) != 0 || unclear != tc.want {
							t.Fatalf("paths=%v unclear=%v, want no paths and unclear=%v", paths, unclear, tc.want)
						}
					} else if (len(paths) > 0) != tc.want || unclear {
						t.Fatalf("paths=%v unclear=%v, want exposed=%v", paths, unclear, tc.want)
					}
				})
			}
		}
	}
}

func TestServiceExposure_ZeroWeightDoesNotHideAnotherRule(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		t.Run(kind, func(t *testing.T) {
			route, err := decodeGatewayRoute(kind, map[string]any{
				"metadata": map[string]any{"name": "route", "namespace": "ns"},
				"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}, "rules": []any{
					map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": 80, "weight": 0}}},
					map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": 80, "weight": 1}}},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, nil, nil)
			paths, _ := idx.ServiceExposure(ref("ns", "app"))
			if len(paths) != 1 {
				t.Fatalf("paths=%v, want one active path", paths)
			}
		})
	}
}
