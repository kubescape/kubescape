package attackpath

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	exposurepkg "github.com/kubescape/kubescape/v4/core/pkg/exposure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCollectInputsConflictingServices(t *testing.T) {
	for _, types := range [][]string{
		{"LoadBalancer", "ClusterIP"},
		{"ClusterIP", "LoadBalancer"},
		{"LoadBalancer", "ClusterIP", "LoadBalancer"},
		{"ClusterIP", "LoadBalancer", "ClusterIP"},
		{"LoadBalancer", "LoadBalancer"},
	} {
		t.Run(strings.Join(types, "-"), func(t *testing.T) {
			resources := make(map[string]workloadinterface.IMetadata)
			var ordered []corev1.Service
			for i, serviceType := range types {
				resources[fmt.Sprintf("file-%d", i)] = resource(map[string]any{
					"apiVersion": "v1", "kind": "Service",
					"metadata": map[string]any{
						"name": "app", "namespace": "apps", "resourceVersion": fmt.Sprint(i),
						"annotations": map[string]any{"source": fmt.Sprintf("file-%d", i)},
					},
					"spec": map[string]any{"type": serviceType},
				})
				ordered = append(ordered, corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceType(serviceType)},
				})
			}
			wantConflict := types[0] != types[1]
			// Exercise exact orders as well as the adapter's map iteration order.
			if refs := conflictingServices(ordered); (len(refs) != 0) != wantConflict {
				t.Fatalf("ordered conflicts = %v, want conflict=%v", refs, wantConflict)
			}
			inputs := CollectInputs(resources)
			if !wantConflict {
				if inputs.ExposureIndex == nil || len(inputs.AmbiguousServices) != 0 || len(inputs.Warnings) != 0 {
					t.Fatalf("equivalent duplicates should remain usable: %+v", inputs)
				}
				paths, unclear := inputs.ExposureIndex.ServiceExposure(exposurepkg.ServiceRef{Namespace: "apps", Name: "app"})
				if unclear || len(paths) != 1 || paths[0].Kind != exposurepkg.ExposureLoadBalancer {
					t.Fatalf("equivalent services lost exposure: paths=%+v unclear=%v", paths, unclear)
				}
				return
			}
			if inputs.ExposureIndex != nil {
				t.Fatal("conflicting definitions must not produce a definite exposure index")
			}
			if len(inputs.AmbiguousServices) != 1 || inputs.AmbiguousServices[0] != (exposurepkg.ServiceRef{Namespace: "apps", Name: "app"}) {
				t.Fatalf("unexpected ambiguous identities: %v", inputs.AmbiguousServices)
			}
			if len(inputs.Warnings) != 1 || inputs.Warnings[0] != "exposure: conflicting Service definitions for apps/app; exposure index unavailable" {
				t.Fatalf("missing ambiguity diagnostic: %v", inputs.Warnings)
			}
		})
	}
}

func TestCollectInputsRetainsGatewayExposure(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, admitted := range []bool{true, false} {
			name := kind + "/denied"
			if admitted {
				name = kind + "/admitted"
			}
			t.Run(name, func(t *testing.T) {
				env := "dev"
				if admitted {
					env = "prod"
				}
				resources := makeResources(
					resource(map[string]any{
						"apiVersion": "v1", "kind": "Service",
						"metadata": map[string]any{"name": "app", "namespace": "apps"},
						"spec":     map[string]any{"ports": []any{map[string]any{"port": 80}}},
					}),
					resource(map[string]any{
						"apiVersion": "v1", "kind": "Namespace",
						"metadata": map[string]any{"name": "apps", "labels": map[string]any{"env": env}},
					}),
					resource(map[string]any{
						"apiVersion": "gateway.networking.k8s.io/v1", "kind": kind,
						"metadata": map[string]any{"name": "route", "namespace": "apps"},
						"spec": map[string]any{
							"parentRefs": []any{map[string]any{"name": "gw", "namespace": "edge"}},
							"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": 80}}}},
						},
					}),
					resource(map[string]any{
						"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
						"metadata": map[string]any{"name": "gw", "namespace": "edge"},
						"spec": map[string]any{"listeners": []any{map[string]any{
							"name": "http", "protocol": "HTTP", "port": 80, "hostname": "app.example.com",
							"allowedRoutes": map[string]any{"namespaces": map[string]any{
								"from": "Selector", "selector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
							}},
						}}},
					}),
				)
				inputs := CollectInputs(resources)
				if len(inputs.Warnings) != 0 {
					t.Fatalf("unexpected warnings: %v", inputs.Warnings)
				}
				if inputs.ExposureIndex == nil {
					t.Fatal("missing exposure index")
				}
				paths, unclear := inputs.ExposureIndex.ServiceExposure(exposurepkg.ServiceRef{Namespace: "apps", Name: "app"})
				if unclear {
					t.Fatal("same-namespace backend exposure should be determined")
				}
				if !admitted {
					if len(paths) != 0 {
						t.Fatalf("denied route exposed service: %+v", paths)
					}
					return
				}
				if len(paths) != 1 || paths[0].Kind.String() != kind || paths[0].Source != "apps/route" || paths[0].Host != "app.example.com" {
					t.Fatalf("expected retained %s/Gateway exposure, got %+v", kind, paths)
				}
			})
		}
	}
}

func TestCollectInputsPreservesGatewayDecodeWarnings(t *testing.T) {
	inputs := CollectInputs(makeResources(resource(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": "broken", "namespace": "apps"},
		"spec":     map[string]any{"parentRefs": "invalid"},
	})))
	if inputs.ExposureIndex == nil {
		t.Fatal("decode failure should not prevent index construction")
	}
	if len(inputs.Warnings) != 1 || !strings.HasPrefix(inputs.Warnings[0], "exposure/gateway: ") {
		t.Fatalf("expected attributed gateway decode warning, got %v", inputs.Warnings)
	}
}

func TestCollectInputsLeavesUncollectedReferenceGrantsUnclear(t *testing.T) {
	inputs := CollectInputs(makeResources(
		resource(map[string]any{
			"apiVersion": "v1", "kind": "Service",
			"metadata": map[string]any{"name": "app", "namespace": "backend"},
			"spec":     map[string]any{"ports": []any{map[string]any{"port": 80}}},
		}),
		resource(map[string]any{
			"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
			"metadata": map[string]any{"name": "route", "namespace": "edge"},
			"spec": map[string]any{
				"parentRefs": []any{map[string]any{"name": "gw"}},
				"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "namespace": "backend", "port": 80}}}},
			},
		}),
	))
	paths, unclear := inputs.ExposureIndex.ServiceExposure(exposurepkg.ServiceRef{Namespace: "backend", Name: "app"})
	if len(paths) != 0 || !unclear {
		t.Fatalf("uncollected grants must leave authorization unclear: paths=%+v, unclear=%v", paths, unclear)
	}
}

func TestCollectInputsConflictingExposureDefinitions(t *testing.T) {
	for _, kind := range []string{"Gateway", "Namespace"} {
		for _, values := range [][]string{{"All", "Same"}, {"Same", "All"}, {"All", "Same", "All"}, {"All", "All"}} {
			t.Run(kind+"/"+strings.Join(values, "-"), func(t *testing.T) {
				resources := make(map[string]workloadinterface.IMetadata)
				for i, value := range values {
					metadata := map[string]any{
						"name": "edge", "resourceVersion": fmt.Sprint(i),
						"annotations": map[string]any{"source": fmt.Sprint(i)},
					}
					obj := map[string]any{"kind": kind, "metadata": metadata}
					if kind == "Gateway" {
						obj["apiVersion"] = "gateway.networking.k8s.io/v1"
						metadata["namespace"] = "edge"
						obj["spec"] = map[string]any{"listeners": []any{map[string]any{
							"name": "http", "protocol": "HTTP", "port": 80,
							"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": value}},
						}}}
					} else {
						obj["apiVersion"] = "v1"
						metadata["labels"] = map[string]any{"env": value}
					}
					resources[fmt.Sprint(i)] = resource(obj)
				}
				// Repeat to exercise independently randomized adapter iteration.
				for attempt := 0; attempt < 10; attempt++ {
					inputs := CollectInputs(resources)
					conflict := values[0] != values[1]
					if !conflict {
						if inputs.ExposureIndex == nil || len(inputs.Warnings) != 0 || len(inputs.AmbiguousGateways) != 0 || len(inputs.AmbiguousNamespaces) != 0 {
							t.Fatalf("equivalent %s definitions must stay usable: %+v", kind, inputs)
						}
						continue
					}
					if inputs.ExposureIndex != nil {
						t.Fatal("conflicting exposure definitions must not produce a definite index")
					}
					if len(inputs.Warnings) != 1 || !strings.Contains(inputs.Warnings[0], "conflicting "+kind) {
						t.Fatalf("missing explicit diagnostic: %v", inputs.Warnings)
					}
					if kind == "Gateway" {
						if len(inputs.AmbiguousGateways) != 1 || inputs.AmbiguousGateways[0] != (exposurepkg.ServiceRef{Namespace: "edge", Name: "edge"}) {
							t.Fatalf("unexpected Gateway ambiguity: %v", inputs.AmbiguousGateways)
						}
					} else if len(inputs.AmbiguousNamespaces) != 1 || inputs.AmbiguousNamespaces[0] != "edge" {
						t.Fatalf("unexpected Namespace ambiguity: %v", inputs.AmbiguousNamespaces)
					}
				}
			})
		}
	}
}

func TestCollectInputsIgnoresUnrelatedGatewayGroups(t *testing.T) {
	inputs := CollectInputs(map[string]workloadinterface.IMetadata{
		"real": resource(map[string]any{
			"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
			"metadata": map[string]any{"name": "edge", "namespace": "apps"},
			"spec":     map[string]any{"listeners": []any{map[string]any{"name": "http", "protocol": "HTTP", "port": 80}}},
		}),
		"istio": resource(map[string]any{
			"apiVersion": "networking.istio.io/v1", "kind": "Gateway",
			"metadata": map[string]any{"name": "edge", "namespace": "apps"},
			"spec":     map[string]any{"servers": []any{}},
		}),
		"foreign-route": resource(map[string]any{
			"apiVersion": "other.example/v1", "kind": "HTTPRoute",
			"metadata": map[string]any{"name": "foreign", "namespace": "apps"},
			"spec":     map[string]any{"parentRefs": "not-a-gateway-api-route"},
		}),
	})
	if inputs.ExposureIndex == nil || len(inputs.AmbiguousGateways) != 0 || len(inputs.Warnings) != 0 {
		t.Fatalf("unrelated API groups affected Gateway exposure: %+v", inputs)
	}
}

func exposureRouteResource(kind, backend, source string) workloadinterface.IMetadata {
	obj := map[string]any{
		"kind":     kind,
		"metadata": map[string]any{"name": "route", "namespace": "apps", "annotations": map[string]any{"source": source}},
	}
	if kind == "Ingress" {
		obj["apiVersion"] = "networking.k8s.io/v1"
		obj["spec"] = map[string]any{"defaultBackend": map[string]any{"service": map[string]any{"name": backend, "port": map[string]any{"number": 80}}}}
	} else {
		obj["apiVersion"] = "gateway.networking.k8s.io/v1"
		obj["spec"] = map[string]any{
			"parentRefs": []any{map[string]any{"name": "edge"}},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": backend, "port": 80}}}},
		}
	}
	return resource(obj)
}

func TestCollectInputsConflictingIngressAndRoutes(t *testing.T) {
	for _, kind := range []string{"Ingress", "HTTPRoute", "GRPCRoute"} {
		for _, backends := range [][]string{{"one", "two"}, {"two", "one"}, {"one", "two", "one"}, {"two", "one", "two"}, {"one", "one"}} {
			t.Run(kind+"/"+strings.Join(backends, "-"), func(t *testing.T) {
				resources := make(map[string]workloadinterface.IMetadata)
				for i, backend := range backends {
					resources[fmt.Sprint(i)] = exposureRouteResource(kind, backend, fmt.Sprint(i))
				}
				for attempt := 0; attempt < 10; attempt++ {
					inputs := CollectInputs(resources)
					if backends[0] == backends[1] {
						if inputs.ExposureIndex == nil || len(inputs.Warnings) != 0 {
							t.Fatalf("equivalent route definitions should remain usable: %+v", inputs)
						}
						continue
					}
					if inputs.ExposureIndex != nil || len(inputs.Warnings) != 1 || !strings.Contains(inputs.Warnings[0], "conflicting "+kind+" definitions for apps/route") {
						t.Fatalf("conflict must disable index with identity diagnostic: %+v", inputs)
					}
				}
			})
		}
	}
}

func TestCollectInputsKeepsRouteKindsSeparate(t *testing.T) {
	inputs := CollectInputs(map[string]workloadinterface.IMetadata{
		"http": exposureRouteResource("HTTPRoute", "one", "http"),
		"grpc": exposureRouteResource("GRPCRoute", "two", "grpc"),
	})
	if inputs.ExposureIndex == nil || len(inputs.Warnings) != 0 {
		t.Fatalf("distinct route kinds cannot conflict: %+v", inputs)
	}
}
