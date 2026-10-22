package attackpath

import (
	"strings"
	"testing"

	exposurepkg "github.com/kubescape/kubescape/v4/core/pkg/exposure"
)

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
