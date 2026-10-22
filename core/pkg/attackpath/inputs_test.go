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
	if inputs.ExposureIndex != nil {
		t.Fatal("decode failure must leave exposure unavailable")
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
					warningCount := 1
					if kind == "Namespace" {
						warningCount = 2 // Exposure and NetworkPolicy both depend on Namespace labels.
					}
					if len(inputs.Warnings) != warningCount || !strings.Contains(inputs.Warnings[0], "conflicting "+kind) {
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

func TestCollectInputsFiltersForeignKindsAcrossAdapters(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			resources := make(map[string]workloadinterface.IMetadata)
			add := func(kind, version string, native bool, fields map[string]any) {
				obj := map[string]any{"apiVersion": version, "kind": kind, "metadata": map[string]any{"name": "shared", "namespace": "apps"}}
				for key, value := range fields {
					obj[key] = value
				}
				order := "a"
				if native == reverse {
					order = "z"
				}
				resources[order+kind] = resource(obj)
			}
			add("Service", "v1", true, map[string]any{"spec": map[string]any{"type": "LoadBalancer"}})
			add("Service", "serving.knative.dev/v1", false, nil)
			add("NetworkPolicy", "networking.k8s.io/v1", true, map[string]any{"spec": map[string]any{"podSelector": map[string]any{}}})
			add("NetworkPolicy", "projectcalico.org/v3", false, map[string]any{"spec": map[string]any{"selector": "all()"}})
			add("Role", "rbac.authorization.k8s.io/v1", true, map[string]any{"rules": []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"}}}})
			add("Role", "foreign.example/v1", false, map[string]any{"rules": []any{map[string]any{"verbs": []any{"*"}}}})
			add("ServiceAccount", "foreign.example/v1", false, nil)
			inputs := CollectInputs(resources)
			if inputs.ExposureIndex == nil || len(inputs.AmbiguousServices) != 0 || len(inputs.Services) != 1 {
				t.Fatalf("foreign Service contaminated exposure: %+v", inputs)
			}
			paths, unclear := inputs.ExposureIndex.ServiceExposure(exposurepkg.ServiceRef{Namespace: "apps", Name: "shared"})
			if unclear || len(paths) != 1 || paths[0].Kind != exposurepkg.ExposureLoadBalancer {
				t.Fatalf("native exposure lost: %v %v", paths, unclear)
			}
			if len(inputs.Policies) != 1 || inputs.Policies[0].APIVersion != "networking.k8s.io/v1" {
				t.Fatalf("foreign policy decoded: %+v", inputs.Policies)
			}
			if len(inputs.Roles) != 1 || len(inputs.Roles[0].Rules) != 1 || inputs.Roles[0].Rules[0].Verbs[0] != "get" {
				t.Fatalf("foreign Role replaced native: %+v", inputs.Roles)
			}
			if len(inputs.ServiceAccounts) != 0 {
				t.Fatalf("foreign ServiceAccount became native identity: %+v", inputs.ServiceAccounts)
			}
			if len(inputs.Warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", inputs.Warnings)
			}
		})
	}
}

func TestCollectInputsRetainsNativeDecodeWarnings(t *testing.T) {
	inputs := CollectInputs(map[string]workloadinterface.IMetadata{
		"service": resource(map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "bad"}, "spec": "invalid"}),
		"policy":  resource(map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "bad"}, "spec": "invalid"}),
		"role":    resource(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": map[string]any{"name": "bad"}, "rules": "invalid"}),
	})
	if len(inputs.Warnings) != 3 {
		t.Fatalf("native decode warnings lost: %v", inputs.Warnings)
	}
	if !inputs.NetworkPolicyUnavailable || !inputs.RBACUnavailable {
		t.Fatalf("decode failures must make incomplete analysis unavailable: %+v", inputs)
	}
}

func TestSupportedInputResourcesGroups(t *testing.T) {
	for kind, versions := range map[string][]string{
		"Service": {"v1"}, "Namespace": {"v1"}, "ServiceAccount": {"v1"},
		"Ingress":       {"networking.k8s.io/v1", "extensions/v1beta1"},
		"NetworkPolicy": {"networking.k8s.io/v1", "extensions/v1beta1"},
		"Role":          {"rbac.authorization.k8s.io/v1"}, "ClusterRole": {"rbac.authorization.k8s.io/v1"},
		"RoleBinding": {"rbac.authorization.k8s.io/v1"}, "ClusterRoleBinding": {"rbac.authorization.k8s.io/v1"},
		"Gateway": {"gateway.networking.k8s.io/v1"}, "HTTPRoute": {"gateway.networking.k8s.io/v1"}, "GRPCRoute": {"gateway.networking.k8s.io/v1"},
	} {
		for _, version := range append(versions, "other.example/v1", "", "invalid/group/v1", "gateway.networking.k8s.io/") {
			t.Run(kind+"/"+version, func(t *testing.T) {
				inputs := map[string]workloadinterface.IMetadata{"resource": resource(map[string]any{
					"apiVersion": version, "kind": kind, "metadata": map[string]any{"name": "test"},
				})}
				want := false
				for _, supported := range versions {
					if version == supported {
						want = true
					}
				}
				if got := len(supportedInputResources(inputs)) == 1; got != want {
					t.Fatalf("accepted=%v, want %v", got, want)
				}
			})
		}
	}
}

func TestCollectInputsLegacyIngressExposureUnavailable(t *testing.T) {
	for _, version := range []string{"extensions/v1beta1", "networking.k8s.io/v1beta1"} {
		for _, backendLocation := range []string{"default", "rule"} {
			t.Run(version+"/"+backendLocation, func(t *testing.T) {
				backend := map[string]any{"serviceName": "app", "servicePort": 80}
				spec := map[string]any{"backend": backend}
				if backendLocation == "rule" {
					spec = map[string]any{"rules": []any{map[string]any{"http": map[string]any{"paths": []any{map[string]any{"path": "/", "backend": backend}}}}}}
				}
				inputs := CollectInputs(makeResources(
					resource(map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "app", "namespace": "apps"}, "spec": map[string]any{"type": "ClusterIP", "ports": []any{map[string]any{"port": 80}}}}),
					resource(map[string]any{"apiVersion": version, "kind": "Ingress", "metadata": map[string]any{"name": "legacy", "namespace": "apps"}, "spec": spec}),
					resource(map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "policy", "namespace": "apps"}, "spec": map[string]any{"podSelector": map[string]any{}}}),
					resource(map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "sa", "namespace": "apps"}}),
				))
				if inputs.ExposureIndex != nil {
					t.Fatal("legacy Ingress must not produce a definite all-clear")
				}
				if len(inputs.Warnings) != 1 || !strings.Contains(inputs.Warnings[0], "unsupported Ingress API version "+version+" for apps/legacy; exposure index unavailable") {
					t.Fatalf("missing unsupported-version diagnostic: %v", inputs.Warnings)
				}
				if len(inputs.Ingresses) != 0 {
					t.Fatalf("legacy backends silently decoded into v1: %+v", inputs.Ingresses)
				}
				if len(inputs.Services) != 1 || len(inputs.Policies) != 1 || len(inputs.ServiceAccounts) != 1 {
					t.Fatalf("other inputs were lost: %+v", inputs)
				}
			})
		}
	}
}

func TestCollectInputsV1IngressStillExposesService(t *testing.T) {
	inputs := CollectInputs(makeResources(
		resource(map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "app", "namespace": "apps"}, "spec": map[string]any{"type": "ClusterIP", "ports": []any{map[string]any{"port": 80}}}}),
		exposureRouteResource("Ingress", "app", "v1"),
	))
	if inputs.ExposureIndex == nil || len(inputs.Warnings) != 0 {
		t.Fatalf("valid v1 Ingress became unavailable: %+v", inputs)
	}
	paths, unclear := inputs.ExposureIndex.ServiceExposure(exposurepkg.ServiceRef{Namespace: "apps", Name: "app"})
	if unclear || len(paths) != 1 || paths[0].Kind != exposurepkg.ExposureIngress {
		t.Fatalf("v1 Ingress exposure lost: paths=%v unclear=%v", paths, unclear)
	}
}

func TestCollectInputsConflictingPolicyAndRBACDefinitions(t *testing.T) {
	for _, kind := range []string{"NetworkPolicy", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} {
		for _, variants := range [][]string{{"deny", "allow"}, {"allow", "deny"}, {"deny", "allow", "deny"}, {"allow", "deny", "allow"}, {"allow", "allow"}} {
			t.Run(kind+"/"+strings.Join(variants, "-"), func(t *testing.T) {
				resources := make(map[string]workloadinterface.IMetadata)
				for i, variant := range variants {
					version := "rbac.authorization.k8s.io/v1"
					metadata := map[string]any{"name": "shared", "annotations": map[string]any{"source": fmt.Sprint(i)}}
					if kind != "ClusterRole" && kind != "ClusterRoleBinding" {
						metadata["namespace"] = "apps"
					}
					obj := map[string]any{"apiVersion": version, "kind": kind, "metadata": metadata}
					switch kind {
					case "NetworkPolicy":
						obj["apiVersion"] = "networking.k8s.io/v1"
						spec := map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}}
						if variant == "allow" {
							spec["ingress"] = []any{map[string]any{}}
						}
						obj["spec"] = spec
					case "Role", "ClusterRole":
						obj["rules"] = []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{variant}}}
					default:
						obj["roleRef"] = map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": variant}
						obj["subjects"] = []any{map[string]any{"kind": "ServiceAccount", "name": variant, "namespace": "apps"}}
					}
					resources[fmt.Sprintf("source-%d", i)] = resource(obj)
				}
				for attempt := 0; attempt < 5; attempt++ {
					inputs := CollectInputs(resources)
					conflict := variants[0] != variants[1]
					unavailable, ambiguous := inputs.RBACUnavailable, inputs.AmbiguousRBAC
					count := len(inputs.Roles) + len(inputs.ClusterRoles) + len(inputs.RoleBindings) + len(inputs.ClusterRoleBindings)
					if kind == "NetworkPolicy" {
						unavailable, ambiguous, count = inputs.NetworkPolicyUnavailable, inputs.AmbiguousPolicies, len(inputs.Policies)
					}
					if unavailable != conflict {
						t.Fatalf("unavailable=%v want %v", unavailable, conflict)
					}
					if !conflict {
						if count != 1 || len(ambiguous) != 0 || len(inputs.Warnings) != 0 {
							t.Fatalf("equivalent definitions not coalesced: count=%d ambiguous=%v warnings=%v", count, ambiguous, inputs.Warnings)
						}
					} else {
						if count != 2 || len(ambiguous) != 1 || !strings.HasPrefix(ambiguous[0], kind+"/") || len(inputs.Warnings) != 1 || !strings.Contains(inputs.Warnings[0], "unavailable") {
							t.Fatalf("conflict not preserved and diagnosed: count=%d ambiguous=%v warnings=%v", count, ambiguous, inputs.Warnings)
						}
					}
				}
			})
		}
	}
}

func TestCollectInputsNamespaceConflictDisablesNetworkPolicy(t *testing.T) {
	for _, labels := range [][]string{{"prod", "dev"}, {"dev", "prod"}, {"prod", "dev", "prod"}, {"prod", "prod"}} {
		t.Run(strings.Join(labels, "-"), func(t *testing.T) {
			resources := makeResources(resource(map[string]any{
				"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
				"metadata": map[string]any{"name": "allow-prod", "namespace": "apps"},
				"spec":     map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}, "ingress": []any{map[string]any{"from": []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}}}}}}},
			}))
			for i, env := range labels {
				resources[fmt.Sprintf("namespace-%d", i)] = resource(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "client", "labels": map[string]any{"env": env}}})
			}
			for attempt := 0; attempt < 5; attempt++ {
				inputs := CollectInputs(resources)
				wantUnavailable := labels[0] != labels[1]
				if inputs.NetworkPolicyUnavailable != wantUnavailable || len(inputs.Policies) != 1 || len(inputs.AmbiguousPolicies) != 0 {
					t.Fatalf("namespace conflict availability incorrect: %+v", inputs)
				}
				if wantUnavailable && !strings.Contains(strings.Join(inputs.Warnings, "\n"), "networkpolicy: conflicting Namespace definitions for client") {
					t.Fatalf("missing NetworkPolicy namespace diagnostic: %v", inputs.Warnings)
				}
			}
		})
	}
}

func TestCollectInputsBindingConflictFields(t *testing.T) {
	for _, kind := range []string{"RoleBinding", "ClusterRoleBinding"} {
		for _, field := range []string{"roleRef", "subjects"} {
			t.Run(kind+"/"+field, func(t *testing.T) {
				resources := make(map[string]workloadinterface.IMetadata)
				for i := 0; i < 2; i++ {
					role, subject := "reader", "alice"
					if i == 1 {
						if field == "roleRef" {
							role = "admin"
						} else {
							subject = "bob"
						}
					}
					resources[fmt.Sprint(i)] = resource(map[string]any{
						"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
						"metadata": map[string]any{"name": "binding", "namespace": "apps"},
						"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
						"subjects": []any{map[string]any{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": subject}},
					})
				}
				inputs := CollectInputs(resources)
				if !inputs.RBACUnavailable || len(inputs.AmbiguousRBAC) != 1 {
					t.Fatalf("%s difference did not disable RBAC: %+v", field, inputs)
				}
			})
		}
	}
}

func TestCollectInputsMalformedNamespaceLabels(t *testing.T) {
	for _, variants := range [][]string{{"bad"}, {"bad", "valid"}, {"valid", "bad"}, {"valid", "bad", "valid"}, {"omitted"}} {
		t.Run(strings.Join(variants, "-"), func(t *testing.T) {
			resources := make(map[string]workloadinterface.IMetadata)
			for i, variant := range variants {
				metadata := map[string]any{"name": "client"}
				if variant == "bad" {
					metadata["labels"] = map[string]any{"env": true}
				}
				if variant == "valid" {
					metadata["labels"] = map[string]any{}
				}
				resources[fmt.Sprint(i)] = resource(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": metadata})
			}
			inputs := CollectInputs(resources)
			bad := variants[0] != "omitted"
			if inputs.NetworkPolicyUnavailable != bad || (inputs.ExposureIndex == nil) != bad {
				t.Fatalf("malformed namespace availability: %+v", inputs)
			}
			if bad && !strings.Contains(strings.Join(inputs.Warnings, "\n"), "malformed Namespace labels for client") {
				t.Fatalf("missing diagnostic: %v", inputs.Warnings)
			}
		})
	}
}

func TestCollectInputsDroppedIngressUnavailable(t *testing.T) {
	inputs := CollectInputs(makeResources(
		resource(map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "app", "namespace": "apps"}, "spec": map[string]any{"ports": []any{map[string]any{"port": 80}}}}),
		resource(map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": map[string]any{"name": "bad", "namespace": "apps"}, "spec": map[string]any{"rules": "invalid"}}),
	))
	if inputs.ExposureIndex != nil || len(inputs.Services) != 1 || inputs.NetworkPolicyUnavailable || inputs.RBACUnavailable || len(inputs.Warnings) != 1 {
		t.Fatalf("exposure decode failure not isolated: %+v", inputs)
	}
}
