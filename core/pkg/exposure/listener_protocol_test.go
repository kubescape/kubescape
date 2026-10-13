package exposure_test

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/exposure"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func protocolResource(kind, name, namespace string, spec map[string]any) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       spec,
	})
}

func protocolIndex(t *testing.T, listeners []any, parents []any, routeKind, routeNS, backendNS string, extra ...workloadinterface.IMetadata) *exposure.Index {
	t.Helper()
	service := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "app", "namespace": backendNS},
		"spec":       map[string]any{"type": "ClusterIP"},
	})
	resources := map[string]workloadinterface.IMetadata{
		"service": service,
		"gateway": protocolResource("Gateway", "edge", "ingress", map[string]any{"listeners": listeners}),
		"route": protocolResource(routeKind, "web", routeNS, map[string]any{
			"parentRefs": parents,
			"rules": []any{map[string]any{
				"backendRefs": []any{map[string]any{"name": "app", "namespace": backendNS, "port": 8080}},
			}},
		}),
	}
	for _, resource := range extra {
		if resource.GetKind() == "Service" && resource.GetName() == "app" && resource.GetNamespace() == backendNS {
			resources["service"] = resource
		} else {
			resources[resource.GetID()] = resource
		}
	}
	services, ingresses, namespaces, errs := exposure.FromResources(resources)
	require.Empty(t, errs)
	routes, gateways, errs := exposure.FromUnstructuredGatewayAPI(resources)
	require.Empty(t, errs)
	return exposure.NewIndex(services, ingresses, routes, gateways, namespaces)
}

func protocolListener(name, protocol string, port int, kinds []any) map[string]any {
	entry := map[string]any{
		"name":     name,
		"port":     port,
		"protocol": protocol,
		"hostname": name + ".example.com",
		"allowedRoutes": map[string]any{
			"namespaces": map[string]any{"from": "All"},
		},
	}
	if kinds != nil {
		entry["allowedRoutes"].(map[string]any)["kinds"] = kinds
	}
	return entry
}

func TestServiceExposure_ListenerProtocolCompatibility(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, tc := range []struct {
			protocol string
			want     bool
		}{
			{protocol: "HTTP", want: true},
			{protocol: "HTTPS", want: true},
			{protocol: "TCP", want: false},
			{protocol: "UDP", want: false},
			{protocol: "TLS", want: false},
			// An absent or extension protocol is incomplete/unknown data,
			// not evidence that a listener cannot admit this route.
			{protocol: "", want: true},
			{protocol: "example.com/custom", want: true},
		} {
			for _, crossNamespace := range []bool{false, true} {
				t.Run(kind+"/"+tc.protocol+"/"+map[bool]string{false: "same", true: "cross"}[crossNamespace], func(t *testing.T) {
					backendNS := "apps"
					if crossNamespace {
						backendNS = "backend"
					}
					idx := protocolIndex(t,
						[]any{protocolListener("public", tc.protocol, 443, nil)},
						[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
						kind, "apps", backendNS,
					)
					paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: backendNS, Name: "app"})
					if crossNamespace {
						require.Empty(t, paths)
						require.Equal(t, tc.want, unclear)
					} else {
						require.False(t, unclear)
						require.Equal(t, tc.want, len(paths) > 0)
						if tc.want {
							require.Len(t, paths, 1)
							require.Equal(t, "public.example.com", paths[0].Host)
						}
					}
				})
			}
		}
	}
}

func TestServiceExposure_AllowedKindsCannotOverrideProtocol(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, protocol := range []string{"TCP", "UDP", "TLS"} {
			t.Run(kind+"/"+protocol, func(t *testing.T) {
				idx := protocolIndex(t,
					[]any{protocolListener("transport", protocol, 443, []any{map[string]any{"kind": kind}})},
					[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
					kind, "apps", "apps",
				)
				paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
				require.Empty(t, paths)
				require.False(t, unclear)
			})
		}
	}
}

func TestServiceExposure_ProtocolAndParentSelectionCompose(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, tc := range []struct {
			name   string
			parent map[string]any
			want   []string
		}{
			{
				name:   "unrestricted parent excludes transport listener",
				parent: map[string]any{},
				want:   []string{"web.example.com", "secure.example.com"},
			},
			{
				name:   "port selects both protocols but only HTTP is compatible",
				parent: map[string]any{"port": 80},
				want:   []string{"web.example.com"},
			},
			{
				name:   "section pins incompatible listener",
				parent: map[string]any{"sectionName": "transport"},
			},
			{
				name:   "section pins compatible listener",
				parent: map[string]any{"sectionName": "secure"},
				want:   []string{"secure.example.com"},
			},
			{
				name:   "port and section both match",
				parent: map[string]any{"port": 443, "sectionName": "secure"},
				want:   []string{"secure.example.com"},
			},
			{
				name:   "port does not override mismatching section",
				parent: map[string]any{"port": 80, "sectionName": "secure"},
			},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				tc.parent["name"] = "edge"
				tc.parent["namespace"] = "ingress"
				idx := protocolIndex(t,
					[]any{
						protocolListener("transport", "TCP", 80, nil),
						protocolListener("web", "HTTP", 80, nil),
						protocolListener("secure", "HTTPS", 443, nil),
					},
					[]any{tc.parent}, kind, "apps", "apps",
				)
				paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
				require.False(t, unclear)
				var hosts []string
				for _, path := range paths {
					hosts = append(hosts, path.Host)
				}
				require.Equal(t, tc.want, hosts)
			})
		}
	}
}

func TestServiceExposure_CompatibleListenerStillHonorsKindAdmission(t *testing.T) {
	idx := protocolIndex(t,
		[]any{protocolListener("web", "HTTP", 80, []any{map[string]any{"kind": "GRPCRoute"}})},
		[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
		"HTTPRoute", "apps", "apps",
	)
	paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
	require.Empty(t, paths)
	require.False(t, unclear)
}

func TestServiceExposure_MissingGatewayRemainsConservative(t *testing.T) {
	idx := protocolIndex(t,
		[]any{protocolListener("transport", "UDP", 80, nil)},
		[]any{
			map[string]any{"name": "edge", "namespace": "ingress"},
			map[string]any{"name": "not-collected", "namespace": "ingress"},
		},
		"HTTPRoute", "apps", "apps",
	)
	paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
	require.False(t, unclear)
	require.Len(t, paths, 1)
	require.Empty(t, paths[0].Host)
}

func TestServiceExposure_ProtocolDoesNotBypassNamespaceAdmission(t *testing.T) {
	for _, protocol := range []string{"HTTP", "HTTPS", "TCP"} {
		t.Run(protocol, func(t *testing.T) {
			entry := protocolListener("web", protocol, 443, nil)
			entry["allowedRoutes"] = map[string]any{
				"namespaces": map[string]any{"from": "Same"},
			}
			idx := protocolIndex(t,
				[]any{entry},
				[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
				"HTTPRoute", "apps", "apps",
			)
			paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
			require.Empty(t, paths)
			require.False(t, unclear)
		})
	}
}

func TestServiceExposure_IncompatibleListenerDoesNotHideIndependentExposure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		serviceSpec map[string]any
		want        exposure.ExposureKind
	}{
		{
			name:        "load balancer",
			serviceSpec: map[string]any{"type": "LoadBalancer"},
			want:        exposure.ExposureLoadBalancer,
		},
		{
			name:        "node port",
			serviceSpec: map[string]any{"type": "NodePort"},
			want:        exposure.ExposureNodePort,
		},
		{
			name:        "external IP",
			serviceSpec: map[string]any{"type": "ClusterIP", "externalIPs": []any{"198.51.100.10"}},
			want:        exposure.ExposureExternalIP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1",
				"kind":       "Service",
				"metadata":   map[string]any{"name": "app", "namespace": "apps"},
				"spec":       tc.serviceSpec,
			})
			idx := protocolIndex(t,
				[]any{protocolListener("transport", "TCP", 443, nil)},
				[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
				"HTTPRoute", "apps", "apps", service,
			)
			paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
			require.False(t, unclear)
			require.Len(t, paths, 1)
			for _, path := range paths {
				require.Equal(t, tc.want, path.Kind, "transport listener must never add an HTTP route path")
			}
		})
	}
}

func TestListenerProtocol_CorrelationDoesNotElevateTransportOnlyWorkload(t *testing.T) {
	for _, protocol := range []string{"TCP", "UDP", "TLS"} {
		t.Run(protocol, func(t *testing.T) {
			idx := protocolIndex(t,
				[]any{protocolListener("transport", protocol, 443, nil)},
				[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
				"HTTPRoute", "apps", "apps",
			)
			paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
			require.False(t, unclear)
			np, errs := networkpolicy.NewIndex(nil, nil)
			require.Empty(t, errs)
			transport := vulnexposure.Workload{Namespace: "apps", Kind: "Deployment", Name: "a-transport"}
			public := vulnexposure.Workload{Namespace: "apps", Kind: "Deployment", Name: "z-public"}
			vulnerabilities := map[vulnexposure.Workload][]storagev1beta1.Vulnerability{
				transport: {{VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-transport", Severity: "Critical"}}},
				public:    {{VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-public", Severity: "High"}}},
			}
			endpoints := map[vulnexposure.Workload]networkpolicy.Endpoint{
				transport: {Namespace: "apps", Name: "transport"},
				public:    {Namespace: "apps", Name: "public"},
			}
			external := map[vulnexposure.Workload][]exposure.ExposurePath{
				transport: paths,
				public:    {{Kind: exposure.ExposureLoadBalancer, Source: "apps/public"}},
			}
			findings, skipped := vulnexposure.Correlate(np, endpoints, vulnerabilities, vulnexposure.SeverityLow, external)
			require.Empty(t, skipped)
			require.Len(t, findings, 2)
			require.Equal(t, public, findings[0].Workload, "real external reachability outranks transport-only false paths")
			require.Equal(t, transport, findings[1].Workload)
			require.Empty(t, findings[1].ExternalExposure)
		})
	}
}

func TestListenerProtocol_DecodeRejectsMalformedProtocol(t *testing.T) {
	for _, protocol := range []any{123, true, []any{"HTTP"}, map[string]any{"type": "HTTP"}} {
		resource := protocolResource("Gateway", "bad", "ingress", map[string]any{
			"listeners": []any{map[string]any{"name": "web", "port": 80, "protocol": protocol}},
		})
		_, gateways, errs := exposure.FromUnstructuredGatewayAPI(map[string]workloadinterface.IMetadata{"bad": resource})
		require.Empty(t, gateways)
		require.Len(t, errs, 1)
	}
}

func TestServiceExposure_ProtocolFilteringStillIntersectsHostnames(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, hostname := range []string{"web.example.com", "transport.example.com", "unrelated.example.net"} {
			t.Run(kind+"/"+hostname, func(t *testing.T) {
				service := workloadinterface.NewWorkloadObj(map[string]any{
					"apiVersion": "v1", "kind": "Service",
					"metadata": map[string]any{"name": "app", "namespace": "apps"},
					"spec":     map[string]any{"type": "ClusterIP"},
				})
				resources := map[string]workloadinterface.IMetadata{
					"service": service,
					"gateway": protocolResource("Gateway", "edge", "ingress", map[string]any{
						"listeners": []any{
							protocolListener("transport", "TLS", 443, nil),
							protocolListener("web", "HTTPS", 443, nil),
						},
					}),
					"route": protocolResource(kind, "web", "apps", map[string]any{
						"hostnames":  []any{hostname},
						"parentRefs": []any{map[string]any{"name": "edge", "namespace": "ingress"}},
						"rules": []any{map[string]any{
							"backendRefs": []any{map[string]any{"name": "app"}},
						}},
					}),
				}
				services, ingresses, namespaces, errs := exposure.FromResources(resources)
				require.Empty(t, errs)
				routes, gateways, errs := exposure.FromUnstructuredGatewayAPI(resources)
				require.Empty(t, errs)
				idx := exposure.NewIndex(services, ingresses, routes, gateways, namespaces)
				paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "apps", Name: "app"})
				require.False(t, unclear)
				if hostname == "web.example.com" {
					require.Len(t, paths, 1)
					require.Equal(t, hostname, paths[0].Host)
				} else {
					require.Empty(t, paths, "a matching hostname on a transport listener is not HTTP exposure")
				}
			})
		}
	}
}

func TestServiceExposure_ActiveListenerAfterTransportKeepsCrossNamespaceUncertainty(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		t.Run(kind, func(t *testing.T) {
			idx := protocolIndex(t,
				[]any{
					protocolListener("transport", "TCP", 443, nil),
					protocolListener("web", "HTTPS", 443, nil),
				},
				[]any{map[string]any{"name": "edge", "namespace": "ingress"}},
				kind, "apps", "backend",
			)
			paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: "backend", Name: "app"})
			require.Empty(t, paths)
			require.True(t, unclear, "an incompatible listener must not terminate the search for compatible ones")
		})
	}
}
