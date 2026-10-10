package exposure

import (
	corev1 "k8s.io/api/core/v1"
	"reflect"
	"testing"
)

func TestServiceExposure_ParentListenerPort(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, tc := range []struct {
			name    string
			port    any
			section string
			want    []string
		}{
			{"omitted", nil, "", []string{"http.example.com", "https.example.com", "other.example.com"}},
			{"matching", 443, "", []string{"https.example.com", "other.example.com"}},
			{"missing", 8080, "", nil},
			{"section and port match", 443, "https", []string{"https.example.com"}},
			{"section and port disagree", 80, "https", nil},
			{"section only", nil, "https", []string{"https.example.com"}},
		} {
			for _, ns := range []string{"ns", "other"} {
				t.Run(kind+"/"+ns+"/"+tc.name, func(t *testing.T) {
					parent := map[string]any{"name": "gw"}
					if tc.port != nil {
						parent["port"] = tc.port
					}
					if tc.section != "" {
						parent["sectionName"] = tc.section
					}
					route, err := decodeGatewayRoute(kind, map[string]any{
						"metadata": map[string]any{"name": "route", "namespace": ns},
						"spec":     map[string]any{"parentRefs": []any{parent}, "rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "namespace": "ns", "port": 80}}}}},
					})
					if err != nil {
						t.Fatal(err)
					}
					gw, err := decodeGateway(map[string]any{
						"metadata": map[string]any{"name": "gw", "namespace": ns},
						"spec": map[string]any{"listeners": []any{
							map[string]any{"name": "http", "port": 80, "protocol": "HTTP", "hostname": "http.example.com"},
							map[string]any{"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "https.example.com"},
							map[string]any{"name": "other", "port": 443, "protocol": "HTTPS", "hostname": "other.example.com"},
						}},
					})
					if err != nil {
						t.Fatal(err)
					}
					idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
					paths, unclear := idx.ServiceExposure(ref("ns", "app"))
					if ns != "ns" {
						if len(paths) != 0 || unclear != (len(tc.want) > 0) {
							t.Fatalf("paths=%v unclear=%v, want unclear=%v", paths, unclear, len(tc.want) > 0)
						}
						return
					}
					var hosts []string
					for _, path := range paths {
						hosts = append(hosts, path.Host)
					}
					if !reflect.DeepEqual(hosts, tc.want) || unclear {
						t.Fatalf("hosts=%v unclear=%v, want hosts=%v", hosts, unclear, tc.want)
					}
				})
			}
		}
	}
}

func TestServiceExposure_ParentPortWithMissingGateway(t *testing.T) {
	route, err := decodeGatewayRoute("HTTPRoute", map[string]any{
		"metadata": map[string]any{"name": "route", "namespace": "ns"},
		"spec":     map[string]any{"parentRefs": []any{map[string]any{"name": "missing", "port": 443}}, "rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": 80}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 {
		t.Fatalf("paths=%v, want conservative possible exposure", paths)
	}
}
