package exposure

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBackendMirrorKeepsParentServiceConstraints(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, tc := range []struct {
			name          string
			parentPresent bool
			parentPorts   []corev1.ServicePort
			want          bool
		}{
			{name: "wrong parent port", parentPresent: true, parentPorts: []corev1.ServicePort{{Port: 90}}},
			{name: "valid parent port", parentPresent: true, parentPorts: []corev1.ServicePort{{Port: 80}}, want: true},
			{name: "wrong parent protocol", parentPresent: true, parentPorts: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolUDP}}},
			{name: "targetPort is not service port", parentPresent: true, parentPorts: []corev1.ServicePort{{Port: 90, TargetPort: intstr.FromInt32(80)}}},
			{name: "parent not collected", want: true},
			{name: "parent ports not collected", parentPresent: true, want: true},
		} {
			for _, onBackend := range []bool{false, true} {
				t.Run(kind+"/"+tc.name+map[bool]string{false: "/rule", true: "/backend"}[onBackend], func(t *testing.T) {
					route := mirrorRoute(t, kind, mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), onBackend, 1)
					shadow := svc("app", "shadow", corev1.ServiceTypeClusterIP)
					shadow.Spec.Ports = []corev1.ServicePort{{Port: 80}}
					services := []corev1.Service{shadow}
					if tc.parentPresent {
						primary := svc("app", "primary", corev1.ServiceTypeClusterIP)
						primary.Spec.Ports = tc.parentPorts
						services = append(services, primary)
					}
					idx := NewIndex(services, nil, []gatewayRoute{route}, nil, nil)
					paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
					require.False(t, unclear)
					require.Equal(t, tc.want || !onBackend, len(paths) > 0, "only backend-scoped filters depend on forwarding to primary")
				})
			}
		}
	}
}

func TestCrossNamespaceMirrorKeepsParentServiceConstraints(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, port := range []int32{80, 90} {
			route := mirrorRoute(t, kind, mirrorFilter(map[string]any{"name": "shadow", "namespace": "other", "port": 80}, nil), true, 1)
			primary := svc("app", "primary", corev1.ServiceTypeClusterIP)
			primary.Spec.Ports = []corev1.ServicePort{{Port: port}}
			shadow := svc("other", "shadow", corev1.ServiceTypeClusterIP)
			shadow.Spec.Ports = []corev1.ServicePort{{Port: 80}}
			idx := NewIndex([]corev1.Service{primary, shadow}, nil, []gatewayRoute{route}, nil, nil)
			paths, unclear := idx.ServiceExposure(ref("other", "shadow"))
			require.Empty(t, paths)
			require.Equal(t, port == 80, unclear, "an impossible parent cannot create a possible cross-namespace mirror path")
		}
	}
}

func TestBackendMirrorResolvesParentInItsOwnNamespace(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, parentPort := range []int32{80, 90} {
			route := mirrorRoute(t, kind, mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), true, 1)
			parentNamespace := "backends"
			for i := range route.Rules[0].BackendRefs {
				b := &route.Rules[0].BackendRefs[i]
				if b.Parent != nil {
					b.Parent.Namespace = &parentNamespace
				}
			}
			primary := svc("backends", "primary", corev1.ServiceTypeClusterIP)
			primary.Spec.Ports = []corev1.ServicePort{{Port: parentPort}}
			decoy := svc("app", "primary", corev1.ServiceTypeClusterIP)
			decoy.Spec.Ports = []corev1.ServicePort{{Port: 90}}
			idx := NewIndex([]corev1.Service{primary, decoy, svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, nil, nil)
			paths, _ := idx.ServiceExposure(ref("app", "shadow"))
			require.Equal(t, parentPort == 80, len(paths) > 0)
		}
	}
}

func TestBackendMirrorWithAnotherValidOriginRemainsExposed(t *testing.T) {
	route := mirrorRoute(t, "HTTPRoute", mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), true, 1)
	second := route.Rules[0].BackendRefs[1]
	parent := *second.Parent
	parent.Name = "healthy"
	second.Parent = &parent
	route.Rules[0].BackendRefs = append(route.Rules[0].BackendRefs, second)
	primary := svc("app", "primary", corev1.ServiceTypeClusterIP)
	primary.Spec.Ports = []corev1.ServicePort{{Port: 90}}
	healthy := svc("app", "healthy", corev1.ServiceTypeClusterIP)
	healthy.Spec.Ports = []corev1.ServicePort{{Port: 80}}
	idx := NewIndex([]corev1.Service{primary, healthy, svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, nil, nil)
	paths, _ := idx.ServiceExposure(ref("app", "shadow"))
	require.Len(t, paths, 1, "an invalid origin must not suppress another valid mirror to the same service")
}
