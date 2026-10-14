package exposure

import corev1 "k8s.io/api/core/v1"

func gatewayBackendPortMatches(backend backendRef, svc *corev1.Service) bool {
	var port int32
	if backend.Port != nil {
		port = *backend.Port
	}
	return serviceBackendPortMatches(svc, "", port)
}

// serviceBackendPortMatches resolves HTTP backend references against the
// Service's public ports. Container targetPorts and nodePorts are not valid
// substitutes. A snapshot without Service port data retains the existing
// conservative possible-exposure result rather than inventing a denial.
func serviceBackendPortMatches(svc *corev1.Service, name string, number int32) bool {
	if svc == nil || len(svc.Spec.Ports) == 0 {
		return true
	}
	if name == "" && (number < 1 || number > 65535) {
		return false
	}
	for _, port := range svc.Spec.Ports {
		if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
			continue
		}
		if name != "" {
			if port.Name == name {
				return true
			}
		} else if port.Port == number {
			return true
		}
	}
	return false
}
