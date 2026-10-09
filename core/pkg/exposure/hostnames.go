package exposure

import "strings"

// listenerRouteHostnames implements Gateway API hostname intersection.
// Wildcards match a nonempty DNS suffix, including multiple labels, but
// not the suffix's apex. Report the narrower hostname when one side is a
// wildcard: a route for *.example.com on api.example.com does not expose
// every host in example.com through that listener.
func listenerRouteHostnames(listenerHost string, routeHosts []string) []string {
	if len(routeHosts) == 0 {
		return []string{listenerHost}
	}
	var hosts []string
	for _, routeHost := range routeHosts {
		switch {
		case listenerHost == "", listenerHost == routeHost:
			hosts = append(hosts, routeHost)
		case wildcardHostnameMatches(routeHost, listenerHost):
			hosts = append(hosts, listenerHost)
		case wildcardHostnameMatches(listenerHost, routeHost):
			hosts = append(hosts, routeHost)
		}
	}
	return hosts
}

func wildcardHostnameMatches(pattern, hostname string) bool {
	return strings.HasPrefix(pattern, "*.") && strings.HasSuffix(hostname, pattern[1:])
}
