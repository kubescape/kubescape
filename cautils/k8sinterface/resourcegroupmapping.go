package k8sinterface

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const ValueNotFound = -1

// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#-strong-api-groups-strong-
var ResourceGroupMapping = map[string]string{
	"services":                        "/v1",
	"pods":                            "/v1",
	"replicationcontrollers":          "/v1",
	"podtemplates":                    "/v1",
	"namespaces":                      "/v1",
	"nodes":                           "/v1",
	"configmaps":                      "/v1",
	"secrets":                         "/v1",
	"serviceaccounts":                 "/v1",
	"persistentvolumeclaims":          "/v1",
	"limitranges":                     "/v1",
	"resourcequotas":                  "/v1",
	"daemonsets":                      "apps/v1",
	"deployments":                     "apps/v1",
	"replicasets":                     "apps/v1",
	"statefulsets":                    "apps/v1",
	"controllerrevisions":             "apps/v1",
	"jobs":                            "batch/v1",
	"cronjobs":                        "batch/v1beta1",
	"horizontalpodautoscalers":        "autoscaling/v1",
	"ingresses":                       "extensions/v1beta1",
	"networkpolicies":                 "networking.k8s.io/v1",
	"clusterroles":                    "rbac.authorization.k8s.io/v1",
	"clusterrolebindings":             "rbac.authorization.k8s.io/v1",
	"roles":                           "rbac.authorization.k8s.io/v1",
	"rolebindings":                    "rbac.authorization.k8s.io/v1",
	"mutatingwebhookconfigurations":   "admissionregistration.k8s.io/v1",
	"validatingwebhookconfigurations": "admissionregistration.k8s.io/v1",
}

var GroupsClusterScope = []string{}
var ResourceClusterScope = []string{"nodes", "namespaces", "clusterroles", "clusterrolebindings"}

func GetGroupVersionResource(resource string) (schema.GroupVersionResource, error) {
	resource = updateResourceKind(resource)
	if r, ok := ResourceGroupMapping[resource]; ok {
		gv := strings.Split(r, "/")
		return schema.GroupVersionResource{Group: gv[0], Version: gv[1], Resource: resource}, nil
	}
	return schema.GroupVersionResource{}, fmt.Errorf("resource '%s' not found in resourceMap", resource)
}

func IsNamespaceScope(apiGroup, resource string) bool {
	return StringInSlice(GroupsClusterScope, apiGroup) == ValueNotFound &&
		StringInSlice(ResourceClusterScope, resource) == ValueNotFound
}

func StringInSlice(strSlice []string, str string) int {
	for i := range strSlice {
		if strSlice[i] == str {
			return i
		}
	}
	return ValueNotFound
}

func JoinResourceTriplets(group, version, resource string) string {
	return fmt.Sprintf("%s/%s/%s", group, version, resource)
}
func GetResourceTriplets(group, version, resource string) []string {
	resourceTriplets := []string{}
	if resource == "" {
		// load full map
		for k, v := range ResourceGroupMapping {
			g := strings.Split(v, "/")
			resourceTriplets = append(resourceTriplets, JoinResourceTriplets(g[0], g[1], k))
		}
	} else if version == "" {
		// load by resource
		if v, ok := ResourceGroupMapping[resource]; ok {
			g := strings.Split(v, "/")
			if group == "" {
				group = g[0]
			}
			resourceTriplets = append(resourceTriplets, JoinResourceTriplets(group, g[1], resource))
		} else {
			glog.Errorf("Resource '%s' unknown", resource)
		}
	} else if group == "" {
		// load by resource and version
		if v, ok := ResourceGroupMapping[resource]; ok {
			g := strings.Split(v, "/")
			resourceTriplets = append(resourceTriplets, JoinResourceTriplets(g[0], version, resource))
		} else {
			glog.Errorf("Resource '%s' unknown", resource)
		}
	} else {
		resourceTriplets = append(resourceTriplets, JoinResourceTriplets(group, version, resource))
	}
	return resourceTriplets
}
func ResourceGroupToString(group, version, resource string) []string {
	if group == "*" {
		group = ""
	}
	if version == "*" {
		version = ""
	}
	if resource == "*" {
		resource = ""
	}
	resource = updateResourceKind(resource)
	return GetResourceTriplets(group, version, resource)
}

func StringToResourceGroup(str string) (string, string, string) {
	splitted := strings.Split(str, "/")
	for i := range splitted {
		if splitted[i] == "*" {
			splitted[i] = ""
		}
	}
	return splitted[0], splitted[1], splitted[2]
}

func updateResourceKind(resource string) string {
	resource = strings.ToLower(resource)

	if resource != "" && !strings.HasSuffix(resource, "s") {
		if strings.HasSuffix(resource, "y") {
			return fmt.Sprintf("%sies", strings.TrimSuffix(resource, "y")) // e.g. NetworkPolicy -> networkpolicies
		} else {
			return fmt.Sprintf("%ss", resource) // add 's' at the end of a resource
		}
	}
	return resource

}
