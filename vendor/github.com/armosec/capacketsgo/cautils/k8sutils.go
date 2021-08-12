package cautils

import (
	"fmt"
	"hash/fnv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var NamespacesListToIgnore = make([]string, 0)
var KubeNamespaces = []string{metav1.NamespaceSystem, metav1.NamespacePublic}

// NamespacesListToIgnore namespaces to ignore if a pod
func InitNamespacesListToIgnore(caNamespace string) {
	if len(NamespacesListToIgnore) > 0 {
		return
	}
	NamespacesListToIgnore = append(NamespacesListToIgnore, KubeNamespaces...)
	NamespacesListToIgnore = append(NamespacesListToIgnore, caNamespace)
}

func IfIgnoreNamespace(ns string) bool {
	for i := range NamespacesListToIgnore {
		if NamespacesListToIgnore[i] == ns {
			return true
		}
	}
	return false
}

func IfKubeNamespace(ns string) bool {
	for i := range KubeNamespaces {
		if NamespacesListToIgnore[i] == ns {
			return true
		}
	}
	return false
}

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprintf("%d", h.Sum32())
}
func GenarateConfigMapName(wlid string) string {
	name := strings.ToLower(fmt.Sprintf("ca-%s-%s-%s", GetNamespaceFromWlid(wlid), GetKindFromWlid(wlid), GetNameFromWlid(wlid)))
	if len(name) >= 63 {
		name = hash(name)
	}
	return name
}
