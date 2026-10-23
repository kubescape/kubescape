package mcpserver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

// nameSelector lists only the objects with this name. Storage applies it
// server-side; items are still checked by name, since not every client does.
func nameSelector(name string) metav1.ListOptions {
	return metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String()}
}

// pickNamespace returns the namespace of the only object called name. Get
// tools use it when no namespace is given: container profiles and the scans
// of namespaced workloads are stored in the workload's own namespace, so the
// caller often does not know where to look.
func pickNamespace(kind, name string, objects []metav1.ObjectMeta) (string, *mcp.CallToolResult) {
	var namespaces []string
	for _, object := range objects {
		if object.Name == name {
			namespaces = append(namespaces, object.Namespace)
		}
	}
	sort.Strings(namespaces)
	switch len(namespaces) {
	case 0:
		return "", mcpToolError(ErrCodeResourceNotFound,
			fmt.Sprintf("no %s named %q in any namespace", kind, name),
			map[string]any{"name": name})
	case 1:
		return namespaces[0], nil
	default:
		return "", mcpToolError(ErrCodeAmbiguousResource,
			fmt.Sprintf("%s %q exists in namespaces %s; set namespace", kind, name, strings.Join(namespaces, ", ")),
			map[string]any{"name": name, "namespaces": namespaces})
	}
}
