// Package namespaceselector matches namespace labels without guessing labels
// absent from a scan. Kubernetes supplies the immutable namespace-name label,
// even when it is omitted from a Namespace manifest or the object was not listed.
package namespaceselector

import (
	"maps"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Matches reports whether selector matches a namespace and whether the answer
// is conclusive. With a collected namespace, ordinary missing labels are known
// to be absent. Without one, only the automatic name label can be evaluated:
// a failed name requirement rejects the whole conjunction, while an unresolved
// custom-label requirement keeps a possible match unknown.
//
// namespace is authoritative for kubernetes.io/metadata.name, which Kubernetes
// has supplied as an immutable label since v1.22. Input maps are never modified.
func Matches(selector labels.Selector, namespace string, namespaceLabels map[string]string, collected bool) (matched, determinable bool) {
	requirements, selectable := selector.Requirements()
	if !selectable {
		return false, true
	}
	known := maps.Clone(namespaceLabels)
	if known == nil {
		known = make(map[string]string)
	}
	if namespace != "" {
		known[corev1.LabelMetadataName] = namespace
	}
	if collected {
		return selector.Matches(labels.Set(known)), true
	}

	unresolved := false
	for _, requirement := range requirements {
		if requirement.Key() != corev1.LabelMetadataName || namespace == "" {
			unresolved = true
			continue
		}
		if !requirement.Matches(labels.Set(known)) {
			return false, true
		}
	}
	if unresolved {
		return false, false
	}
	return true, true
}
