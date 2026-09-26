package attackpath

import corev1 "k8s.io/api/core/v1"

// ServiceAccountAutomountIndex builds the "namespace/name" → *bool map
// that ResolveServiceAccountBindings needs from the ServiceAccounts the
// RBAC adapter already collected. A ServiceAccount with no
// automountServiceAccountToken field maps to a nil pointer, which
// ResolveServiceAccountBindings treats as the Kubernetes default (true).
func ServiceAccountAutomountIndex(sas []corev1.ServiceAccount) map[string]*bool {
    out := make(map[string]*bool, len(sas))
    for i := range sas {
        sa := &sas[i]
        key := sa.Namespace + "/" + sa.Name
        out[key] = sa.AutomountServiceAccountToken
    }
    return out
}
