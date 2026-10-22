package attackpath

import corev1 "k8s.io/api/core/v1"

// ServiceAccountAutomountIndex builds the "namespace/name" → *bool map
// that ResolveServiceAccountBindings needs from the ServiceAccounts the
// RBAC adapter already collected. A ServiceAccount with no
// automountServiceAccountToken field maps to a nil pointer, which
// ResolveServiceAccountBindings treats as the Kubernetes default (true).
// Conflicting duplicate accounts are omitted so their token access remains
// unknown. An unset field and explicit true are equivalent.
func ServiceAccountAutomountIndex(sas []corev1.ServiceAccount) map[string]*bool {
	out := make(map[string]*bool, len(sas))
	ambiguous := make(map[string]bool)
	for i := range sas {
		sa := &sas[i]
		key := sa.Namespace + "/" + sa.Name
		if ambiguous[key] {
			continue
		}
		if previous, exists := out[key]; exists {
			previousEnabled := previous == nil || *previous
			currentEnabled := sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken
			if previousEnabled != currentEnabled {
				delete(out, key)
				ambiguous[key] = true
			}
			continue
		}
		// A collected object may be reused or modified after indexing. Keep
		// its value, not its pointer, so the snapshot cannot change silently.
		var snapshot *bool
		if sa.AutomountServiceAccountToken != nil {
			value := *sa.AutomountServiceAccountToken
			snapshot = &value
		}
		out[key] = snapshot
	}
	return out
}
