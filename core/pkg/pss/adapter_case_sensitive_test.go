package pss

import "testing"

// Kubernetes matches JSON field names case-sensitively, so a key that differs
// from an API field only in case is an unknown field, not that field.
func TestExtractPodSpec_FieldNamesAreCaseSensitive(t *testing.T) {
	pod := func(spec map[string]any) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "p"}, "spec": spec}
	}
	// restricted returns a container security context that satisfies every
	// Restricted check except runAsNonRoot, plus the given extra fields.
	restricted := func(extra map[string]any) []any {
		securityContext := map[string]any{
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
			"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
		}
		for k, v := range extra {
			securityContext[k] = v
		}
		return []any{map[string]any{"name": "app", "image": "nginx", "securityContext": securityContext}}
	}

	tests := []struct {
		name          string
		spec          map[string]any
		level         Level
		check         string
		wantViolation bool
	}{
		{
			name:          "correctly cased runAsNonRoot is honoured",
			spec:          map[string]any{"containers": restricted(map[string]any{"runAsNonRoot": true})},
			level:         Restricted,
			check:         "RunAsNonRoot",
			wantViolation: false,
		},
		{
			name:          "missing runAsNonRoot is a violation",
			spec:          map[string]any{"containers": restricted(nil)},
			level:         Restricted,
			check:         "RunAsNonRoot",
			wantViolation: true,
		},
		{
			name:          "mis-cased runAsNonRoot is not decoded",
			spec:          map[string]any{"containers": restricted(map[string]any{"runasNonRoot": true})},
			level:         Restricted,
			check:         "RunAsNonRoot",
			wantViolation: true,
		},
		{
			name:          "mis-cased duplicate does not override hostNetwork",
			spec:          map[string]any{"hostNetwork": true, "hostnetwork": false, "containers": restricted(map[string]any{"runAsNonRoot": true})},
			level:         Baseline,
			check:         "HostNetwork",
			wantViolation: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations, err := EvaluateUnstructured("Pod", pod(tc.spec), tc.level)
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, v := range violations {
				if v.Check == tc.check {
					got = true
				}
			}
			if got != tc.wantViolation {
				t.Errorf("%s violation at %s = %v, want %v; violations: %+v", tc.check, tc.level, got, tc.wantViolation, violations)
			}
		})
	}
}
