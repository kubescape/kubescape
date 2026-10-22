package attackpath

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestServiceAccountAutomountIndex_EquivalentDuplicates(t *testing.T) {
	for _, tt := range []struct {
		name    string
		values  []*bool
		enabled bool
	}{
		{name: "unset then true", values: []*bool{nil, automountBoolPtr(true)}, enabled: true},
		{name: "true then unset", values: []*bool{automountBoolPtr(true), nil}, enabled: true},
		{name: "both unset", values: []*bool{nil, nil}, enabled: true},
		{name: "both true", values: []*bool{automountBoolPtr(true), automountBoolPtr(true)}, enabled: true},
		{name: "both false", values: []*bool{automountBoolPtr(false), automountBoolPtr(false)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var sas []corev1.ServiceAccount
			for _, value := range tt.values {
				sas = append(sas, automountSAObj("prod", "app", value))
			}
			idx := ServiceAccountAutomountIndex(sas)
			value, exists := idx["prod/app"]
			if !exists || (value == nil || *value) != tt.enabled {
				t.Fatalf("expected present account with effective automount=%v, got %+v", tt.enabled, idx)
			}
		})
	}
}

func TestServiceAccountAutomountIndex_ConflictingDuplicatesRemainUnknown(t *testing.T) {
	values := []struct {
		name  string
		value *bool
	}{
		{name: "unset"},
		{name: "true", value: automountBoolPtr(true)},
		{name: "false", value: automountBoolPtr(false)},
	}
	for _, first := range values {
		for _, second := range values {
			if (first.value == nil || *first.value) == (second.value == nil || *second.value) {
				continue
			}
			for _, third := range values {
				t.Run(first.name+"/"+second.name+"/"+third.name, func(t *testing.T) {
					sas := []corev1.ServiceAccount{
						automountSAObj("prod", "app", first.value),
						automountSAObj("prod", "app", second.value),
						automountSAObj("prod", "app", third.value),
						automountSAObj("staging", "app", nil),
						automountSAObj("prod", "other", nil),
					}
					idx := ServiceAccountAutomountIndex(sas)
					if _, exists := idx["prod/app"]; exists {
						t.Fatal("conflicting account must remain absent after a third duplicate")
					}
					if len(idx) != 2 {
						t.Fatalf("expected unrelated accounts to be retained, got %+v", idx)
					}
					workload := workloadWithSA("prod", "web", "app", nil, nil)
					binding := resultFor(t, ResolveServiceAccountBindings(makeResources(workload), idx), "web")
					if !binding.TokenUnknown || binding.TokenMounted || binding.Skipped {
						t.Errorf("expected resolved identity with unknown token access, got %+v", binding)
					}
				})
			}
		}
	}
}
