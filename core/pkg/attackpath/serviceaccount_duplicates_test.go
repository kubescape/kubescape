package attackpath

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

func TestResolveServiceAccountBindings_DuplicateWorkloads(t *testing.T) {
	for _, tc := range []struct {
		name, otherSA    string
		otherAutomount   *bool
		skipped, unknown bool
	}{
		{name: "equivalent", otherSA: "one", otherAutomount: automountBoolPtr(true)},
		{name: "identity conflict", otherSA: "two", otherAutomount: automountBoolPtr(true), skipped: true},
		{name: "token conflict", otherSA: "one", otherAutomount: automountBoolPtr(false), unknown: true},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/forward", true: "/reverse"}[reverse], func(t *testing.T) {
				first := workloadWithSA("prod", "api", "one", automountBoolPtr(true), nil)
				other := workloadWithSA("prod", "api", tc.otherSA, tc.otherAutomount, nil)
				if reverse {
					first, other = other, first
				}
				resources := map[string]workloadinterface.IMetadata{"a.yaml": first, "b.yaml": other, "c.yaml": first}
				results := ResolveServiceAccountBindings(resources, nil)
				if len(results) != 1 {
					t.Fatalf("expected coalesced binding, got %+v", results)
				}
				r := results[0]
				if r.Skipped != tc.skipped || r.TokenUnknown != tc.unknown {
					t.Fatalf("got %+v", r)
				}
				if tc.skipped {
					if r.ServiceAccountName != "" || r.SkipReason == "" || r.TokenMounted {
						t.Fatalf("identity conflict must be skipped: %+v", r)
					}
				} else if r.ServiceAccountName != "one" || r.TokenMounted == tc.unknown {
					t.Fatalf("got %+v", r)
				}
			})
		}
	}
}
