package opaprocessor

import "testing"

func TestSkipNamespace_ClusterScopedResourcesMustNotBeFilteredByIncludeNamespaces(t *testing.T) {
	tests := []struct {
		name              string
		includeNamespaces []string
		excludeNamespaces []string
		resourceNS        string
		wantSkip          bool
		why               string
	}{
		{
			name:              "cluster-scoped resource with include-namespaces set MUST be evaluated",
			includeNamespaces: []string{"production"},
			resourceNS:        "",
			wantSkip:          false,
			why:               "C-0035, C-0036, C-0262 all read cluster-scoped input; dropping them yields a green scan on a misconfigured cluster",
		},
		{
			name:              "cluster-scoped resource with exclude-namespaces set MUST be evaluated",
			excludeNamespaces: []string{"kube-system"},
			resourceNS:        "",
			wantSkip:          false,
			why:               "exclude-namespaces filters namespaced workloads only; cluster-scoped objects have no namespace to match against",
		},
		{
			name:              "namespaced resource in included namespace is kept (control case)",
			includeNamespaces: []string{"production"},
			resourceNS:        "production",
			wantSkip:          false,
			why:               "sanity: namespaced resources in the include list must still be evaluated",
		},
		{
			name:              "namespaced resource outside include list is correctly skipped (control case)",
			includeNamespaces: []string{"production"},
			resourceNS:        "staging",
			wantSkip:          true,
			why:               "sanity: the include filter must still apply to genuinely namespaced resources",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opap := &OPAProcessor{
				includeNamespaces: tc.includeNamespaces,
				excludeNamespaces: tc.excludeNamespaces,
			}
			got := opap.skipNamespace(tc.resourceNS)
			if got != tc.wantSkip {
				t.Errorf(
					"skipNamespace(ns=%q) with include=%v exclude=%v = %v; want %v\n  reason: %s",
					tc.resourceNS, tc.includeNamespaces, tc.excludeNamespaces,
					got, tc.wantSkip, tc.why,
				)
			}
		})
	}
}

func TestSkipNamespace_ClusterScopedKindMatrix(t *testing.T) {
	opap := &OPAProcessor{
		includeNamespaces: []string{"app-prod"},
	}
	clusterScopedKinds := []struct {
		kind            string
		exampleControls string
	}{
		{"ClusterRole", "C-0015, C-0035, C-0185"},
		{"ClusterRoleBinding", "C-0035, C-0262"},
		{"ValidatingWebhookConfiguration", "C-0036"},
		{"MutatingWebhookConfiguration", "C-0036"},
		{"Node", "C-0066, C-0088"},
		{"PersistentVolume", "C-0257"},
		{"StorageClass", "C-0257"},
		{"CustomResourceDefinition", "framework-wide"},
		{"APIService", "framework-wide"},
	}
	for _, k := range clusterScopedKinds {
		if opap.skipNamespace("") {
			t.Errorf(
				"skipNamespace returned true for cluster-scoped kind %q under --include-namespaces=app-prod: silently drops input for controls %s",
				k.kind, k.exampleControls,
			)
		}
	}
}
