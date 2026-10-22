package attackpath

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestServiceAccountSnapshotConflictsStayUnknown(t *testing.T) {
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{
		saWith("shop", "default", boolPtr(true)), saWith("shop", "default", boolPtr(false)),
	})
	got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), idx)
	require.True(t, got.Resolved)
	require.Equal(t, TokenUnknown, got.Token)
}

func TestServiceAccountSnapshotAllDuplicateOrders(t *testing.T) {
	values := []struct {
		name  string
		value *bool
	}{
		{"unset", nil},
		{"enabled", boolPtr(true)},
		{"disabled", boolPtr(false)},
	}
	for _, first := range values {
		for _, second := range values {
			for _, third := range values {
				t.Run(first.name+"/"+second.name+"/"+third.name, func(t *testing.T) {
					sas := []corev1.ServiceAccount{
						saWith("shop", "default", first.value),
						saWith("shop", "default", second.value),
						saWith("shop", "default", third.value),
					}
					enabled := func(v *bool) bool { return v == nil || *v }
					want := TokenMounted
					if !enabled(first.value) {
						want = TokenNotMounted
					}
					if enabled(first.value) != enabled(second.value) || enabled(first.value) != enabled(third.value) {
						want = TokenUnknown
					}
					idx := NewServiceAccountIndex(sas)
					got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), idx)
					require.True(t, got.Resolved)
					require.Equal(t, "default", got.Name)
					require.Equal(t, want, got.Token)
					if want == TokenUnknown {
						require.NotEmpty(t, got.TokenReason)
					}
				})
			}
		}
	}
}

func snapshotWorkload(kind string, spec map[string]any) (vulnexposure.Workload, map[string]any) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata":   map[string]any{"namespace": "shop", "name": "web"},
	}
	if kind == "Pod" {
		obj["apiVersion"] = "v1"
	}
	if kind == "Job" || kind == "CronJob" {
		obj["apiVersion"] = "batch/v1"
	}
	// The resolver reads the same paths as the scanner's workload adapter.
	_ = unstructured.SetNestedMap(obj, spec, workloadinterface.PodSpec(kind)...)
	return vulnexposure.Workload{Namespace: "shop", Kind: kind, Name: "web"}, obj
}

func TestServiceAccountSnapshotPodSettingsOverrideConflict(t *testing.T) {
	for _, kind := range []string{"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"} {
		for _, enabled := range []bool{false, true} {
			t.Run(kind+"/"+snapshotTokenStateName(enabled), func(t *testing.T) {
				idx := NewServiceAccountIndex([]corev1.ServiceAccount{
					saWith("shop", "worker", boolPtr(false)),
					saWith("shop", "worker", boolPtr(true)),
				})
				workload, obj := snapshotWorkload(kind, map[string]any{
					"serviceAccountName":           "worker",
					"automountServiceAccountToken": enabled,
					"containers":                   []any{map[string]any{"name": "app", "image": "fixture"}},
				})
				got := ResolveServiceAccount(workload, obj, idx)
				require.True(t, got.Resolved)
				require.Equal(t, "worker", got.Name)
				require.Equal(t, OriginExplicit, got.Origin)
				want := TokenNotMounted
				if enabled {
					want = TokenMounted
				}
				require.Equal(t, want, got.Token)
			})
		}
	}
}

func snapshotTokenStateName(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func TestServiceAccountSnapshotConflictsDoNotSpread(t *testing.T) {
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{
		saWith("shop", "default", boolPtr(true)),
		saWith("shop", "default", boolPtr(false)),
		saWith("other", "default", boolPtr(true)),
		saWith("shop", "worker", boolPtr(false)),
	})
	for _, tc := range []struct {
		namespace, account string
		want               TokenState
	}{
		{"shop", "default", TokenUnknown},
		{"other", "default", TokenMounted},
		{"shop", "worker", TokenNotMounted},
		{"absent", "default", TokenUnknown},
	} {
		t.Run(tc.namespace+"/"+tc.account, func(t *testing.T) {
			w := vulnexposure.Workload{Namespace: tc.namespace, Kind: "Deployment", Name: "web"}
			got := ResolveServiceAccount(w, deployment(tc.namespace, "web", map[string]any{"serviceAccountName": tc.account}), idx)
			require.True(t, got.Resolved)
			require.Equal(t, tc.want, got.Token)
		})
	}
}

func TestServiceAccountSnapshotBatchAndSingleAgree(t *testing.T) {
	for _, values := range [][]*bool{
		{nil}, {boolPtr(false)}, {boolPtr(true)},
		{nil, boolPtr(true)}, {boolPtr(false), boolPtr(false)},
		{boolPtr(false), nil}, {nil, boolPtr(false), nil},
	} {
		var sas []corev1.ServiceAccount
		for _, v := range values {
			sas = append(sas, saWith("shop", "default", v))
		}
		obj := deployment("shop", "web", map[string]any{})
		single := ResolveServiceAccount(shopWeb, obj, NewServiceAccountIndex(sas))
		resources := map[string]workloadinterface.IMetadata{"workload": workloadinterface.NewWorkloadObj(obj)}
		batch := ResolveServiceAccountBindings(resources, ServiceAccountAutomountIndex(sas))
		require.Len(t, batch, 1)
		require.Equal(t, single.Token == TokenMounted, batch[0].TokenMounted)
		require.Equal(t, single.Token == TokenUnknown, batch[0].TokenUnknown)
		require.False(t, batch[0].Skipped)
		require.Equal(t, single.Name, batch[0].ServiceAccountName)
	}
}

func TestServiceAccountSnapshotProjectedProofWinsOverConflict(t *testing.T) {
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{
		saWith("shop", "default", boolPtr(false)),
		saWith("shop", "default", boolPtr(true)),
	})
	obj := deployment("shop", "web", map[string]any{
		"automountServiceAccountToken": false,
		"volumes":                      []any{tokenVolume("identity", "token")},
		"containers":                   []any{containerMounting(mount("identity", "/identity"))},
	})
	got := ResolveServiceAccount(shopWeb, obj, idx)
	require.True(t, got.Resolved)
	require.Equal(t, TokenMounted, got.Token)
	require.Empty(t, got.TokenReason)
}

func TestServiceAccountSnapshotBlockedInjectionStillKnown(t *testing.T) {
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{
		saWith("shop", "default", boolPtr(false)),
		saWith("shop", "default", boolPtr(true)),
	})
	obj := deployment("shop", "web", map[string]any{
		"containers": []any{containerMounting(mount("non-token", serviceAccountTokenMountPath))},
		"volumes":    []any{map[string]any{"name": "non-token", "emptyDir": map[string]any{}}},
	})
	got := ResolveServiceAccount(shopWeb, obj, idx)
	require.True(t, got.Resolved)
	require.Equal(t, TokenNotMounted, got.Token)
}

func TestServiceAccountSnapshotEachConstructorOwnsValues(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(snapshotTokenStateName(enabled), func(t *testing.T) {
			original := enabled
			sas := []corev1.ServiceAccount{saWith("shop", "default", &original)}
			idx := NewServiceAccountIndex(sas)
			batch := ServiceAccountAutomountIndex(sas)
			original = !enabled
			sas[0].Name = "renamed"
			sas[0].Namespace = "elsewhere"
			sas[0].AutomountServiceAccountToken = boolPtr(!enabled)
			stored, exists := idx.lookup("shop", "default")
			require.True(t, exists)
			require.NotNil(t, stored)
			require.Equal(t, enabled, *stored)
			require.Equal(t, enabled, *batch["shop/default"])
			_, exists = idx.lookup("elsewhere", "renamed")
			require.False(t, exists)
		})
	}
}

func TestServiceAccountSnapshotConstructorsAreIndependent(t *testing.T) {
	enabled := true
	sas := []corev1.ServiceAccount{saWith("shop", "default", &enabled)}
	first := ServiceAccountAutomountIndex(sas)
	second := ServiceAccountAutomountIndex(sas)
	index := NewServiceAccountIndex(sas)
	*first["shop/default"] = false
	require.True(t, enabled)
	require.True(t, *second["shop/default"])
	stored, exists := index.lookup("shop", "default")
	require.True(t, exists)
	require.True(t, *stored)
}

func TestServiceAccountSnapshotDoesNotMutateInput(t *testing.T) {
	sas := []corev1.ServiceAccount{
		saWith("shop", "default", nil),
		saWith("shop", "default", boolPtr(true)),
		saWith("shop", "default", boolPtr(false)),
	}
	before, err := json.Marshal(sas)
	require.NoError(t, err)
	NewServiceAccountIndex(sas)
	ServiceAccountAutomountIndex(sas)
	after, err := json.Marshal(sas)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Nil(t, sas[0].AutomountServiceAccountToken)
	require.True(t, *sas[1].AutomountServiceAccountToken)
	require.False(t, *sas[2].AutomountServiceAccountToken)
}

func TestServiceAccountSnapshotConcurrentReadersAndCallerMutation(t *testing.T) {
	enabled := true
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{saWith("shop", "default", &enabled)})
	states := make(chan TokenState, 80)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			enabled = i%2 == 0
		}
	}()
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), idx)
				states <- got.Token
			}
		}()
	}
	wg.Wait()
	close(states)
	for state := range states {
		require.Equal(t, TokenMounted, state)
	}
}

func TestServiceAccountSnapshotNilAndEmptyIndexes(t *testing.T) {
	for _, idx := range []*ServiceAccountIndex{nil, NewServiceAccountIndex(nil), NewServiceAccountIndex([]corev1.ServiceAccount{})} {
		got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), idx)
		require.True(t, got.Resolved)
		require.Equal(t, "default", got.Name)
		require.Equal(t, TokenUnknown, got.Token)
	}
}

func TestServiceAccountSnapshotConflictReachesCorrelationAsUnknown(t *testing.T) {
	sas := []corev1.ServiceAccount{
		saWith("shop", "default", boolPtr(true)),
		saWith("shop", "default", boolPtr(false)),
	}
	objects := map[vulnexposure.Workload]map[string]any{
		shopWeb: deployment("shop", "web", map[string]any{}),
	}
	identities, unresolved := ResolveWorkloadIdentities(objects, []vulnexposure.Workload{shopWeb}, NewServiceAccountIndex(sas))
	require.Empty(t, unresolved)
	require.Equal(t, TokenUnknown, identities[shopWeb].Token)
	idx := rbacgraph.NewIndex(nil,
		[]rbacv1.ClusterRole{clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))},
		nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("grant", "admin", saSubject("shop", "default"))},
		[]corev1.ServiceAccount{saObj("shop", "default")},
	)
	contexts := CorrelateIdentity(IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: shopWeb, Vulnerabilities: []VulnerabilityRef{critical("CVE-2026-1001")}}},
		Identities: identities,
		RBAC:       completeRBAC(idx),
	})
	require.Len(t, contexts, 1)
	require.Equal(t, IdentityAnalyzed, contexts[0].Status)
	require.Equal(t, TokenUnknown, contexts[0].Token)
	require.NotEmpty(t, contexts[0].TokenReason)
	require.Equal(t, "Critical", contexts[0].Vulnerabilities[0].Severity)
	require.NotNil(t, contexts[0].ServiceAccount)
	data, err := json.Marshal(contexts)
	require.NoError(t, err)
	var decoded []IdentityContext
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, TokenUnknown, decoded[0].Token)
	require.Equal(t, IdentityAnalyzed, decoded[0].Status)
}

func TestServiceAccountSnapshotMetadataDoesNotCreateConflict(t *testing.T) {
	first := saWith("shop", "default", boolPtr(true))
	second := saWith("shop", "default", nil)
	first.Labels = map[string]string{"managed-by": "one"}
	second.Labels = map[string]string{"managed-by": "two"}
	first.ResourceVersion = "100"
	second.ResourceVersion = "101"
	for _, accounts := range [][]corev1.ServiceAccount{{first, second}, {second, first}} {
		got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), NewServiceAccountIndex(accounts))
		require.True(t, got.Resolved)
		require.Equal(t, TokenMounted, got.Token)
	}
}

func TestServiceAccountSnapshotUsesExactAccountIdentity(t *testing.T) {
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{
		saWith("shop", "default", boolPtr(false)),
		saWith("shopping", "default", boolPtr(true)),
		saWith("shop", "default-other", boolPtr(true)),
	})
	for _, tc := range []struct {
		namespace, name string
		want            TokenState
	}{
		{"shop", "default", TokenNotMounted},
		{"shopping", "default", TokenMounted},
		{"shop", "default-other", TokenMounted},
		{"shop", "missing", TokenUnknown},
	} {
		w := vulnexposure.Workload{Namespace: tc.namespace, Kind: "Deployment", Name: "web"}
		obj := deployment(tc.namespace, "web", map[string]any{"serviceAccountName": tc.name})
		got := ResolveServiceAccount(w, obj, idx)
		require.True(t, got.Resolved)
		require.Equal(t, tc.name, got.Name)
		require.Equal(t, tc.want, got.Token)
	}
}

func TestServiceAccountSnapshotNilDefaultDoesNotBecomeCallerAssignment(t *testing.T) {
	sas := []corev1.ServiceAccount{saWith("shop", "default", nil)}
	idx := NewServiceAccountIndex(sas)
	batch := ServiceAccountAutomountIndex(sas)
	sas[0].AutomountServiceAccountToken = boolPtr(false)
	stored, exists := idx.lookup("shop", "default")
	require.True(t, exists)
	require.Nil(t, stored)
	value, exists := batch["shop/default"]
	require.True(t, exists)
	require.Nil(t, value)
	got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), idx)
	require.Equal(t, TokenMounted, got.Token)
}

func TestServiceAccountSnapshotRefreshRequiresNewIndex(t *testing.T) {
	enabled := false
	sas := []corev1.ServiceAccount{saWith("shop", "default", &enabled)}
	old := NewServiceAccountIndex(sas)
	enabled = true
	fresh := NewServiceAccountIndex(sas)
	object := deployment("shop", "web", map[string]any{})
	oldResolution := ResolveServiceAccount(shopWeb, object, old)
	freshResolution := ResolveServiceAccount(shopWeb, object, fresh)
	require.Equal(t, TokenNotMounted, oldResolution.Token)
	require.Equal(t, TokenMounted, freshResolution.Token)
	require.True(t, oldResolution.Resolved)
	require.True(t, freshResolution.Resolved)
}

func TestServiceAccountSnapshotOwnsAutomountValue(t *testing.T) {
	enabled := true
	idx := NewServiceAccountIndex([]corev1.ServiceAccount{saWith("shop", "default", &enabled)})
	enabled = false
	got := ResolveServiceAccount(shopWeb, deployment("shop", "web", map[string]any{}), idx)
	require.Equal(t, TokenMounted, got.Token)
}
