package scancache

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

func TestVerdictIsolation_PutDoesNotBorrowCallerRules(t *testing.T) {
	store, err := Load(t.TempDir(), "version")
	require.NoError(t, err)
	verdict := resourcesresults.ResourceAssociatedControl{ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule", Status: apis.StatusFailed}}}
	store.Put("control", "resource", "hash", verdict)
	verdict.ResourceAssociatedRules[0].Status = apis.StatusPassed
	got, ok := store.Get("control", "resource", "hash")
	require.True(t, ok)
	require.Equal(t, apis.StatusFailed, got.ResourceAssociatedRules[0].Status)
}

func isolationVerdict() resourcesresults.ResourceAssociatedControl {
	reason := "approved reason"
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	return resourcesresults.ResourceAssociatedControl{
		ControlID: "control", Name: "original control",
		Status: apis.StatusInfo{InnerStatus: apis.StatusFailed, InnerInfo: "original info"},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
			Name: "rule", Status: apis.StatusFailed,
			ControlConfigurations: map[string][]string{"input": {"original"}},
			RelatedResourcesIDs:   []string{"related-original"},
			Paths:                 []armotypes.PosturePaths{{FailedPath: "spec.original", FixPath: armotypes.FixPath{Path: "spec.fix", Value: "original"}}},
			Exception: []armotypes.PostureExceptionPolicy{{
				Reason: &reason, ExpirationDate: &expiry,
				Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
				ObjectSelector: &armotypes.LabelSelector{
					MatchLabels:      map[string]string{"team": "original"},
					MatchExpressions: []armotypes.LabelSelectorRequirement{{Key: "team", Values: []string{"original"}}},
				},
			}},
		}},
	}
}

func isolationStore(t *testing.T) *Store {
	t.Helper()
	store, err := Load(t.TempDir(), "version")
	require.NoError(t, err)
	return store
}

func isolationGet(t *testing.T, store *Store) resourcesresults.ResourceAssociatedControl {
	t.Helper()
	got, ok := store.Get("control", "resource", "hash")
	require.True(t, ok)
	return got
}

func TestVerdictIsolation_AllNestedInputsAreOwnedAfterPut(t *testing.T) {
	for _, mutate := range []struct {
		name string
		call func(*resourcesresults.ResourceAssociatedControl)
	}{
		{"rule", func(v *resourcesresults.ResourceAssociatedControl) { v.ResourceAssociatedRules[0].Name = "changed" }},
		{"configuration map", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].ControlConfigurations["other"] = []string{"changed"}
		}},
		{"configuration slice", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].ControlConfigurations["input"][0] = "changed"
		}},
		{"related resource", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].RelatedResourcesIDs[0] = "changed"
		}},
		{"evidence path", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].Paths[0].FailedPath = "changed"
		}},
		{"fix value", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].Paths[0].FixPath.Value = "changed"
		}},
		{"exception reason", func(v *resourcesresults.ResourceAssociatedControl) {
			*v.ResourceAssociatedRules[0].Exception[0].Reason = "changed"
		}},
		{"exception expiry", func(v *resourcesresults.ResourceAssociatedControl) {
			*v.ResourceAssociatedRules[0].Exception[0].ExpirationDate = time.Time{}
		}},
		{"exception action", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].Exception[0].Actions[0] = armotypes.Disable
		}},
		{"exception labels", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].Exception[0].ObjectSelector.MatchLabels["team"] = "changed"
		}},
		{"exception expressions", func(v *resourcesresults.ResourceAssociatedControl) {
			v.ResourceAssociatedRules[0].Exception[0].ObjectSelector.MatchExpressions[0].Values[0] = "changed"
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			store := isolationStore(t)
			verdict := isolationVerdict()
			store.Put("control", "resource", "hash", verdict)
			mutate.call(&verdict)
			require.Equal(t, isolationVerdict(), isolationGet(t, store))
			require.NoError(t, store.Flush())
			require.Equal(t, isolationVerdict(), isolationGet(t, store))
		})
	}
}

func TestVerdictIsolation_GetReturnsIndependentRuleStatus(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	first := isolationGet(t, store)
	first.ResourceAssociatedRules[0].Status = apis.StatusPassed
	first.ResourceAssociatedRules[0].SubStatus = apis.SubStatusException
	second := isolationGet(t, store)
	require.Equal(t, apis.StatusFailed, second.ResourceAssociatedRules[0].Status)
	require.Empty(t, second.ResourceAssociatedRules[0].SubStatus)
	require.Equal(t, isolationVerdict(), second)
}

func TestVerdictIsolation_GetDoesNotExposeNestedConfigurations(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	first := isolationGet(t, store)
	first.ResourceAssociatedRules[0].ControlConfigurations["input"][0] = "changed"
	delete(first.ResourceAssociatedRules[0].ControlConfigurations, "input")
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
}

func TestVerdictIsolation_GetDoesNotExposeExceptionSelectors(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	first := isolationGet(t, store)
	first.ResourceAssociatedRules[0].Exception[0].ObjectSelector.MatchExpressions[0].Values[0] = "changed"
	first.ResourceAssociatedRules[0].Exception[0].ObjectSelector.MatchLabels["team"] = "changed"
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
}

func TestVerdictIsolation_PendingPersistenceCannotBeChangedByGet(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	first := isolationGet(t, store)
	first.ResourceAssociatedRules[0].Status = apis.StatusPassed
	first.ResourceAssociatedRules[0].Paths[0].FailedPath = "changed"
	require.NoError(t, store.Flush())
	loaded, err := Load(filepath.Dir(store.path), "version")
	require.NoError(t, err)
	require.Equal(t, isolationVerdict(), isolationGet(t, loaded))
}

func TestVerdictIsolation_LoadedVerdictDoesNotExposePersistedTree(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	require.NoError(t, store.Flush())
	loaded, err := Load(filepath.Dir(store.path), "version")
	require.NoError(t, err)
	first := isolationGet(t, loaded)
	first.ResourceAssociatedRules[0].RelatedResourcesIDs[0] = "changed"
	*first.ResourceAssociatedRules[0].Exception[0].Reason = "changed"
	require.Equal(t, isolationVerdict(), isolationGet(t, loaded))
}

func TestVerdictIsolation_PutReplacementDoesNotBorrowNewInput(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "old-hash", isolationVerdict())
	replacement := isolationVerdict()
	replacement.ResourceAssociatedRules[0].Name = "new-rule"
	store.Put("control", "resource", "hash", replacement)
	replacement.ResourceAssociatedRules[0].Name = "changed"
	got := isolationGet(t, store)
	require.Equal(t, "new-rule", got.ResourceAssociatedRules[0].Name)
	_, ok := store.Get("control", "resource", "old-hash")
	require.False(t, ok)
}

func TestVerdictIsolation_SameInputCanPopulateIndependentEntries(t *testing.T) {
	store := isolationStore(t)
	verdict := isolationVerdict()
	store.Put("control", "resource", "hash", verdict)
	store.Put("control", "another", "hash", verdict)
	first := isolationGet(t, store)
	first.ResourceAssociatedRules[0].Name = "changed"
	other, ok := store.Get("control", "another", "hash")
	require.True(t, ok)
	require.Equal(t, isolationVerdict(), other)
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
}

func TestVerdictIsolation_ReturnedResultsCanBeMutatedConcurrently(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				got, ok := store.Get("control", "resource", "hash")
				if !ok {
					t.Error("unexpected cache miss")
					return
				}
				got.ResourceAssociatedRules[0].Status = apis.StatusPassed
				got.ResourceAssociatedRules[0].ControlConfigurations["input"][0] = "changed"
			}
		}()
	}
	wg.Wait()
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
}

func TestVerdictIsolation_FlushAndClientResultMutationDoNotRace(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	got := isolationGet(t, store)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			got.ResourceAssociatedRules[0].Paths[0].FixPath.Value = fmt.Sprint(i)
		}
	}()
	require.NoError(t, store.Flush())
	<-done
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
}

func TestVerdictIsolation_NilAndEmptyRuleSlicesStayDistinct(t *testing.T) {
	for _, rules := range [][]resourcesresults.ResourceAssociatedRule{nil, {}} {
		verdict := isolationVerdict()
		verdict.ResourceAssociatedRules = rules
		copied, err := cloneVerdict(verdict)
		require.NoError(t, err)
		require.Equal(t, verdict, copied)
		store := isolationStore(t)
		store.Put("control", "resource", "hash", verdict)
		require.Equal(t, verdict, isolationGet(t, store))
	}
}

func TestVerdictIsolation_EmptyNestedValuesStayDistinct(t *testing.T) {
	verdict := isolationVerdict()
	verdict.ResourceAssociatedRules[0].ControlConfigurations = map[string][]string{"nil": nil, "empty": {}}
	verdict.ResourceAssociatedRules[0].RelatedResourcesIDs = []string{}
	verdict.ResourceAssociatedRules[0].Paths = []armotypes.PosturePaths{}
	store := isolationStore(t)
	store.Put("control", "resource", "hash", verdict)
	require.Equal(t, verdict, isolationGet(t, store))
}

func TestVerdictIsolation_AbsentNestedPointersStayNil(t *testing.T) {
	verdict := isolationVerdict()
	verdict.ResourceAssociatedRules[0].Exception[0].Reason = nil
	verdict.ResourceAssociatedRules[0].Exception[0].ExpirationDate = nil
	verdict.ResourceAssociatedRules[0].Exception[0].ObjectSelector = nil
	store := isolationStore(t)
	store.Put("control", "resource", "hash", verdict)
	require.Equal(t, verdict, isolationGet(t, store))
}

func TestVerdictIsolation_ClonePreservesTimeAndTimezone(t *testing.T) {
	verdict := isolationVerdict()
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 123, time.FixedZone("fixture", 19800))
	verdict.ResourceAssociatedRules[0].Exception[0].ExpirationDate = &expiry
	copied, err := cloneVerdict(verdict)
	require.NoError(t, err)
	require.Equal(t, verdict, copied)
	require.NotSame(t, verdict.ResourceAssociatedRules[0].Exception[0].ExpirationDate, copied.ResourceAssociatedRules[0].Exception[0].ExpirationDate)
}

func TestVerdictIsolation_ControlValueFieldsArePreserved(t *testing.T) {
	store := isolationStore(t)
	verdict := isolationVerdict()
	store.Put("control", "resource", "hash", verdict)
	got := isolationGet(t, store)
	require.Equal(t, verdict.ControlID, got.ControlID)
	require.Equal(t, verdict.Name, got.Name)
	require.Equal(t, verdict.Status, got.Status)
	got.Status.InnerStatus = apis.StatusPassed
	got.Name = "changed"
	require.Equal(t, verdict, isolationGet(t, store))
}

func TestVerdictIsolation_JSONShapeDoesNotChange(t *testing.T) {
	verdict := isolationVerdict()
	before, err := json.Marshal(verdict)
	require.NoError(t, err)
	store := isolationStore(t)
	store.Put("control", "resource", "hash", verdict)
	after, err := json.Marshal(isolationGet(t, store))
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after))
}

func TestVerdictIsolation_EmptyHashStillDoesNotPopulateStore(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "", isolationVerdict())
	_, ok := store.Get("control", "resource", "")
	require.False(t, ok)
	require.Empty(t, store.pending)
	require.False(t, store.dirty)
}

func TestVerdictIsolation_MissCannotExposeAnotherEntry(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	for _, key := range []struct{ control, resource, hash string }{
		{"other", "resource", "hash"},
		{"control", "other", "hash"},
		{"control", "resource", "other"},
	} {
		got, ok := store.Get(key.control, key.resource, key.hash)
		require.False(t, ok)
		require.Empty(t, got.ResourceAssociatedRules)
	}
}

func TestVerdictIsolation_GetMutationDoesNotDirtyCleanStore(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	require.NoError(t, store.Flush())
	got := isolationGet(t, store)
	got.ResourceAssociatedRules[0].Status = apis.StatusPassed
	require.False(t, store.dirty)
	require.Empty(t, store.pending)
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
}

func TestVerdictIsolation_TwoLoadedStoresStayIndependent(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	require.NoError(t, store.Flush())
	other, err := Load(filepath.Dir(store.path), "version")
	require.NoError(t, err)
	first := isolationGet(t, other)
	first.ResourceAssociatedRules[0].Status = apis.StatusPassed
	require.Equal(t, isolationVerdict(), isolationGet(t, store))
	require.Equal(t, isolationVerdict(), isolationGet(t, other))
}

func TestVerdictIsolation_ActionRequiredStateSurvivesCopy(t *testing.T) {
	for _, action := range []apis.ScanningSubStatus{apis.SubStatusManualReview, apis.SubStatusRequiresReview, apis.SubStatusConfiguration} {
		t.Run(string(action), func(t *testing.T) {
			verdict := isolationVerdict()
			control := reporthandling.Control{}
			control.Attributes = map[string]interface{}{reporthandling.ActionRequiredAttribute: string(action)}
			verdict.SetStatus(control)
			store := isolationStore(t)
			store.Put("control", "resource", "hash", verdict)
			got := isolationGet(t, store)
			require.Equal(t, verdict, got, "including control's private actionRequired field")
			require.Equal(t, verdict.GetStatus(nil).Status(), got.GetStatus(nil).Status())
			require.Equal(t, verdict.GetSubStatus(), got.GetSubStatus())
		})
	}
}

func TestVerdictIsolation_OriginalMutationCannotChangeDiskGeneration(t *testing.T) {
	store := isolationStore(t)
	verdict := isolationVerdict()
	store.Put("control", "resource", "hash", verdict)
	verdict.ResourceAssociatedRules[0].Status = apis.StatusPassed
	*verdict.ResourceAssociatedRules[0].Exception[0].Reason = "changed"
	require.NoError(t, store.Flush())
	loaded, err := Load(filepath.Dir(store.path), "version")
	require.NoError(t, err)
	require.Equal(t, isolationVerdict(), isolationGet(t, loaded))
}

func TestVerdictIsolation_ChangingHashDoesNotReuseOldResultTree(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "old", isolationVerdict())
	old, ok := store.Get("control", "resource", "old")
	require.True(t, ok)
	updated := isolationVerdict()
	updated.ResourceAssociatedRules[0].Status = apis.StatusPassed
	store.Put("control", "resource", "hash", updated)
	old.ResourceAssociatedRules[0].Name = "old mutated"
	got := isolationGet(t, store)
	require.Equal(t, apis.StatusPassed, got.ResourceAssociatedRules[0].Status)
	require.Equal(t, "rule", got.ResourceAssociatedRules[0].Name)
}

func TestVerdictIsolation_AppendingRulesCannotOverwriteCachedBackingArray(t *testing.T) {
	store := isolationStore(t)
	rules := make([]resourcesresults.ResourceAssociatedRule, 1, 4)
	rules[0] = isolationVerdict().ResourceAssociatedRules[0]
	verdict := isolationVerdict()
	verdict.ResourceAssociatedRules = rules
	store.Put("control", "resource", "hash", verdict)
	verdict.ResourceAssociatedRules = append(verdict.ResourceAssociatedRules[:0], resourcesresults.ResourceAssociatedRule{Name: "replaced"})
	got := isolationGet(t, store)
	require.Len(t, got.ResourceAssociatedRules, 1)
	require.Equal(t, "rule", got.ResourceAssociatedRules[0].Name)
}

func TestVerdictIsolation_MultipleRulesRemainInOrder(t *testing.T) {
	verdict := isolationVerdict()
	second := resourcesresults.ResourceAssociatedRule{Name: "second", Status: apis.StatusPassed}
	verdict.ResourceAssociatedRules = append(verdict.ResourceAssociatedRules, second)
	store := isolationStore(t)
	store.Put("control", "resource", "hash", verdict)
	got := isolationGet(t, store)
	require.Equal(t, verdict, got)
	got.ResourceAssociatedRules[1].Name = "changed"
	require.Equal(t, "second", isolationGet(t, store).ResourceAssociatedRules[1].Name)
}

func TestVerdictIsolation_FlushMergesWithoutBorrowingOtherStoreResults(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir, "version")
	require.NoError(t, err)
	second, err := Load(dir, "version")
	require.NoError(t, err)
	first.Put("control", "resource", "hash", isolationVerdict())
	require.NoError(t, first.Flush())
	second.Put("another", "another", "hash", isolationVerdict())
	require.NoError(t, second.Flush())
	got := isolationGet(t, second)
	got.ResourceAssociatedRules[0].Name = "changed"
	loaded, err := Load(dir, "version")
	require.NoError(t, err)
	require.Equal(t, isolationVerdict(), isolationGet(t, loaded))
}

func TestVerdictIsolation_DifferentVersionsDoNotExposeOldEntries(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	require.NoError(t, store.Flush())
	other, err := Load(filepath.Dir(store.path), "new-version")
	require.NoError(t, err)
	_, ok := other.Get("control", "resource", "hash")
	require.False(t, ok)
	require.Empty(t, other.data)
}

func TestVerdictIsolation_EmptyRuleConfigurationRemainsWritable(t *testing.T) {
	verdict := isolationVerdict()
	verdict.ResourceAssociatedRules[0].ControlConfigurations = map[string][]string{}
	store := isolationStore(t)
	store.Put("control", "resource", "hash", verdict)
	got := isolationGet(t, store)
	got.ResourceAssociatedRules[0].ControlConfigurations["new"] = []string{"value"}
	require.Empty(t, isolationGet(t, store).ResourceAssociatedRules[0].ControlConfigurations)
}

func TestVerdictIsolation_ReaderCanRemoveItsOwnRulesWithoutChangingCache(t *testing.T) {
	store := isolationStore(t)
	store.Put("control", "resource", "hash", isolationVerdict())
	got := isolationGet(t, store)
	got.ResourceAssociatedRules = got.ResourceAssociatedRules[:0]
	require.Empty(t, got.ResourceAssociatedRules)
	require.Len(t, isolationGet(t, store).ResourceAssociatedRules, 1)
	require.NoError(t, store.Flush())
	require.Len(t, isolationGet(t, store).ResourceAssociatedRules, 1)
}

func TestVerdictIsolation_RuleConfigurationDoesNotShareCallerSliceCapacity(t *testing.T) {
	verdict := isolationVerdict()
	values := make([]string, 1, 4)
	values[0] = "original"
	verdict.ResourceAssociatedRules[0].ControlConfigurations["input"] = values
	store := isolationStore(t)
	store.Put("control", "resource", "hash", verdict)
	values = append(values[:0], "replaced")
	require.Equal(t, "replaced", values[0])
	require.Equal(t, []string{"original"}, isolationGet(t, store).ResourceAssociatedRules[0].ControlConfigurations["input"])
}
