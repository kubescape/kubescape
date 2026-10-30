package pss

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func listValidationPod(name string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "main", "image": "example.invalid/app:1",
			"securityContext": map[string]any{"privileged": true},
		}}},
	}
}

func listValidationJSON(t *testing.T, kind string, items ...any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": kind, "items": items,
	})
	require.NoError(t, err)
	return string(raw)
}

func TestListValidationRejectsMissingItemKind(t *testing.T) {
	for _, value := range []struct {
		name string
		set  bool
		kind any
	}{
		{name: "absent"},
		{name: "null", set: true},
		{name: "empty", set: true, kind: ""},
		{name: "number", set: true, kind: 42},
		{name: "boolean", set: true, kind: true},
		{name: "object", set: true, kind: map[string]any{"kind": "Pod"}},
		{name: "array", set: true, kind: []any{"Pod"}},
	} {
		t.Run(value.name, func(t *testing.T) {
			item := listValidationPod("unsafe")
			delete(item, "kind")
			if value.set {
				item["kind"] = value.kind
			}
			input := listValidationJSON(t, "List", listValidationPod("first"), item)
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "bundle.json")
			require.Error(t, err, "a malformed item must not disappear from a compliance scan")
			require.Nil(t, objects, "do not expose a successful partial scan")
			require.Contains(t, err.Error(), "bundle.json")
			require.Contains(t, err.Error(), "document 0 record 0")
			require.Contains(t, err.Error(), "List.items[1]")
			require.Contains(t, err.Error(), "kind")
		})
	}
}

func TestListValidationRejectsNestedMissingKind(t *testing.T) {
	invalid := listValidationPod("unsafe")
	delete(invalid, "kind")
	inner := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{invalid}}
	outer := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{inner}}
	for _, envelope := range []string{"List", "PodList"} {
		t.Run(envelope, func(t *testing.T) {
			input := listValidationJSON(t, envelope, listValidationPod("valid"), outer)
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "nested.json")
			require.Error(t, err)
			require.Nil(t, objects)
			require.Contains(t, err.Error(), envelope+".items[1]: List.items[0]: List.items[0]")
		})
	}
}

func TestListValidationErrorsAcrossYAMLAndJSONBoundaries(t *testing.T) {
	valid, err := json.Marshal(listValidationPod("valid"))
	require.NoError(t, err)
	invalid := listValidationPod("unsafe")
	delete(invalid, "kind")
	badList := listValidationJSON(t, "List", invalid)
	for _, tc := range []struct {
		name, input, location string
	}{
		{"standalone list", badList, "document 0 record 0"},
		{"later JSON record", string(valid) + "\n" + badList, "document 0 record 1"},
		{"later YAML document", string(valid) + "\n---\n" + badList, "document 1 record 0"},
		{"YAML list", "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  metadata:\n    name: unsafe\n", "document 0 record 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(tc.input), "stdin")
			require.Error(t, err)
			require.Nil(t, objects)
			require.Contains(t, err.Error(), tc.location)
			require.Contains(t, err.Error(), "List.items[0]")
		})
	}
}

func TestListValidationFileAndDirectoryAreFailClosed(t *testing.T) {
	invalid := listValidationPod("unsafe")
	delete(invalid, "kind")
	dir := t.TempDir()
	validFile := filepath.Join(dir, "a-valid.json")
	invalidFile := filepath.Join(dir, "z-invalid.json")
	valid, err := json.Marshal(listValidationPod("valid"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(validFile, valid, 0o600))
	require.NoError(t, os.WriteFile(invalidFile, []byte(listValidationJSON(t, "List", invalid)), 0o600))
	for _, paths := range [][]string{
		{invalidFile}, {validFile, invalidFile}, {dir},
	} {
		t.Run(strings.Join(paths, ","), func(t *testing.T) {
			objects, err := ParseLocalWorkloads(paths)
			require.Error(t, err)
			require.Nil(t, objects)
			require.Contains(t, err.Error(), invalidFile)
			require.Contains(t, err.Error(), "List.items[0]")
		})
	}
}

func TestListValidationTypedListsInheritKindBeforeValidation(t *testing.T) {
	for _, tc := range []struct{ kind, apiVersion string }{
		{"Pod", "v1"},
		{"Deployment", "apps/v1"},
		{"StatefulSet", "apps/v1"},
		{"DaemonSet", "apps/v1"},
		{"ReplicaSet", "apps/v1"},
		{"Job", "batch/v1"},
		{"CronJob", "batch/v1"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			for _, inherited := range []any{nil, ""} {
				item := listValidationPod("inherited")
				item["kind"] = inherited
				delete(item, "apiVersion")
				raw, err := json.Marshal(map[string]any{
					"apiVersion": tc.apiVersion, "kind": tc.kind + "List", "items": []any{item},
				})
				require.NoError(t, err)
				objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(string(raw)), "typed.json")
				require.NoError(t, err)
				require.Len(t, objects, 1)
				require.Equal(t, tc.kind, objects[0].GetKind())
				require.Equal(t, tc.apiVersion, objects[0].GetAPIVersion())
			}
		})
	}
}

func TestListValidationTypedListsRejectNonStringKinds(t *testing.T) {
	for _, bad := range []any{true, 7, []any{"Pod"}, map[string]any{"name": "Pod"}} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			item := listValidationPod("unsafe")
			item["kind"] = bad
			input := listValidationJSON(t, "PodList", item)
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "typed.json")
			require.Error(t, err)
			require.Nil(t, objects)
			require.Contains(t, err.Error(), "PodList.items[0]")
		})
	}
}

func TestListValidationPreservesExplicitKindsAndUnsupportedObjects(t *testing.T) {
	input := listValidationJSON(t, "PodList",
		map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings"}},
		listValidationPod("unsafe"),
	)
	objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "mixed.json")
	require.NoError(t, err)
	require.Len(t, objects, 1)
	require.Equal(t, "unsafe", objects[0].GetName())
	result := Aggregate("", objects, Baseline)
	require.True(t, result.HasFailures())
	require.Equal(t, 1, result.FailingWorkloads)
}

func TestListValidationEmptyRecordsDoNotHideLaterWorkloads(t *testing.T) {
	for _, empty := range []any{nil, map[string]any{}} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			input := listValidationJSON(t, "List", empty, listValidationPod("unsafe"))
			objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "empty.json")
			// List items are Kubernetes objects, not stream separators. Even
			// an empty item needs a kind; top-level {} and null stay skippable.
			require.Error(t, err)
			require.Nil(t, objects)
		})
	}
	input := "{}\nnull\n" + listValidationJSON(t, "List", listValidationPod("unsafe"))
	objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "empty-stream.json")
	require.NoError(t, err)
	require.Len(t, objects, 1)
}

func TestListValidationValidNestedListsStillEvaluateEveryPod(t *testing.T) {
	inner := map[string]any{
		"apiVersion": "v1", "kind": "PodList", "items": []any{
			map[string]any{
				"metadata": map[string]any{"name": "inherited"},
				"spec":     listValidationPod("template")["spec"],
			},
		},
	}
	input := listValidationJSON(t, "List", listValidationPod("outer"), inner)
	objects, err := ParseLocalWorkloadsFromReader(strings.NewReader(input), "valid.json")
	require.NoError(t, err)
	require.Len(t, objects, 2)
	result := Aggregate("", objects, Baseline)
	require.Equal(t, 2, result.TotalWorkloads)
	require.Equal(t, 2, result.FailingWorkloads)
	require.Zero(t, result.UnevaluatedWorkloads)
}
