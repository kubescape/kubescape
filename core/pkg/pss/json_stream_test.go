package pss

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestJSONStream_EvaluatesEveryJSONRecord(t *testing.T) {
	source := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"safe"},"spec":{"containers":[{"name":"app","image":"fixture"}]}}
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"unsafe"},"spec":{"containers":[{"name":"app","image":"fixture","securityContext":{"privileged":true}}]}}`)
	items, err := parseMultiDoc(source, "stream.json")
	require.NoError(t, err)
	require.Len(t, items, 2)
	result := Aggregate("", items, Baseline)
	require.Equal(t, 1, result.FailingWorkloads)
}

func streamPod(name string, privileged bool) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": "ns"},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "app", "image": "fixture", "securityContext": map[string]any{"privileged": privileged},
		}}},
	}
}

func jsonRecord(t *testing.T, object any) string {
	t.Helper()
	data, err := json.Marshal(object)
	require.NoError(t, err)
	return string(data)
}

func streamNames(items []unstructured.Unstructured) []string {
	names := make([]string, len(items))
	for i := range items {
		names[i] = items[i].GetName()
	}
	return names
}

func TestJSONStream_WhitespaceAndAdjacentJSONRecords(t *testing.T) {
	first := jsonRecord(t, streamPod("first", false))
	second := jsonRecord(t, streamPod("second", true))
	for _, separator := range []string{"\n", "\r\n", " ", "\t", "\n\n", ""} {
		t.Run(fmt.Sprintf("separator-%q", separator), func(t *testing.T) {
			items, err := parseMultiDoc([]byte(first+separator+second), "stream.json")
			require.NoError(t, err)
			require.Equal(t, []string{"first", "second"}, streamNames(items))
			require.Equal(t, 1, Aggregate("", items, Baseline).FailingWorkloads)
		})
	}
}

func TestJSONStream_InvalidTrailingJSONMustFailWholeParse(t *testing.T) {
	first := jsonRecord(t, streamPod("first", false))
	for _, trailing := range []string{`{"kind":`, `not-json`, `{"metadata":]}`} {
		t.Run(trailing, func(t *testing.T) {
			items, err := parseMultiDoc([]byte(first+"\n"+trailing), "invalid-stream.json")
			require.Error(t, err, "a valid prefix must not hide invalid trailing input")
			require.Nil(t, items)
			require.Contains(t, err.Error(), "invalid-stream.json")
		})
	}
}

func TestJSONStream_SecondRecordListIsExpanded(t *testing.T) {
	list := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{streamPod("listed", true)}}
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, list)
	items, err := parseMultiDoc([]byte(source), "list-stream.json")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "listed"}, streamNames(items))
	require.Equal(t, 1, Aggregate("", items, Baseline).FailingWorkloads)
}

func TestJSONStream_TypedListThenPodPreservesTypeMetadata(t *testing.T) {
	member := streamPod("typed", false)
	delete(member, "kind")
	delete(member, "apiVersion")
	list := map[string]any{"apiVersion": "v1", "kind": "PodList", "items": []any{member}}
	source := jsonRecord(t, list) + "\n" + jsonRecord(t, streamPod("last", true))
	items, err := parseMultiDoc([]byte(source), "typed-stream.json")
	require.NoError(t, err)
	require.Equal(t, []string{"typed", "last"}, streamNames(items))
	require.Equal(t, "Pod", items[0].GetKind())
	require.Equal(t, "v1", items[0].GetAPIVersion())
}

func TestJSONStream_UnsupportedRecordsDoNotHideLaterWorkload(t *testing.T) {
	for _, unsupported := range []map[string]any{
		{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "svc"}},
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "config"}},
		{"apiVersion": "custom.example/v1", "kind": "Custom", "metadata": map[string]any{"name": "custom"}},
	} {
		source := jsonRecord(t, unsupported) + "\n" + jsonRecord(t, streamPod("last", true))
		items, err := parseMultiDoc([]byte(source), "unsupported.json")
		require.NoError(t, err)
		require.Equal(t, []string{"last"}, streamNames(items))
	}
}

func TestJSONStream_EmptyObjectsDoNotTerminateStream(t *testing.T) {
	// Begin with an object so the decoder selects JSON stream mode.
	for _, prefix := range []string{"{}", "{}\nnull\n{}"} {
		source := prefix + "\n" + jsonRecord(t, streamPod("last", true))
		items, err := parseMultiDoc([]byte(source), "empty-prefix.json")
		require.NoError(t, err)
		require.Equal(t, []string{"last"}, streamNames(items))
	}
}

func TestJSONStream_LocalParserRejectsPopulatedObjectsWithoutKind(t *testing.T) {
	for _, kind := range []string{"absent", "null", "empty"} {
		for _, prefix := range []string{"", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: safe\n---\n", jsonRecord(t, streamPod("safe", false)) + "\n"} {
			t.Run(fmt.Sprintf("%s/prefix-%d", kind, len(prefix)), func(t *testing.T) {
				object := streamPod("unsafe", true)
				switch kind {
				case "absent":
					delete(object, "kind")
				case "null":
					object["kind"] = nil
				case "empty":
					object["kind"] = ""
				}
				path := filepath.Join(t.TempDir(), "missing-kind.yaml")
				require.NoError(t, os.WriteFile(path, []byte(prefix+jsonRecord(t, object)), 0o600))
				items, err := ParseLocalWorkloads([]string{path})
				require.ErrorContains(t, err, "kind is required")
				require.ErrorContains(t, err, path)
				require.ErrorContains(t, err, "document")
				require.ErrorContains(t, err, "record")
				require.Empty(t, items, "an invalid suffix must not return a successful prefix")
			})
		}
	}
}

func TestJSONStream_RejectsMetadataOnlyObject(t *testing.T) {
	items, err := parseMultiDoc([]byte(`{"metadata":{"name":"unknown"}}`), "metadata.json")
	require.ErrorContains(t, err, "kind is required")
	require.Empty(t, items)
}

func TestJSONStream_NestedListsRemainSupportedInAnyRecord(t *testing.T) {
	nested := map[string]any{"kind": "List", "apiVersion": "v1", "items": []any{
		map[string]any{"kind": "List", "apiVersion": "v1", "items": []any{streamPod("nested", true)}},
	}}
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, nested)
	items, err := parseMultiDoc([]byte(source), "nested-stream.json")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "nested"}, streamNames(items))
}

func TestJSONStream_MalformedLaterListDoesNotReturnEarlierWorkloads(t *testing.T) {
	for _, itemsValue := range []any{nil, "not-an-array", map[string]any{"kind": "Pod"}} {
		list := map[string]any{"kind": "List", "apiVersion": "v1", "items": itemsValue}
		source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, list)
		items, err := parseMultiDoc([]byte(source), "bad-list.json")
		require.Error(t, err)
		require.Nil(t, items)
		require.Contains(t, err.Error(), "bad-list.json")
	}
}

func TestJSONStream_YAMLDocumentBoundariesStillWork(t *testing.T) {
	source := jsonRecord(t, streamPod("first", false)) + "\n---\n" + jsonRecord(t, streamPod("second", true)) + "\n---\n"
	items, err := parseMultiDoc([]byte(source), "boundaries.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, streamNames(items))
}

func TestJSONStream_JSONStreamInsideSeveralYAMLDocuments(t *testing.T) {
	first := jsonRecord(t, streamPod("first", false))
	second := jsonRecord(t, streamPod("second", false))
	third := jsonRecord(t, streamPod("third", true))
	source := first + "\n" + second + "\n---\n" + third
	items, err := parseMultiDoc([]byte(source), "mixed.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second", "third"}, streamNames(items))
}

func TestJSONStream_QuotedDocumentSeparatorsAreNotBoundaries(t *testing.T) {
	pod := streamPod("first", false)
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{"text": "---\n{not another document}"}
	source := jsonRecord(t, pod) + "\n" + jsonRecord(t, streamPod("second", true))
	items, err := parseMultiDoc([]byte(source), "strings.json")
	require.NoError(t, err)
	require.Len(t, items, 2)
	require.Equal(t, "---\n{not another document}", items[0].GetAnnotations()["text"])
}

func TestJSONStream_LocalFilePipelineReadsEveryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workloads.json")
	source := jsonRecord(t, streamPod("safe", false)) + "\n" + jsonRecord(t, streamPod("unsafe", true))
	require.NoError(t, os.WriteFile(path, []byte(source), 0o600))
	items, err := ParseLocalWorkloads([]string{path})
	require.NoError(t, err)
	result := Aggregate("", items, Baseline)
	require.Equal(t, 2, result.TotalWorkloads)
	require.Equal(t, 1, result.PassingWorkloads)
	require.Equal(t, 1, result.FailingWorkloads)
	require.Equal(t, Privileged, result.CurrentEffectiveLevel)
}

func TestJSONStream_DirectoryPipelineReadsStreamFiles(t *testing.T) {
	dir := t.TempDir()
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, streamPod("second", true))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(source), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(jsonRecord(t, streamPod("third", false))), 0o600))
	items, err := ParseLocalWorkloads([]string{dir})
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second", "third"}, streamNames(items))
}

func TestJSONStream_TrailingInvalidRecordFailsPublicParser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	require.NoError(t, os.WriteFile(path, []byte(jsonRecord(t, streamPod("safe", false))+"\n{"), 0o600))
	items, err := ParseLocalWorkloads([]string{path})
	require.Error(t, err)
	require.Nil(t, items)
	require.Contains(t, err.Error(), path)
}

func TestJSONStream_WhitespaceOnlyDocumentsAreIgnored(t *testing.T) {
	for _, source := range []string{"", "  \n\t\r\n", "---\n---\n", "# comment only\n"} {
		items, err := parseMultiDoc([]byte(source), "empty.yaml")
		require.NoError(t, err)
		require.Empty(t, items)
	}
}

func TestJSONStream_PrettyPrintedRecordsAreDecodedIndependently(t *testing.T) {
	first, err := json.MarshalIndent(streamPod("first", false), "", "  ")
	require.NoError(t, err)
	second, err := json.MarshalIndent(streamPod("second", true), "", "\t")
	require.NoError(t, err)
	items, err := parseMultiDoc(append(append(first, '\n'), second...), "pretty.json")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, streamNames(items))
}

func TestJSONStream_LargeRecordDoesNotSwallowFollowingPod(t *testing.T) {
	first := streamPod("first", false)
	first["metadata"].(map[string]any)["annotations"] = map[string]any{"large": strings.Repeat("x", 128*1024)}
	source := jsonRecord(t, first) + "\n" + jsonRecord(t, streamPod("second", true))
	items, err := parseMultiDoc([]byte(source), "large.json")
	require.NoError(t, err)
	require.Len(t, items, 2)
	require.Len(t, items[0].GetAnnotations()["large"], 128*1024)
	require.Equal(t, "second", items[1].GetName())
}

func TestJSONStream_ExplicitKindsAndNamespacesAreNotRewritten(t *testing.T) {
	first := streamPod("first", false)
	first["metadata"].(map[string]any)["namespace"] = "other"
	source := jsonRecord(t, first) + "\n" + jsonRecord(t, streamPod("second", true))
	items, err := parseMultiDoc([]byte(source), "identity.json")
	require.NoError(t, err)
	require.Equal(t, "other", items[0].GetNamespace())
	require.Equal(t, "ns", items[1].GetNamespace())
	require.Equal(t, "Pod", items[0].GetKind())
	require.Equal(t, "v1", items[1].GetAPIVersion())
}

func streamWorkload(kind, name string, privileged bool) map[string]any {
	pod := streamPod(name, privileged)
	if kind == "Pod" {
		return pod
	}
	apiVersion := "apps/v1"
	if kind == "Job" || kind == "CronJob" {
		apiVersion = "batch/v1"
	}
	spec := map[string]any{"template": map[string]any{"spec": pod["spec"]}}
	if kind == "CronJob" {
		spec = map[string]any{"jobTemplate": map[string]any{"spec": spec}}
	}
	return map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"name": name}, "spec": spec,
	}
}

func TestJSONStream_AllSupportedWorkloadKindsAreEvaluated(t *testing.T) {
	for _, kind := range []string{"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"} {
		t.Run(kind, func(t *testing.T) {
			source := jsonRecord(t, streamWorkload(kind, "safe", false)) + "\n" + jsonRecord(t, streamWorkload(kind, "unsafe", true))
			items, err := parseMultiDoc([]byte(source), "controllers.json")
			require.NoError(t, err)
			require.Len(t, items, 2)
			result := Aggregate("", items, Baseline)
			require.Equal(t, 1, result.FailingWorkloads)
			require.Zero(t, result.UnevaluatedWorkloads)
			require.Equal(t, kind, items[1].GetKind())
		})
	}
}

func TestJSONStream_IntegerPrecisionIsPreserved(t *testing.T) {
	pod := streamPod("large-uid", false)
	container := pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	container["securityContext"].(map[string]any)["runAsUser"] = int64(9007199254740993)
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, pod)
	items, err := parseMultiDoc([]byte(source), "precision.json")
	require.NoError(t, err)
	require.Len(t, items, 2)
	spec, err := ExtractPodSpec("Pod", items[1].Object)
	require.NoError(t, err)
	require.Equal(t, int64(9007199254740993), *spec.Containers[0].SecurityContext.RunAsUser)
}

func TestJSONStream_NullWithinObjectStreamDoesNotHideLaterWorkload(t *testing.T) {
	source := jsonRecord(t, streamPod("first", false)) + "\nnull\n" + jsonRecord(t, streamPod("last", true))
	items, err := parseMultiDoc([]byte(source), "null-record.json")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "last"}, streamNames(items))
}

func TestJSONStream_LaterScalarRecordIsNotAWorkload(t *testing.T) {
	for _, scalar := range []string{`true`, `42`, `"plain string"`, `[]`} {
		source := jsonRecord(t, streamPod("first", false)) + "\n" + scalar
		items, err := parseMultiDoc([]byte(source), "scalar.json")
		require.Error(t, err)
		require.Nil(t, items)
		require.Contains(t, err.Error(), "scalar.json")
	}
}

func TestJSONStream_ErrorNamesDocumentAndRecord(t *testing.T) {
	first := jsonRecord(t, streamPod("first", false))
	second := jsonRecord(t, streamPod("second", false))
	source := first + "\n---\n" + second + "\n{"
	items, err := parseMultiDoc([]byte(source), "position.json")
	require.Error(t, err)
	require.Nil(t, items)
	require.Contains(t, err.Error(), "document 1 record 1")
	require.Contains(t, err.Error(), "position.json")
}

func TestJSONStream_DirectoryParseDoesNotReturnValidPrefixOnError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(jsonRecord(t, streamPod("safe", false))), 0o600))
	invalid := jsonRecord(t, streamPod("another", false)) + "\n{"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte(invalid), 0o600))
	items, err := ParseLocalWorkloads([]string{dir})
	require.Error(t, err)
	require.Nil(t, items)
	require.Contains(t, err.Error(), "b.json")
}

func TestJSONStream_MultipleInputFilesKeepEveryRecordInOrder(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, fmt.Sprintf("%d.json", i))
		source := jsonRecord(t, streamPod(fmt.Sprintf("%d-a", i), false)) + "\n" + jsonRecord(t, streamPod(fmt.Sprintf("%d-b", i), false))
		require.NoError(t, os.WriteFile(path, []byte(source), 0o600))
		paths = append(paths, path)
	}
	items, err := ParseLocalWorkloads(paths)
	require.NoError(t, err)
	require.Equal(t, []string{"0-a", "0-b", "1-a", "1-b", "2-a", "2-b"}, streamNames(items))
}

func TestJSONStream_DoesNotMutateSourceBytes(t *testing.T) {
	source := []byte(jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, streamPod("last", true)))
	before := string(source)
	items, err := parseMultiDoc(source, "immutable.json")
	require.NoError(t, err)
	require.Len(t, items, 2)
	require.Equal(t, before, string(source))
}

func TestJSONStream_UnicodeMetadataSurvivesAllRecords(t *testing.T) {
	pod := streamPod("unicode", false)
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{"message": "安全 🔒"}
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, pod)
	items, err := parseMultiDoc([]byte(source), "unicode.json")
	require.NoError(t, err)
	require.Equal(t, "安全 🔒", items[1].GetAnnotations()["message"])
}

func TestJSONStream_ManyRecordsKeepLastViolation(t *testing.T) {
	var records []string
	for i := 0; i < 100; i++ {
		records = append(records, jsonRecord(t, streamPod(fmt.Sprintf("pod-%d", i), i == 99)))
	}
	items, err := parseMultiDoc([]byte(strings.Join(records, "\n")), "many.json")
	require.NoError(t, err)
	require.Len(t, items, 100)
	result := Aggregate("", items, Baseline)
	require.Equal(t, 99, result.PassingWorkloads)
	require.Equal(t, 1, result.FailingWorkloads)
	require.Equal(t, "pod-99", result.FailingResults()[0].Name)
}

func TestJSONStream_TrailingWhitespaceDoesNotCreateWorkload(t *testing.T) {
	source := jsonRecord(t, streamPod("only", false)) + "\r\n \t\n"
	items, err := parseMultiDoc([]byte(source), "whitespace.json")
	require.NoError(t, err)
	require.Equal(t, []string{"only"}, streamNames(items))
}

func TestJSONStream_EmptyListFollowedByPodDoesNotTerminateStream(t *testing.T) {
	list := map[string]any{"kind": "List", "apiVersion": "v1", "items": []any{}}
	source := jsonRecord(t, list) + "\n" + jsonRecord(t, streamPod("last", true))
	items, err := parseMultiDoc([]byte(source), "empty-list.json")
	require.NoError(t, err)
	require.Equal(t, []string{"last"}, streamNames(items))
}

func TestJSONStream_CompleteRecordThenTruncatedThirdRecordFails(t *testing.T) {
	first := jsonRecord(t, streamPod("first", false))
	second := jsonRecord(t, streamPod("second", false))
	items, err := parseMultiDoc([]byte(first+"\n"+second+"\n"+`{"kind":"Pod"`), "third.json")
	require.Error(t, err)
	require.Nil(t, items)
	require.Contains(t, err.Error(), "record 2")
}

func TestJSONStream_EveryTypedControllerListWorksInLaterRecord(t *testing.T) {
	for _, kind := range []string{"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"} {
		member := streamWorkload(kind, "listed", true)
		apiVersion := member["apiVersion"]
		delete(member, "kind")
		delete(member, "apiVersion")
		list := map[string]any{"kind": kind + "List", "apiVersion": apiVersion, "items": []any{member}}
		source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, list)
		items, err := parseMultiDoc([]byte(source), "controller-lists.json")
		require.NoError(t, err)
		require.Len(t, items, 2)
		require.Equal(t, kind, items[1].GetKind())
		require.Equal(t, 1, Aggregate("", items, Baseline).FailingWorkloads)
	}
}

func TestJSONStream_EvidenceIsIndependentBetweenRecords(t *testing.T) {
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, streamPod("second", true))
	items, err := parseMultiDoc([]byte(source), "independent.json")
	require.NoError(t, err)
	items[0].SetName("changed")
	require.Equal(t, "second", items[1].GetName())
	require.Equal(t, 1, Aggregate("", items, Baseline).FailingWorkloads)
}

func TestJSONStream_SourceFilenameIsOnlyDiagnosticContext(t *testing.T) {
	source := []byte(jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, streamPod("second", true)))
	first, err := parseMultiDoc(source, "one.json")
	require.NoError(t, err)
	second, err := parseMultiDoc(source, "two.yaml")
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestJSONStream_AppliedSecurityContextsArePreserved(t *testing.T) {
	pod := streamPod("restricted", false)
	spec := pod["spec"].(map[string]any)
	spec["securityContext"] = map[string]any{"runAsNonRoot": true, "runAsUser": 1000}
	source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, pod)
	items, err := parseMultiDoc([]byte(source), "contexts.json")
	require.NoError(t, err)
	decoded, err := ExtractPodSpec("Pod", items[1].Object)
	require.NoError(t, err)
	require.True(t, *decoded.SecurityContext.RunAsNonRoot)
	require.Equal(t, int64(1000), *decoded.SecurityContext.RunAsUser)
}

func TestJSONStream_RepeatedNamesAreNotSilentlyDeduplicated(t *testing.T) {
	source := jsonRecord(t, streamPod("same", false)) + "\n" + jsonRecord(t, streamPod("same", true))
	items, err := parseMultiDoc([]byte(source), "duplicates.json")
	require.NoError(t, err)
	require.Len(t, items, 2)
	result := Aggregate("", items, Baseline)
	require.Equal(t, 1, result.PassingWorkloads)
	require.Equal(t, 1, result.FailingWorkloads)
}

func TestJSONStream_InvalidLaterKindCannotBecomeAnIgnoredRecord(t *testing.T) {
	for _, kind := range []any{42, true, []string{"Pod"}} {
		bad := map[string]any{"kind": kind, "metadata": map[string]any{"name": "invalid"}}
		source := jsonRecord(t, streamPod("first", false)) + "\n" + jsonRecord(t, bad)
		items, err := parseMultiDoc([]byte(source), "kind-type.json")
		require.ErrorContains(t, err, "kind must be a string")
		require.Nil(t, items)
	}
}
