package resourcehandler

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

// Initializes a new instance of FileResourceHandler.
func TestNewFileResourceHandler_InitializesNewInstance(t *testing.T) {
	fileHandler := NewFileResourceHandler()
	assert.NotNil(t, fileHandler)
}

// newLocalWorkload builds a LocalWorkload (with a sourcePath that distinguishes
// otherwise-identical resources, mirroring how the file/helm/kustomize loaders
// produce different IDs for the same logical resource).
func newLocalWorkload(t *testing.T, raw, sourcePath string) workloadinterface.IMetadata {
	t.Helper()
	var obj map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(raw), &obj))
	w := localworkload.NewLocalWorkload(obj)
	w.SetPath(sourcePath)
	return w
}

func TestDedupWorkloadsBySource_NoOverlapKeepsAll(t *testing.T) {
	w1 := newLocalWorkload(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"default"}}`, "a.yaml")
	w2 := newLocalWorkload(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"b","namespace":"default"}}`, "b.yaml")
	workloads := []workloadinterface.IMetadata{w1, w2}
	src := map[string]reporthandling.Source{
		w1.GetID(): {RelativePath: "a.yaml", FileType: reporthandling.SourceTypeYaml},
		w2.GetID(): {RelativePath: "b.yaml", FileType: reporthandling.SourceTypeYaml},
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 2)
	assert.Len(t, gotS, 2)
}

// TestDedupWorkloadsBySource_HelmBeatsPlainYaml exercises the regression that
// shipped with kubescape's kustomize+helm test fixture: a chart template that
// happens to be valid plain YAML is picked up both by the plain YAML walker
// (FileType=YAML, no chart name) and by the helm renderer (FileType=Helm
// Chart, helmChartName set). After dedup only the helm-attributed copy
// survives.
func TestDedupWorkloadsBySource_HelmBeatsPlainYaml(t *testing.T) {
	const cm = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test-config","namespace":""}}`
	const path = "core/cautils/testdata/kustomize/helm/charts/test-chart/templates/configmap.yaml"
	// Plain YAML and Helm renderers tag the same logical resource with different
	// sourcePath values, so their IDs differ even though apiVersion+kind+name match.
	wYaml := newLocalWorkload(t, cm, path)
	wHelm := newLocalWorkload(t, cm, "helm-rendered:"+path)
	assert.NotEqual(t, wYaml.GetID(), wHelm.GetID())
	workloads := []workloadinterface.IMetadata{wYaml, wHelm}
	src := map[string]reporthandling.Source{
		wYaml.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
		wHelm.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeHelmChart, HelmChartName: "test-chart"},
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 1, "expected helm-attributed workload to win the dedup")
	assert.Equal(t, wHelm.GetID(), gotW[0].GetID())
	assert.Len(t, gotS, 1)
	assert.Equal(t, "test-chart", gotS[wHelm.GetID()].HelmChartName)
}

func TestDedupWorkloadsBySource_KustomizeBeatsPlainYaml(t *testing.T) {
	const cm = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"only-here","namespace":""}}`
	const path = "manifests/configmap.yaml"
	wYaml := newLocalWorkload(t, cm, path)
	wKustomize := newLocalWorkload(t, cm, "kustomize-rendered:"+path)
	workloads := []workloadinterface.IMetadata{wYaml, wKustomize}
	src := map[string]reporthandling.Source{
		wYaml.GetID():      {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
		wKustomize.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: "manifests"},
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 1)
	assert.Equal(t, wKustomize.GetID(), gotW[0].GetID())
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, gotS[wKustomize.GetID()].FileType)
}

func TestDedupWorkloadsBySource_DifferentResourcesInSameFileKept(t *testing.T) {
	wA := newLocalWorkload(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":""}}`, "multi.yaml")
	wB := newLocalWorkload(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"b","namespace":""}}`, "multi.yaml")
	workloads := []workloadinterface.IMetadata{wA, wB}
	src := map[string]reporthandling.Source{
		wA.GetID(): {RelativePath: "multi.yaml", FileType: reporthandling.SourceTypeYaml},
		wB.GetID(): {RelativePath: "multi.yaml", FileType: reporthandling.SourceTypeYaml},
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 2, "multi-document YAML must keep both resources")
	assert.Len(t, gotS, 2)
}

// TestDedupWorkloadsBySource_MultiDocSameIdentityKept locks in that
// multi-document YAML files which legitimately reuse the same resource
// identity (e.g. fixhandler test fixtures pairing input + expected Pods)
// are preserved when only one loader is involved. Cross-loader collapse
// must not eat them.
func TestDedupWorkloadsBySource_MultiDocSameIdentityKept(t *testing.T) {
	const pod = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"remove_example","namespace":""}}`
	const path = "core/pkg/fixhandler/testdata/removals/tc-04-00-input.yaml"
	w1 := newLocalWorkload(t, pod, path+"#0")
	w2 := newLocalWorkload(t, pod, path+"#1")
	workloads := []workloadinterface.IMetadata{w1, w2}
	src := map[string]reporthandling.Source{
		w1.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
		w2.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 2, "two YAML docs sharing identity must both survive")
	assert.Len(t, gotS, 2)
}

func TestDedupWorkloadsBySource_MultiDocCollapsesAcrossLoaders(t *testing.T) {
	// Same file rendered twice by helm and twice as plain YAML — keep both
	// helm copies, drop both plain-YAML copies.
	const pod = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"dup-pod","namespace":""}}`
	const path = "charts/x/templates/multi.yaml"
	wYaml1 := newLocalWorkload(t, pod, path+"#yaml-0")
	wYaml2 := newLocalWorkload(t, pod, path+"#yaml-1")
	wHelm1 := newLocalWorkload(t, pod, path+"#helm-0")
	wHelm2 := newLocalWorkload(t, pod, path+"#helm-1")
	workloads := []workloadinterface.IMetadata{wYaml1, wYaml2, wHelm1, wHelm2}
	src := map[string]reporthandling.Source{
		wYaml1.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
		wYaml2.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
		wHelm1.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeHelmChart, HelmChartName: "x"},
		wHelm2.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeHelmChart, HelmChartName: "x"},
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 2, "expected only the two helm-attributed copies to survive")
	for _, w := range gotW {
		assert.Equal(t, reporthandling.SourceTypeHelmChart, gotS[w.GetID()].FileType)
	}
}

// A workload present in `workloads` but absent from the source map must
// survive dedup, even when other groups collapse.
func TestDedupWorkloadsBySource_OrphanWorkloadKept(t *testing.T) {
	const cm = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test-config","namespace":""}}`
	const path = "templates/configmap.yaml"
	wOrphan := newLocalWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"orphan"}}`, "orphan.yaml")
	wYaml := newLocalWorkload(t, cm, path)
	wHelm := newLocalWorkload(t, cm, "helm:"+path)
	workloads := []workloadinterface.IMetadata{wOrphan, wYaml, wHelm}
	src := map[string]reporthandling.Source{
		// wOrphan intentionally absent from the source map.
		wYaml.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeYaml},
		wHelm.GetID(): {RelativePath: path, FileType: reporthandling.SourceTypeHelmChart, HelmChartName: "x"},
	}

	gotW, _ := dedupWorkloadsBySource(workloads, src)

	gotIDs := map[string]struct{}{}
	for _, w := range gotW {
		gotIDs[w.GetID()] = struct{}{}
	}
	assert.Contains(t, gotIDs, wOrphan.GetID(), "orphan workload (no source entry) must be preserved")
	assert.Contains(t, gotIDs, wHelm.GetID())
	assert.NotContains(t, gotIDs, wYaml.GetID())
}

// Direct coverage for the generic helper, independent of the kubescape
// types it's wrapped in.
func TestDedupByRank(t *testing.T) {
	type item struct {
		key  string
		rank int
		// hasKey false → opts out of grouping (kept as-is)
		hasKey bool
		tag    string
	}
	keyRankOf := func(it item) (string, int, bool) { return it.key, it.rank, it.hasKey }
	tagsOf := func(items []item) []string {
		out := make([]string, len(items))
		for i, it := range items {
			out[i] = it.tag
		}
		return out
	}

	cases := []struct {
		name string
		in   []item
		want []string
	}{
		{
			name: "single key wins",
			in: []item{
				{key: "p", rank: 1, hasKey: true, tag: "yaml"},
				{key: "p", rank: 3, hasKey: true, tag: "helm"},
			},
			want: []string{"helm"},
		},
		{
			name: "ties at the top survive together",
			in: []item{
				{key: "p", rank: 1, hasKey: true, tag: "yaml-a"},
				{key: "p", rank: 3, hasKey: true, tag: "helm-a"},
				{key: "p", rank: 3, hasKey: true, tag: "helm-b"},
			},
			want: []string{"helm-a", "helm-b"},
		},
		{
			name: "items without a key are passed through",
			in: []item{
				{tag: "orphan"},
				{key: "p", rank: 1, hasKey: true, tag: "yaml"},
				{key: "p", rank: 3, hasKey: true, tag: "helm"},
			},
			want: []string{"orphan", "helm"},
		},
		{
			name: "different keys are independent",
			in: []item{
				{key: "p", rank: 1, hasKey: true, tag: "p-yaml"},
				{key: "q", rank: 1, hasKey: true, tag: "q-yaml"},
			},
			want: []string{"p-yaml", "q-yaml"},
		},
		{
			name: "stable order",
			in: []item{
				{key: "p", rank: 3, hasKey: true, tag: "first"},
				{key: "p", rank: 1, hasKey: true, tag: "drop-me"},
				{key: "p", rank: 3, hasKey: true, tag: "second"},
			},
			want: []string{"first", "second"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupByRank(tc.in, keyRankOf)
			assert.Equal(t, tc.want, tagsOf(got))
		})
	}
}

func TestDedupWorkloadsBySource_NoSourceAttributionLeftAlone(t *testing.T) {
	wA := newLocalWorkload(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a"}}`, "a.yaml")
	workloads := []workloadinterface.IMetadata{wA}
	src := map[string]reporthandling.Source{
		wA.GetID(): {}, // no RelativePath
	}

	gotW, gotS := dedupWorkloadsBySource(workloads, src)

	assert.Len(t, gotW, 1)
	assert.Len(t, gotS, 1)
}
