package printer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLineFor builds a lineFor lookup from a fixed path->line map, so the
// annotation logic can be tested without a manifest on disk.
func stubLineFor(lines map[string]int) func(string) (int, bool) {
	return func(path string) (int, bool) {
		line, ok := lines[path]
		return line, ok
	}
}

func fixPathControl(paths ...armotypes.FixPath) *resourcesresults.ResourceAssociatedControl {
	posture := make([]armotypes.PosturePaths, 0, len(paths))
	for _, p := range paths {
		posture = append(posture, armotypes.PosturePaths{FixPath: p})
	}
	return &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Paths: posture}},
	}
}

func TestAnnotateFixPathLines(t *testing.T) {
	cases := []struct {
		name    string
		paths   []string
		control *resourcesresults.ResourceAssociatedControl
		lineFor func(string) (int, bool)
		want    []string
	}{
		{
			name:    "resolved fix path is annotated",
			paths:   []string{"spec.hostPID=false"},
			control: fixPathControl(armotypes.FixPath{Path: "spec.hostPID", Value: "false"}),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 23}),
			want:    []string{"spec.hostPID=false (line 23)"},
		},
		{
			name:    "unresolved fix path is left alone",
			paths:   []string{"spec.hostPID=false"},
			control: fixPathControl(armotypes.FixPath{Path: "spec.hostPID", Value: "false"}),
			lineFor: stubLineFor(nil),
			want:    []string{"spec.hostPID=false"},
		},
		{
			name:    "nil lookup leaves every path untouched",
			paths:   []string{"spec.hostPID=false"},
			control: fixPathControl(armotypes.FixPath{Path: "spec.hostPID", Value: "false"}),
			lineFor: nil,
			want:    []string{"spec.hostPID=false"},
		},
		{
			// PR scope is FixPath only. A review path renders as
			// "<path> (current: <value>)" and a delete path renders bare, so
			// neither carries the "<path>=" shape the annotation matches on.
			name:  "review and delete paths are not annotated",
			paths: []string{"spec.hostPID (current: true)", "spec.hostNetwork"},
			control: fixPathControl(
				armotypes.FixPath{Path: "spec.hostPID", Value: "false"},
				armotypes.FixPath{Path: "spec.hostNetwork", Value: "false"},
			),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 12, "spec.hostNetwork": 14}),
			want:    []string{"spec.hostPID (current: true)", "spec.hostNetwork"},
		},
		{
			// The "=" in the match is what keeps a shorter path from claiming
			// a longer one that merely starts the same way.
			name:  "a shorter path does not claim a longer one",
			paths: []string{"spec.host=a", "spec.hostPID=false"},
			control: fixPathControl(
				armotypes.FixPath{Path: "spec.host", Value: "a"},
				armotypes.FixPath{Path: "spec.hostPID", Value: "false"},
			),
			lineFor: stubLineFor(map[string]int{"spec.host": 7}),
			want:    []string{"spec.host=a (line 7)", "spec.hostPID=false"},
		},
		{
			// annotateFixPathLines runs after addContainerNameToAssistedRemediation,
			// so the line lands last and the container hint keeps its place.
			name:    "line is appended after an existing container-name suffix",
			paths:   []string{"spec.containers[0].image=nginx:1 (app)"},
			control: fixPathControl(armotypes.FixPath{Path: "spec.containers[0].image", Value: "nginx:1"}),
			lineFor: stubLineFor(map[string]int{"spec.containers[0].image": 9}),
			want:    []string{"spec.containers[0].image=nginx:1 (app) (line 9)"},
		},
		{
			// A control can carry the same fix path more than once across its
			// rules, and fixPathsToString does not deduplicate while the
			// rendered list does. Resolving per bare path would then stamp the
			// one surviving entry twice.
			name:  "a fix path repeated across rules is annotated once",
			paths: []string{"spec.hostPID=false"},
			control: fixPathControl(
				armotypes.FixPath{Path: "spec.hostPID", Value: "false"},
				armotypes.FixPath{Path: "spec.hostPID", Value: "false"},
			),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 23}),
			want:    []string{"spec.hostPID=false (line 23)"},
		},
		{
			name:    "empty path list is a no-op",
			paths:   nil,
			control: fixPathControl(armotypes.FixPath{Path: "spec.hostPID", Value: "false"}),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 3}),
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := tc.paths
			annotateFixPathLines(&paths, tc.control, tc.lineFor)
			assert.Equal(t, tc.want, paths)
		})
	}
}

// TestFailedResourcesInPrintOrder pins the ordering the manifest cache depends
// on: resources of one file must arrive together, and the order must not vary
// between runs the way ranging over the results map did.
func TestFailedResourcesInPrintOrder(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	// NewOPASessionObjMock leaves ResourceSource nil.
	session.ResourceSource = make(map[string]reporthandling.Source)

	add := func(resourceID, relPath string, failed bool) {
		status := apis.StatusPassed
		if failed {
			status = apis.StatusFailed
		}
		session.AllResources[resourceID] = workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": resourceID},
		})
		session.ResourcesResult[resourceID] = resourcesresults.Result{
			ResourceID: resourceID,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: "C-0001", Status: apis.StatusInfo{InnerStatus: status}},
			},
		}
		if relPath != "" {
			session.ResourceSource[resourceID] = reporthandling.Source{RelativePath: relPath, Path: "/base"}
		}
	}

	add("b-second-in-b", "b.yaml", true)
	add("a-only-in-a", "a.yaml", true)
	add("b-first-in-b", "b.yaml", true)
	add("z-no-source", "", true)
	add("passing", "a.yaml", false)

	var ids []string
	for _, r := range failedResourcesInPrintOrder(session) {
		ids = append(ids, r.resourceID)
	}

	// Pathless resources sort first on an empty absPath, then each manifest's
	// resources arrive consecutively and in a stable order within the file.
	assert.Equal(t, []string{"z-no-source", "a-only-in-a", "b-first-in-b", "b-second-in-b"}, ids)
	assert.NotContains(t, ids, "passing", "only failed resources belong in the table")

	// The same session must produce the same order on a second pass.
	var again []string
	for _, r := range failedResourcesInPrintOrder(session) {
		again = append(again, r.resourceID)
	}
	assert.Equal(t, ids, again)
}

const lineNumberManifest = "apiVersion: apps/v1\n" +
	"kind: Deployment\n" +
	"metadata:\n" +
	"  name: demo\n" +
	"spec:\n" +
	"  template:\n" +
	"    spec:\n" +
	"      containers:\n" +
	"        - name: app\n" +
	"          image: nginx:1\n" +
	"          securityContext:\n" +
	"            privileged: true\n"

// resourceTableLineNumberSession writes a real manifest and returns a session
// whose single failed resource points into it, so the full path runs: doc index
// parsing, resolver construction and yq evaluation against the file on disk.
func resourceTableLineNumberSession(t *testing.T, manifest, docSuffix string) *cautils.OPASessionObj {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte(manifest), 0o600))

	resourceID := "apps/v1/default/Deployment/demo"
	lw := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "demo", "namespace": "default"},
		"spec":       map[string]interface{}{},
	})
	lw.SetPath("deploy.yaml" + docSuffix)

	session := cautils.NewOPASessionObjMock()
	// NewOPASessionObjMock leaves ResourceSource nil.
	session.ResourceSource = make(map[string]reporthandling.Source)
	session.AllResources[resourceID] = lw
	session.ResourceSource[resourceID] = reporthandling.Source{RelativePath: "deploy.yaml", Path: dir}
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0001",
				Name:      "Privileged container",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:   "privileged-container",
						Status: apis.StatusFailed,
						Paths: []armotypes.PosturePaths{
							{FixPath: armotypes.FixPath{
								Path:  "spec.template.spec.containers[0].securityContext.privileged",
								Value: "false",
							}},
						},
					},
				},
			},
		},
	}
	session.Report.SummaryDetails = reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Name: "Privileged container", ScoreFactor: 8.0},
		},
	}
	return session
}

func renderResourceTable(t *testing.T, session *cautils.OPASessionObj, showEvidence bool) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "resource-table-*.txt")
	require.NoError(t, err)

	pp := &PrettyPrinter{writer: f, showEvidence: showEvidence}
	pp.resourceTable(session)

	require.NoError(t, f.Close())
	out, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	return string(out)
}

// TestResourceTable_FixPathResolvesToLine is the end-to-end case: a fix path
// pointing at a field that exists in the manifest renders with its line.
func TestResourceTable_FixPathResolvesToLine(t *testing.T) {
	out := renderResourceTable(t, resourceTableLineNumberSession(t, lineNumberManifest, ":0"), true)

	assert.Contains(t, out, "(line 12)", "privileged: true is line 12 of the fixture")
}

// TestResourceTable_UnresolvableFixPathDegrades covers a fix path whose field
// is absent, which is the normal case for a fix that adds something. The path
// still prints; it just carries no line.
func TestResourceTable_UnresolvableFixPathDegrades(t *testing.T) {
	manifest := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"

	out := renderResourceTable(t, resourceTableLineNumberSession(t, manifest, ":0"), true)

	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ", "an unresolved path must not be given a fabricated line")
}

// TestResourceTable_WithoutShowEvidenceHasNoLines keeps the non -E path
// unchanged: no evidence column, and no manifest is opened to build one.
func TestResourceTable_WithoutShowEvidenceHasNoLines(t *testing.T) {
	out := renderResourceTable(t, resourceTableLineNumberSession(t, lineNumberManifest, ":0"), false)

	assert.NotContains(t, out, "(line ")
	assert.NotContains(t, out, "privileged=false")
}

// TestResourceTable_MissingDocIndexDegrades covers Helm-rendered resources,
// whose path carries no ":<index>" suffix, so getDocIndex reports nothing and
// the resolver is never reached.
func TestResourceTable_MissingDocIndexDegrades(t *testing.T) {
	out := renderResourceTable(t, resourceTableLineNumberSession(t, lineNumberManifest, ""), true)

	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ")
}

// TestResourceTable_SecondDocumentResolvesAgainstItsOwnDocument checks the doc
// index is honoured rather than always reading the first document: the same
// field sits at a different line in each document of the file.
func TestResourceTable_SecondDocumentResolvesAgainstItsOwnDocument(t *testing.T) {
	multiDoc := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: filler\n---\n" + lineNumberManifest

	out := renderResourceTable(t, resourceTableLineNumberSession(t, multiDoc, ":1"), true)

	// The first document and its separator take five lines, so the field that is
	// line 12 on its own is line 17 here. That it moved at all is the point:
	// the resolver honoured the document index instead of reading document 0.
	assert.Contains(t, out, "(line 17)")
}

// TestResourceTable_ClusterResourceHasNoLines covers a resource with no source
// manifest at all, which is every resource in a cluster scan.
func TestResourceTable_ClusterResourceHasNoLines(t *testing.T) {
	session := resourceTableLineNumberSession(t, lineNumberManifest, ":0")
	for id := range session.ResourceSource {
		delete(session.ResourceSource, id)
	}

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ")
}
