package printer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
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

// postureControl builds a control from arbitrary rule paths, so a case can mix
// fix, delete and review paths the way real rules do.
func postureControl(paths ...armotypes.PosturePaths) *resourcesresults.ResourceAssociatedControl {
	return &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Paths: paths}},
	}
}

func TestAnnotatePathLines(t *testing.T) {
	cases := []struct {
		name    string
		paths   []string
		control *resourcesresults.ResourceAssociatedControl
		lineFor func(string) (int, bool)
		want    []string
	}{
		// Fix paths, rendered "<path>=<value>".
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
			// The "=" in the match is what keeps a shorter path from claiming
			// a longer one that merely starts the same way.
			name:  "a shorter fix path does not claim a longer one",
			paths: []string{"spec.host=a", "spec.hostPID=false"},
			control: fixPathControl(
				armotypes.FixPath{Path: "spec.host", Value: "a"},
				armotypes.FixPath{Path: "spec.hostPID", Value: "false"},
			),
			lineFor: stubLineFor(map[string]int{"spec.host": 7}),
			want:    []string{"spec.host=a (line 7)", "spec.hostPID=false"},
		},

		// Review paths, rendered bare or with " (current: <value>)".
		{
			name:    "review path with a current value is annotated",
			paths:   []string{"spec.automountServiceAccountToken (current: true)"},
			control: postureControl(armotypes.PosturePaths{ReviewPath: "spec.automountServiceAccountToken"}),
			lineFor: stubLineFor(map[string]int{"spec.automountServiceAccountToken": 12}),
			want:    []string{"spec.automountServiceAccountToken (current: true) (line 12)"},
		},
		{
			name:    "bare review path is annotated",
			paths:   []string{"spec.automountServiceAccountToken"},
			control: postureControl(armotypes.PosturePaths{ReviewPath: "spec.automountServiceAccountToken"}),
			lineFor: stubLineFor(map[string]int{"spec.automountServiceAccountToken": 12}),
			want:    []string{"spec.automountServiceAccountToken (line 12)"},
		},
		{
			name:    "unresolved review path is left alone",
			paths:   []string{"spec.automountServiceAccountToken (current: true)"},
			control: postureControl(armotypes.PosturePaths{ReviewPath: "spec.automountServiceAccountToken"}),
			lineFor: stubLineFor(nil),
			want:    []string{"spec.automountServiceAccountToken (current: true)"},
		},

		// Delete paths, rendered bare.
		{
			name:    "delete path is annotated",
			paths:   []string{"spec.hostNetwork"},
			control: postureControl(armotypes.PosturePaths{DeletePath: "spec.hostNetwork"}),
			lineFor: stubLineFor(map[string]int{"spec.hostNetwork": 14}),
			want:    []string{"spec.hostNetwork (line 14)"},
		},
		{
			name:    "unresolved delete path is left alone",
			paths:   []string{"spec.hostNetwork"},
			control: postureControl(armotypes.PosturePaths{DeletePath: "spec.hostNetwork"}),
			lineFor: stubLineFor(nil),
			want:    []string{"spec.hostNetwork"},
		},

		// Every type in one control, as real rules emit them.
		{
			name:  "fix, delete and review paths each get their own line",
			paths: []string{"spec.hostPID=false", "spec.hostNetwork", "spec.automountServiceAccountToken (current: true)"},
			control: postureControl(
				armotypes.PosturePaths{FixPath: armotypes.FixPath{Path: "spec.hostPID", Value: "false"}},
				armotypes.PosturePaths{DeletePath: "spec.hostNetwork"},
				armotypes.PosturePaths{ReviewPath: "spec.automountServiceAccountToken"},
			),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 10, "spec.hostNetwork": 11, "spec.automountServiceAccountToken": 12}),
			want: []string{
				"spec.hostPID=false (line 10)",
				"spec.hostNetwork (line 11)",
				"spec.automountServiceAccountToken (current: true) (line 12)",
			},
		},

		// Matching stays pinned to each entry's own path.
		{
			// A bare path must not claim a longer path that starts with it: the
			// match requires the path alone or followed by " (".
			name:  "a shorter bare path does not claim a longer one",
			paths: []string{"spec.containers[0] (current: x)", "spec.containers[0].image (current: nginx)"},
			control: postureControl(
				armotypes.PosturePaths{ReviewPath: "spec.containers[0]"},
				armotypes.PosturePaths{ReviewPath: "spec.containers[0].image"},
			),
			lineFor: stubLineFor(map[string]int{"spec.containers[0]": 20}),
			want:    []string{"spec.containers[0] (current: x) (line 20)", "spec.containers[0].image (current: nginx)"},
		},
		{
			// Without its own fix path, a "<path>=<value>" entry is not
			// claimed by a review path of the same field, and vice versa.
			name:    "a review path does not claim a fix entry",
			paths:   []string{"spec.hostPID=false"},
			control: postureControl(armotypes.PosturePaths{ReviewPath: "spec.hostPID"}),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 12}),
			want:    []string{"spec.hostPID=false"},
		},
		{
			name:    "a fix path does not claim a review entry",
			paths:   []string{"spec.hostPID (current: true)"},
			control: fixPathControl(armotypes.FixPath{Path: "spec.hostPID", Value: "false"}),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 12}),
			want:    []string{"spec.hostPID (current: true)"},
		},

		// Container-name suffixes are appended before annotation.
		{
			name:    "fix path: line lands after the container-name suffix",
			paths:   []string{"spec.containers[0].image=nginx:1 (app)"},
			control: fixPathControl(armotypes.FixPath{Path: "spec.containers[0].image", Value: "nginx:1"}),
			lineFor: stubLineFor(map[string]int{"spec.containers[0].image": 9}),
			want:    []string{"spec.containers[0].image=nginx:1 (app) (line 9)"},
		},
		{
			name:    "review path: line lands after the container-name suffix",
			paths:   []string{"spec.containers[0].image (current: nginx:1) (app)"},
			control: postureControl(armotypes.PosturePaths{ReviewPath: "spec.containers[0].image"}),
			lineFor: stubLineFor(map[string]int{"spec.containers[0].image": 9}),
			want:    []string{"spec.containers[0].image (current: nginx:1) (app) (line 9)"},
		},
		{
			name:    "delete path: line lands after the container-name suffix",
			paths:   []string{"spec.containers[0].securityContext (app)"},
			control: postureControl(armotypes.PosturePaths{DeletePath: "spec.containers[0].securityContext"}),
			lineFor: stubLineFor(map[string]int{"spec.containers[0].securityContext": 8}),
			want:    []string{"spec.containers[0].securityContext (app) (line 8)"},
		},

		// Each entry is annotated at most once.
		{
			// fixPathsToString does not deduplicate while the rendered list
			// does, so a fix path repeated across rules matches one entry twice.
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
			// The rendered list deduplicates with " (current: ...)" stripped, so
			// a delete path and a review path naming the same field survive as
			// one entry. Both types match it; it must still get one line.
			name:  "a delete and review path collapsed into one entry is annotated once",
			paths: []string{"spec.hostPID"},
			control: postureControl(
				armotypes.PosturePaths{DeletePath: "spec.hostPID"},
				armotypes.PosturePaths{ReviewPath: "spec.hostPID"},
			),
			lineFor: stubLineFor(map[string]int{"spec.hostPID": 12}),
			want:    []string{"spec.hostPID (line 12)"},
		},

		{
			name:    "nil lookup leaves every path untouched",
			paths:   []string{"spec.hostPID=false", "spec.hostNetwork"},
			control: postureControl(armotypes.PosturePaths{DeletePath: "spec.hostNetwork"}),
			lineFor: nil,
			want:    []string{"spec.hostPID=false", "spec.hostNetwork"},
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
			annotatePathLines(&paths, tc.control, tc.lineFor)
			assert.Equal(t, tc.want, paths)
		})
	}
}

// TestAnnotatePathLines_ResolvesEachPathOnce pins that a path named by several
// rules, or by several path types, is resolved once. Each resolution evaluates
// a yq expression against the manifest.
func TestAnnotatePathLines_ResolvesEachPathOnce(t *testing.T) {
	calls := make(map[string]int)
	lineFor := func(path string) (int, bool) {
		calls[path]++
		return 5, true
	}

	paths := []string{"spec.hostPID=false", "spec.hostPID (current: true)", "spec.hostNetwork"}
	control := postureControl(
		armotypes.PosturePaths{FixPath: armotypes.FixPath{Path: "spec.hostPID", Value: "false"}},
		armotypes.PosturePaths{ReviewPath: "spec.hostPID"},
		armotypes.PosturePaths{DeletePath: "spec.hostNetwork"},
		armotypes.PosturePaths{DeletePath: "spec.hostNetwork"},
	)

	annotatePathLines(&paths, control, lineFor)

	assert.Equal(t, map[string]int{"spec.hostPID": 1, "spec.hostNetwork": 1}, calls)
	assert.Equal(t, []string{
		"spec.hostPID=false (line 5)",
		"spec.hostPID (current: true) (line 5)",
		"spec.hostNetwork (line 5)",
	}, paths)
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

// TestResourceTable_BracketedFixPathResolvesToLine is the end-to-end case for
// the parser and resolver working together. Before the resolver built its
// expressions from parsed segments, a fix path naming a label key printed with
// no line at all: yq was handed ".metadata.labels[app.kubernetes.io/name]",
// read the dots inside the key as path separators, and failed to parse it.
func TestResourceTable_BracketedFixPathResolvesToLine(t *testing.T) {
	manifest := "apiVersion: apps/v1\n" + // 1
		"kind: Deployment\n" + // 2
		"metadata:\n" + // 3
		"  name: demo\n" + // 4
		"  labels:\n" + // 5
		"    app.kubernetes.io/name: payments\n" // 6

	session := resourceTableLineNumberSession(t, manifest, ":0")
	const resourceID = "apps/v1/default/Deployment/demo"
	result := session.ResourcesResult[resourceID]
	result.AssociatedControls[0].ResourceAssociatedRules[0].Paths = []armotypes.PosturePaths{
		{FixPath: armotypes.FixPath{Path: "metadata.labels[app.kubernetes.io/name]", Value: "payments"}},
	}
	session.ResourcesResult[resourceID] = result

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "metadata.labels[app.kubernetes.io/name]=payments")
	assert.Contains(t, out, "(line 6)")
}

// TestResourceTable_DotQuotedFixPathPointsAtItsOwnLine checks the evidence
// column end to end for the dot-quoted spelling kubescape fix uses. Split at
// the dot inside its quotes, the key was not found and the line reported was
// that of the sibling above it.
func TestResourceTable_DotQuotedFixPathPointsAtItsOwnLine(t *testing.T) {
	manifest := "apiVersion: apps/v1\n" + // 1
		"kind: Deployment\n" + // 2
		"metadata:\n" + // 3
		"  name: demo\n" + // 4
		"  annotations:\n" + // 5
		"    other.io/first: a\n" + // 6
		"    foo.bar/baz: b\n" // 7

	session := resourceTableLineNumberSession(t, manifest, ":0")
	const resourceID = "apps/v1/default/Deployment/demo"
	result := session.ResourcesResult[resourceID]
	result.AssociatedControls[0].ResourceAssociatedRules[0].Paths = []armotypes.PosturePaths{
		{FixPath: armotypes.FixPath{Path: `metadata.annotations."foo.bar/baz"`, Value: "hello"}},
	}
	session.ResourcesResult[resourceID] = result

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "(line 7)")
	assert.NotContains(t, out, "(line 6)")
}

// allPathTypesManifest places each field these tests name on its own line.
const allPathTypesManifest = "apiVersion: apps/v1\n" + // 1
	"kind: Deployment\n" + // 2
	"metadata:\n" + // 3
	"  name: demo\n" + // 4
	"spec:\n" + // 5
	"  template:\n" + // 6
	"    spec:\n" + // 7
	"      hostNetwork: true\n" + // 8
	"      automountServiceAccountToken: true\n" + // 9
	"      containers:\n" + // 10
	"        - name: app\n" + // 11
	"          image: nginx:1\n" + // 12
	"          securityContext:\n" + // 13
	"            privileged: true\n" // 14

const allPathTypesResourceID = "apps/v1/default/Deployment/demo"

// withControlPaths replaces the session's single control's rule paths.
func withControlPaths(session *cautils.OPASessionObj, paths ...armotypes.PosturePaths) {
	result := session.ResourcesResult[allPathTypesResourceID]
	result.AssociatedControls[0].ResourceAssociatedRules[0].Paths = paths
	session.ResourcesResult[allPathTypesResourceID] = result
}

// outputLineWith returns the rendered line carrying needle, failing if none does.
func outputLineWith(t *testing.T, out, needle string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no output line contains %q:\n%s", needle, out)
	return ""
}

// TestResourceTable_EveryPathTypeResolvesToLine is the end-to-end case for each
// path type against a real manifest.
func TestResourceTable_EveryPathTypeResolvesToLine(t *testing.T) {
	session := resourceTableLineNumberSession(t, allPathTypesManifest, ":0")
	withControlPaths(session,
		armotypes.PosturePaths{FixPath: armotypes.FixPath{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		armotypes.PosturePaths{DeletePath: "spec.template.spec.hostNetwork"},
		armotypes.PosturePaths{ReviewPath: "spec.template.spec.automountServiceAccountToken"},
	)

	out := renderResourceTable(t, session, true)

	assert.Contains(t, outputLineWith(t, out, "securityContext.privileged=false"), "(line 14)", "fix path")
	assert.Contains(t, outputLineWith(t, out, "spec.template.spec.hostNetwork"), "(line 8)", "delete path")
	assert.Contains(t, outputLineWith(t, out, "spec.template.spec.automountServiceAccountToken"), "(line 9)", "review path")
}

// TestResourceTable_AbsentReviewAndDeletePathsMatchSARIF covers a review or
// delete path whose field is not in the manifest. It gets its nearest existing
// ancestor's line - the answer SARIF already reports as the review path's
// related location - so both outputs point at the same place.
func TestResourceTable_AbsentReviewAndDeletePathsMatchSARIF(t *testing.T) {
	const (
		absentReview = "spec.template.spec.securityContext.runAsNonRoot"
		absentDelete = "spec.template.spec.hostPID"
	)
	session := resourceTableLineNumberSession(t, allPathTypesManifest, ":0")
	withControlPaths(session,
		armotypes.PosturePaths{ReviewPath: absentReview},
		armotypes.PosturePaths{DeletePath: absentDelete},
	)

	out := renderResourceTable(t, session, true)

	source := session.ResourceSource[allPathTypesResourceID]
	resolver, err := locationresolver.NewPathLocationResolver(filepath.Join(source.Path, source.RelativePath))
	require.NoError(t, err)
	control := session.ResourcesResult[allPathTypesResourceID].AssociatedControls[0]
	sarif := resolveReviewPathLocations(session, resolver, &control, allPathTypesResourceID)
	require.Contains(t, sarif, absentReview, "SARIF should report a related location for the absent review path")

	// Both absent fields sit directly under the pod spec, whose first entry is
	// on line 8.
	assert.Equal(t, 8, sarif[absentReview].Line)
	assert.Contains(t, outputLineWith(t, out, absentReview), fmt.Sprintf("(line %d)", sarif[absentReview].Line))
	assert.Contains(t, outputLineWith(t, out, absentDelete), "(line 8)")
}

// TestResourceTable_ManyControlsKeepOneLinePerPath covers a resource failing
// many controls at once, each naming every path type. Every path must carry
// exactly one line annotation, whichever table layout the width check picks.
func TestResourceTable_ManyControlsKeepOneLinePerPath(t *testing.T) {
	const controlCount = 12
	session := resourceTableLineNumberSession(t, allPathTypesManifest, ":0")

	result := session.ResourcesResult[allPathTypesResourceID]
	result.AssociatedControls = nil
	summaries := reportsummary.ControlSummaries{}
	for i := range controlCount {
		id := fmt.Sprintf("C-%04d", i+1)
		result.AssociatedControls = append(result.AssociatedControls, resourcesresults.ResourceAssociatedControl{
			ControlID: id,
			Name:      "Control " + id,
			Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
				Name:   "rule-" + id,
				Status: apis.StatusFailed,
				Paths: []armotypes.PosturePaths{
					{FixPath: armotypes.FixPath{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
					{DeletePath: "spec.template.spec.hostNetwork"},
					{ReviewPath: "spec.template.spec.automountServiceAccountToken"},
				},
			}},
		})
		summaries[id] = reportsummary.ControlSummary{ControlID: id, Name: "Control " + id, ScoreFactor: 5.0}
	}
	session.ResourcesResult[allPathTypesResourceID] = result
	session.Report.SummaryDetails = reportsummary.SummaryDetails{Controls: summaries}

	out := renderResourceTable(t, session, true)

	assert.Equal(t, 3*controlCount, strings.Count(out, "(line "), "one annotation per path per control")
	assert.Equal(t, controlCount, strings.Count(out, "privileged=false (line 14)"))
	assert.Equal(t, controlCount, strings.Count(out, "spec.template.spec.hostNetwork (line 8)"))
	assert.Equal(t, controlCount, strings.Count(out, "spec.template.spec.automountServiceAccountToken (line 9)"))
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, strings.Count(line, "(line "), 1, "no path annotated twice: %q", line)
	}
}
