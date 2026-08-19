package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fix paths every generated document fails on, so the same fix is reported by
// more than one control and document.
const (
	privilegedFixPath = "spec.template.spec.containers[0].securityContext.privileged"
	replicasFixPath   = "spec.replicas"
)

// writeManifest writes nDocs Deployment documents into one manifest and returns
// its path plus the 1-based start line of each document.
func writeManifest(t *testing.T, nDocs int) (string, []int) {
	t.Helper()

	var sb strings.Builder
	starts := make([]int, 0, nDocs)
	lines := 0
	for i := 0; i < nDocs; i++ {
		if i > 0 {
			sb.WriteString("---\n")
			lines++
		}
		starts = append(starts, lines+1)

		doc := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-%d
  namespace: default
spec:
  replicas: 1
  selector: {matchLabels: {app: demo-%d}}
  template:
    metadata: {labels: {app: demo-%d}}
    spec:
      containers:
      - name: app
        image: nginx:1.23
        securityContext: {privileged: true}
`, i, i, i)
		sb.WriteString(doc)
		lines += strings.Count(doc, "\n")
	}

	path := filepath.Join(t.TempDir(), "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(sb.String()), 0600))
	return path, starts
}

// documentForLine returns the index of the document a 1-based line falls in.
func documentForLine(starts []int, line int) int {
	index := -1
	for i, start := range starts {
		if line >= start {
			index = i
		}
	}
	return index
}

func TestFixReportCache_FileStringReadsFileOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, os.WriteFile(path, []byte("kind: Pod\n"), 0600))

	cache := newFixReportCache()
	first, err := cache.fileString(path)
	require.NoError(t, err)
	assert.Equal(t, "kind: Pod\n", first)

	// a re-read would pick this up, a cache hit cannot
	require.NoError(t, os.WriteFile(path, []byte("kind: Service\n"), 0600))

	second, err := cache.fileString(path)
	require.NoError(t, err)
	assert.Equal(t, first, second, "the manifest must be read once per report, not once per finding")
}

func TestFixReportCache_FileStringCachesFailedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	cache := newFixReportCache()
	_, err := cache.fileString(path)
	require.Error(t, err)

	// creating the file afterwards must not resurrect it: a failed read is an
	// answer too
	require.NoError(t, os.WriteFile(path, []byte("kind: Pod\n"), 0600))

	content, err := cache.fileString(path)
	require.Error(t, err)
	assert.Empty(t, content)
}

// TestFixReportCache_LocationResolverMatchesFreshResolver guards sharing one
// resolver across a file's resources. A resolver evaluates against yaml nodes it
// holds, so sharing is only safe if evaluation leaves them alone. Each lookup is
// compared against a fresh resolver, so a mutated tree disagrees here.
func TestFixReportCache_LocationResolverMatchesFreshResolver(t *testing.T) {
	const nDocs = 3
	path, starts := writeManifest(t, nDocs)

	cache := newFixReportCache()
	shared := cache.locationResolver(path, "SARIF")
	require.NotNil(t, shared)
	assert.Same(t, shared, cache.locationResolver(path, "SARIF"), "one resolver per file, not per resource")

	// documents in order, then back to the first, then a path that does not exist
	lookups := []struct {
		fixPath  string
		docIndex int
	}{
		{privilegedFixPath, 0},
		{privilegedFixPath, 1},
		{privilegedFixPath, 2},
		{privilegedFixPath, 0},
		{replicasFixPath, 1},
		{"spec.template.spec.containers[0].securityContext.doesNotExist", 2},
	}

	for _, lookup := range lookups {
		t.Run(fmt.Sprintf("%s@%d", lookup.fixPath, lookup.docIndex), func(t *testing.T) {
			fresh, err := locationresolver.NewFixPathLocationResolver(path)
			require.NoError(t, err)
			want, err := fresh.ResolveLocation(lookup.fixPath, lookup.docIndex)
			require.NoError(t, err)

			got, err := shared.ResolveLocation(lookup.fixPath, lookup.docIndex)
			require.NoError(t, err)

			assert.Equal(t, want, got, "shared resolver must resolve as a fresh one does")
			assert.Equal(t, lookup.docIndex, documentForLine(starts, got.Line),
				"line %d must fall in document %d", got.Line, lookup.docIndex)
		})
	}
}

func TestFixReportCache_LocationResolverCachesFailure(t *testing.T) {
	cache := newFixReportCache()
	missing := filepath.Join(t.TempDir(), "missing.yaml")

	assert.Nil(t, cache.locationResolver(missing, "SARIF"))
	assert.Nil(t, cache.locationResolver(missing, "SARIF"))
	assert.Len(t, cache.resolvers, 1, "a failure is an answer and is cached like one")
}

func TestFixReportCache_FixRegionsCachedPerExpression(t *testing.T) {
	path, _ := writeManifest(t, 2)
	ctx := context.Background()

	cache := newFixReportCache()
	doc0 := cache.fixRegions(ctx, path, fixhandler.DocumentFix{DocumentIndex: 0, Fix: armotypes.FixPath{Path: privilegedFixPath, Value: "false"}})
	doc1 := cache.fixRegions(ctx, path, fixhandler.DocumentFix{DocumentIndex: 1, Fix: armotypes.FixPath{Path: privilegedFixPath, Value: "false"}})

	require.NotEmpty(t, doc0)
	require.NotEmpty(t, doc1)
	assert.NotEqual(t, doc0, doc1, "the document index is part of the key, so each document gets its own regions")

	// removing the file proves the repeat came from the cache rather than disk
	require.NoError(t, os.Remove(path))
	assert.Equal(t, doc0, cache.fixRegions(ctx, path, fixhandler.DocumentFix{DocumentIndex: 0, Fix: armotypes.FixPath{Path: privilegedFixPath, Value: "false"}}))
	assert.Len(t, cache.regions, 2)
}

func TestFixReportCache_FixRegionsCachesUnappliableExpression(t *testing.T) {
	path, _ := writeManifest(t, 1)
	ctx := context.Background()

	cache := newFixReportCache()
	assert.Empty(t, cache.fixRegions(ctx, path, fixhandler.DocumentFix{Fix: armotypes.FixPath{Path: "this is not a yq expression", Value: ""}}))
	assert.Len(t, cache.regions, 1, "an expression that cannot be applied is diagnosed once, not once per control")
}

func TestAddFixRegions_DeduplicatesIdenticalRegions(t *testing.T) {
	result := sarif.NewRuleResult("rule")
	region := fixRegion{startLine: 3, startColumn: 1, endLine: 3, endColumn: 8, text: "false"}

	addFixRegions(result, "deploy.yaml", []fixRegion{region, region})

	assert.Len(t, result.Fixes, 1, "the same region reported twice is one fix")
}

// TestPrintConfigurationScan_MultiDocumentFixesPerDocument covers the report the
// cache serves: many documents in one file, each failing two controls, one fix
// path shared and one per document. Every finding stays anchored to its own.
func TestPrintConfigurationScan_MultiDocumentFixesPerDocument(t *testing.T) {
	const nDocs = 3
	manifestPath, starts := writeManifest(t, nDocs)
	manifestDir := filepath.Dir(manifestPath)

	sharedControlID := "C-0001"
	perDocControlID := "C-0002"

	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Directory},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{BasePath: manifestDir},
		},
	}
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				sharedControlID: reportsummary.ControlSummary{
					ControlID: sharedControlID, Name: "Privileged container", ScoreFactor: 8.0,
				},
				perDocControlID: reportsummary.ControlSummary{
					ControlID: perDocControlID, Name: "Replica count", ScoreFactor: 4.0,
				},
			},
		},
	}
	session.ResourceSource = map[string]reporthandling.Source{}

	failedControl := func(controlID, fixPath, value string) resourcesresults.ResourceAssociatedControl {
		return resourcesresults.ResourceAssociatedControl{
			ControlID: controlID,
			Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
				Name:   "rule-" + controlID,
				Status: apis.StatusFailed,
				Paths: []armotypes.PosturePaths{{
					FixPath: armotypes.FixPath{Path: fixPath, Value: value},
				}},
			}},
		}
	}

	for i := 0; i < nDocs; i++ {
		resourceID := fmt.Sprintf("apps/v1/Deployment/default/demo-%d", i)
		lw := localworkload.NewLocalWorkload(map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": fmt.Sprintf("demo-%d", i), "namespace": "default"},
			"spec":       map[string]interface{}{},
		})
		lw.SetPath(fmt.Sprintf("deploy.yaml:%d", i))

		session.ResourcesResult[resourceID] = resourcesresults.Result{
			ResourceID: resourceID,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl(sharedControlID, privilegedFixPath, "false"),
				failedControl(perDocControlID, replicasFixPath, "2"),
			},
		}
		session.ResourceSource[resourceID] = reporthandling.Source{
			Path: manifestDir, RelativePath: "deploy.yaml", FileType: reporthandling.SourceTypeYaml,
		}
		session.AllResources[resourceID] = lw
	}

	out, err := os.CreateTemp(t.TempDir(), "multidoc-*.sarif")
	require.NoError(t, err)
	defer out.Close()

	sp := NewSARIFPrinter()
	sp.writer = out
	require.NoError(t, sp.printConfigurationScan(context.Background(), session))

	raw, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, nDocs*2, "every failed control on every document is reported")

	// each document owns a band of lines, so a finding that picked up another
	// document's location or fix region lands outside its band
	perDocument := map[int]int{}
	for _, result := range report.Runs[0].Results {
		require.NotEmpty(t, result.Locations)
		require.NotNil(t, result.Locations[0].PhysicalLocation.Region)
		startLine := *result.Locations[0].PhysicalLocation.Region.StartLine

		docIndex := documentForLine(starts, startLine)
		require.GreaterOrEqual(t, docIndex, 0, "location line %d is outside every document", startLine)
		perDocument[docIndex]++
		assert.NotEqual(t, 1, startLine, "locations must resolve, not fall back to line 1")

		require.NotEmpty(t, result.Fixes, "a failed control with a fix path reports a fix")
		for _, fix := range result.Fixes {
			for _, change := range fix.ArtifactChanges {
				require.NotEmpty(t, change.Replacements)
				fixLine := *change.Replacements[0].DeletedRegion.StartLine
				assert.Equal(t, docIndex, documentForLine(starts, fixLine),
					"fix region on line %d belongs to a different document than its finding on line %d", fixLine, startLine)
			}
		}
	}

	for i := 0; i < nDocs; i++ {
		assert.Equal(t, 2, perDocument[i], "document %d must report both of its failed controls", i)
	}
}

// BenchmarkPrintConfigurationScan tracks report generation as the document and
// control counts grow; both used to multiply a whole-file read, parse and diff.
// The two fix shapes bound what caching recovers: distinct paths share only the
// reads and the decode, a shared path shares the applied fix and its diff too.
func BenchmarkPrintConfigurationScan(b *testing.B) {
	for _, tc := range []struct {
		docs      int
		controls  int
		sharedFix bool
		fixShape  string
	}{
		{10, 10, false, "distinct-fixes"},
		{20, 10, false, "distinct-fixes"},
		{40, 10, false, "distinct-fixes"},
		{80, 10, false, "distinct-fixes"},
		{10, 10, true, "shared-fixes"},
		{20, 10, true, "shared-fixes"},
		{40, 10, true, "shared-fixes"},
		{80, 10, true, "shared-fixes"},
	} {
		b.Run(fmt.Sprintf("docs=%d/controls=%d/%s", tc.docs, tc.controls, tc.fixShape), func(b *testing.B) {
			session := benchmarkSession(b, tc.docs, tc.controls, tc.sharedFix)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := os.CreateTemp(b.TempDir(), "bench-*.sarif")
				require.NoError(b, err)
				sp := NewSARIFPrinter()
				sp.writer = out
				require.NoError(b, sp.printConfigurationScan(context.Background(), session))
				require.NoError(b, out.Close())
			}
		})
	}
}

// benchmarkSession builds a session over one manifest of nDocs documents, each
// failing nControls controls. sharedFix decides one fix path between them or one
// each.
func benchmarkSession(b *testing.B, nDocs, nControls int, sharedFix bool) *cautils.OPASessionObj {
	b.Helper()

	var sb strings.Builder
	for i := 0; i < nDocs; i++ {
		if i > 0 {
			sb.WriteString("---\n")
		}
		fmt.Fprintf(&sb, `apiVersion: apps/v1
kind: Deployment
metadata: {name: demo-%d, namespace: default}
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.23
        securityContext: {privileged: true}
`, i)
	}
	dir := b.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	require.NoError(b, os.WriteFile(path, []byte(sb.String()), 0600))

	summaries := reportsummary.ControlSummaries{}
	for c := 0; c < nControls; c++ {
		id := fmt.Sprintf("C-%04d", c)
		summaries[id] = reportsummary.ControlSummary{ControlID: id, Name: "control " + id, ScoreFactor: 8.0}
	}

	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Directory},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{BasePath: dir},
		},
	}
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{Controls: summaries},
	}
	session.ResourceSource = map[string]reporthandling.Source{}

	for i := 0; i < nDocs; i++ {
		resourceID := fmt.Sprintf("apps/v1/Deployment/default/demo-%d", i)
		lw := localworkload.NewLocalWorkload(map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": fmt.Sprintf("demo-%d", i), "namespace": "default"},
			"spec":       map[string]interface{}{},
		})
		lw.SetPath(fmt.Sprintf("deploy.yaml:%d", i))

		controls := make([]resourcesresults.ResourceAssociatedControl, 0, nControls)
		for c := 0; c < nControls; c++ {
			fixPath := privilegedFixPath
			fixValue := "false"
			if !sharedFix {
				fixPath = fmt.Sprintf("spec.template.spec.containers[0].env[%d].name", c)
				fixValue = fmt.Sprintf("VAR_%d", c)
			}

			controls = append(controls, resourcesresults.ResourceAssociatedControl{
				ControlID: fmt.Sprintf("C-%04d", c),
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name:   fmt.Sprintf("rule-%d", c),
					Status: apis.StatusFailed,
					Paths: []armotypes.PosturePaths{{
						FixPath: armotypes.FixPath{Path: fixPath, Value: fixValue},
					}},
				}},
			})
		}

		session.ResourcesResult[resourceID] = resourcesresults.Result{
			ResourceID:         resourceID,
			AssociatedControls: controls,
		}
		session.ResourceSource[resourceID] = reporthandling.Source{
			Path: dir, RelativePath: "deploy.yaml", FileType: reporthandling.SourceTypeYaml,
		}
		session.AllResources[resourceID] = lw
	}

	return session
}

func TestGroupByManifest_VisitsEachManifestConsecutively(t *testing.T) {
	resources := []scannedResource{
		{resourceID: "r3", absPath: "/repo/b.yaml"},
		{resourceID: "r1", absPath: "/repo/a.yaml"},
		{resourceID: "r4", absPath: "/repo/b.yaml"},
		{resourceID: "r2", absPath: "/repo/a.yaml"},
	}

	ordered := groupByManifest(resources)

	paths := make([]string, 0, len(ordered))
	ids := make([]string, 0, len(ordered))
	for _, resource := range ordered {
		paths = append(paths, resource.absPath)
		ids = append(ids, resource.resourceID)
	}

	assert.Equal(t, []string{"/repo/a.yaml", "/repo/a.yaml", "/repo/b.yaml", "/repo/b.yaml"}, paths)
	assert.Equal(t, []string{"r1", "r2", "r3", "r4"}, ids, "resources of a manifest are ordered, so the report is deterministic")

	seen := map[string]bool{}
	previous := ""
	for _, resource := range ordered {
		if resource.absPath != previous {
			require.False(t, seen[resource.absPath], "manifest %s is revisited after moving on", resource.absPath)
			seen[resource.absPath] = true
			previous = resource.absPath
		}
	}
}

// TestManifestCache_HoldsOneManifestAtATime is the memory guard: a cache kept for
// the whole report retains a decoded document tree per file, so it must be
// dropped when the walk reaches the next manifest.
func TestManifestCache_HoldsOneManifestAtATime(t *testing.T) {
	var caches manifestCache

	first := caches.get("/repo/a.yaml")
	assert.Same(t, first, caches.get("/repo/a.yaml"), "the same manifest reuses its cache")

	second := caches.get("/repo/b.yaml")
	assert.NotSame(t, first, second, "a new manifest starts a fresh cache")

	assert.NotSame(t, second, caches.get("/repo/a.yaml"), "returning to a manifest does not resurrect its cache")
}
