package printer

import (
	"context"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/locationresolver"
	"github.com/sergi/go-diff/diffmatchpatch"
)

// fixRegion is one replacement a fix produces: a region of the manifest and the
// text that replaces it.
type fixRegion struct {
	startLine   int
	startColumn int
	endLine     int
	endColumn   int
	text        string
}

// fixCacheKey identifies one yq expression applied to one manifest. Both halves
// matter: regions differ per file and per expression.
type fixCacheKey struct {
	path       string
	expression string
}

// readResult keeps a read with its error, so a failed read is answered from the
// cache rather than retried per finding.
type readResult struct {
	content string
	err     error
}

// fixReportCache memoizes the per-file work that report generation would
// otherwise repeat for every finding: the read, the location resolver, and the
// regions a fix expression produces. None of it depends on which finding asked,
// and every pass covers the whole file, so uncached the cost grew with resources
// times controls times file size. Report generation only reads, so a repeat
// lookup has the same answer. One cache per report.
type fixReportCache struct {
	reads     map[string]readResult
	resolvers map[string]*locationresolver.FixPathLocationResolver
	regions   map[fixCacheKey][]fixRegion
}

// scannedResource is one failed resource paired with the manifest it came from.
type scannedResource struct {
	resourceID string
	relPath    string
	absPath    string
}

// groupByManifest orders failed resources so every resource of one manifest is
// visited consecutively, which is what lets a cache serve a whole file and then
// be dropped. Held across the report instead, the caches would retain a decoded
// document tree per file, making memory proportional to everything scanned
// rather than to the largest file. Sorting also makes the report order
// deterministic, which map iteration was not.
func groupByManifest(resources []scannedResource) []scannedResource {
	ordered := slices.Clone(resources)
	slices.SortFunc(ordered, func(a, b scannedResource) int {
		if a.absPath != b.absPath {
			return strings.Compare(a.absPath, b.absPath)
		}
		return strings.Compare(a.resourceID, b.resourceID)
	})
	return ordered
}

// manifestCache hands out one cache per manifest, dropping the previous one when
// the walk reaches the next file, so only one manifest's decoded documents are
// held at a time. Callers must visit a manifest's resources consecutively.
type manifestCache struct {
	path    string
	current *fixReportCache
}

func (m *manifestCache) get(path string) *fixReportCache {
	if m.current == nil || m.path != path {
		m.path = path
		m.current = newFixReportCache()
	}
	return m.current
}

func newFixReportCache() *fixReportCache {
	return &fixReportCache{
		reads:     make(map[string]readResult),
		resolvers: make(map[string]*locationresolver.FixPathLocationResolver),
		regions:   make(map[fixCacheKey][]fixRegion),
	}
}

// fileString returns a manifest's content, reading it from disk on first use.
func (c *fixReportCache) fileString(path string) (string, error) {
	if cached, ok := c.reads[path]; ok {
		return cached.content, cached.err
	}

	content, err := fixhandler.GetFileString(path)
	if err != nil {
		logger.L().Debug("failed to access "+path, helpers.Error(err))
	}
	c.reads[path] = readResult{content: content, err: err}
	return content, err
}

// locationResolver returns a manifest's location resolver, building it on first
// use. One per file is enough: it decodes every document up front and selects
// between them by index, so it is the file's resolver, not a resource's. format
// only names the output format in the warning. A failure caches a nil resolver,
// which resolveFixLocation already reads as "fall back to line 1".
func (c *fixReportCache) locationResolver(path, format string) *locationresolver.FixPathLocationResolver {
	if resolver, ok := c.resolvers[path]; ok {
		return resolver
	}

	resolver, err := locationresolver.NewFixPathLocationResolver(path)
	if err != nil {
		logger.L().Warning("failed to create location resolver, "+format+" locations will default to line 1", helpers.Error(err))
		resolver = nil
	}
	c.resolvers[path] = resolver
	return resolver
}

// fixRegions returns the regions applying one fix expression to one manifest
// produces, computing them on first use. An expression that cannot be applied
// caches an empty set, so it is diagnosed once rather than per control.
func (c *fixReportCache) fixRegions(ctx context.Context, path, expression string) []fixRegion {
	key := fixCacheKey{path: path, expression: expression}
	if regions, ok := c.regions[key]; ok {
		return regions
	}

	regions := c.computeFixRegions(ctx, path, expression)
	c.regions[key] = regions
	return regions
}

func (c *fixReportCache) computeFixRegions(ctx context.Context, path, expression string) []fixRegion {
	fileAsString, err := c.fileString(path)
	if err != nil {
		return nil
	}

	fixedYamlString, err := fixhandler.ApplyFixToContent(ctx, fileAsString, expression)
	if err != nil {
		logger.L().Debug("failed to fix "+path+" with "+expression, helpers.Error(err))
		return nil
	}

	dmp := diffmatchpatch.New()
	return diffRegions(dmp, dmp.DiffMain(fileAsString, fixedYamlString, false), fileAsString)
}
