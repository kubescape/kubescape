package resourcehandler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// parseKindSet splits a comma-separated kind list into a normalised (lowercase)
// set. An empty input returns a nil map so callers can use a cheap len() guard.
func parseKindSet(kinds string) map[string]struct{} {
	if kinds == "" {
		return nil
	}
	set := make(map[string]struct{})
	for _, k := range strings.Split(kinds, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			set[strings.ToLower(k)] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// kindFilters is the parsed --include-kinds/--exclude-kinds pair. Parsing the
// flags once keeps query planning and the post-collection pass reading them the
// same way.
type kindFilters struct {
	include map[string]struct{}
	exclude map[string]struct{}
}

func newKindFilters(scanInfo *cautils.ScanInfo) kindFilters {
	return kindFilters{
		include: parseKindSet(scanInfo.IncludeKinds),
		exclude: parseKindSet(scanInfo.ExcludeKinds),
	}
}

func (f kindFilters) active() bool {
	return f.include != nil || f.exclude != nil
}

func (f kindFilters) allows(kind string) bool {
	return kindAllowed(strings.ToLower(kind), f.include, f.exclude)
}

// filterQueryableResourcesByKind drops the queries whose Kind the filters
// reject. Pruning only after collection still listed every excluded kind
// cluster-wide, and a listing that failed reached InfoMap, where
// BuildScanCoverage docks the coverage score over a kind the scan was told to
// leave out.
//
// A query whose Kind the resolver could not name is kept; applyKindFilter still
// prunes its objects after collection.
func filterQueryableResourcesByKind(queryableResources QueryableResources, scanInfo *cautils.ScanInfo) {
	filters := newKindFilters(scanInfo)
	if !filters.active() {
		return
	}

	skipped := make(map[string]struct{})
	for key := range queryableResources {
		kind := queryableResources[key].Kind
		if kind == "" || filters.allows(kind) {
			continue
		}
		skipped[queryableResources[key].GroupVersionResourceTriplet] = struct{}{}
		delete(queryableResources, key)
	}
	if len(skipped) == 0 {
		return
	}

	triplets := make([]string, 0, len(skipped))
	for triplet := range skipped {
		triplets = append(triplets, triplet)
	}
	sort.Strings(triplets)
	logger.L().Debug("kind filter skipped resource queries",
		helpers.String("skipped", strings.Join(triplets, ",")),
		helpers.String("include", scanInfo.IncludeKinds),
		helpers.String("exclude", scanInfo.ExcludeKinds),
	)
}

// kindAllowed reports whether kind (already lowercased) passes the include/exclude
// filters. When include is non-nil only listed kinds pass; when exclude is
// non-nil listed kinds are rejected. Both filters may be active simultaneously:
// include is checked first, then exclude.
func kindAllowed(kind string, include, exclude map[string]struct{}) bool {
	if include != nil {
		if _, ok := include[kind]; !ok {
			return false
		}
	}
	if exclude != nil {
		if _, ok := exclude[kind]; ok {
			return false
		}
	}
	return true
}

// applyKindFilter removes resources that do not satisfy the kind filters
// expressed by scanInfo.IncludeKinds and scanInfo.ExcludeKinds. It modifies
// both allResources (the full object store) and k8sResources (the GVR→ID
// index) so that downstream OPA evaluation never sees a filtered-out resource.
//
// singleScan is the explicit workload targeted by a single-resource scan
// (sessionObj.SingleResourceScan). When non-nil and its kind would be excluded
// by the active filters the function returns an error instead of silently
// dropping the requested target — a silent drop produces a false-negative that
// reads as "nothing to report" rather than "nothing was scanned".
//
// When neither flag is set the function is a no-op.
func applyKindFilter(
	k8sResources cautils.K8SResources,
	allResources map[string]workloadinterface.IMetadata,
	scanInfo *cautils.ScanInfo,
	singleScan workloadinterface.IMetadata,
) error {
	filters := newKindFilters(scanInfo)
	if !filters.active() {
		return nil
	}

	if singleScan != nil {
		if !filters.allows(singleScan.GetKind()) {
			return fmt.Errorf(
				"kind filter excludes the explicitly requested scan target %q (kind: %s); "+
					"adjust --include-kinds / --exclude-kinds or remove the conflicting filter",
				singleScan.GetName(), singleScan.GetKind(),
			)
		}
	}

	removed := make(map[string]struct{})
	for id, res := range allResources {
		if !filters.allows(res.GetKind()) {
			removed[id] = struct{}{}
			delete(allResources, id)
		}
	}

	if len(removed) == 0 {
		return nil
	}

	logger.L().Debug("kind filter removed resources",
		helpers.Int("count", len(removed)),
		helpers.String("include", scanInfo.IncludeKinds),
		helpers.String("exclude", scanInfo.ExcludeKinds),
	)

	for gvr, ids := range k8sResources {
		kept := ids[:0]
		for _, id := range ids {
			if _, drop := removed[id]; !drop {
				kept = append(kept, id)
			}
		}
		if len(kept) == 0 {
			delete(k8sResources, gvr)
		} else {
			k8sResources[gvr] = kept
		}
	}
	return nil
}
