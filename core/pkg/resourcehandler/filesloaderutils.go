package resourcehandler

import (
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
)

// providerRank ranks discovery providers so rendered output wins over raw file input.
func providerRank(fileType string) int {
	switch fileType {
	case reporthandling.SourceTypeKustomizeDirectory, reporthandling.SourceTypeHelmChart, "Terraform":
		return 2
	case reporthandling.SourceTypeYaml, reporthandling.SourceTypeJson:
		return 1
	default:
		return 0
	}
}

// resourceIdentity returns the path-independent k8s identity tuple used for dedup.
func resourceIdentity(w workloadinterface.IMetadata) string {
	group, _ := k8sinterface.SplitApiVersion(w.GetApiVersion())
	kind := w.GetKind()
	if cautils.IsBuiltinGroup(group) {
		kind = cautils.NormalizeWorkloadKind(kind)
	}
	return fmt.Sprintf("%s/%s/%s/%s", w.GetApiVersion(), w.GetNamespace(), kind, w.GetName())
}

// dedupWorkloads drops lower-ranked cross-provider duplicates only; same-rank duplicates are kept.
func dedupWorkloads(workloads []workloadinterface.IMetadata, workloadIDToSource map[string]reporthandling.Source) ([]workloadinterface.IMetadata, map[string]reporthandling.Source) {
	maxRank := make(map[string]int, len(workloads))
	for _, w := range workloads {
		key := resourceIdentity(w)
		rank := providerRank(workloadIDToSource[w.GetID()].FileType)
		if rank > maxRank[key] {
			maxRank[key] = rank
		}
	}

	out := make([]workloadinterface.IMetadata, 0, len(workloads))
	pruned := make(map[string]reporthandling.Source, len(workloads))
	for _, w := range workloads {
		rank := providerRank(workloadIDToSource[w.GetID()].FileType)
		if rank == maxRank[resourceIdentity(w)] {
			out = append(out, w)
			if s, ok := workloadIDToSource[w.GetID()]; ok {
				pruned[w.GetID()] = s
			}
		}
	}
	return out, pruned
}

func addWorkloadsToResourcesMap(allResources map[string][]workloadinterface.IMetadata, workloads []workloadinterface.IMetadata) {
	for i := range workloads {
		workload := workloads[i]
		group, version := k8sinterface.SplitApiVersion(workload.GetApiVersion())
		resourceTriplets := offlineManifestResourceTriplets(group, version, workload.GetKind())
		if len(resourceTriplets) == 0 {
			logger.L().Warning("unable to resolve object resource", helpers.String("kind", workload.GetKind()), helpers.String("id", workload.GetID()))
			continue
		}

		for _, resourceTriplet := range resourceTriplets {
			allResources[resourceTriplet] = append(allResources[resourceTriplet], workload)
		}
	}
}

func offlineManifestResourceTriplets(group, version, kind string) []string {
	if version == "" || kind == "" {
		return nil
	}

	aliases := offlineManifestResourceAliases(kind)

	triplets := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		triplets = append(triplets, k8sinterface.JoinResourceTriplets(group, version, alias))
	}
	return triplets
}

// offlineManifestResourceAliases returns comparison keys for file indexing.
// They are never used to construct live API requests, so retaining all common
// candidates is safer than guessing one plural without CRD discovery data.
func offlineManifestResourceAliases(kind string) []string {
	singular := strings.ToLower(kind)
	aliases := []string{singular}
	if strings.HasSuffix(singular, "s") {
		return append(aliases, singular+"es")
	}

	aliases = append(aliases, singular+"s")
	if strings.HasSuffix(singular, "x") || strings.HasSuffix(singular, "z") ||
		strings.HasSuffix(singular, "ch") || strings.HasSuffix(singular, "sh") {
		aliases = append(aliases, singular+"es")
	}
	if n := len(singular); n >= 2 && singular[n-1] == 'y' &&
		!strings.ContainsRune("aeiou", rune(singular[n-2])) {
		aliases = append(aliases, singular[:n-1]+"ies")
	}
	return aliases
}

/* unused for now
func addCommitData(input string, workloadIDToSource map[string]reporthandling.Source) {
	giRepo, err := cautils.NewLocalGitRepository(input)
	if err != nil || giRepo == nil {
		return
	}
	for k := range workloadIDToSource {
		sourceObj := workloadIDToSource[k]
		lastCommit, err := giRepo.GetFileLastCommit(sourceObj.RelativePath)
		if err != nil {
			continue
		}
		sourceObj.LastCommit = reporthandling.LastCommit{
			Hash:           lastCommit.SHA,
			Date:           lastCommit.Author.Date,
			CommitterName:  lastCommit.Author.Name,
			CommitterEmail: lastCommit.Author.Email,
			Message:        lastCommit.Message,
		}
		workloadIDToSource[k] = sourceObj
	}
}
*/

// findScanObjectResource finds the requested k8s object to be scanned in the resources map
func findScanObjectResource(mappedResources map[string][]workloadinterface.IMetadata, resource *objectsenvelopes.ScanObject) (workloadinterface.IWorkload, error) {
	if resource == nil {
		return nil, nil
	}

	logger.L().Debug("Single resource scan", helpers.String("resource", resource.GetID()))

	collectMatches := func(kindPredicate func(r workloadinterface.IMetadata) bool) []workloadinterface.IWorkload {
		var wls []workloadinterface.IWorkload
		seenResources := make(map[string]struct{})
		for _, resources := range mappedResources {
			for _, r := range resources {
				// File-loaded resource IDs include their source path, so aliases of
				// one object collapse while distinct manifests remain distinguishable.
				if _, seen := seenResources[r.GetID()]; seen {
					continue
				}
				if r.GetName() != resource.GetName() {
					continue
				}
				if resource.GetNamespace() != "" && resource.GetNamespace() != r.GetNamespace() {
					continue
				}
				if resource.GetApiVersion() != "" && !strings.EqualFold(resource.GetApiVersion(), r.GetApiVersion()) {
					continue
				}
				if !kindPredicate(r) {
					continue
				}

				if k8sinterface.IsTypeWorkload(r.GetObject()) {
					wl := workloadinterface.NewWorkloadObj(r.GetObject())
					wls = append(wls, wl)
					seenResources[r.GetID()] = struct{}{}
				}
			}
		}
		return wls
	}

	// Pass 1: Direct case-insensitive match on the requested kind.
	// This preserves bare CRD Kinds (e.g. Deploy for an example.com/v1 resource)
	// without alias normalization colliding or rewriting the kind.
	wls := collectMatches(func(r workloadinterface.IMetadata) bool {
		return strings.EqualFold(r.GetKind(), resource.GetKind())
	})

	// Pass 2: Fallback alias normalization for built-in Kubernetes resources.
	// If direct matching finds no candidates and the requested kind is a recognized
	// alias/short name for a built-in workload (e.g. "deploy", "po", "ds"), attempt
	// matching against built-in API group resources with the canonical kind.
	if len(wls) == 0 {
		normalizedKind := cautils.NormalizeWorkloadKind(resource.GetKind())
		if !strings.EqualFold(normalizedKind, resource.GetKind()) {
			wls = collectMatches(func(r workloadinterface.IMetadata) bool {
				group, _ := k8sinterface.SplitApiVersion(r.GetApiVersion())
				return cautils.IsBuiltinGroup(group) && strings.EqualFold(r.GetKind(), normalizedKind)
			})
		}
	}

	if len(wls) == 0 {
		return nil, fmt.Errorf("k8s resource '%s' not found", k8sinterface.GetReadableID(resource))
	} else if len(wls) > 1 {
		return nil, fmt.Errorf("more than one k8s resource found for '%s'", k8sinterface.GetReadableID(resource))
	}

	return wls[0], nil
}


