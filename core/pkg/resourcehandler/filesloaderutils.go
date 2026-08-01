package resourcehandler

import (
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
)

// providerRank ranks discovery providers so rendered output wins over raw file input.
func providerRank(fileType string) int {
	switch fileType {
	case reporthandling.SourceTypeKustomizeDirectory, reporthandling.SourceTypeHelmChart:
		return 2
	case reporthandling.SourceTypeYaml, reporthandling.SourceTypeJson:
		return 1
	default:
		return 0
	}
}

// resourceIdentity returns the path-independent k8s identity tuple used for dedup.
func resourceIdentity(w workloadinterface.IMetadata) string {
	return fmt.Sprintf("%s/%s/%s/%s", w.GetApiVersion(), w.GetNamespace(), w.GetKind(), w.GetName())
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
		canonical, canonicalErr := k8sinterface.GetGroupVersionResource(workload.GetKind())

		var resourceTriplets []string
		if canonicalErr == nil && isBuiltInAPIGroup(group) {
			if canonical.Group != group || canonical.Version != version {
				logger.L().Warning("workload GroupVersion mismatch", helpers.String("id", workload.GetID()), helpers.String("kind", workload.GetKind()), helpers.String("expectedGroup", canonical.Group), helpers.String("actualGroup", group), helpers.String("expectedVersion", canonical.Version), helpers.String("actualVersion", version))
				continue
			}
			resourceTriplets = []string{k8sinterface.JoinResourceTriplets(canonical.Group, canonical.Version, canonical.Resource)}
		} else {
			resourceTriplets = offlineManifestResourceTriplets(group, version, workload.GetKind())
			if len(resourceTriplets) == 0 {
				logger.L().Warning("unable to resolve object resource", helpers.String("kind", workload.GetKind()), helpers.String("id", workload.GetID()))
				continue
			}
			logger.L().Debug("using manifest identity for custom resource unavailable in discovery",
				helpers.String("kind", workload.GetKind()), helpers.String("id", workload.GetID()))
		}

		for _, resourceTriplet := range resourceTriplets {
			allResources[resourceTriplet] = append(allResources[resourceTriplet], workload)
		}
	}
}

func offlineManifestResourceTriplets(group, version, kind string) []string {
	if group == "" || version == "" || kind == "" {
		return nil
	}

	singular := strings.ToLower(kind)
	aliases := []string{singular}
	switch singular {
	case "ingress":
		aliases = append(aliases, "ingresses")
	case "storageclass":
		aliases = append(aliases, "storageclasses")
	default:
		if !strings.HasSuffix(singular, "s") {
			if strings.HasSuffix(singular, "y") {
				aliases = append(aliases, strings.TrimSuffix(singular, "y")+"ies")
			} else {
				// Preserve the k8s-interface comparison form while also accepting
				// the conventional plural commonly declared by CRDs such as
				// Sandbox (sandboxes). These are file-index aliases only and are
				// never used to construct a live API query.
				aliases = append(aliases, singular+"s")
				if strings.HasSuffix(singular, "x") || strings.HasSuffix(singular, "ch") ||
					strings.HasSuffix(singular, "sh") || strings.HasSuffix(singular, "ss") {
					aliases = append(aliases, singular+"es")
				}
			}
		}
	}

	triplets := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		triplets = append(triplets, k8sinterface.JoinResourceTriplets(group, version, alias))
	}
	return triplets
}

func isBuiltInAPIGroup(group string) bool {
	// A Kind that collides with a built-in Kind is only treated as built-in when
	// its manifest group is an actual Kubernetes API group. A different custom
	// group (for example serving.knative.dev/v1 Service) belongs on the CRD path.
	switch group {
	case "", "admissionregistration.k8s.io", "apiextensions.k8s.io", "apiregistration.k8s.io",
		"apps", "authentication.k8s.io", "authorization.k8s.io", "autoscaling", "batch",
		"certificates.k8s.io", "coordination.k8s.io", "discovery.k8s.io", "events.k8s.io",
		"extensions", "flowcontrol.apiserver.k8s.io", "internal.apiserver.k8s.io", "migration.k8s.io",
		"networking.k8s.io", "node.k8s.io", "policy", "rbac.authorization.k8s.io",
		"resource.k8s.io", "scheduling.k8s.io", "storage.k8s.io", "storagemigration.k8s.io":
		return true
	default:
		return false
	}
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

	var wls []workloadinterface.IWorkload
	for _, resources := range mappedResources {
		for _, r := range resources {
			if r.GetKind() == resource.GetKind() && r.GetName() == resource.GetName() {
				if resource.GetNamespace() != "" && resource.GetNamespace() != r.GetNamespace() {
					continue
				}
				if resource.GetApiVersion() != "" && resource.GetApiVersion() != r.GetApiVersion() {
					continue
				}

				if k8sinterface.IsTypeWorkload(r.GetObject()) {
					wl := workloadinterface.NewWorkloadObj(r.GetObject())
					wls = append(wls, wl)
				}
			}
		}
	}

	if len(wls) == 0 {
		return nil, fmt.Errorf("k8s resource '%s' not found", getReadableID(resource))
	} else if len(wls) > 1 {
		return nil, fmt.Errorf("more than one k8s resource found for '%s'", getReadableID(resource))
	}

	return wls[0], nil
}

// TODO: move this to k8s-interface
func getReadableID(obj *objectsenvelopes.ScanObject) string {
	var ID string
	if obj.GetApiVersion() != "" {
		ID += fmt.Sprintf("%s/", k8sinterface.JoinGroupVersion(k8sinterface.SplitApiVersion(obj.GetApiVersion())))
	}

	if obj.GetNamespace() != "" {
		ID += fmt.Sprintf("%s/", obj.GetNamespace())
	}

	ID += fmt.Sprintf("%s/%s", obj.GetKind(), obj.GetName())

	return ID
}
