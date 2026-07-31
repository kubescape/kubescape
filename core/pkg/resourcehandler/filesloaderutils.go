package resourcehandler

import (
	"fmt"

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
		group, version := k8sinterface.SplitApiVersion(workloads[i].GetApiVersion())
		resourceGroups := resolveResourceGroups(group, version, workloads[i].GetKind())
		if len(resourceGroups) != 1 {
			logger.L().Warning("unable to resolve object resource", helpers.String("kind", workloads[i].GetKind()), helpers.String("id", workloads[i].GetID()))
			continue
		}
		resourceTriplets := resourceGroups[0]
		if r, ok := allResources[resourceTriplets]; ok {
			allResources[resourceTriplets] = append(r, workloads[i])
		} else {
			allResources[resourceTriplets] = []workloadinterface.IMetadata{workloads[i]}
		}
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
