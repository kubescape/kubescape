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

// dedupWorkloads keeps one copy per resource identity, preferring the highest-ranked provider.
func dedupWorkloads(workloads []workloadinterface.IMetadata, workloadIDToSource map[string]reporthandling.Source) ([]workloadinterface.IMetadata, map[string]reporthandling.Source) {
	seen := make(map[string]int, len(workloads))
	out := make([]workloadinterface.IMetadata, 0, len(workloads))
	for _, w := range workloads {
		key := resourceIdentity(w)
		rank := providerRank(workloadIDToSource[w.GetID()].FileType)
		if i, dup := seen[key]; dup {
			if rank > providerRank(workloadIDToSource[out[i].GetID()].FileType) {
				out[i] = w
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, w)
	}

	pruned := make(map[string]reporthandling.Source, len(out))
	for _, w := range out {
		if s, ok := workloadIDToSource[w.GetID()]; ok {
			pruned[w.GetID()] = s
		}
	}
	return out, pruned
}

func addWorkloadsToResourcesMap(allResources map[string][]workloadinterface.IMetadata, workloads []workloadinterface.IMetadata) {
	for i := range workloads {
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(workloads[i].GetKind())
		if err != nil {
			logger.L().Warning("unsupported/unmapped object kind", helpers.String("kind", workloads[i].GetKind()), helpers.String("id", workloads[i].GetID()), helpers.Error(err))
			continue
		}

		if k8sinterface.IsTypeWorkload(workloads[i].GetObject()) {
			w := workloadinterface.NewWorkloadObj(workloads[i].GetObject())
			if groupVersionResource.Group != w.GetGroup() || groupVersionResource.Version != w.GetVersion() {
				logger.L().Warning("workload GroupVersion mismatch", helpers.String("id", workloads[i].GetID()), helpers.String("kind", workloads[i].GetKind()), helpers.String("expectedGroup", groupVersionResource.Group), helpers.String("actualGroup", w.GetGroup()), helpers.String("expectedVersion", groupVersionResource.Version), helpers.String("actualVersion", w.GetVersion()))
				continue
			}
		}
		resourceTriplets := k8sinterface.JoinResourceTriplets(groupVersionResource.Group, groupVersionResource.Version, groupVersionResource.Resource)
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
