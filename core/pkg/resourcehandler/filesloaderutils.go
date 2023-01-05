package resourcehandler

import (
	"fmt"
	"path/filepath"

	giturl "github.com/kubescape/go-git-url"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
)

// Clone git repository
func cloneGitRepo(path *string) (string, error) {
	var clonedDir string

	// Clone git repository if needed
	gitURL, err := giturl.NewGitAPI(*path)
	if err == nil {
		logger.L().Info("cloning", helpers.String("repository url", gitURL.GetURL().String()))
		cautils.StartSpinner()
		clonedDir, err = cloneRepo(gitURL)
		cautils.StopSpinner()
		if err != nil {
			return "", fmt.Errorf("failed to clone git repo '%s',  %w", gitURL.GetURL().String(), err)
		}

		*path = filepath.Join(clonedDir, gitURL.GetPath())

	}
	return clonedDir, nil
}

// build resources map
func mapResources(workloads []workloadinterface.IMetadata) map[string][]workloadinterface.IMetadata {

	allResources := map[string][]workloadinterface.IMetadata{}
	for i := range workloads {
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(workloads[i].GetKind())
		if err != nil {
			// TODO - print warning
			continue
		}

		if k8sinterface.IsTypeWorkload(workloads[i].GetObject()) {
			w := workloadinterface.NewWorkloadObj(workloads[i].GetObject())
			if groupVersionResource.Group != w.GetGroup() || groupVersionResource.Version != w.GetVersion() {
				// TODO - print warning
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
	return allResources

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
