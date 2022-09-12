package resourcehandler

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
)

// FileResourceHandler handle resources from files and URLs
type FileResourceHandler struct {
	inputPatterns    []string
	registryAdaptors *RegistryAdaptors
}

func NewFileResourceHandler(inputPatterns []string, registryAdaptors *RegistryAdaptors) *FileResourceHandler {
	k8sinterface.InitializeMapResourcesMock() // initialize the resource map
	return &FileResourceHandler{
		inputPatterns:    inputPatterns,
		registryAdaptors: registryAdaptors,
	}
}

func (fileHandler *FileResourceHandler) GetResources(sessionObj *cautils.OPASessionObj, designator *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.KSResources, error) {

	//
	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	k8sResources := setK8sResourceMap(sessionObj.Policies)
	allResources := map[string]workloadinterface.IMetadata{}
	ksResources := &cautils.KSResources{}

	if len(fileHandler.inputPatterns) == 0 {
		return nil, nil, nil, fmt.Errorf("missing input")
	}

	logger.L().Info("Accessing local objects")
	cautils.StartSpinner()

	for path := range fileHandler.inputPatterns {
		workloadIDToSource, workloads, err := getResourcesFromPath(fileHandler.inputPatterns[path])
		if err != nil {
			return nil, allResources, nil, err
		}
		if len(workloads) == 0 {
			logger.L().Debug("path ignored because contains only a non-kubernetes file", helpers.String("path", fileHandler.inputPatterns[path]))
		}

		for k, v := range workloadIDToSource {
			sessionObj.ResourceSource[k] = v
		}

		// map all resources: map["/apiVersion/version/kind"][]<k8s workloads>
		mappedResources := mapResources(workloads)

		// save only relevant resources
		for i := range mappedResources {
			if _, ok := (*k8sResources)[i]; ok {
				ids := []string{}
				for j := range mappedResources[i] {
					ids = append(ids, mappedResources[i][j].GetID())
					allResources[mappedResources[i][j].GetID()] = mappedResources[i][j]
				}
				(*k8sResources)[i] = append((*k8sResources)[i], ids...)
			}
		}

	}

	if err := fileHandler.registryAdaptors.collectImagesVulnerabilities(k8sResources, allResources, ksResources); err != nil {
		logger.L().Warning("failed to collect images vulnerabilities", helpers.Error(err))
	}

	cautils.StopSpinner()
	logger.L().Success("Done accessing local objects")

	return k8sResources, allResources, ksResources, nil
}

func getResourcesFromPath(path string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
	workloadIDToSource := make(map[string]reporthandling.Source, 0)
	workloads := []workloadinterface.IMetadata{}

	clonedRepo, err := cloneGitRepo(&path)
	if err != nil {
		return nil, nil, err
	}
	if clonedRepo != "" {
		defer os.RemoveAll(clonedRepo)
	}

	// Get repo root
	repoRoot := ""
	gitRepo, err := cautils.NewLocalGitRepository(path)
	if err == nil && gitRepo != nil {
		repoRoot, _ = gitRepo.GetRootDir()
	}

	// load resource from local file system
	sourceToWorkloads := cautils.LoadResourcesFromFiles(path, repoRoot)

	// update workloads and workloadIDToSource
	for source, ws := range sourceToWorkloads {
		workloads = append(workloads, ws...)

		relSource, err := filepath.Rel(repoRoot, source)
		if err == nil {
			source = relSource
		}

		var filetype string
		if cautils.IsYaml(source) {
			filetype = reporthandling.SourceTypeYaml
		} else if cautils.IsJson(source) {
			filetype = reporthandling.SourceTypeJson
		} else {
			continue
		}

		var lastCommit reporthandling.LastCommit
		if gitRepo != nil {
			commitInfo, _ := gitRepo.GetFileLastCommit(source)
			if commitInfo != nil {
				lastCommit = reporthandling.LastCommit{
					Hash:           commitInfo.SHA,
					Date:           commitInfo.Author.Date,
					CommitterName:  commitInfo.Author.Name,
					CommitterEmail: commitInfo.Author.Email,
					Message:        commitInfo.Message,
				}
			}
		}

		workloadSource := reporthandling.Source{
			RelativePath: source,
			FileType:     filetype,
			LastCommit:   lastCommit,
		}

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	if len(workloads) == 0 {
		logger.L().Debug("files found in local storage", helpers.Int("files", len(sourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	// load resources from helm charts
	helmSourceToWorkloads, helmSourceToChartName := cautils.LoadResourcesFromHelmCharts(path)
	for source, ws := range helmSourceToWorkloads {
		workloads = append(workloads, ws...)
		helmChartName := helmSourceToChartName[source]

		relSource, err := filepath.Rel(repoRoot, source)
		if err == nil {
			source = relSource
		}

		var lastCommit reporthandling.LastCommit
		if gitRepo != nil {
			commitInfo, _ := gitRepo.GetFileLastCommit(source)
			if commitInfo != nil {
				lastCommit = reporthandling.LastCommit{
					Hash:           commitInfo.SHA,
					Date:           commitInfo.Author.Date,
					CommitterName:  commitInfo.Author.Name,
					CommitterEmail: commitInfo.Author.Email,
					Message:        commitInfo.Message,
				}
			}
		}

		workloadSource := reporthandling.Source{
			RelativePath:  source,
			FileType:      reporthandling.SourceTypeHelmChart,
			HelmChartName: helmChartName,
			LastCommit:    lastCommit,
		}

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	if len(helmSourceToWorkloads) > 0 {
		logger.L().Debug("helm templates found in local storage", helpers.Int("helmTemplates", len(helmSourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	return workloadIDToSource, workloads, nil
}

func (fileHandler *FileResourceHandler) GetClusterAPIServerInfo() *version.Info {
	return nil
}
