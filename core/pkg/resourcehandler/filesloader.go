package resourcehandler

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
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

func (fileHandler *FileResourceHandler) GetResources(sessionObj *cautils.OPASessionObj, designator *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.ArmoResources, error) {

	//
	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	k8sResources := setK8sResourceMap(sessionObj.Policies)
	allResources := map[string]workloadinterface.IMetadata{}
	workloadIDToSource := make(map[string]reporthandling.Source, 0)
	armoResources := &cautils.ArmoResources{}

	workloads := []workloadinterface.IMetadata{}

	if len(fileHandler.inputPatterns) == 0 {
		return nil, nil, nil, fmt.Errorf("missing input")
	}
	path := fileHandler.inputPatterns[0]

	clonedRepo, err := cloneGitRepo(&path)
	if err != nil {
		return nil, allResources, nil, err
	}
	if clonedRepo != "" {
		defer os.RemoveAll(clonedRepo)
	}

	// Get repo root
	repoRoot := ""
	giRepo, err := cautils.NewLocalGitRepository(path)
	if err == nil {
		repoRoot, _ = giRepo.GetRootDir()
	}

	// load resource from local file system
	logger.L().Info("Accessing local objects")

	sourceToWorkloads := cautils.LoadResourcesFromFiles(path, repoRoot)

	// update workloads and workloadIDToSource
	for source, ws := range sourceToWorkloads {
		workloads = append(workloads, ws...)

		relSource, err := filepath.Rel(repoRoot, source)
		if err == nil {
			source = relSource
		}
		for i := range ws {
			var filetype string
			if cautils.IsYaml(source) {
				filetype = reporthandling.SourceTypeYaml
			} else if cautils.IsJson(source) {
				filetype = reporthandling.SourceTypeJson
			} else {
				continue
			}
			workloadIDToSource[ws[i].GetID()] = reporthandling.Source{
				RelativePath: source,
				FileType:     filetype,
			}
		}
	}

	if len(workloads) == 0 {
		logger.L().Debug("files found in local storage", helpers.Int("files", len(sourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	// load resources from helm charts
	helmSourceToWorkloads := cautils.LoadResourcesFromHelmCharts(path)
	for source, ws := range helmSourceToWorkloads {
		workloads = append(workloads, ws...)

		relSource, err := filepath.Rel(repoRoot, source)
		if err == nil {
			source = relSource
		}
		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = reporthandling.Source{
				RelativePath: source,
				FileType:     reporthandling.SourceTypeHelmChart,
			}
		}
	}

	if len(helmSourceToWorkloads) > 0 {
		logger.L().Debug("helm templates found in local storage", helpers.Int("helmTemplates", len(helmSourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	// addCommitData(fileHandler.inputPatterns[0], workloadIDToSource)

	if len(workloads) == 0 {
		return nil, allResources, nil, fmt.Errorf("empty list of workloads - no workloads found")
	}

	sessionObj.ResourceSource = workloadIDToSource

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
			(*k8sResources)[i] = ids
		}
	}

	if err := fileHandler.registryAdaptors.collectImagesVulnerabilities(k8sResources, allResources, armoResources); err != nil {
		logger.L().Warning("failed to collect images vulnerabilities", helpers.Error(err))
	}

	logger.L().Success("Accessed to local objects")

	return k8sResources, allResources, armoResources, nil
}

func (fileHandler *FileResourceHandler) GetClusterAPIServerInfo() *version.Info {
	return nil
}
