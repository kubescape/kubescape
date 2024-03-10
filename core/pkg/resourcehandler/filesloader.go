package resourcehandler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
)

// FileResourceHandler handle resources from files and URLs
type FileResourceHandler struct{}

func NewFileResourceHandler() *FileResourceHandler {
	k8sinterface.InitializeMapResourcesMock() // initialize the resource map
	return &FileResourceHandler{}
}

func (fileHandler *FileResourceHandler) GetResources(ctx context.Context, sessionObj *cautils.OPASessionObj, progressListener opaprocessor.IJobProgressNotificationClient, scanInfo *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error) {
	allResources := map[string]workloadinterface.IMetadata{}
	externalResources := cautils.ExternalResources{}

	if len(scanInfo.InputPatterns) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("missing input")
	}

	logger.L().Start("Accessing local objects...")

	// load resources from all input paths
	mappedResources := map[string][]workloadinterface.IMetadata{}
	for path := range scanInfo.InputPatterns {
		var workloadIDToSource map[string]reporthandling.Source
		var workloads []workloadinterface.IMetadata
		var workloadIDToMappingNodes map[string]cautils.MappingNodes
		var err error

		if scanInfo.ChartPath != "" && scanInfo.FilePath != "" {
			workloadIDToSource, workloads, workloadIDToMappingNodes, err = getWorkloadFromHelmChart(ctx, scanInfo.ChartPath, scanInfo.FilePath)
			if err != nil {
				// We should probably ignore the error so we can continue scanning other charts
			}
		} else {
			workloadIDToSource, workloads, workloadIDToMappingNodes, err = getResourcesFromPath(ctx, scanInfo.InputPatterns[path])
			if err != nil {
				return nil, allResources, nil, nil, err
			}
		}
		if len(workloads) == 0 {
			continue
		}

		for k, v := range workloadIDToSource {
			sessionObj.ResourceSource[k] = v
			sessionObj.TemplateMapping[k] = workloadIDToMappingNodes[k]
		}

		// map all resources: map["/apiVersion/version/kind"][]<k8s workloads>
		addWorkloadsToResourcesMap(mappedResources, workloads)
	}

	// locate input k8s object in the mapped resources - if not found or not a valid resource, return error
	var err error
	if sessionObj.SingleResourceScan, err = findScanObjectResource(mappedResources, scanInfo.ScanObject); err != nil {
		return nil, nil, nil, nil, err
	}

	if sessionObj.SingleResourceScan != nil && k8sinterface.WorkloadHasParent(sessionObj.SingleResourceScan) {
		return nil, nil, nil, nil, fmt.Errorf("resource %s has a parent and cannot be scanned", sessionObj.SingleResourceScan.GetID())
	}

	scanningScope := cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)

	// build a resources map, based on the policies
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	resourceToQuery, excludedRulesMap := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope)
	k8sResources := resourceToQuery.ToK8sResourceMap()

	// save only relevant resources
	for i := range mappedResources {
		if _, ok := k8sResources[i]; ok {
			ids := []string{}
			for j := range mappedResources[i] {
				ids = append(ids, mappedResources[i][j].GetID())
				allResources[mappedResources[i][j].GetID()] = mappedResources[i][j]
			}
			k8sResources[i] = append(k8sResources[i], ids...)
		}
	}

	logger.L().StopSuccess("Done accessing local objects")
	// save input resource in resource maps
	addSingleResourceToResourceMaps(k8sResources, allResources, sessionObj.SingleResourceScan)

	return k8sResources, allResources, externalResources, excludedRulesMap, nil
}

func (fileHandler *FileResourceHandler) GetCloudProvider() string {
	return ""
}
func getWorkloadFromHelmChart(ctx context.Context, helmPath, workloadPath string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, map[string]cautils.MappingNodes, error) {
	clonedRepo, err := cloneGitRepo(&helmPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if clonedRepo != "" {
		defer os.RemoveAll(clonedRepo)
	}

	// Get repo root
	repoRoot, gitRepo := extractGitRepo(helmPath)

	helmSourceToWorkloads, helmSourceToChart, helmSourceToNodes := cautils.LoadResourcesFromHelmCharts(ctx, helmPath)

	if clonedRepo != "" {
		workloadPath = clonedRepo + workloadPath
	}

	wlSource, ok := helmSourceToWorkloads[workloadPath]
	if !ok {
		return nil, nil, nil, fmt.Errorf("workload %s not found in chart %s", workloadPath, helmPath)
	}

	if len(wlSource) != 1 {
		return nil, nil, nil, fmt.Errorf("workload %s found multiple times in chart %s", workloadPath, helmPath)
	}

	helmChart, ok := helmSourceToChart[workloadPath]
	if !ok {
		return nil, nil, nil, fmt.Errorf("helmChart not found for workload %s", workloadPath)
	}

	templatesNodes, ok := helmSourceToNodes[workloadPath]
	if !ok {
		return nil, nil, nil, fmt.Errorf("templatesNodes not found for workload %s", workloadPath)
	}

	workloadSource := getWorkloadSourceHelmChart(repoRoot, helmPath, gitRepo, helmChart)

	workloadIDToSource := make(map[string]reporthandling.Source, 1)
	workloadIDToNodes := make(map[string]cautils.MappingNodes, 1)
	workloadIDToSource[wlSource[0].GetID()] = workloadSource
	workloadIDToNodes[wlSource[0].GetID()] = templatesNodes

	workloads := []workloadinterface.IMetadata{}
	workloads = append(workloads, wlSource...)

	return workloadIDToSource, workloads, workloadIDToNodes, nil

}

func getWorkloadSourceHelmChart(repoRoot string, source string, gitRepo *cautils.LocalGitRepository, helmChart cautils.Chart) reporthandling.Source {
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

	return reporthandling.Source{
		Path:          repoRoot,
		HelmPath:      helmChart.Path,
		RelativePath:  source,
		FileType:      reporthandling.SourceTypeHelmChart,
		HelmChartName: helmChart.Name,
		LastCommit:    lastCommit,
	}
}

func getResourcesFromPath(ctx context.Context, path string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, map[string]cautils.MappingNodes, error) {
	workloadIDToSource := make(map[string]reporthandling.Source, 0)
	workloadIDToNodes := make(map[string]cautils.MappingNodes)
	workloads := []workloadinterface.IMetadata{}

	clonedRepo, err := cloneGitRepo(&path)
	if err != nil {
		return nil, nil, nil, err
	}
	if clonedRepo != "" {
		defer os.RemoveAll(clonedRepo)
	}

	// Get repo root
	repoRoot, gitRepo := extractGitRepo(path)

	// when scanning a single file, we consider the repository root to be
	// the directory of the scanned file
	if cautils.IsYaml(repoRoot) {
		repoRoot = filepath.Dir(repoRoot)
	}

	// load resource from local file system
	sourceToWorkloads := cautils.LoadResourcesFromFiles(ctx, path, repoRoot)

	// update workloads and workloadIDToSource
	var warnIssued bool
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
			commitInfo, err := gitRepo.GetFileLastCommit(source)
			if err != nil && !warnIssued {
				logger.L().Debug("Git scan skipped", helpers.Error(err))
				warnIssued = true // croak only once
			}

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

		var workloadSource reporthandling.Source
		if clonedRepo != "" {
			workloadSource = reporthandling.Source{
				Path:         "",
				RelativePath: relSource,
				FileType:     filetype,
				LastCommit:   lastCommit,
			}
		} else {
			workloadSource = reporthandling.Source{
				Path:         repoRoot,
				RelativePath: relSource,
				FileType:     filetype,
				LastCommit:   lastCommit,
			}
		}

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	if len(workloads) == 0 {
		logger.L().Debug("files found in local storage", helpers.Int("files", len(sourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	// load resources from helm charts
	helmSourceToWorkloads, helmSourceToChart, helmSourceToNodes := cautils.LoadResourcesFromHelmCharts(ctx, path)
	for source, ws := range helmSourceToWorkloads {
		workloads = append(workloads, ws...)
		helmChart := helmSourceToChart[source]
		var templatesNodes cautils.MappingNodes
		if nodes, ok := helmSourceToNodes[source]; ok {
			templatesNodes = nodes
		}

		if clonedRepo != "" {
			url, err := gitRepo.GetRemoteUrl()
			if err != nil {
				logger.L().Warning("failed to get remote url", helpers.Error(err))
				break
			}
			helmChart.Path = strings.TrimSuffix(url, ".git")
			repoRoot = ""
			source = strings.TrimPrefix(source, fmt.Sprintf("%s/", clonedRepo))
			templatesNodes.TemplateFileName = source
		}

		workloadSource := getWorkloadSourceHelmChart(repoRoot, source, gitRepo, helmChart)

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
			workloadIDToNodes[ws[i].GetID()] = templatesNodes
		}
	}

	if len(helmSourceToWorkloads) > 0 { // && len(helmSourceToNodes) > 0
		logger.L().Debug("helm templates found in local storage", helpers.Int("helmTemplates", len(helmSourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	//patch, get value from env
	// Load resources from Kustomize directory
	kustomizeSourceToWorkloads, kustomizeDirectoryName := cautils.LoadResourcesFromKustomizeDirectory(ctx, path) //?

	// update workloads and workloadIDToSource with workloads from Kustomize Directory
	for source, ws := range kustomizeSourceToWorkloads {
		workloads = append(workloads, ws...)
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
			RelativePath:           source,
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: kustomizeDirectoryName,
			LastCommit:             lastCommit,
		}

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	return workloadIDToSource, workloads, workloadIDToNodes, nil
}

func extractGitRepo(path string) (string, *cautils.LocalGitRepository) {
	repoRoot := ""
	gitRepo, err := cautils.NewLocalGitRepository(path)
	if err == nil && gitRepo != nil {
		repoRoot, _ = gitRepo.GetRootDir()
	} else {
		repoRoot, _ = filepath.Abs(path)
	}
	return repoRoot, gitRepo
}

func (fileHandler *FileResourceHandler) GetClusterAPIServerInfo(_ context.Context) *version.Info {
	return nil
}
