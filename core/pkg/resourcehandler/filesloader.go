package resourcehandler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/opaprocessor"
)

// FileResourceHandler handle resources from files and URLs
type FileResourceHandler struct {
	singleResourceScan *objectsenvelopes.ScanObject
	inputPatterns      []string
}

func NewFileResourceHandler(_ context.Context, inputPatterns []string, singleResourceScan *objectsenvelopes.ScanObject) *FileResourceHandler {
	k8sinterface.InitializeMapResourcesMock() // initialize the resource map
	return &FileResourceHandler{
		inputPatterns:      inputPatterns,
		singleResourceScan: singleResourceScan,
	}
}

func (fileHandler *FileResourceHandler) GetResources(ctx context.Context, sessionObj *cautils.OPASessionObj, progressListener opaprocessor.IJobProgressNotificationClient, scanInfo cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.KSResources, map[string]bool, error) {
	allResources := map[string]workloadinterface.IMetadata{}
	ksResources := cautils.KSResources{}

	if len(fileHandler.inputPatterns) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("missing input")
	}

	logger.L().Info("Accessing local objects")
	cautils.StartSpinner()

	// load resources from all input paths
	mappedResources := map[string][]workloadinterface.IMetadata{}
	for path := range fileHandler.inputPatterns {
		var workloadIDToSource map[string]reporthandling.Source
		var workloads []workloadinterface.IMetadata
		var err error

		if scanInfo.ChartPath != "" && scanInfo.FilePath != "" {
			workloadIDToSource, workloads, err = getWorkloadFromHelmChart(ctx, scanInfo.ChartPath, scanInfo.FilePath)
		} else {
			workloadIDToSource, workloads, err = getResourcesFromPath(ctx, fileHandler.inputPatterns[path])
			if err != nil {
				return nil, allResources, nil, nil, err
			}
		}
		if len(workloads) == 0 {
			logger.L().Debug("path ignored because contains only a non-kubernetes file", helpers.String("path", fileHandler.inputPatterns[path]))
		}

		for k, v := range workloadIDToSource {
			sessionObj.ResourceSource[k] = v
		}

		// map all resources: map["/apiVersion/version/kind"][]<k8s workloads>
		addWorkloadsToResourcesMap(mappedResources, workloads)
	}

	// locate input k8s object in the mapped resources - if not found or not a valid resource, return error
	var err error
	if sessionObj.SingleResourceScan, err = findScanObjectResource(mappedResources, fileHandler.singleResourceScan); err != nil {
		return nil, nil, nil, nil, err
	}

	if sessionObj.SingleResourceScan != nil && k8sinterface.WorkloadHasParent(sessionObj.SingleResourceScan) {
		return nil, nil, nil, nil, fmt.Errorf("resource %s has a parent and cannot be scanned", sessionObj.SingleResourceScan.GetID())
	}

	// build a resources map, based on the policies
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	resourceToQuery, excludedRulesMap := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan)
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

	// save input resource in resource maps
	addSingleResourceToResourceMaps(k8sResources, allResources, sessionObj.SingleResourceScan)

	cautils.StopSpinner()
	logger.L().Success("Done accessing local objects")

	return k8sResources, allResources, ksResources, excludedRulesMap, nil
}

func getWorkloadFromHelmChart(ctx context.Context, helmPath, workloadPath string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
	clonedRepo, err := cloneGitRepo(&helmPath)
	if err != nil {
		return nil, nil, err
	}
	if clonedRepo != "" {
		defer os.RemoveAll(clonedRepo)
	}

	// Get repo root
	repoRoot, gitRepo := extractGitRepo(helmPath)

	helmSourceToWorkloads, helmSourceToChart := cautils.LoadResourcesFromHelmCharts(ctx, helmPath)

	wlSource, _ := helmSourceToWorkloads[workloadPath]

	helmChart := helmSourceToChart[workloadPath]

	relSource, err := filepath.Rel(repoRoot, helmPath)
	if err == nil {
		helmPath = relSource
	}

	var lastCommit reporthandling.LastCommit
	if gitRepo != nil {
		commitInfo, _ := gitRepo.GetFileLastCommit(helmPath)
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
		Path:          repoRoot,
		HelmPath:      helmChart.Path,
		RelativePath:  helmPath,
		FileType:      reporthandling.SourceTypeHelmChart,
		HelmChartName: helmChart.Name,
		LastCommit:    lastCommit,
	}

	workloadIDToSource := make(map[string]reporthandling.Source, 0)
	workloadIDToSource[wlSource[0].GetID()] = workloadSource

	workloads := []workloadinterface.IMetadata{}
	workloads = append(workloads, wlSource...)

	return workloadIDToSource, workloads, nil

}

func getResourcesFromPath(ctx context.Context, path string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
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
				cautils.StopSpinner()
				logger.L().Ctx(ctx).Warning("git scan skipped", helpers.Error(err))
				cautils.StartSpinner()
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
	helmSourceToWorkloads, helmSourceToChart := cautils.LoadResourcesFromHelmCharts(ctx, path)
	for source, ws := range helmSourceToWorkloads {
		workloads = append(workloads, ws...)
		helmChart := helmSourceToChart[source]

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
			Path:          repoRoot,
			HelmPath:      helmChart.Path,
			RelativePath:  source,
			FileType:      reporthandling.SourceTypeHelmChart,
			HelmChartName: helmChart.Name,
			LastCommit:    lastCommit,
		}

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	if len(helmSourceToWorkloads) > 0 {
		logger.L().Debug("helm templates found in local storage", helpers.Int("helmTemplates", len(helmSourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	// Load resources from Kustomize directory
	kustomizeSourceToWorkloads, kustomizeDirectoryName := cautils.LoadResourcesFromKustomizeDirectory(ctx, path)

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

	return workloadIDToSource, workloads, nil
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
