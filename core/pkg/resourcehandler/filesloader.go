package resourcehandler

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"
)

// FileResourceHandler handle resources from files and URLs
type FileResourceHandler struct{}

func NewFileResourceHandler() *FileResourceHandler {
	return &FileResourceHandler{}
}

func (fileHandler *FileResourceHandler) GetResources(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error) {
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
		var err error

		helmValueOpts := helmValueOptionsFromScanInfo(scanInfo)
		if scanInfo.ChartPath != "" && scanInfo.FilePath != "" {
			workloadIDToSource, workloads, err = getWorkloadFromHelmChart(ctx, scanInfo.InputPatterns[path], scanInfo.ChartPath, scanInfo.FilePath, helmValueOpts)
		} else {
			workloadIDToSource, workloads, err = getResourcesFromPath(ctx, scanInfo.InputPatterns[path], helmValueOpts)
		}
		if err != nil {
			return nil, allResources, nil, nil, err
		}
		if len(workloads) == 0 {
			continue
		}

		maps.Copy(sessionObj.ResourceSource, workloadIDToSource)

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
	offlineResolver := newOfflineManifestResourceResolver(mappedResources)
	resourceToQuery, excludedRulesMap := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope, offlineResolver)
	k8sResources := resourceToQuery.ToK8sResourceMap()

	// save only relevant resources
	for i := range mappedResources {
		if _, ok := k8sResources[i]; ok {
			var ids []string
			for j := range mappedResources[i] {
				ids = append(ids, mappedResources[i][j].GetID())
				allResources[mappedResources[i][j].GetID()] = mappedResources[i][j]
			}
			k8sResources[i] = append(k8sResources[i], ids...)
		}
	}

	logger.L().StopSuccess("Done accessing local objects")
	// save input resource in resource maps
	addSingleResourceToResourceMaps(k8sResources, allResources, sessionObj.SingleResourceScan, offlineResolver)

	return k8sResources, allResources, externalResources, excludedRulesMap, nil
}

func (fileHandler *FileResourceHandler) GetCloudProvider() string {
	return ""
}

// EstimateClusterSize always returns 0 for file-based scans since streaming
// is not needed for local or URL-based resources.
func (fileHandler *FileResourceHandler) EstimateClusterSize(ctx context.Context, scanInfo *cautils.ScanInfo) (int, error) {
	return 0, nil
}

// StreamResourcesBatches provides a streaming interface for file-based resources.
// This implementation loads all resources via GetResources and returns them as a
// single batch — it provides no memory bound and behaves identically to the
// non-streaming path. File-based scans should not rely on --enable-streaming for
// memory reduction.
func (fileHandler *FileResourceHandler) StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error) {
	batchChan := make(chan *cautils.ResourceBatch, 1)
	errChan := make(chan error, 1)

	// Collect synchronously so sessionObj mutations (ExcludedRules,
	// SingleResourceScan, ResourceSource) happen-before the caller's
	// NewOPAProcessor/ProcessWithStreaming read them, instead of racing from a
	// producer goroutine like the eager path did. File collection is local and
	// fast, so this blocks no longer than the old async body did.
	k8sResources, allResources, externalResources, excludedRulesMap, err := fileHandler.GetResources(ctx, sessionObj, scanInfo)
	if err != nil {
		return nil, nil, 0, err
	}
	sessionObj.ExcludedRules = excludedRulesMap

	go func() {
		defer close(errChan)
		defer close(batchChan)

		// Create a single batch with all resources
		batch := cautils.NewResourceBatch(cautils.ClusterScope)
		batch.K8SResources = k8sResources
		batch.AllResources = allResources
		batch.ExternalResources = externalResources

		select {
		case batchChan <- batch:
		case <-ctx.Done():
		}
	}()

	return batchChan, errChan, 0, nil
}

// helmValueOptionsFromScanInfo extracts the user-supplied Helm value/release flags from ScanInfo
// into the cautils.HelmValueOptions used by chart rendering.
func helmValueOptionsFromScanInfo(scanInfo *cautils.ScanInfo) cautils.HelmValueOptions {
	if scanInfo == nil {
		return cautils.HelmValueOptions{}
	}
	return cautils.HelmValueOptions{
		ValueFiles:       scanInfo.HelmValueFiles,
		Values:           scanInfo.HelmSetValues,
		StringValues:     scanInfo.HelmSetStringValues,
		FileValues:       scanInfo.HelmSetFileValues,
		ReleaseName:      scanInfo.HelmReleaseName,
		ReleaseNamespace: scanInfo.HelmReleaseNamespace,
	}
}

func getWorkloadFromHelmChart(ctx context.Context, path, helmPath, workloadPath string, helmValueOpts cautils.HelmValueOptions) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
	clonedRepo := cautils.GetClonedPath(path)

	if clonedRepo != "" {
		// if the repo was cloned, add the workload path to the cloned repo
		workloadPath = filepath.Join(clonedRepo, workloadPath)
	} else {
		// if the repo was not cloned
		clonedRepo = path
	}

	// Get repo root
	repoRoot, gitRepo := extractGitRepo(clonedRepo)

	helmSourceToWorkloads, helmSourceToChart, _, err := cautils.LoadResourcesFromHelmCharts(ctx, helmPath, helmValueOpts)
	if err != nil {
		return nil, nil, err
	}

	wlSource, ok := helmSourceToWorkloads[workloadPath]
	if !ok {
		return nil, nil, fmt.Errorf("workload %s not found in chart %s", workloadPath, helmPath)
	}

	if len(wlSource) != 1 {
		return nil, nil, fmt.Errorf("workload %s found multiple times in chart %s", workloadPath, helmPath)
	}

	helmChart, ok := helmSourceToChart[workloadPath]
	if !ok {
		return nil, nil, fmt.Errorf("helmChart not found for workload %s", workloadPath)
	}

	workloadSource := getWorkloadSourceHelmChart(repoRoot, helmPath, gitRepo, helmChart)

	workloadIDToSource := make(map[string]reporthandling.Source, 1)
	workloadIDToSource[wlSource[0].GetID()] = workloadSource

	var workloads []workloadinterface.IMetadata
	workloads = append(workloads, wlSource...)

	return workloadIDToSource, workloads, nil

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
		Path:             repoRoot,
		HelmPath:         helmChart.Path,
		RelativePath:     source,
		FileType:         reporthandling.SourceTypeHelmChart,
		HelmChartName:    helmChart.Name,
		HelmTemplateFile: helmChart.Provenance.TemplateFile,
		HelmValuesPaths:  helmChart.Provenance.ValuesPaths,
		HelmTemplateLine: helmChart.Provenance.TemplateLine,
		LastCommit:       lastCommit,
	}
}

// resolveHelmRemotePath returns the repository-level remote path used to rewrite helm
// chart provenance, or "" when this is not a cloned-repo scan or the remote URL is
// unavailable — in which case callers fall back to local paths.
func resolveHelmRemotePath(clonedRepo string, gitRepo *cautils.LocalGitRepository) string {
	if clonedRepo == "" || gitRepo == nil {
		return ""
	}
	url, err := gitRepo.GetRemoteUrl()
	if err != nil {
		logger.L().Warning("failed to get remote url, helm sources will use local paths", helpers.Error(err))
		return ""
	}
	return strings.TrimSuffix(url, ".git")
}

// getResourcesFromPath loads every scannable resource under path, from plain
// manifests, helm charts and kustomize directories, and maps each workload to the
// source file it came from.
func getResourcesFromPath(ctx context.Context, path string, helmValueOpts cautils.HelmValueOptions) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
	workloadIDToSource := make(map[string]reporthandling.Source)
	var workloads []workloadinterface.IMetadata

	clonedRepo := cautils.GetClonedPath(path)
	if clonedRepo != "" {
		// if the repo was cloned, add the workload path to the cloned repo
		path = clonedRepo
	}

	// Get repo root
	repoRoot, gitRepo := extractGitRepo(path)

	// when scanning a single file, we consider the repository root to be
	// the directory of the scanned file
	if cautils.IsYaml(repoRoot) {
		repoRoot = filepath.Dir(repoRoot)
	}

	// render helm charts first, so the plain-YAML loader knows which charts' templates the render
	// already covered and can skip only those. A chart whose render failed is dropped whole here, so
	// its templates must stay plainly scanned rather than vanish from the scan.
	helmSourceToWorkloads, helmSourceToChart, renderedCharts, err := cautils.LoadResourcesFromHelmCharts(ctx, path, helmValueOpts)
	if err != nil {
		return nil, nil, err
	}

	// load resource from local file system
	sourceToWorkloads, err := cautils.LoadResourcesFromFiles(ctx, path, repoRoot, renderedCharts)
	if err != nil {
		return nil, nil, err
	}

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

		// source falls back to the unmodified path when filepath.Rel failed above;
		// relSource is empty there, and a source with no relative path is dropped
		// outright by the SARIF and GitLab SAST printers
		var workloadSource reporthandling.Source
		if clonedRepo != "" {
			workloadSource = reporthandling.Source{
				Path:         "",
				RelativePath: source,
				FileType:     filetype,
				LastCommit:   lastCommit,
			}
		} else {
			workloadSource = reporthandling.Source{
				Path:         repoRoot,
				RelativePath: source,
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

	helmRemotePath := resolveHelmRemotePath(clonedRepo, gitRepo)

	// process the helm charts rendered above
	for source, ws := range helmSourceToWorkloads {
		workloads = append(workloads, ws...)
		helmChart := helmSourceToChart[source]

		chartRoot := repoRoot
		if helmRemotePath != "" {
			helmChart.Path = helmRemotePath
			chartRoot = ""
			source = strings.TrimPrefix(source, fmt.Sprintf("%s/", clonedRepo))
		}

		workloadSource := getWorkloadSourceHelmChart(chartRoot, source, gitRepo, helmChart)

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	if len(helmSourceToWorkloads) > 0 { // && len(helmSourceToNodes) > 0
		logger.L().Debug("helm templates found in local storage", helpers.Int("helmTemplates", len(helmSourceToWorkloads)), helpers.Int("workloads", len(workloads)))
	}

	//patch, get value from env
	// Load resources from Kustomize directory
	kustomizeSourceToWorkloads, kustomizeDirectoryName, err := cautils.LoadResourcesFromKustomizeDirectory(ctx, path)
	if err != nil {
		return nil, nil, err
	}

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

		// Path carries the root RelativePath was computed against, so consumers can
		// resolve the file without guessing at the scan's base
		workloadSource := reporthandling.Source{
			Path:                   repoRoot,
			RelativePath:           source,
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: kustomizeDirectoryName,
			LastCommit:             lastCommit,
		}

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
		}
	}

	// backstop: drop cross-provider identity collisions the path-level kustomize skip can't see (e.g. helm + raw YAML)
	workloads, workloadIDToSource = dedupWorkloads(workloads, workloadIDToSource)
	if len(workloads) == 0 {
		return nil, nil, fmt.Errorf("no scannable Kubernetes resources found for input %q", path)
	}

	return workloadIDToSource, workloads, nil
}

// extractGitRepo returns the root every reported path for this scan is relative to,
// along with the git repository when its metadata is usable enough to attribute commits.
func extractGitRepo(path string) (string, *cautils.LocalGitRepository) {
	gitRepo, err := cautils.NewLocalGitRepository(path)
	if err == nil && gitRepo != nil {
		repoRoot, _ := gitRepo.GetRootDir()
		return repoRoot, gitRepo
	}

	// The git metadata is unusable, but reported paths must still be anchored to the
	// repository root when there is one, or a scan of a subdirectory loses its prefix
	// and the paths resolve against nothing. Reuse the repository the constructor
	// already opened rather than opening it a second time.
	var repoRoot string
	var rootErr error
	if gitRepo != nil {
		repoRoot, rootErr = gitRepo.GetRootDir()
	} else {
		repoRoot, rootErr = cautils.GetGitRootDir(path)
	}

	if rootErr == nil && repoRoot != "" {
		// re-anchoring is invisible in the output otherwise, and any ancestor .git
		// counts, including one left behind by a stray `git init`
		if absPath, err := filepath.Abs(path); err != nil || absPath != repoRoot {
			logger.L().Debug("anchoring reported paths on the repository root", helpers.String("root", repoRoot), helpers.String("scanPath", path))
		}
		return repoRoot, gitRepo
	}

	repoRoot, _ = filepath.Abs(path)
	return repoRoot, gitRepo
}

func (fileHandler *FileResourceHandler) GetClusterAPIServerInfo(_ context.Context) *version.Info {
	return nil
}
