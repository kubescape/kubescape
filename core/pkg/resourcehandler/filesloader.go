package resourcehandler

import (
	"context"
	"fmt"
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
	k8sinterface.InitializeMapResourcesMock() // initialize the resource map
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

		if scanInfo.ChartPath != "" && scanInfo.FilePath != "" {
			workloadIDToSource, workloads, _ = getWorkloadFromHelmChart(ctx, scanInfo.InputPatterns[path], scanInfo.ChartPath, scanInfo.FilePath)
		} else {
			workloadIDToSource, workloads, err = getResourcesFromPath(ctx, scanInfo.InputPatterns[path])
			if err != nil {
				return nil, allResources, nil, nil, err
			}
		}
		if len(workloads) == 0 {
			continue
		}

		for k, v := range workloadIDToSource {
			sessionObj.ResourceSource[k] = v
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
	addSingleResourceToResourceMaps(k8sResources, allResources, sessionObj.SingleResourceScan)

	return k8sResources, allResources, externalResources, excludedRulesMap, nil
}

func (fileHandler *FileResourceHandler) GetCloudProvider() string {
	return ""
}
func getWorkloadFromHelmChart(ctx context.Context, path, helmPath, workloadPath string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
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

	helmSourceToWorkloads, helmSourceToChart := cautils.LoadResourcesFromHelmCharts(ctx, helmPath)

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
		Path:          repoRoot,
		HelmPath:      helmChart.Path,
		RelativePath:  source,
		FileType:      reporthandling.SourceTypeHelmChart,
		HelmChartName: helmChart.Name,
		LastCommit:    lastCommit,
	}
}

func getResourcesFromPath(ctx context.Context, path string) (map[string]reporthandling.Source, []workloadinterface.IMetadata, error) {
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
	helmSourceToWorkloads, helmSourceToChart := cautils.LoadResourcesFromHelmCharts(ctx, path)
	for source, ws := range helmSourceToWorkloads {
		workloads = append(workloads, ws...)
		helmChart := helmSourceToChart[source]

		if clonedRepo != "" && gitRepo != nil {
			url, err := gitRepo.GetRemoteUrl()
			if err != nil {
				logger.L().Warning("failed to get remote url", helpers.Error(err))
				break
			}
			helmChart.Path = strings.TrimSuffix(url, ".git")
			repoRoot = ""
			source = strings.TrimPrefix(source, fmt.Sprintf("%s/", clonedRepo))
		}

		workloadSource := getWorkloadSourceHelmChart(repoRoot, source, gitRepo, helmChart)

		for i := range ws {
			workloadIDToSource[ws[i].GetID()] = workloadSource
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

	workloads, workloadIDToSource = dedupWorkloadsBySource(workloads, workloadIDToSource)

	return workloadIDToSource, workloads, nil
}

// fileTypeRank ranks Source.FileType when the same logical resource is
// emitted by more than one loader. Higher rank wins. Helm beats kustomize
// because the chart name is more specific attribution; both beat plain
// YAML/JSON.
var fileTypeRank = map[string]int{
	reporthandling.SourceTypeHelmChart:          3,
	reporthandling.SourceTypeKustomizeDirectory: 2,
	reporthandling.SourceTypeYaml:               1,
	reporthandling.SourceTypeJson:               1,
}

// dedupByRank collapses items that share a key, keeping every item whose
// rank ties for the maximum within the group. Items for which keyRankOf
// returns hasKey=false are passed through untouched (no group membership,
// no collapse).
//
// Stable: the relative order of kept items mirrors their order in `items`.
func dedupByRank[T any](items []T, keyRankOf func(T) (key string, rank int, hasKey bool)) []T {
	if len(items) < 2 {
		return items
	}
	type entry struct {
		idx, rank int
	}
	groups := make(map[string][]entry, len(items))
	keep := make(map[int]struct{}, len(items))
	for i, it := range items {
		key, rank, ok := keyRankOf(it)
		if !ok {
			keep[i] = struct{}{}
			continue
		}
		groups[key] = append(groups[key], entry{idx: i, rank: rank})
	}
	for _, g := range groups {
		best := g[0].rank
		for _, e := range g[1:] {
			if e.rank > best {
				best = e.rank
			}
		}
		for _, e := range g {
			if e.rank == best {
				keep[e.idx] = struct{}{}
			}
		}
	}
	if len(keep) == len(items) {
		return items
	}
	out := make([]T, 0, len(keep))
	for i, it := range items {
		if _, ok := keep[i]; ok {
			out = append(out, it)
		}
	}
	return out
}

// dedupWorkloadsBySource collapses workloads that point to the same logical
// resource (RelativePath + apiVersion + kind + namespace + name) when emitted
// by *different* loaders. The plain YAML walker, the helm renderer, and the
// kustomize renderer each scan the input recursively, so a chart whose
// templates are valid plain YAML (no `{{ }}` placeholders) would otherwise
// surface twice — once with FileType=YAML and once with FileType=Helm Chart.
//
// Multi-document YAML files where the same resource identity legitimately
// repeats within one file are preserved: their entries share a FileType and
// therefore tie at the highest rank.
func dedupWorkloadsBySource(workloads []workloadinterface.IMetadata, sources map[string]reporthandling.Source) ([]workloadinterface.IMetadata, map[string]reporthandling.Source) {
	deduped := dedupByRank(workloads, func(w workloadinterface.IMetadata) (string, int, bool) {
		src, ok := sources[w.GetID()]
		if !ok || src.RelativePath == "" {
			return "", 0, false
		}
		key := src.RelativePath + "\x00" + w.GetApiVersion() + "\x00" + w.GetKind() + "\x00" + w.GetNamespace() + "\x00" + w.GetName()
		return key, fileTypeRank[src.FileType], true
	})
	if len(deduped) == len(workloads) {
		return workloads, sources
	}
	survivors := make(map[string]struct{}, len(deduped))
	for _, w := range deduped {
		survivors[w.GetID()] = struct{}{}
	}
	for id := range sources {
		if _, ok := survivors[id]; !ok {
			delete(sources, id)
		}
	}
	return deduped, sources
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
