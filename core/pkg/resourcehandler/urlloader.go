package resourcehandler

import (
	"context"
	"fmt"
	"path/filepath"

	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
)

// LoadResourcesFromUrl loads Kubernetes resources from Git URLs using the GitHub/GitLab REST API.
// NOTE: This function is currently exported but not integrated into the main resource loading flow.
// The existing git clone-based approach (via ScanInfo.getScanningContext and getResourcesFromPath)
// is preferred because it provides:
// - LastCommit attribution for finding sources
// - Helm chart rendering support
// - Kustomize support
// - Better rate-limit resilience (no API rate limits vs. 60 req/h for unauthenticated API calls)
//
// Additional limitations of this function:
// - Uses giturl.NewGitAPI parser (different from giturl.NewGitURL used elsewhere)
// - Returns raw URLs as map keys instead of repo-relative paths
// - Does not populate Source metadata (Path, RelativePath, FileType, LastCommit)
// - Caller would need to extract repo-relative paths from raw URLs and handle Source attribution
// This function may be useful for future work that needs API-based downloading without full clones,
// but would require significant additional work to match the existing clone-based flow's functionality.
func LoadResourcesFromUrl(inputPatterns []string) (map[string][]workloadinterface.IMetadata, error) {
	if len(inputPatterns) == 0 {
		return nil, nil
	}
	g, err := giturl.NewGitAPI(inputPatterns[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Git URL %q: %w", inputPatterns[0], err)
	}

	files, errs := g.DownloadFilesWithExtension(append(cautils.YAML_PREFIX, cautils.JSON_PREFIX...))
	if len(errs) > 0 {
		for i, j := range errs {
			logger.L().Ctx(context.Background()).Error(i, helpers.Error(j))
		}
	}

	if len(files) == 0 {
		return nil, nil
	}

	// convert files to IMetadata
	workloads := make(map[string][]workloadinterface.IMetadata, 0)

	for i, j := range files {
		// Determine file format from extension
		var fileFormat cautils.FileFormat
		switch ext := filepath.Ext(i); ext {
		case ".yaml", ".yml":
			fileFormat = cautils.YAML_FILE_FORMAT
		case ".json":
			fileFormat = cautils.JSON_FILE_FORMAT
		}

		w, e := cautils.ReadFile(j, fileFormat)
		if e != nil || len(w) == 0 {
			continue
		}
		if _, ok := workloads[i]; !ok {
			workloads[i] = make([]workloadinterface.IMetadata, 0)
		}
		wSlice := workloads[i]
		wSlice = append(wSlice, w...)
		workloads[i] = wSlice
	}

	return workloads, nil
}
