package resourcehandler

import (
	"context"
	"path/filepath"

	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
)

func loadResourcesFromUrl(inputPatterns []string) (map[string][]workloadinterface.IMetadata, error) {
	if len(inputPatterns) == 0 {
		return nil, nil
	}
	g, err := giturl.NewGitAPI(inputPatterns[0])
	if err != nil {
		return nil, nil
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
