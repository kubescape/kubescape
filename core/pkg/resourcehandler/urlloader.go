package resourcehandler

import (
	giturl "github.com/armosec/go-git-url"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/v2/core/cautils"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"
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
			logger.L().Error(i, helpers.Error(j))
		}
	}

	if len(files) == 0 {
		return nil, nil
	}

	// convert files to IMetadata
	workloads := make(map[string][]workloadinterface.IMetadata, 0)

	for i, j := range files {
		w, e := cautils.ReadFile(j, cautils.GetFileFormat(i))
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
