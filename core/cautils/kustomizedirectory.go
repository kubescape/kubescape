package cautils

import (
	"os"
	"path/filepath"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

type KustomizeDirectory struct {
	path string
}

// Used for checking if there is "Kustomization" file in the given Directory
var kustomizationFileMatchers = [3]string{"kustomization.yml", "kustomization.yaml", "Kustomization"}

func IsKustomizeDirectory(path string) bool {
	if isDir := IsDir(path); !isDir {
		return false
	}

	if lastChar := path[len(path)-1:]; lastChar != "/" {
		path += "/"
	}

	matches := 0
	for _, kustomizationFileMatcher := range kustomizationFileMatchers {
		checkPath := path + kustomizationFileMatcher
		if _, err := os.Stat(checkPath); err == nil {
			matches++
		}
	}

	switch matches {
	case 0:
		return false
	case 1:
		return true
	default:
		logger.L().Info("Multiple kustomize files found while checking Kustomize Directory")
		return false
	}
}

// Used for checking if the path is Kustomization file.
func IsKustomizeFile(path string) bool {
	fileName := filepath.Base(path)

	for _, kustomizationFileMatcher := range kustomizationFileMatchers {
		if fileName == kustomizationFileMatcher {
			return true
		}
	}

	return false
}

func NewKustomizeDirectory(path string) *KustomizeDirectory {
	return &KustomizeDirectory{
		path: path,
	}
}

func GetKustomizeDirectoryName(path string) string {
	if isKustomizeDirectory := IsKustomizeDirectory(path); !isKustomizeDirectory {
		return ""
	}
	return filepath.Dir(path)
}

// Get Workloads, creates the yaml files(K8s resources) using Kustomize and
// renders the workloads from the yaml files (k8s resources)
func (kd *KustomizeDirectory) GetWorkloads(kustomizeDirectoryPath string) (map[string][]workloadinterface.IMetadata, []error) {

	fSys := filesys.MakeFsOnDisk()
	kustomizer := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resmap, err := kustomizer.Run(fSys, kustomizeDirectoryPath)

	if err != nil {
		return nil, []error{err}
	}

	yml, err := resmap.AsYaml()

	if err != nil {
		return nil, []error{err}
	}

	workloads := make(map[string][]workloadinterface.IMetadata, 0)
	errs := []error{}

	wls, e := ReadFile(yml, YAML_FILE_FORMAT)

	if e != nil {
		logger.L().Debug("failed to read rendered yaml file", helpers.String("file", kustomizeDirectoryPath), helpers.Error(e))
	}

	if len(wls) != 0 {
		workloads[kustomizeDirectoryPath] = []workloadinterface.IMetadata{}
		for i := range wls {
			lw := localworkload.NewLocalWorkload(wls[i].GetObject())
			lw.SetPath(kustomizeDirectoryPath)
			workloads[kustomizeDirectoryPath] = append(workloads[kustomizeDirectoryPath], lw)
		}
	}

	return workloads, errs

}
