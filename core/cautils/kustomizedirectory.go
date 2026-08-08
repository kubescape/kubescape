package cautils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

type KustomizeDirectory struct {
	path string
}

// Used for checking if there is "Kustomization" file in the given Directory
var kustomizationFileMatchers = [3]string{"kustomization.yml", "kustomization.yaml", "Kustomization"}

func isKustomizeDirectory(path string) bool {
	if ok := isDir(path); !ok {
		return false
	}

	matches := 0
	for _, kustomizationFileMatcher := range kustomizationFileMatchers {
		checkPath := filepath.Join(path, kustomizationFileMatcher)
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
		logger.L().Info("Multiple kustomize files found while checking the Kustomize Directory")
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

func getKustomizeDirectoryName(path string) string {
	if ok := isKustomizeDirectory(path); !ok {
		return ""
	}

	return path
}

// KustomizeHelmChartDirectories returns the local chart directories owned by the
// Kustomize configuration selected by path. Returning only explicitly referenced
// charts keeps unrelated charts under the same tree available to the generic Helm
// loader. Nested chart directories are owned by the referenced parent chart too.
func KustomizeHelmChartDirectories(path string) ([]string, error) {
	kustomizationPath := selectedKustomizationFile(path)
	if kustomizationPath == "" {
		return nil, nil
	}
	var chartDirectories []string
	seenKustomizations := map[string]struct{}{}
	seenChartDirectories := map[string]struct{}{}
	if err := collectKustomizeHelmChartDirectories(
		kustomizationPath,
		seenKustomizations,
		seenChartDirectories,
		&chartDirectories,
	); err != nil {
		return nil, err
	}
	return chartDirectories, nil
}

func collectKustomizeHelmChartDirectories(
	kustomizationPath string,
	seenKustomizations map[string]struct{},
	seenChartDirectories map[string]struct{},
	chartDirectories *[]string,
) error {
	absKustomizationPath, err := filepath.Abs(kustomizationPath)
	if err != nil {
		return fmt.Errorf("failed to resolve Kustomization path %q: %w", kustomizationPath, err)
	}
	if resolved, err := filepath.EvalSymlinks(absKustomizationPath); err == nil {
		absKustomizationPath = resolved
	}
	if _, ok := seenKustomizations[absKustomizationPath]; ok {
		return nil
	}
	seenKustomizations[absKustomizationPath] = struct{}{}

	contents, err := os.ReadFile(absKustomizationPath)
	if err != nil {
		return fmt.Errorf("failed to read Kustomization %q: %w", absKustomizationPath, err)
	}
	var kustomization types.Kustomization
	if err := kustomization.Unmarshal(contents); err != nil {
		return fmt.Errorf("failed to parse Kustomization %q: %w", absKustomizationPath, err)
	}
	kustomization.FixKustomization()

	chartHome := types.HelmDefaultHome
	if kustomization.HelmGlobals != nil && kustomization.HelmGlobals.ChartHome != "" {
		chartHome = kustomization.HelmGlobals.ChartHome
	}
	if !filepath.IsAbs(chartHome) {
		chartHome = filepath.Join(filepath.Dir(absKustomizationPath), chartHome)
	}

	for _, chart := range kustomization.HelmCharts {
		if chart.Name == "" {
			continue
		}
		chartRoot := chartHome
		// Kustomize isolates a versioned chart fetched from a repository below
		// <name>-<version> before untarring it. Mirror absChartHome in the Helm
		// inflator so a chart left there from an earlier build has the same owner.
		if chart.Repo != "" && chart.Version != "" {
			chartRoot = filepath.Join(chartRoot, fmt.Sprintf("%s-%s", chart.Name, chart.Version))
		}
		directory := filepath.Clean(filepath.Join(chartRoot, chart.Name))
		if err := appendOwnedHelmChartTree(directory, seenChartDirectories, chartDirectories); err != nil {
			return err
		}
	}

	// A selected Kustomize build can compose local bases and components that carry
	// their own helmCharts. Follow only those explicit local graph edges; do not
	// discover unrelated Kustomizations elsewhere below the scan root.
	references := make([]string, 0, len(kustomization.Resources)+len(kustomization.Components))
	references = append(references, kustomization.Resources...)
	references = append(references, kustomization.Components...)
	for _, reference := range references {
		candidate := reference
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(filepath.Dir(absKustomizationPath), candidate)
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		childKustomization := selectedKustomizationFile(candidate)
		if childKustomization == "" {
			continue
		}
		if err := collectKustomizeHelmChartDirectories(
			childKustomization,
			seenKustomizations,
			seenChartDirectories,
			chartDirectories,
		); err != nil {
			return err
		}
	}
	return nil
}

func appendOwnedHelmChartTree(directory string, seen map[string]struct{}, directories *[]string) error {
	if _, ok := seen[directory]; !ok {
		seen[directory] = struct{}{}
		*directories = append(*directories, directory)
	}

	info, err := os.Stat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect Kustomize-owned Helm chart %q: %w", directory, err)
	}
	if !info.IsDir() {
		return nil
	}

	nestedDirectories, discoveryErrs := listHelmChartDirs(directory)
	if len(discoveryErrs) > 0 {
		return fmt.Errorf("failed to discover Kustomize-owned Helm chart dependencies below %q: %w", directory, errors.Join(discoveryErrs...))
	}
	for _, nestedDirectory := range nestedDirectories {
		if _, ok := seen[nestedDirectory]; ok {
			continue
		}
		seen[nestedDirectory] = struct{}{}
		*directories = append(*directories, nestedDirectory)
	}
	return nil
}

func selectedKustomizationFile(path string) string {
	if IsKustomizeFile(path) {
		return path
	}
	if !isKustomizeDirectory(path) {
		return ""
	}
	for _, matcher := range kustomizationFileMatchers {
		candidate := filepath.Join(path, matcher)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// Get Workloads, creates the yaml files(K8s resources) using Kustomize and
// renders the workloads from the yaml files (k8s resources)
func (kd *KustomizeDirectory) GetWorkloads(kustomizeDirectoryPath string) (map[string][]workloadinterface.IMetadata, []error) {

	fSys := filesys.MakeFsOnDisk()
	// Use LoadRestrictionsNone to allow loading resources from outside the kustomize directory.
	// This is necessary for overlays that reference base configurations in parent directories.
	opts := krusty.MakeDefaultOptions()
	opts.LoadRestrictions = types.LoadRestrictionsNone
	opts.PluginConfig = types.EnabledPluginConfig(types.BploUseStaticallyLinked)
	opts.PluginConfig.HelmConfig.Command = "helm"
	kustomizer := krusty.MakeKustomizer(opts)
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
		errs = append(errs, e)
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
