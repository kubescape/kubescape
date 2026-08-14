package cautils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

type KustomizeDirectory struct {
	path        string
	helmCommand string
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
		logger.L().Debug("Multiple kustomize files found while checking the Kustomize Directory")
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

func (kd *KustomizeDirectory) SetHelmCommand(cmd string) {
	kd.helmCommand = cmd
}

func getKustomizeDirectoryName(path string) string {
	if ok := isKustomizeDirectory(path); !ok {
		return ""
	}

	return path
}

// KustomizeInputOwnership describes the local inputs selected by a Kustomize
// build. HelmCRDDirectories contains only crds/ directories whose chart is
// rendered with includeCRDs, so callers can retain raw CRDs when Kustomize omits
// them. SourcePaths contains exact local build inputs rather than the whole
// Kustomization directory, preserving unrelated manifests beside a build.
type KustomizeInputOwnership struct {
	SourcePaths          []string
	HelmChartDirectories []string
	HelmCRDDirectories   []string
}

// KustomizeHelmChartDirectories returns the local chart directories owned by the
// Kustomize configuration selected by path. Returning only explicitly referenced
// charts keeps unrelated charts under the same tree available to the generic Helm
// loader. Nested chart directories are owned by the referenced parent chart too.
func KustomizeHelmChartDirectories(ctx context.Context, path string) ([]string, error) {
	ownership, err := KustomizeInputOwnershipForPath(ctx, path)
	return ownership.HelmChartDirectories, err
}

// KustomizeInputOwnershipForPath returns the local source and chart inputs owned
// by the selected Kustomize build.
func KustomizeInputOwnershipForPath(ctx context.Context, path string) (KustomizeInputOwnership, error) {
	kustomizationPath := selectedKustomizationFile(path)
	if kustomizationPath == "" {
		return KustomizeInputOwnership{}, nil
	}
	ownership := KustomizeInputOwnership{}
	seenKustomizations := map[string]struct{}{}
	seenSourcePaths := map[string]struct{}{}
	seenChartDirectories := map[string]struct{}{}
	seenCRDDirectories := map[string]struct{}{}
	chartTrees := map[string][]string{}
	if err := collectKustomizeInputOwnership(
		ctx,
		kustomizationPath,
		seenKustomizations,
		seenSourcePaths,
		seenChartDirectories,
		seenCRDDirectories,
		chartTrees,
		&ownership,
	); err != nil {
		return KustomizeInputOwnership{}, err
	}
	return ownership, nil
}

func collectKustomizeInputOwnership(
	ctx context.Context,
	kustomizationPath string,
	seenKustomizations map[string]struct{},
	seenSourcePaths map[string]struct{},
	seenChartDirectories map[string]struct{},
	seenCRDDirectories map[string]struct{},
	chartTrees map[string][]string,
	ownership *KustomizeInputOwnership,
) error {
	absKustomizationPath, err := canonicalPath(kustomizationPath)
	if err != nil {
		return fmt.Errorf("failed to resolve Kustomization path %q: %w", kustomizationPath, err)
	}
	if _, ok := seenKustomizations[absKustomizationPath]; ok {
		return nil
	}
	seenKustomizations[absKustomizationPath] = struct{}{}
	appendUniquePath(absKustomizationPath, seenSourcePaths, &ownership.SourcePaths)

	contents, err := os.ReadFile(filepath.Clean(absKustomizationPath))
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
		chartKey := normalizePath(directory)
		chartTree, ok := chartTrees[chartKey]
		if !ok {
			chartTree = make([]string, 0, 1)
			appendOwnedHelmChartTree(ctx, directory, map[string]struct{}{}, &chartTree)
			chartTrees[chartKey] = chartTree
		}
		for _, chartDirectory := range chartTree {
			if _, ok := seenChartDirectories[chartDirectory]; !ok {
				seenChartDirectories[chartDirectory] = struct{}{}
				ownership.HelmChartDirectories = append(ownership.HelmChartDirectories, chartDirectory)
			}
			if !chart.IncludeCRDs {
				continue
			}
			crdDirectory := normalizePath(filepath.Join(chartDirectory, "crds"))
			if _, ok := seenCRDDirectories[crdDirectory]; ok {
				continue
			}
			seenCRDDirectories[crdDirectory] = struct{}{}
			ownership.HelmCRDDirectories = append(ownership.HelmCRDDirectories, crdDirectory)
		}

		valuesFiles := append([]string{}, chart.AdditionalValuesFiles...)
		if chart.ValuesFile != "" {
			valuesFiles = append(valuesFiles, chart.ValuesFile)
		} else {
			valuesFiles = append(valuesFiles, filepath.Join(directory, "values.yaml"))
		}
		for _, valuesFile := range valuesFiles {
			candidate, ok := localKustomizeReference(filepath.Dir(absKustomizationPath), valuesFile)
			if !ok {
				continue
			}
			appendUniquePath(normalizePath(candidate), seenSourcePaths, &ownership.SourcePaths)
		}
	}

	// A selected Kustomize build can compose local bases and components that carry
	// their own helmCharts. Follow only those explicit local graph edges; do not
	// discover unrelated Kustomizations elsewhere below the scan root.
	references := make([]string, 0, len(kustomization.Resources)+len(kustomization.Components))
	references = append(references, kustomization.Resources...)
	references = append(references, kustomization.Components...)
	for _, reference := range references {
		candidate, ok := localKustomizeReference(filepath.Dir(absKustomizationPath), reference)
		if !ok {
			continue
		}
		childKustomization := selectedKustomizationFile(candidate)
		if childKustomization == "" {
			appendUniquePath(normalizePath(candidate), seenSourcePaths, &ownership.SourcePaths)
			continue
		}
		if err := collectKustomizeInputOwnership(
			ctx,
			childKustomization,
			seenKustomizations,
			seenSourcePaths,
			seenChartDirectories,
			seenCRDDirectories,
			chartTrees,
			ownership,
		); err != nil {
			return err
		}
	}

	inputReferences := make([]string, 0,
		len(kustomization.Crds)+len(kustomization.Configurations)+len(kustomization.Generators)+
			len(kustomization.Transformers)+len(kustomization.Validators)+
			len(kustomization.Patches)+len(kustomization.Replacements),
	)
	inputReferences = append(inputReferences, kustomization.Crds...)
	inputReferences = append(inputReferences, kustomization.Configurations...)
	inputReferences = append(inputReferences, kustomization.Generators...)
	inputReferences = append(inputReferences, kustomization.Transformers...)
	inputReferences = append(inputReferences, kustomization.Validators...)
	for _, patch := range kustomization.Patches {
		inputReferences = append(inputReferences, patch.Path)
	}
	// FixKustomization intentionally leaves the deprecated patch fields intact;
	// only FixKustomizationPreMarshalling migrates them, and that requires a
	// Kustomize filesystem. Track their local files here so legacy builds get the
	// same ownership behavior as the normalized Patches field.
	for _, patch := range kustomization.PatchesJson6902 { //nolint:staticcheck // Required for legacy Kustomization input ownership.
		inputReferences = append(inputReferences, patch.Path)
	}
	for _, patch := range kustomization.PatchesStrategicMerge { //nolint:staticcheck // Required for legacy Kustomization input ownership.
		inputReferences = append(inputReferences, string(patch))
	}
	for _, replacement := range kustomization.Replacements {
		inputReferences = append(inputReferences, replacement.Path)
	}
	if openAPIPath := kustomization.OpenAPI["path"]; openAPIPath != "" {
		inputReferences = append(inputReferences, openAPIPath)
	}
	for _, generator := range kustomization.ConfigMapGenerator {
		inputReferences = append(inputReferences, generatorInputPaths(generator.FileSources, generator.EnvSources, generator.EnvSource)...)
	}
	for _, generator := range kustomization.SecretGenerator {
		inputReferences = append(inputReferences, generatorInputPaths(generator.FileSources, generator.EnvSources, generator.EnvSource)...)
	}
	for _, reference := range inputReferences {
		candidate, ok := localKustomizeReference(filepath.Dir(absKustomizationPath), reference)
		if !ok {
			continue
		}
		appendUniquePath(normalizePath(candidate), seenSourcePaths, &ownership.SourcePaths)
	}
	return nil
}

func localKustomizeReference(baseDirectory, reference string) (string, bool) {
	if reference == "" {
		return "", false
	}
	candidate := reference
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(baseDirectory, candidate)
	}
	if _, err := os.Stat(candidate); err != nil {
		return "", false
	}
	return candidate, true
}

func generatorInputPaths(files, envs []string, env string) []string {
	paths := make([]string, 0, len(files)+len(envs)+1)
	for _, file := range files {
		if _, value, ok := strings.Cut(file, "="); ok {
			file = value
		}
		paths = append(paths, file)
	}
	paths = append(paths, envs...)
	if env != "" {
		paths = append(paths, env)
	}
	return paths
}

func appendUniquePath(path string, seen map[string]struct{}, paths *[]string) {
	if _, ok := seen[path]; ok {
		return
	}
	seen[path] = struct{}{}
	*paths = append(*paths, path)
}

type helmChartDirectoryLister func(string) ([]string, []error)

func appendOwnedHelmChartTree(ctx context.Context, directory string, seen map[string]struct{}, directories *[]string) {
	appendOwnedHelmChartTreeWithLister(ctx, directory, seen, directories, listHelmChartDirs)
}

func appendOwnedHelmChartTreeWithLister(ctx context.Context, directory string, seen map[string]struct{}, directories *[]string, discover helmChartDirectoryLister) {
	normalizedDirectory, err := canonicalPath(directory)
	if err != nil {
		logger.L().Ctx(ctx).Warning("Skipping path while discovering Helm charts", helpers.Error(err))
		normalizedDirectory = filepath.Clean(directory)
	}
	directory = normalizedDirectory
	if _, ok := seen[directory]; !ok {
		seen[directory] = struct{}{}
		*directories = append(*directories, directory)
	}

	info, err := os.Stat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		logger.L().Ctx(ctx).Warning("Skipping path while discovering Helm charts", helpers.Error(
			fmt.Errorf("failed to inspect Kustomize-owned Helm chart %q: %w", directory, err),
		))
		return
	}
	if !info.IsDir() {
		return
	}

	nestedDirectories, discoveryErrs := discover(directory)
	for _, discoveryErr := range discoveryErrs {
		logger.L().Ctx(ctx).Warning("Skipping path while discovering Helm charts", helpers.Error(discoveryErr))
	}
	for _, nestedDirectory := range nestedDirectories {
		nestedDirectory = normalizePath(nestedDirectory)
		if _, ok := seen[nestedDirectory]; ok {
			continue
		}
		seen[nestedDirectory] = struct{}{}
		*directories = append(*directories, nestedDirectory)
	}
}

func selectedKustomizationFile(path string) string {
	if IsKustomizeFile(path) && isFile(path) {
		return path
	}
	if !isKustomizeDirectory(path) {
		return ""
	}
	for _, matcher := range kustomizationFileMatchers {
		candidate := filepath.Join(path, matcher)
		if isFile(candidate) {
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
	helmCommand := "helm"
	if kd.helmCommand != "" {
		helmCommand = kd.helmCommand
	}
	opts.PluginConfig.HelmConfig.Command = helmCommand
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
