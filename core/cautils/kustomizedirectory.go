package cautils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	helmignore "helm.sh/helm/v3/pkg/ignore"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/provider"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"
)

var (
	// ErrKustomizeHelmSetup identifies Helm installation or version failures.
	ErrKustomizeHelmSetup = errors.New("kustomize Helm command is not usable")
	// ErrKustomizationFileNotRegular is returned when a Kustomization file is not a regular file.
	ErrKustomizationFileNotRegular = errors.New("kustomization file is not a regular file")
	// ErrKustomizationFileTooLarge is returned when a Kustomization file exceeds the maximum allowed size.
	ErrKustomizationFileTooLarge = errors.New("kustomization file exceeds maximum size limit")
)

// openKustomizationFile opens path for reading and rejects anything but a regular file.
// A pre-open stat check prevents opening device nodes (e.g. tape or character devices).
// O_NONBLOCK keeps opening a FIFO from waiting for a writer, and descriptor-based
// validation ensures a path swapped after stat cannot slip past.
func openKustomizationFile(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	cleaned := filepath.Clean(path)
	statInfo, err := os.Stat(cleaned)
	if err != nil {
		return nil, err
	}
	if statInfo.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrKustomizationFileNotRegular)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrKustomizationFileNotRegular, path)
	}

	file, err := os.OpenFile(cleaned, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrKustomizationFileNotRegular)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%w: %q", ErrKustomizationFileNotRegular, path)
	}
	return file, nil
}

func openBoundedKustomizationFile(path string) (*os.File, int64, error) {
	file, err := openKustomizationFile(path)
	if err != nil {
		return nil, 0, err
	}

	limit := getMaxFileSize()
	info, err := file.Stat()
	if err == nil && info.Size() > limit {
		file.Close()
		return nil, 0, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrKustomizationFileTooLarge, path, limit)
	}
	return file, limit, nil
}

func validateKustomizationFile(path string) error {
	file, _, err := openBoundedKustomizationFile(path)
	if err != nil {
		return err
	}
	return file.Close()
}

// readKustomizationFile returns the contents of the Kustomization file at path, reading at most
// getMaxFileSize() bytes (configurable via KUBESCAPE_MAX_FILE_SIZE, defaulting to
// DefaultMaxFileSize) so that reading remains bounded.
func readKustomizationFile(path string) ([]byte, error) {
	file, limit, err := openBoundedKustomizationFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrKustomizationFileTooLarge, path, limit)
	}
	return data, nil
}

type KustomizeDirectory struct {
	path         string
	helmCommand  string
	onDependency func(path string, chart bool)
	// origins maps the ID of each rendered workload to the local file it came
	// from, as far as Kustomize could tell. It is filled by GetWorkloads.
	origins map[string]string
}

type kustomizeDependencyObserverKey struct{}

// WithKustomizeDependencyObserver reports local paths consulted by a Kustomize
// build, including missing inputs and Helm chart directories.
func WithKustomizeDependencyObserver(ctx context.Context, observe func(path string, chart bool)) context.Context {
	return context.WithValue(ctx, kustomizeDependencyObserverKey{}, observe)
}

// OriginFiles returns, for the workloads the last GetWorkloads call rendered,
// the local file each one came from, keyed by the workload's ID. A workload that
// is not in the map has no known file, for example because it came from a remote
// base, and is attributed to the Kustomize directory.
func (kd *KustomizeDirectory) OriginFiles() map[string]string {
	return kd.origins
}

// Used for checking if there is "Kustomization" file in the given Directory
var kustomizationFileMatchers = [3]string{"kustomization.yml", "kustomization.yaml", "Kustomization"}

// IsKustomizeDirectory reports whether path is a directory containing a Kustomization file.
func IsKustomizeDirectory(path string) bool {
	return isKustomizeDirectory(path)
}

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

	contents, err := readKustomizationFile(absKustomizationPath)
	if err != nil {
		return fmt.Errorf("failed to read Kustomization %q: %w", absKustomizationPath, err)
	}
	var kustomization types.Kustomization
	if err := kustomization.Unmarshal(contents); err != nil {
		return fmt.Errorf("failed to parse Kustomization %q: %w", absKustomizationPath, err)
	}
	kustomization.FixKustomization()

	for _, chart := range kustomization.HelmCharts {
		if chart.Name == "" {
			continue
		}
		directory := kustomizeChartDirectory(filepath.Dir(absKustomizationPath), kustomization.HelmGlobals, chart)
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

func kustomizeChartDirectory(loaderRoot string, globals *types.HelmGlobals, chart types.HelmChart) string {
	home := types.HelmDefaultHome
	if globals != nil && globals.ChartHome != "" {
		home = globals.ChartHome
	}
	if !filepath.IsAbs(home) {
		home = filepath.Join(loaderRoot, home)
	}
	// The Helm inflator isolates versioned repository charts in this directory.
	if chart.Repo != "" && chart.Version != "" {
		home = filepath.Join(home, chart.Name+"-"+chart.Version)
	}
	return filepath.Join(home, chart.Name)
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
	// Unfiltered on purpose: an excluded chart leaves discovery, not the record of
	// what the build owns.
	appendOwnedHelmChartTreeWithLister(ctx, directory, seen, directories, func(path string) ([]string, []error) {
		return listHelmChartDirs(path, nil)
	})
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

// kustomizeHelmFileSystem observes the configurations Kustomize actually reads,
// including components and remote bases, without changing their contents or errors.
type kustomizeHelmFileSystem struct {
	filesys.FileSystem
	usesHelm           bool
	kustomizationFiles map[string]string
	generatorFiles     map[string]string // requested or resolved generator path to loader root
	generatorFactory   *resmap.Factory
	dependencies       map[string]bool // true for a Helm chart directory
	dependencyRoot     string
	validationErr      error
	mu                 sync.Mutex
}

func (fs *kustomizeHelmFileSystem) recordValidationErr(err error) {
	if err == nil {
		return
	}
	fs.mu.Lock()
	if fs.validationErr == nil {
		fs.validationErr = err
	}
	fs.mu.Unlock()
}

func (fs *kustomizeHelmFileSystem) recordedValidationErr() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.validationErr != nil {
		return fs.validationErr
	}
	if bfs, ok := fs.FileSystem.(*boundedOnDiskFileSystem); ok {
		return bfs.recordedValidationErr()
	}
	return nil
}

// Remember the requested file's role before the loader resolves symlinks. The
// loader root, rather than the symlink target's directory, anchors generators.
func (fs *kustomizeHelmFileSystem) CleanedAbs(path string) (filesys.ConfirmedDir, string, error) {
	directory, file, err := fs.FileSystem.CleanedAbs(path)
	if fs.dependencies != nil && path != fs.dependencyRoot {
		// Keep the requested name so replacing a link or creating a missing
		// local resource can trigger a new build.
		fs.observeDependency(lexicalAbsPath(path), false)
	}
	if err == nil {
		resolved := directory.Join(file)
		if file != "" && (IsKustomizeFile(path) || IsKustomizeFile(resolved)) {
			if fs.kustomizationFiles == nil {
				fs.kustomizationFiles = map[string]string{}
			}
			fs.kustomizationFiles[resolved] = filepath.Dir(path)
		}
		if root, generator := fs.generatorFiles[filepath.Clean(path)]; generator {
			fs.generatorFiles[resolved] = root
		}
	}
	return directory, file, err
}

func (fs *kustomizeHelmFileSystem) observeDependency(path string, chart bool) {
	if fs.dependencies != nil {
		fs.dependencies[path] = chart || fs.dependencies[path]
	}
}

// Kustomize removes its remote checkouts through this filesystem before the
// build returns. Their contents are not local inputs that can be watched.
func (fs *kustomizeHelmFileSystem) RemoveAll(path string) error {
	if fs.dependencies != nil && path != "" {
		path = filepath.Clean(path)
		for dependency := range fs.dependencies {
			if dependency == path || strings.HasPrefix(dependency, path+string(filepath.Separator)) {
				delete(fs.dependencies, dependency)
			}
		}
	}
	return fs.FileSystem.RemoveAll(path)
}

func (fs *kustomizeHelmFileSystem) ReadFile(path string) ([]byte, error) {
	// The loader has accepted this resolved path under its restrictions.
	fs.observeDependency(path, false)
	contents, err := fs.FileSystem.ReadFile(path)
	if err != nil {
		return contents, err
	}
	if root, configuration := fs.kustomizationFiles[path]; configuration {
		var config types.Kustomization
		if config.Unmarshal(contents) == nil {
			config.FixKustomization()
			for _, chart := range config.HelmCharts {
				fs.usesHelm = true
				if chartErr := fs.observeChart(root, config.HelmGlobals, chart); chartErr != nil {
					fs.recordValidationErr(chartErr)
					return nil, chartErr
				}
			}
			for _, generator := range config.Generators {
				// Use the same inline-vs-file decision and List expansion as
				// Kustomize's configureExternalGenerators.
				handled, genErr := fs.observeGenerators([]byte(generator), root)
				if genErr != nil {
					fs.recordValidationErr(genErr)
					return nil, genErr
				}
				if handled {
					continue
				}
				if fs.generatorFiles == nil {
					fs.generatorFiles = map[string]string{}
				}
				if !filepath.IsAbs(generator) {
					generator = filepath.Join(root, generator)
				}
				fs.generatorFiles[filepath.Clean(generator)] = root
			}
		}
	}
	// Only inspect files selected as generators; a plain resource with the
	// same kind does not make the build invoke Helm.
	if root, generator := fs.generatorRoot(path); generator {
		if _, genErr := fs.observeGenerators(contents, root); genErr != nil {
			fs.recordValidationErr(genErr)
			return nil, genErr
		}
	}
	return contents, err
}

func (fs *kustomizeHelmFileSystem) generatorRoot(path string) (string, bool) {
	cleaned := filepath.Clean(path)
	if root, ok := fs.generatorFiles[cleaned]; ok {
		return root, true
	}
	for gen, root := range fs.generatorFiles {
		rel, err := filepath.Rel(gen, cleaned)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return root, true
		}
	}
	return "", false
}

func (fs *kustomizeHelmFileSystem) observeChart(root string, globals *types.HelmGlobals, chart types.HelmChart) error {
	if fs.dependencies != nil && chart.Name != "" {
		fs.observeDependency(kustomizeChartDirectory(root, globals, chart), true)
	}
	return validateKustomizeHelmChartInputs(root, globals, chart)
}

func validateKustomizeHelmChartInputs(root string, globals *types.HelmGlobals, chart types.HelmChart) error {
	validateExistingFile := func(path string) error {
		if path == "" {
			return nil
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		err := validateKustomizationFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if err := validateExistingFile(chart.ValuesFile); err != nil {
		return err
	}
	for _, valuesFile := range chart.AdditionalValuesFiles {
		if err := validateExistingFile(valuesFile); err != nil {
			return err
		}
	}

	if chart.Name == "" {
		return nil
	}
	chartPath := kustomizeChartDirectory(root, globals, chart)
	info, err := os.Stat(chartPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return validateKustomizationFile(chartPath)
	}

	rules, err := loadHelmIgnoreRules(filepath.Join(chartPath, helmignore.HelmIgnore))
	if err != nil {
		return err
	}

	return filepath.WalkDir(chartPath, func(entryPath string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		rel, relErr := filepath.Rel(chartPath, entryPath)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if d.IsDir() {
			dirInfo, infoErr := d.Info()
			if errors.Is(infoErr, os.ErrNotExist) {
				return nil
			}
			if infoErr != nil {
				return infoErr
			}
			if rules.Ignore(relSlash, dirInfo) {
				return filepath.SkipDir
			}
			return nil
		}
		entryInfo, statErr := os.Stat(entryPath)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return statErr
		}
		if rules.Ignore(relSlash, entryInfo) {
			return nil
		}
		if entryInfo.IsDir() {
			return fmt.Errorf("%w: symlinked directory %q in Helm chart %q is not allowed", ErrKustomizationFileNotRegular, rel, chart.Name)
		}
		err := validateKustomizationFile(entryPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
}

func loadHelmIgnoreRules(ignorePath string) (*helmignore.Rules, error) {
	ignoreBytes, err := readKustomizationFile(ignorePath)
	var rules *helmignore.Rules
	if errors.Is(err, os.ErrNotExist) {
		rules = helmignore.Empty()
	} else if err != nil {
		return nil, err
	} else {
		rules, err = helmignore.Parse(bytes.NewReader(ignoreBytes))
		if err != nil {
			return nil, err
		}
	}
	rules.AddDefaults()
	return rules, nil
}

// observeGenerators returns whether contents is a valid inline resource map.
// Failed observation never changes the renderer's own parsing or error handling.
func (fs *kustomizeHelmFileSystem) observeGenerators(contents []byte, loaderRoot string) (bool, error) {
	if fs.generatorFactory == nil {
		fs.generatorFactory = resmap.NewFactory(provider.NewDepProvider().GetResourceFactory())
	}
	generators, err := fs.generatorFactory.NewResMapFromBytes(contents)
	if err != nil {
		return false, nil
	}
	for _, generator := range generators.Resources() {
		if generator.GetApiVersion() == "builtin" && generator.GetKind() == "HelmChartInflationGenerator" {
			fs.usesHelm = true
			var config struct {
				types.HelmGlobals
				types.HelmChart
			}
			if data, err := generator.AsYAML(); err == nil && yaml.Unmarshal(data, &config) == nil {
				if chartErr := fs.observeChart(loaderRoot, &config.HelmGlobals, config.HelmChart); chartErr != nil {
					return true, chartErr
				}
			}
		}
	}
	return true, nil
}

// Kustomize flattens component errors into strings. Probe the command separately
// after a failed Helm build so setup failures retain a reliable classification.
func validateKustomizeHelmCommand(command string) error {
	output, err := exec.Command(command, "version", "--short").Output()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKustomizeHelmSetup, err)
	}
	// Keep the accepted version strings and major versions aligned with
	// Kustomize's HelmChartInflationGenerator.checkHelmVersion.
	version := regexp.MustCompile(`v?\d+(\.\d+)+`).FindString(string(output))
	major := strings.Split(strings.TrimPrefix(version, "v"), ".")[0]
	if major != "3" && major != "4" {
		return fmt.Errorf("%w: expected Helm v3 or v4, got %q", ErrKustomizeHelmSetup, strings.TrimSpace(string(output)))
	}
	return nil
}

func isKustomizeHelmError(err error, helmCommand string) bool {
	if err == nil {
		return false
	}
	if helmCommand == "" {
		helmCommand = "helm"
	}
	cmdBase := filepath.Base(helmCommand)

	var execErr *exec.Error
	if errors.As(err, &execErr) && (execErr.Name == helmCommand || filepath.Base(execErr.Name) == cmdBase) {
		return true
	}
	// Only a failure to start the command is Helm's. kustomize reports a missing
	// resource or base as a path error too, and one named like the command (a
	// directory called helm, say) is not about Helm.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && pathErr.Op == "fork/exec" && (pathErr.Path == helmCommand || filepath.Base(pathErr.Path) == cmdBase) {
		return true
	}

	errLower := strings.ToLower(err.Error())
	cmdLower := strings.ToLower(helmCommand)
	baseLower := strings.ToLower(cmdBase)

	helmMarkers := []string{
		"helmchartinflationgenerator",
		"requires helm v3 or v4",
		"cannot find version string in",
		"error reading helm output",
		"failed to set helm annotation",
		"cannot create tmp dir to write helm values",
		"unable to run: '" + cmdLower,
		"unable to run: \"" + cmdLower,
		"unable to run: '" + baseLower,
		"unable to run: \"" + baseLower,
		"is '" + cmdLower + "' installed?",
		"is \"" + cmdLower + "\" installed?",
		"is '" + baseLower + "' installed?",
		"is \"" + baseLower + "\" installed?",
		"exec: \"" + cmdLower + "\":",
		"exec: \"" + baseLower + "\":",
		"exec: '" + cmdLower + "':",
		"exec: '" + baseLower + "':",
	}
	for _, marker := range helmMarkers {
		if strings.Contains(errLower, marker) {
			return true
		}
	}
	return false
}

// boundedOnDiskFileSystem wraps an on-disk filesys.FileSystem so that every
// ReadFile enforces regular-file checks, O_NONBLOCK open, and getMaxFileSize().
type boundedOnDiskFileSystem struct {
	filesys.FileSystem
	mu            sync.Mutex
	validationErr error
}

func (fs *boundedOnDiskFileSystem) ReadFile(path string) ([]byte, error) {
	data, err := readKustomizationFile(path)
	if errors.Is(err, ErrKustomizationFileTooLarge) || errors.Is(err, ErrKustomizationFileNotRegular) {
		fs.mu.Lock()
		if fs.validationErr == nil {
			fs.validationErr = err
		}
		fs.mu.Unlock()
	}
	return data, err
}

func (fs *boundedOnDiskFileSystem) recordedValidationErr() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.validationErr
}

// kustomizeDisk is the file system the plain build reads, as a variable so a
// test can change files while the build is reading them.
var kustomizeDisk = func() filesys.FileSystem {
	return &boundedOnDiskFileSystem{FileSystem: filesys.MakeFsOnDisk()}
}

// Get Workloads, creates the yaml files(K8s resources) using Kustomize and
// renders the workloads from the yaml files (k8s resources)
func (kd *KustomizeDirectory) GetWorkloads(kustomizeDirectoryPath string) (map[string][]workloadinterface.IMetadata, []error) {
	// Kustomize's output is the composed result of a base plus its overlays, so
	// no single source line exists for any given field - unlike a plain YAML
	// file or a static Helm template, there is no raw file on disk whose
	// document order matches this output, so no ":<index>" suffix is safe to
	// attach here (see helmchart.go's isStaticTemplate for why that check
	// matters). The path is made absolute so the evidence pointer matches the
	// convention every other source uses (helmchart.go's absPath, fileutils.go's
	// relPath-or-absolute-path), not whatever relative form the caller happened
	// to pass in.
	//
	// Deliberately lexicalAbsPath, not normalizePath: this same string becomes
	// both the workload map key and, in filesloader.go, the input to
	// filepath.Rel(repoRoot, ...) that produces Source.RelativePath. Resolving
	// symlinks here would replace a repository-local Kustomize directory that is
	// a symlink with its external target, so the "relative path" computed
	// against repoRoot would escape the repository - and printers that refuse
	// an out-of-repo location (GitLab SAST) would silently drop the finding.
	// Keep the path the caller selected; kustomizer.Run below still opens the
	// right files either way, since the OS follows the symlink itself.
	kustomizeDirectoryPath = lexicalAbsPath(kustomizeDirectoryPath)

	fSys := &kustomizeHelmFileSystem{FileSystem: kustomizeDisk()}
	if kd.onDependency != nil {
		fSys.dependencies = make(map[string]bool)
		fSys.dependencyRoot = kustomizeDirectoryPath
	}
	opts := krusty.MakeDefaultOptions()
	// Restrict individual files to their Kustomization root. References to base
	// directories outside that root (e.g. ../base) still get their own loader.
	opts.LoadRestrictions = types.LoadRestrictionsRootOnly
	// Builtin plugins only, plus Helm: the equivalent of `kustomize build
	// --enable-helm`. The Kustomization being rendered comes from the scanned
	// repository, so allowing other plugins (EnabledPluginConfig, i.e.
	// --enable-alpha-plugins) would let it start any container image it names
	// in a config.kubernetes.io/function annotation. The Helm chart inflator is
	// itself a builtin plugin and keeps working.
	opts.PluginConfig = types.DisabledPluginConfig()
	opts.PluginConfig.HelmConfig.Enabled = true
	helmCommand := "helm"
	if kd.helmCommand != "" {
		helmCommand = kd.helmCommand
	}
	opts.PluginConfig.HelmConfig.Command = helmCommand
	newKustomizer := func() *krusty.Kustomizer { return krusty.MakeKustomizer(opts) }

	// The graph is inspected before the plain build and again once the files
	// are known (see below). The build and the inspection read the disk at
	// different times, so one inspection alone can describe a graph the build
	// never read.
	plan := originModeFor(kustomizeDirectoryPath)

	// The plain build is what the scan evaluates, always: it is exactly what the
	// scanned kustomization renders.
	resmap, err := newKustomizer().Run(fSys, kustomizeDirectoryPath)
	for dependency, chart := range fSys.dependencies {
		kd.onDependency(dependency, chart)
	}
	if vErr := fSys.recordedValidationErr(); vErr != nil {
		if err == nil {
			err = vErr
		} else if !errors.Is(err, vErr) {
			err = errors.Join(err, vErr)
		}
	}
	if err != nil {
		if !errors.Is(err, ErrKustomizationFileTooLarge) && !errors.Is(err, ErrKustomizationFileNotRegular) &&
			(fSys.usesHelm || isKustomizeHelmError(err, helmCommand)) {
			err = errors.Join(err, validateKustomizeHelmCommand(helmCommand))
		}
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

	// Learn which file each resource came from, so a finding can name it. This
	// only ever adds information: it never changes a resource, and it must happen
	// before the workloads are built below, which add to the objects.
	//
	// A file that changes during the scan, a base link pointed elsewhere or a
	// patch rewritten, would otherwise get the resources attributed to a file
	// the build did not read. So the files are kept only if a second inspection
	// reaches the same plan as the first: with one change, the build read either
	// what the first saw or what the second saw. Changes that undo each other
	// between the two inspections are not caught.
	var originFiles []string
	if e == nil {
		originFiles = originFilesFor(newKustomizer, kustomizeDirectoryPath, plan, wls)
		if originFiles != nil && !plan.sameAs(originModeFor(kustomizeDirectoryPath)) {
			originFiles = nil
		}
	}

	kd.origins = map[string]string{}
	if len(wls) != 0 {
		workloads[kustomizeDirectoryPath] = []workloadinterface.IMetadata{}
		for i := range wls {
			lw := localworkload.NewLocalWorkload(wls[i].GetObject())
			// The workload's own path stays the directory: other code, such as the
			// fix command, reads it, and the file is reported separately.
			lw.SetPath(kustomizeDirectoryPath)
			if originFiles != nil && originFiles[i] != "" {
				kd.origins[lw.GetID()] = originFiles[i]
			}
			workloads[kustomizeDirectoryPath] = append(workloads[kustomizeDirectoryPath], lw)
		}
	}

	return workloads, errs

}
