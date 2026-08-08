package cautils

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/helmprovenance"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"gopkg.in/yaml.v3"
)

var (
	YAML_PREFIX = []string{"yaml", "yml"}
	JSON_PREFIX = []string{"json"}
)

type FileFormat string

const (
	YAML_FILE_FORMAT FileFormat = "yaml"
	JSON_FILE_FORMAT FileFormat = "json"
)

type Chart struct {
	Name string
	Path string
	// Provenance links this rendered source back to its template and the
	// .Values keys that template reads. Zero value when extraction failed
	// or no static refs were found — callers must tolerate empty fields.
	Provenance helmprovenance.Provenance
}

// LoadResourcesFromHelmCharts scans a given path (recursively) for helm charts, renders the templates and returns a map of workloads and a map of chart names.
// Helm value overrides and release identity supplied via valueOpts are merged over the chart defaults before rendering.
// Pass an empty HelmValueOptions{} to render with chart defaults only (preserves prior behavior).
//
// If user-supplied overrides cannot be parsed (bad --set syntax, missing -f file, unreadable
// --set-file path, etc.) the error is returned to the caller. We deliberately do not silently
// fall back to chart defaults — scanning the wrong manifests is worse than failing fast.
func LoadResourcesFromHelmCharts(ctx context.Context, basePath string, valueOpts HelmValueOptions) (map[string][]workloadinterface.IMetadata, map[string]Chart, []string, error) {
	helmDirectories, discoveryErrs := listHelmChartDirs(basePath)
	for _, err := range discoveryErrs {
		logger.L().Ctx(ctx).Warning("Skipping path while discovering Helm charts", helpers.Error(err))
	}

	// Parse user-supplied value overrides once; reuse for every chart we render.
	var userValues map[string]any
	if !valueOpts.IsEmpty() {
		var err error
		userValues, err = valueOpts.MergeValues()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse Helm value overrides: %w", err)
		}
	}
	releaseOpts := valueOpts.ReleaseOptions()

	// A parent chart owns unpacked dependencies below its charts/ directory. Process
	// parents before their descendants so a successful parent render can suppress a
	// second, standalone render of the same dependency. listHelmChartDirs currently
	// inherits filepath.Walk ordering, but keep the ownership rule independent of that
	// implementation detail.
	sort.Slice(helmDirectories, func(i, j int) bool {
		leftDepth := pathDepth(helmDirectories[i])
		rightDepth := pathDepth(helmDirectories[j])
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return helmDirectories[i] < helmDirectories[j]
	})

	sourceToWorkloads := map[string][]workloadinterface.IMetadata{}
	sourceToChart := make(map[string]Chart, 0)
	// renderedCharts holds chart directories covered by a successful Helm render. It includes
	// dependencies rendered through a successful parent, even when the dependency intentionally
	// emitted no resources. Callers use this list to keep those templates out of the plain-YAML
	// fallback. A chart below a failed parent remains eligible for a standalone fallback render.
	renderedCharts := make([]string, 0, len(helmDirectories))
	successfulCharts := make([]*HelmChart, 0, len(helmDirectories))
	for _, helmDir := range helmDirectories {
		if helmChartOwnedByAny(helmDir, successfulCharts) {
			renderedCharts = append(renderedCharts, helmDir)
			continue
		}

		chart, err := NewHelmChart(helmDir)
		if err != nil {
			logger.L().Ctx(ctx).Warning("Failed to load Helm chart", helpers.String("path", helmDir), helpers.Error(err))
			continue
		}
		values := chart.GetDefaultValues()
		if userValues != nil {
			values = mergeMaps(values, userValues)
		}
		wls, errs := chart.GetWorkloadsWithOptions(values, releaseOpts)
		if len(errs) > 0 {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("Rendering of Helm chart template '%s', failed: %v", chart.GetName(), errs))
			continue
		}
		renderedCharts = append(renderedCharts, helmDir)
		successfulCharts = append(successfulCharts, chart)
		chartName := chart.GetName()
		prov := chart.Provenance()
		for k, v := range wls {
			sourceToWorkloads[k] = v
			sourceToChart[k] = Chart{
				Name:       chartName,
				Path:       helmDir,
				Provenance: prov[k],
			}
		}
	}
	return sourceToWorkloads, sourceToChart, renderedCharts, nil
}

// helmChartOwnedByAny reports whether chartDir is inside the unpacked dependency
// tree of a chart that has already rendered successfully. Merely being nested below
// another chart is not enough: Helm only owns charts below its charts/ directory.
func helmChartOwnedByAny(chartDir string, successfulCharts []*HelmChart) bool {
	for _, chart := range successfulCharts {
		if chart.ownsUnpackedDependency(chartDir) {
			return true
		}
	}
	return false
}

func pathDepth(path string) int {
	depth := 0
	for path = filepath.Clean(path); ; path = filepath.Dir(path) {
		parent := filepath.Dir(path)
		if parent == path {
			return depth
		}
		depth++
	}
}

// listHelmChartDirs scans a given path (recursively) and returns the directories holding a helm chart.
// Subcharts are picked up by the same walk, since each carries its own Chart.yaml.
func listHelmChartDirs(basePath string) ([]string, []error) {
	directories, errs := listDirs(basePath)
	helmDirectories := make([]string, 0)
	for _, dir := range directories {
		chartFile := filepath.Join(dir, "Chart.yaml")
		if _, err := os.Stat(chartFile); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			errs = append(errs, fmt.Errorf("failed to inspect Helm chart metadata %q: %w", chartFile, err))
			continue
		}
		ok, err := IsHelmDirectory(dir)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to inspect %q as a Helm chart: %w", dir, err))
			continue
		}
		if ok {
			helmDirectories = append(helmDirectories, dir)
		}
	}
	return helmDirectories, errs
}

// excludeHelmTemplateFiles drops the files living under the templates/ directory of a helm chart.
// LoadResourcesFromHelmCharts renders those templates, so passing them to the plain-YAML loader
// as well duplicates the workloads it already renders, and warns on every raw template whose
// "{{ ... }}" actions are not valid YAML. Only templates/ is excluded: helm renders nothing else,
// so the rest of the chart (crds/ in particular, which helm does apply) stays plainly scanned.
//
// renderedCharts must be the chart directories covered by successful renders, including unpacked
// dependencies covered through a parent. A chart that failed and was not covered by a parent must
// NOT be included — otherwise its resources reach neither loader and vanish from the scan silently.
func excludeHelmTemplateFiles(files, renderedCharts []string) []string {
	if len(renderedCharts) == 0 {
		return files
	}

	templateDirs := make([]string, 0, len(renderedCharts))
	for _, helmDir := range renderedCharts {
		templateDirs = append(templateDirs, filepath.Join(helmDir, "templates"))
	}

	remaining := make([]string, 0, len(files))
	for _, file := range files {
		if !isUnderAnyDir(file, templateDirs) {
			remaining = append(remaining, file)
		}
	}
	return remaining
}

// isUnderAnyDir reports whether path is inside one of dirs. Both are expected to be absolute,
// as returned by listFiles and listDirs.
func isUnderAnyDir(path string, dirs []string) bool {
	for _, dir := range dirs {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			continue
		}
		// a sibling merely sharing a prefix (e.g. "templates-docs" next to "templates") escapes with ".."
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// mergeMaps performs a deep merge of override into a copy of base, with override winning on conflicts.
// This mirrors helm.sh/helm/v3 internal `chartutil.CoalesceTables` semantics for values overlay
// and is used to layer user --set/-f values over a chart's defaults before rendering.
func mergeMaps(base, override map[string]any) map[string]any {
	out := make(map[string]any, len(base))
	maps.Copy(out, base)
	for k, v := range override {
		if vMap, ok := v.(map[string]any); ok {
			if baseMap, ok := out[k].(map[string]any); ok {
				out[k] = mergeMaps(baseMap, vMap)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// If the contents at given path is a Kustomize Directory, LoadResourcesFromKustomizeDirectory will
// generate yaml files using "Kustomize" & renders a map of workloads from those yaml files
func LoadResourcesFromKustomizeDirectory(ctx context.Context, basePath string) (map[string][]workloadinterface.IMetadata, string, error) {
	isKustomizeDirectory := isKustomizeDirectory(basePath)
	isKustomizeFile := IsKustomizeFile(basePath)
	if ok := isKustomizeDirectory || isKustomizeFile; !ok {
		return nil, "", nil
	}

	sourceToWorkloads := map[string][]workloadinterface.IMetadata{}
	kustomizeDirectory := NewKustomizeDirectory(basePath)

	var newBasePath string

	if isKustomizeFile {
		newBasePath = filepath.Dir(basePath)
		logger.L().Info("Kustomize File Detected, Scanning the rendered Kubernetes Objects...")
	} else {
		newBasePath = basePath
		logger.L().Info("Kustomize Directory Detected, Scanning the rendered Kubernetes Objects...")
	}

	wls, errs := kustomizeDirectory.GetWorkloads(newBasePath)
	kustomizeDirectoryName := getKustomizeDirectoryName(newBasePath)

	if len(errs) > 0 {
		err := fmt.Errorf("failed to render Kustomize resources from %q: %w", newBasePath, errors.Join(errs...))
		logger.L().Ctx(ctx).Error("Rendering yaml from Kustomize failed", helpers.Error(err))
		return nil, kustomizeDirectoryName, err
	}

	maps.Copy(sourceToWorkloads, wls)
	return sourceToWorkloads, kustomizeDirectoryName, nil
}

// LoadResourcesFromFiles globs input for plain YAML/JSON manifests and loads them. renderedCharts
// are the chart directories LoadResourcesFromHelmCharts already rendered; their templates are left
// to that render and skipped here. Pass nil to scan everything (e.g. when no charts were rendered).
func LoadResourcesFromFiles(ctx context.Context, input, rootPath string, renderedCharts []string) (map[string][]workloadinterface.IMetadata, error) {
	// skip the plain-YAML glob for a kustomize directory; the kustomize render handles it
	if isKustomizeDirectory(input) {
		return nil, nil
	}

	files, errs := listFiles(input)
	if len(errs) > 0 {
		discoveryErr := fmt.Errorf("failed to discover all manifest files for %q: %w", input, errors.Join(errs...))
		if len(files) == 0 {
			return nil, discoveryErr
		}
		logger.L().Ctx(ctx).Warning("Continuing with manifest files found before a discovery error", helpers.Error(discoveryErr))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no YAML or JSON manifest files found for input %q", input)
	}

	// skip the plain-YAML glob for the templates of charts the helm render already covered; a chart
	// whose render failed is absent from renderedCharts, so its templates stay plainly scanned.
	files = excludeHelmTemplateFiles(files, renderedCharts)

	workloads, errs := loadFiles(rootPath, files)
	if len(errs) > 0 {
		loadErr := fmt.Errorf("failed to load one or more manifests from %q: %w", input, errors.Join(errs...))
		// Directory and glob scans have historically been best effort. Keep the
		// valid resources from mixed inputs, but make the skipped files visible.
		// An explicitly requested file, or an input with no usable resources,
		// remains a hard failure because returning success would scan nothing or
		// conceal corruption in the exact file the user requested.
		if isFile(input) || len(workloads) == 0 {
			return workloads, loadErr
		}
		logger.L().Ctx(ctx).Warning("Skipping invalid manifest files", helpers.Error(loadErr))
	}

	return workloads, nil
}

func loadFiles(rootPath string, filePaths []string) (map[string][]workloadinterface.IMetadata, []error) {
	workloads := make(map[string][]workloadinterface.IMetadata, 0)
	errs := []error{}
	for i := range filePaths {
		f, err := loadFile(filePaths[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(f) == 0 {
			continue // empty file
		}

		w, e := ReadFile(f, getFileFormat(filePaths[i]))
		if e != nil {
			// Raw Helm templates are a best-effort fallback when chart rendering
			// fails. Go-template actions are not valid YAML, so keep scanning any
			// static templates without treating templated siblings as corrupt
			// standalone manifests.
			if !bytes.Contains(f, []byte("{{")) {
				errs = append(errs, fmt.Errorf("failed to parse %q: %w", filePaths[i], e))
			}
		}
		if len(w) != 0 {
			path := filePaths[i]
			if _, ok := workloads[path]; !ok {
				workloads[path] = []workloadinterface.IMetadata{}
			}
			wSlice := workloads[path]
			for j := range w {
				lw := localworkload.NewLocalWorkload(w[j].GetObject())
				if relPath, err := filepath.Rel(rootPath, path); err == nil {
					lw.SetPath(fmt.Sprintf("%s:%d", relPath, j))
				} else {
					lw.SetPath(fmt.Sprintf("%s:%d", path, j))
				}
				wSlice = append(wSlice, lw)
			}
			workloads[path] = wSlice
		}
	}
	return workloads, errs
}

func loadFile(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
func ReadFile(fileContent []byte, fileFormat FileFormat) ([]workloadinterface.IMetadata, error) {

	switch fileFormat {
	case YAML_FILE_FORMAT:
		return readYamlFile(fileContent)
	case JSON_FILE_FORMAT:
		return readJsonFile(fileContent)
	default:
		return nil, nil
	}
}

// listFiles returns the list of absolute paths, full file path and list of errors. The list of abs paths and full path have the same length
func listFiles(pattern string) ([]string, []error) {
	return listFilesOrDirectories(pattern, false)
}

// listDirs returns the list of absolute paths, full directories path and list of errors. The list of abs paths and full path have the same length
func listDirs(pattern string) ([]string, []error) {
	return listFilesOrDirectories(pattern, true)
}

func listFilesOrDirectories(pattern string, onlyDirectories bool) ([]string, []error) {
	var paths []string
	errs := []error{}

	if !filepath.IsAbs(pattern) {
		o, _ := os.Getwd()
		pattern = filepath.Join(o, pattern)
	}

	if !onlyDirectories && isFile(pattern) {
		paths = append(paths, pattern)
		return paths, errs
	}

	root, shouldMatch := filepath.Split(pattern)

	if isDir(pattern) {
		root = pattern
		shouldMatch = "*"
	}
	if shouldMatch == "" {
		shouldMatch = "*"
	}

	f, err := glob(root, shouldMatch, onlyDirectories)
	paths = append(paths, f...)
	if err != nil {
		errs = append(errs, err)
	}

	return paths, errs
}

func readYamlFile(yamlFile []byte) (yamlObjs []workloadinterface.IMetadata, err error) {
	yamlObjs = []workloadinterface.IMetadata{}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during YAML parsing: %v", r)
		}
	}()

	var parseErrs []error
	for i, doc := range splitYAMLDocuments(yamlFile) {
		var t any
		if unmarshalErr := yaml.Unmarshal(doc, &t); unmarshalErr != nil {
			parseErrs = append(parseErrs, fmt.Errorf("document %d: %w", i+1, unmarshalErr))
			continue
		}
		j := convertYamlToJson(t)
		if j == nil {
			continue
		}
		if obj, ok := j.(map[string]any); ok {
			if o := objectsenvelopes.NewObject(obj); o != nil {
				if o.GetObjectType() == workloadinterface.TypeListWorkloads {
					if list := workloadinterface.NewListWorkloadsObj(o.GetObject()); list != nil {
						yamlObjs = append(yamlObjs, list.GetItems()...)
					}
				} else {
					yamlObjs = append(yamlObjs, o)
				}
			}
		}
	}

	return yamlObjs, errors.Join(parseErrs...)
}

func splitYAMLDocuments(data []byte) [][]byte {
	var docs [][]byte
	var current bytes.Buffer

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), len(data)+1)
	for scanner.Scan() {
		line := scanner.Bytes()
		if isYAMLDocumentSeparator(line) {
			if doc := bytes.TrimSpace(current.Bytes()); len(doc) > 0 {
				docs = append(docs, append([]byte{}, doc...))
			}
			current.Reset()
			continue
		}
		current.Write(line)
		current.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		logger.L().Warning(fmt.Sprintf("error scanning YAML input: %v", err))
	}
	if doc := bytes.TrimSpace(current.Bytes()); len(doc) > 0 {
		docs = append(docs, append([]byte{}, doc...))
	}
	return docs
}

func isYAMLDocumentSeparator(line []byte) bool {
	line = bytes.TrimRight(line, "\r")
	if !bytes.HasPrefix(line, []byte("---")) {
		return false
	}
	rest := bytes.TrimLeft(line[3:], " \t")
	return len(rest) == 0 || rest[0] == '#'
}

func readJsonFile(jsonFile []byte) (workloads []workloadinterface.IMetadata, err error) {
	workloads = []workloadinterface.IMetadata{}
	// The object envelopes do unchecked type assertions on the decoded
	// document, so a well formed but wrongly typed manifest panics. Recover
	// the same way readYamlFile does, so one bad file fails that file rather
	// than the whole scan.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during JSON parsing: %v", r)
		}
	}()

	var jsonObj any
	if err := json.Unmarshal(jsonFile, &jsonObj); err != nil {
		return workloads, err
	}

	convertJsonToWorkload(jsonObj, &workloads)

	return workloads, nil
}
func convertJsonToWorkload(jsonObj any, workloads *[]workloadinterface.IMetadata) {

	switch x := jsonObj.(type) {
	case map[string]any:
		if o := objectsenvelopes.NewObject(x); o != nil {
			(*workloads) = append(*workloads, o)
		}
	case []any:
		for i := range x {
			convertJsonToWorkload(x[i], workloads)
		}
	}
}
func convertYamlToJson(i any) any {
	switch x := i.(type) {
	case map[any]any:
		m2 := map[string]any{}
		for k, v := range x {
			if s, ok := k.(string); ok {
				m2[s] = convertYamlToJson(v)
			}
		}
		return m2
	case []any:
		for i, v := range x {
			x[i] = convertYamlToJson(v)
		}
	}
	return i
}

func IsYaml(filePath string) bool {
	return slices.Contains(YAML_PREFIX, strings.ToLower(strings.TrimPrefix(filepath.Ext(filePath), ".")))
}

func IsJson(filePath string) bool {
	return slices.Contains(JSON_PREFIX, strings.ToLower(strings.TrimPrefix(filepath.Ext(filePath), ".")))
}

func glob(root, pattern string, onlyDirectories bool) ([]string, error) {
	var matches []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// listing only directories
		if onlyDirectories {
			if info.IsDir() {
				if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
					return err
				} else if matched {
					matches = append(matches, path)
				}
			}
			return nil
		}

		// listing only files
		if info.IsDir() {
			return nil
		}
		fileFormat := getFileFormat(path)
		if fileFormat != JSON_FILE_FORMAT && fileFormat != YAML_FILE_FORMAT {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			matches = append(matches, path)
		}

		return nil
	})
	if err != nil {
		return matches, err
	}
	return matches, nil
}

// isFile checks if a given path is a file
func isFile(name string) bool {
	if fi, err := os.Stat(name); err == nil {
		if fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// isDir checks if a given path is a directory
func isDir(name string) bool {
	if info, err := os.Stat(name); err == nil {
		if info.IsDir() {
			return true
		}
	}
	return false
}

func getFileFormat(filePath string) FileFormat {
	if IsYaml(filePath) {
		return YAML_FILE_FORMAT
	} else if IsJson(filePath) {
		return JSON_FILE_FORMAT
	} else {
		return FileFormat(filePath)
	}
}
