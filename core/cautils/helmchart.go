package cautils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	posixpath "path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/helmprovenance"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"gopkg.in/yaml.v3"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmengine "helm.sh/helm/v3/pkg/engine"
	helmignore "helm.sh/helm/v3/pkg/ignore"
	k8sversion "k8s.io/apimachinery/pkg/util/version"
	componentversion "k8s.io/component-base/version"
)

type HelmChart struct {
	chart *helmchart.Chart
	path  string
}

func IsHelmDirectory(path string) (bool, error) {
	return helmchartutil.IsChartDir(path)
}

// NewHelmChart loads only the chart and dependencies already present on disk.
// Dependency resolution belongs to an explicit Helm operation, never a scan:
// downloader.Manager.Build can fetch remote content and write into the chart.
func NewHelmChart(path string) (*HelmChart, error) {
	cleaned := filepath.Clean(path)
	statInfo, err := os.Stat(cleaned)
	if err != nil {
		return nil, err
	}

	var chart *helmchart.Chart
	if statInfo.IsDir() {
		if err := validateHelmChartDir(cleaned); err != nil {
			return nil, err
		}
		chart, err = helmloader.Load(cleaned)
	} else {
		chart, err = loadBoundedHelmArchiveFile(cleaned)
	}
	if err != nil {
		return nil, err
	}

	warnMissingHelmDependencies(chart, path)

	return &HelmChart{
		chart: chart,
		path:  path,
	}, nil
}

// Warn for missing dependencies, including those of vendored subcharts, while
// allowing rendering to be attempted. A missing helper can prevent the entire
// chart from rendering. No repository reference is resolved.
func warnMissingHelmDependencies(chart *helmchart.Chart, path string) {
	vendored := make(map[string]bool, len(chart.Dependencies()))
	for _, dependency := range chart.Dependencies() {
		vendored[dependency.Name()] = true
		warnMissingHelmDependencies(dependency, path)
	}
	var missing []string
	for _, dependency := range chart.Metadata.Dependencies {
		if !vendored[dependency.Name] {
			missing = append(missing, dependency.Name)
		}
	}
	if len(missing) > 0 {
		logger.L().Warning("Helm dependencies are missing from charts/; scanning only vendored content. Prepare dependencies explicitly with Helm before scanning to include them",
			helpers.String("path", path), helpers.String("chart", chart.Name()), helpers.String("dependencies", strings.Join(missing, ", ")))
	}
}

func (hc *HelmChart) GetName() string {
	return hc.chart.Name()
}

// ownsUnpackedDependency reports whether candidate is a chart directory loaded
// through hc's on-disk charts/ dependency tree. It follows the loaded chart graph
// instead of relying on the path alone: a directory excluded by .helmignore is not
// owned by the parent and remains eligible for a standalone fallback render.
func (hc *HelmChart) ownsUnpackedDependency(candidate string) bool {
	rel, err := filepath.Rel(hc.path, candidate)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	current := hc.chart
	for len(parts) > 0 {
		if len(parts) < 2 || parts[0] != "charts" {
			return false
		}

		current = loadedUnpackedDependency(current, parts[1])
		if current == nil {
			return false
		}
		parts = parts[2:]
	}
	return true
}

// loadedUnpackedDependency matches a direct charts/<directory> tree from the
// parent's raw, post-.helmignore file set to the dependency object Helm loaded
// from those same files. Comparing the complete file set avoids assuming that
// the directory name equals Chart.yaml's name or that chart names are unique.
func loadedUnpackedDependency(parent *helmchart.Chart, directory string) *helmchart.Chart {
	prefix := filepath.ToSlash(filepath.Join("charts", directory)) + "/"
	files := make(map[string][]byte)
	for _, file := range parent.Raw {
		if strings.HasPrefix(file.Name, prefix) {
			files[strings.TrimPrefix(file.Name, prefix)] = file.Data
		}
	}
	if len(files) == 0 {
		return nil
	}

	for _, dependency := range parent.Dependencies() {
		if len(dependency.Raw) != len(files) {
			continue
		}
		matches := true
		for _, file := range dependency.Raw {
			data, ok := files[file.Name]
			if !ok || !bytes.Equal(data, file.Data) {
				matches = false
				break
			}
		}
		if matches {
			return dependency
		}
	}
	return nil
}

// copyChartTree copies c and its dependencies deeply enough for
// chartutil.ProcessDependenciesWithMerge to work on the copy. That function
// replaces each chart's dependency list and Values, and edits the entries of
// Metadata.Dependencies (Name for an alias, Enabled, ImportValues), so those
// are copied. Templates, files and the values maps themselves are only read,
// and stay shared with c.
func copyChartTree(c *helmchart.Chart) *helmchart.Chart {
	out := *c
	if c.Metadata != nil {
		metadata := *c.Metadata
		// Keep a nil list nil: Helm skips a chart whose list is nil.
		if c.Metadata.Dependencies != nil {
			metadata.Dependencies = make([]*helmchart.Dependency, len(c.Metadata.Dependencies))
			for i, dependency := range c.Metadata.Dependencies {
				if dependency != nil {
					dependencyCopy := *dependency
					metadata.Dependencies[i] = &dependencyCopy
				}
			}
		}
		out.Metadata = &metadata
	}
	dependencies := make([]*helmchart.Chart, 0, len(c.Dependencies()))
	for _, dependency := range c.Dependencies() {
		dependencies = append(dependencies, copyChartTree(dependency))
	}
	// SetDependencies also points each copied dependency's parent at out.
	out.SetDependencies(dependencies...)
	return &out
}

// templateSourcePaths maps the engine path of each template in processed, a
// copy of original that chartutil.ProcessDependenciesWithMerge has worked on,
// to the engine path of the same template in original. An aliased dependency
// renders under charts/<alias>, which does not exist on disk; its templates
// are read from the dependency it was copied from, so the workloads they
// render keep the source file, provenance and evidence of that dependency.
// Two aliases of one dependency both map to it.
func templateSourcePaths(original, processed *helmchart.Chart, out map[string]string) {
	originalPath, processedPath := original.ChartFullPath(), processed.ChartFullPath()
	for _, template := range processed.Templates {
		out[processedPath+"/"+template.Name] = originalPath + "/" + template.Name
	}
	for _, dependency := range processed.Dependencies() {
		if source := sourceDependency(original, dependency); source != nil {
			templateSourcePaths(source, dependency, out)
		}
	}
}

// sourceDependency returns the dependency of original that processed, a
// dependency of its processed copy, was copied from. Helm renames an aliased
// copy, so it is matched on the files it was loaded from, which every copy
// keeps.
func sourceDependency(original, processed *helmchart.Chart) *helmchart.Chart {
	for _, dependency := range original.Dependencies() {
		if sameFiles(dependency.Raw, processed.Raw) {
			return dependency
		}
	}
	return nil
}

// sameFiles reports whether a and b hold the same files in the same order.
func sameFiles(a, b []*helmchart.File) bool {
	return slices.EqualFunc(a, b, func(x, y *helmchart.File) bool {
		return x.Name == y.Name && bytes.Equal(x.Data, y.Data)
	})
}

func (hc *HelmChart) GetDefaultValues() map[string]any {
	return hc.chart.Values
}

// Provenance returns per-template Helm provenance keyed by the same absolute
// source path that GetWorkloads* uses for workloads, so callers can join the
// two maps directly. Keys for templates that produced no workloads (e.g.
// NOTES.txt, helpers) are still included; callers should ignore them.
func (hc *HelmChart) Provenance() map[string]helmprovenance.Provenance {
	raw := helmprovenance.Extract(hc.chart)
	out := make(map[string]helmprovenance.Provenance, len(raw))
	for enginePath, p := range raw {
		// enginePath looks like "<chartName>/templates/foo.yaml" — drop
		// the chart-name prefix and join under the chart's on-disk path,
		// mirroring the conversion in GetWorkloadsWithOptions.
		idx := strings.Index(enginePath, "/")
		if idx == -1 {
			continue
		}
		out[filepath.Join(hc.path, enginePath[idx:])] = p
	}
	return out
}

// GetWorkloadsWithDefaultValues renders chart template using the default values and returns a map of source file to its workloads
func (hc *HelmChart) GetWorkloadsWithDefaultValues() (map[string][]workloadinterface.IMetadata, []error) {
	return hc.GetWorkloads(hc.GetDefaultValues())
}

// GetWorkloads renders chart template using the provided values and returns a map of source (absolute) file path to its workloads.
// Equivalent to GetWorkloadsWithOptions(values, ReleaseOptions{}).
func (hc *HelmChart) GetWorkloads(values map[string]any) (map[string][]workloadinterface.IMetadata, []error) {
	return hc.GetWorkloadsWithOptions(values, helmchartutil.ReleaseOptions{})
}

// GetWorkloadsWithOptions renders chart template using the provided values and Helm release options
// (release name/namespace), returning a map of source (absolute) file path to its workloads.
// Equivalent to GetWorkloadsWithCapabilities(values, releaseOpts, HelmCapabilityOptions{}).
func (hc *HelmChart) GetWorkloadsWithOptions(values map[string]any, releaseOpts helmchartutil.ReleaseOptions) (map[string][]workloadinterface.IMetadata, []error) {
	return hc.GetWorkloadsWithCapabilities(values, releaseOpts, HelmCapabilityOptions{})
}

// GetWorkloadsWithCapabilities renders like GetWorkloadsWithOptions, with the Kubernetes version
// and the extra API versions that templates read from .Capabilities taken from capOpts.
// A zero capOpts renders with Helm's library defaults, except for the Kubernetes version of a
// chart that declares a kubeVersion constraint (see defaultKubeVersion).
// Unset release options use helm template's installation defaults.
func (hc *HelmChart) GetWorkloadsWithCapabilities(values map[string]any, releaseOpts helmchartutil.ReleaseOptions, capOpts HelmCapabilityOptions) (map[string][]workloadinterface.IMetadata, []error) {
	caps, err := hc.capabilities(capOpts)
	if err != nil {
		return nil, []error{err}
	}
	if releaseOpts.Name == "" {
		releaseOpts.Name = "release-name"
	}
	if releaseOpts.Namespace == "" {
		releaseOpts.Namespace = "default"
	}
	if releaseOpts.Revision == 0 {
		releaseOpts.Revision = 1
	}
	if !releaseOpts.IsInstall && !releaseOpts.IsUpgrade {
		releaseOpts.IsInstall = true
	}
	// Like helm template, resolve the dependencies against the values before
	// rendering: drop subcharts that a condition or tag disables, render each
	// alias as its own subchart reading the values under its alias, and apply
	// import-values. Helm does this by editing the chart, so edit a copy:
	// ownsUnpackedDependency and Provenance need hc.chart to keep matching
	// the charts/ tree on disk.
	chart := copyChartTree(hc.chart)
	if err := helmchartutil.ProcessDependenciesWithMerge(chart, values); err != nil {
		return nil, []error{err}
	}
	vals, err := helmchartutil.ToRenderValues(chart, values, releaseOpts, caps)
	if err != nil {
		return nil, []error{err}
	}
	sourceToFile, err := helmengine.Render(chart, vals)
	if err != nil {
		return nil, []error{err}
	}
	sourcePaths := make(map[string]string)
	templateSourcePaths(hc.chart, chart, sourcePaths)

	workloads := make(map[string][]workloadinterface.IMetadata)
	var errs []error

	for path, renderedYaml := range sourceToFile {
		// Skip NOTES.txt and other text, but keep every extension Helm treats
		// as a manifest (.yaml, .yml and .json, see chart.hasManifestExtension).
		// As Helm does, rendered JSON is read with the YAML reader below.
		if !IsYaml(path) && !IsJson(path) {
			continue
		}

		sourcePath := path
		if source, ok := sourcePaths[path]; ok {
			sourcePath = source
		}
		firstPathSeparatorIndex := strings.Index(sourcePath, "/")
		if firstPathSeparatorIndex == -1 {
			continue
		}
		absPath := filepath.Join(hc.path, sourcePath[firstPathSeparatorIndex:])

		// The resolver (locationresolver.go, via getDocIndex/ResolveLocation)
		// reads its line numbers from the source *template* file on disk at
		// absPath, not from renderedYaml below - it has no rendered content
		// to work from at all. That is only safe when the template is one
		// Helm passed through unchanged: no "{{" anywhere. The moment a
		// template contains an action, three things can go wrong if we still
		// claim a line:
		//   - the template is not valid YAML on its own (control structures,
		//     "{{- include ... | nindent 4 }}") so the resolver's YAML
		//     decode of absPath fails outright;
		//   - even when it happens to still parse, "{{ if }}" can drop a
		//     document that exists in the raw file, and "{{ range }}" can
		//     expand one raw document into several rendered ones, so the
		//     rendered ordinal no longer names the same document in the raw
		//     file it named in the render;
		//   - either way the resolver would be reading the wrong document,
		//     which is a *wrong* line, not merely a missing one - exactly
		//     what the evidence feature exists to avoid printing.
		// So the index is appended, the same way fileutils.go and
		// terraform.go already do for plain YAML and Terraform-rendered
		// manifests ("<path>:<index>"), only for a template proven static.
		// Everything else keeps the pre-existing bare path: no line is
		// printed, same as before this change, rather than a confidently
		// wrong one. isStaticTemplate reads the same file the resolver will
		// later open, so "unchanged by rendering" and "safe to index" are
		// decided from the same evidence.
		static, staticErr := isStaticTemplate(absPath)
		if staticErr != nil {
			logger.L().Debug("failed to check Helm template for template actions, leaving path unindexed",
				helpers.String("file", absPath), helpers.Error(staticErr))
		}

		var wls []workloadinterface.IMetadata
		// indexable[n] marks workload n of wls as safe to carry a ":<index>"
		// suffix. The suffix has two consumers that number documents
		// differently, and only one number can be written down:
		//
		//   - line resolution reads it as a *raw document index*.
		//     locationresolver.NewPathLocationResolver decodes every document
		//     the yaml.v3 decoder emits - nulls and comment-only documents
		//     included - and ResolveLocation indexes straight into that slice.
		//   - SARIF remediation reads it as a *workload ordinal*.
		//     collectFixes turns it into "select(di==n)", and
		//     fixhandler.YAMLTreeEditor.Apply resolves n against
		//     yamlWorkloadDocuments(), the *compacted* list of workload-bearing
		//     documents. That is also the repo-wide convention every other
		//     source emits (fileutils.go, terraform.go), pinned by
		//     TestYAMLTreeEditor_ReportApplicationUsesScannerIndex.
		//
		// The two numberings coincide only while nothing has been dropped or
		// expanded earlier in the file. One skipped document (null,
		// comment-only, not a manifest) shifts every later workload's raw
		// index past its ordinal, and a List envelope expands one raw document
		// into several ordinals. Feed the resolver's number to remediation and
		// it edits a *different resource*, or runs off the end of the
		// compacted list; feed remediation's number to the resolver and it
		// cites another document's line.
		//
		// So an index is only emitted where both readings are the same number,
		// which is what the doc.index == ordinal test below establishes. Where
		// they disagree there is no honest answer, and the bare path - no line,
		// no fix region, exactly the behaviour before any of this - is the only
		// safe one.
		indexable := map[int]bool{}
		if static {
			docs, docErr := renderedDocuments([]byte(renderedYaml))
			if docErr != nil {
				logger.L().Debug("failed to align Helm template documents for line resolution, leaving path unindexed",
					helpers.String("file", absPath), helpers.Error(docErr))
				static = false
			} else {
				for _, doc := range docs {
					ordinal := len(wls)
					// A List/PodList envelope is excluded structurally rather
					// than by item count: even a *singleton* list is unsafe,
					// because its one workload is the object at items[0] while
					// both consumers address the wrapper at the document root.
					// The resolver would evaluate the resource's path against
					// the wrapper (citing wrapper metadata, or nothing), and
					// YAMLTreeEditor refuses a List wrapper outright.
					if !doc.isList && len(doc.workloads) == 1 && doc.index == ordinal {
						indexable[ordinal] = true
					}
					wls = append(wls, doc.workloads...)
				}
			}
		}
		if !static {
			var e error
			wls, e = ReadFile([]byte(renderedYaml), YAML_FILE_FORMAT)
			if e != nil {
				logger.L().Debug("failed to read rendered yaml file", helpers.String("file", path), helpers.Error(e))
				errs = append(errs, fmt.Errorf("failed to parse rendered Helm template %q: %w", path, e))
			}
		}
		if len(wls) == 0 {
			continue
		}

		// Each alias of a dependency renders its templates again, so
		// several rendered files can share one source file: keep the
		// workloads of every render.
		for i := range wls {
			lw := localworkload.NewLocalWorkload(wls[i].GetObject())
			// i is the workload ordinal, and indexable[i] is only set where
			// this workload's raw document index is the same number, so the
			// one suffix written here is correct under both readings.
			// The map key stays the bare absPath either way - callers that
			// join against Provenance() (keyed the same way) are unaffected.
			if indexable[i] {
				lw.SetPath(fmt.Sprintf("%s:%d", absPath, i))
			} else {
				lw.SetPath(absPath)
			}
			workloads[absPath] = append(workloads[absPath], lw)
		}
	}
	return workloads, errs
}

// renderedDocument is one YAML document decoded from a rendered chart
// template, along with the workloads readYamlFile produced from it, the
// position it was decoded at, and whether it is a List envelope whose
// workloads are nested items rather than the document root.
type renderedDocument struct {
	index     int
	workloads []workloadinterface.IMetadata
	isList    bool
}

// renderedDocuments splits renderedYaml into documents the same way
// NewPathLocationResolver (locationresolver.go) will later split the raw
// template once it is reopened from disk: one gopkg.in/yaml.v3 Decode call
// per document, in order, counting a null or comment-only document exactly
// as the decoder counts it. That position is what nodeIndex means to
// ResolveLocation, so it is the only document numbering worth computing here.
//
// readYamlFile's own splitting (scanYAMLDocuments, in fileutils.go) is not
// used for this numbering: it silently drops a document that trims to
// nothing, which the decoder still counts as one, so counting positions in
// its output would misalign every document from that point on against what
// the resolver will later see - the exact failure mode this function exists
// to avoid.
//
// Each decoded document is re-marshaled and handed to readYamlFile on its own
// (never sourceToFile's whole-file bytes) so the actual object conversion -
// JSON conversion, manifest validation, List-envelope expansion - goes
// through the same already-tested code every other manifest source uses,
// rather than a second copy of it here that could drift from it.
func renderedDocuments(renderedYaml []byte) ([]renderedDocument, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(renderedYaml))

	var docs []renderedDocument
	for i := 0; ; i++ {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// The resolver will reach this same document, at this same
			// index, when it decodes the raw file. If it cannot be decoded
			// here, the document count from here on is no longer trustworthy
			// evidence of what the resolver will see, so the whole file is
			// treated as unindexable rather than guessing past this point.
			return nil, fmt.Errorf("document %d: %w", i, err)
		}

		docBytes, err := yaml.Marshal(&node)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		wls, err := readYamlFile(docBytes)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		docs = append(docs, renderedDocument{index: i, workloads: wls, isList: isListEnvelope(docBytes)})
	}
	return docs, nil
}

// isListEnvelope reports whether a single rendered document is a List or
// typed-list wrapper, using the same classification readYamlFile applies when
// it decides to expand one. It is asked structurally rather than inferred
// from how many workloads came out, because a one-item list produces exactly
// one workload while still keeping that workload under items[0] instead of at
// the document root. Anything unreadable counts as a list: the only use of
// this answer is to withhold an index, so the unsure case takes the same
// route as the known-unsafe one.
func isListEnvelope(doc []byte) bool {
	var decoded any
	if err := yaml.Unmarshal(doc, &decoded); err != nil {
		return true
	}
	converted, err := convertYamlToJson(decoded)
	if err != nil {
		return true
	}
	obj, ok := converted.(map[string]any)
	if !ok {
		return false
	}
	_, isList, err := listEnvelopeKind(obj)
	return isList || err != nil
}

var (
	// ErrHelmTemplateNotRegular is returned when a Helm template file is not a regular file.
	ErrHelmTemplateNotRegular = errors.New("helm template file is not a regular file")
	// ErrHelmTemplateTooLarge is returned when a Helm template file exceeds the maximum allowed size.
	ErrHelmTemplateTooLarge = errors.New("helm template file exceeds maximum size limit")
)

// openHelmTemplateFile opens path for reading and rejects anything but a regular file.
// A pre-open stat check prevents opening device nodes (e.g. tape or character devices).
// O_NONBLOCK keeps opening a FIFO from waiting for a writer, and descriptor-based
// validation ensures a path swapped after stat cannot slip past.
func openHelmTemplateFile(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	cleaned := filepath.Clean(path)
	statInfo, err := os.Stat(cleaned)
	if err != nil {
		return nil, err
	}
	if statInfo.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrHelmTemplateNotRegular)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrHelmTemplateNotRegular, path)
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
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrHelmTemplateNotRegular)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%w: %q", ErrHelmTemplateNotRegular, path)
	}
	return file, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// boundedArchiveStreamReader bounds total decompressed bytes read from gzip into tar.Reader,
// including PAX/GNU metadata records and padding, against a fixed stream budget
// (helmloader.MaxDecompressedChartSize). On budget exhaustion it returns an error wrapping
// ErrHelmTemplateTooLarge rather than io.EOF so tar.Reader cannot mistake truncation for end-of-archive.
type boundedArchiveStreamReader struct {
	r           io.Reader
	archiveName string
	read        int64
	budget      int64
}

func (b *boundedArchiveStreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.budget < 0 {
		return 0, fmt.Errorf("%w: decompressed archive stream in %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, b.archiveName, b.budget)
	}
	remaining := b.budget - b.read
	if remaining == 0 {
		var probe [1]byte
		n, err := b.r.Read(probe[:])
		if n > 0 {
			b.read++
			return 0, fmt.Errorf("%w: decompressed archive stream in %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, b.archiveName, b.budget)
		}
		return 0, err
	}

	readBuf := p
	if int64(len(readBuf))-1 > remaining {
		readBuf = readBuf[:int(remaining+1)]
	}
	n, err := b.r.Read(readBuf)
	b.read += int64(n)
	if int64(n) > remaining {
		return 0, fmt.Errorf("%w: decompressed archive stream in %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, b.archiveName, b.budget)
	}
	return n, err
}

func openBoundedHelmFile(path string) (*os.File, int64, error) {
	file, err := openHelmTemplateFile(path)
	if err != nil {
		return nil, 0, err
	}

	limit := getMaxFileSize()
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if info.Size() > limit {
		file.Close()
		return nil, 0, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, path, limit)
	}
	return file, limit, nil
}

func validateHelmRegularFile(path string) error {
	file, _, err := openBoundedHelmFile(path)
	if err != nil {
		return err
	}
	return file.Close()
}

// readHelmTemplateFile returns the contents of the Helm template file at path, reading at most
// getMaxFileSize() bytes (configurable via KUBESCAPE_MAX_FILE_SIZE, defaulting to
// DefaultMaxFileSize) so that reading remains bounded.
func readHelmTemplateFile(path string) ([]byte, error) {
	file, limit, err := openBoundedHelmFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, path, limit)
	}
	return data, nil
}

var helmDrivePathPattern = regexp.MustCompile(`^[a-zA-Z]:/`)

func loadBoundedHelmArchiveFiles(in io.Reader, archiveName string, limit int64) ([]*helmloader.BufferedFile, error) {
	unzipped, err := gzip.NewReader(in)
	if err != nil {
		return nil, err
	}
	defer unzipped.Close()

	var files []*helmloader.BufferedFile
	streamBudget := helmloader.MaxDecompressedChartSize
	tr := tar.NewReader(&boundedArchiveStreamReader{
		r:           unzipped,
		archiveName: archiveName,
		budget:      streamBudget,
	})
	var totalDecompressed int64
	for {
		hd, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hd.Size < 0 {
			return nil, fmt.Errorf("invalid negative tar entry size %d for %q in %q", hd.Size, hd.Name, archiveName)
		}
		if hd.Size > limit {
			return nil, fmt.Errorf("%w: archive entry %q in %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, hd.Name, archiveName, limit)
		}
		if helmloader.MaxDecompressedChartSize < 0 || hd.Size > helmloader.MaxDecompressedChartSize-totalDecompressed {
			return nil, fmt.Errorf("decompressed chart is larger than the maximum file size %d", helmloader.MaxDecompressedChartSize)
		}
		totalDecompressed += hd.Size
		if hd.FileInfo().IsDir() {
			continue
		}
		switch hd.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		}

		delimiter := "/"
		if strings.ContainsRune(hd.Name, '\\') {
			delimiter = "\\"
		}
		parts := strings.Split(hd.Name, delimiter)
		n := strings.Join(parts[1:], delimiter)
		n = strings.ReplaceAll(n, delimiter, "/")

		if posixpath.IsAbs(n) {
			return nil, errors.New("chart illegally contains absolute paths")
		}
		n = posixpath.Clean(n)
		if n == "." {
			return nil, fmt.Errorf("chart illegally contains content outside the base directory: %q", hd.Name)
		}
		if strings.HasPrefix(n, "..") {
			return nil, errors.New("chart illegally references parent directory")
		}
		if helmDrivePathPattern.MatchString(n) {
			return nil, errors.New("chart contains illegally named files")
		}
		if parts[0] == "Chart.yaml" {
			return nil, errors.New("chart yaml not in base directory")
		}

		data, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%w: archive entry %q in %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, hd.Name, archiveName, limit)
		}
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		files = append(files, &helmloader.BufferedFile{Name: n, Data: data})
	}
	if len(files) == 0 {
		return nil, errors.New("no files in chart archive")
	}
	return files, nil
}

func validateBoundedHelmChartFiles(files []*helmloader.BufferedFile, archiveName string, limit int64) error {
	subcharts := make(map[string][]*helmloader.BufferedFile)
	for _, f := range files {
		if int64(len(f.Data)) > limit {
			return fmt.Errorf("%w: archive entry %q in %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, f.Name, archiveName, limit)
		}
		if !strings.HasPrefix(f.Name, "charts/") {
			continue
		}
		if posixpath.Ext(f.Name) == ".prov" {
			continue
		}
		fname := strings.TrimPrefix(f.Name, "charts/")
		cname := strings.SplitN(fname, "/", 2)[0]
		if strings.IndexAny(cname, "_.") == 0 {
			continue
		}
		subcharts[cname] = append(subcharts[cname], &helmloader.BufferedFile{Name: fname, Data: f.Data})
	}

	for cname, subFiles := range subcharts {
		if posixpath.Ext(cname) == ".tgz" {
			file := subFiles[0]
			if file.Name != cname {
				return fmt.Errorf("error unpacking subchart tar in %s: expected %s, got %s", archiveName, cname, file.Name)
			}
			nestedName := archiveName + ":" + file.Name
			if int64(len(file.Data)) > limit {
				return fmt.Errorf("%w: %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, nestedName, limit)
			}
			nestedFiles, err := loadBoundedHelmArchiveFiles(bytes.NewReader(file.Data), nestedName, limit)
			if err != nil {
				return err
			}
			if err := validateBoundedHelmChartFiles(nestedFiles, nestedName, limit); err != nil {
				return err
			}
			continue
		}
		unpacked := make([]*helmloader.BufferedFile, 0, len(subFiles))
		for _, sf := range subFiles {
			parts := strings.SplitN(sf.Name, "/", 2)
			if len(parts) < 2 {
				continue
			}
			unpacked = append(unpacked, &helmloader.BufferedFile{Name: parts[1], Data: sf.Data})
		}
		if err := validateBoundedHelmChartFiles(unpacked, archiveName+":"+cname, limit); err != nil {
			return err
		}
	}
	return nil
}

func isPackagedHelmDependencyRel(relSlash string) bool {
	parts := strings.Split(relSlash, "/")
	if len(parts) < 2 || len(parts)%2 != 0 {
		return false
	}
	for i := 0; i < len(parts); i += 2 {
		if parts[i] != "charts" {
			return false
		}
		name := parts[i+1]
		if name == "" || strings.IndexAny(name, "_.") == 0 {
			return false
		}
		isLast := i+2 == len(parts)
		hasTgzExt := posixpath.Ext(name) == ".tgz"
		if isLast {
			return hasTgzExt
		}
		if hasTgzExt {
			return false
		}
	}
	return false
}

func loadBoundedHelmArchiveFile(path string) (*helmchart.Chart, error) {
	file, limit, err := openBoundedHelmFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	head := make([]byte, 512)
	n, readErr := file.Read(head)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("file %q cannot be read: %w", path, readErr)
	}
	sample := head[:n]
	if contentType := http.DetectContentType(sample); contentType != "application/x-gzip" && !bytes.HasPrefix(sample, []byte("\x1f\x8b\x08")) {
		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			return nil, fmt.Errorf("file %q seems to be a YAML file, but expected a gzipped archive", path)
		}
		return nil, fmt.Errorf("file %q does not appear to be a gzipped archive; got %q", path, contentType)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	cr := &countingReader{r: io.LimitReader(file, limit+1)}
	files, err := loadBoundedHelmArchiveFiles(cr, path, limit)
	if cr.n > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, path, limit)
	}
	if err != nil {
		return nil, err
	}
	if err := validateBoundedHelmChartFiles(files, path, limit); err != nil {
		return nil, err
	}
	return helmloader.LoadFiles(files)
}

func loadHelmChartIgnoreRules(ignorePath string) (*helmignore.Rules, error) {
	ignoreBytes, err := readHelmTemplateFile(ignorePath)
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

func validateHelmChartDir(rootDir string) error {
	rules, err := loadHelmChartIgnoreRules(filepath.Join(rootDir, helmignore.HelmIgnore))
	if err != nil {
		return err
	}

	activeAncestors := make(map[string]bool)
	var walkDir func(currentDir string) error
	walkDir = func(currentDir string) error {
		resolvedDir, err := filepath.EvalSymlinks(currentDir)
		if err != nil {
			return err
		}
		if activeAncestors[resolvedDir] {
			return fmt.Errorf("symlink cycle detected in Helm chart directory %q (resolves to %q)", currentDir, resolvedDir)
		}
		activeAncestors[resolvedDir] = true
		defer delete(activeAncestors, resolvedDir)

		entries, err := os.ReadDir(currentDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			entryPath := filepath.Join(currentDir, entry.Name())
			rel, relErr := filepath.Rel(rootDir, entryPath)
			if relErr != nil {
				return relErr
			}
			relSlash := filepath.ToSlash(rel)

			if entry.Type()&os.ModeSymlink != 0 {
				lstatInfo, lerr := entry.Info()
				if lerr == nil && rules.Ignore(relSlash, lstatInfo) {
					continue
				}
				targetInfo, statErr := os.Stat(entryPath)
				if errors.Is(statErr, os.ErrNotExist) {
					continue
				}
				if statErr != nil {
					return statErr
				}
				if rules.Ignore(relSlash, targetInfo) {
					continue
				}
				if targetInfo.IsDir() {
					if err := walkDir(entryPath); err != nil {
						return err
					}
					continue
				}
			} else {
				info, infoErr := entry.Info()
				if errors.Is(infoErr, os.ErrNotExist) {
					continue
				}
				if infoErr != nil {
					return infoErr
				}
				if rules.Ignore(relSlash, info) {
					continue
				}
				if info.IsDir() {
					if err := walkDir(entryPath); err != nil {
						return err
					}
					continue
				}
			}

			if err := validateHelmRegularFile(entryPath); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			if isPackagedHelmDependencyRel(relSlash) {
				if _, err := loadBoundedHelmArchiveFile(entryPath); err != nil {
					return err
				}
			}
		}
		return nil
	}

	return walkDir(rootDir)
}

// isStaticTemplate reports whether the file at absPath contains no Go template
// action delimiter ("{{"), i.e. Helm's render passed it through byte-for-byte.
// This is deliberately conservative: a literal "{{" that is not really a
// template action (vanishingly rare in a Kubernetes manifest) is enough to
// call a file templated, which only costs a missed opportunity to show a
// line - never a wrong one. A read failure is treated the same way, for the
// same reason: os.Open is what the resolver itself will do with this exact
// path once evidence is requested, so if that is going to fail, failing safe
// here is consistent with failing safe there.
func isStaticTemplate(absPath string) (bool, error) {
	content, err := readHelmTemplateFile(absPath)
	if err != nil {
		return false, err
	}
	return !bytes.Contains(content, []byte("{{")), nil
}

// capabilities returns the Helm capabilities to render hc with, or nil for Helm's library
// defaults: Kubernetes v1.20 and the built-in API versions.
//
// The Kubernetes version is opts.KubeVersion when set, otherwise the one defaultKubeVersion
// picks from the chart's kubeVersion constraint. An explicit version that the constraint
// rejects is an error, worded as Helm words it.
func (hc *HelmChart) capabilities(opts HelmCapabilityOptions) (*helmchartutil.Capabilities, error) {
	kubeVersion, err := hc.kubeVersion(opts.KubeVersion)
	if err != nil {
		return nil, err
	}
	if kubeVersion == nil && len(opts.APIVersions) == 0 {
		return nil, nil
	}
	caps := helmchartutil.DefaultCapabilities.Copy()
	if kubeVersion != nil {
		caps.KubeVersion = *kubeVersion
	}
	// Copy returns the shared DefaultVersionSet slice, so clone it before appending.
	caps.APIVersions = append(slices.Clone(helmchartutil.DefaultVersionSet), opts.APIVersions...)
	return caps, nil
}

// kubeVersion returns the Kubernetes version to render hc for, or nil for Helm's library
// default. explicit is the version the caller asked for; empty leaves the choice to the chart.
func (hc *HelmChart) kubeVersion(explicit string) (*helmchartutil.KubeVersion, error) {
	if explicit == "" {
		return hc.defaultKubeVersion(), nil
	}
	kubeVersion, err := helmchartutil.ParseKubeVersion(explicit)
	if err != nil {
		return nil, fmt.Errorf("%q is not a Kubernetes version: %w", explicit, err)
	}
	if constraint := hc.kubeVersionConstraint(); constraint != "" &&
		!helmchartutil.IsCompatibleRange(constraint, kubeVersion.String()) {
		return nil, fmt.Errorf("chart requires kubeVersion: %s which is incompatible with Kubernetes %s", constraint, kubeVersion.String())
	}
	return kubeVersion, nil
}

// defaultKubeVersion returns the Kubernetes version to render hc for when the caller does not
// choose one: the newest minor, v1.N.0 down to v1.0.0, that satisfies the chart's kubeVersion
// constraint, checked as Helm checks it. N is the minor of the vendored Kubernetes libraries,
// so it moves when they are bumped.
//
// It returns nil, which keeps Helm's library default of v1.20, when the chart declares no
// constraint, when the constraint does not parse, or when no such version satisfies it (a
// constraint on a patch release, such as "~1.29.3", or on a minor newer than N). Rendering
// those charts as before is preferred over failing them.
func (hc *HelmChart) defaultKubeVersion() *helmchartutil.KubeVersion {
	constraint := hc.kubeVersionConstraint()
	if constraint == "" {
		return nil
	}
	newest, err := newestKubeVersion()
	if err != nil {
		logger.L().Debug("failed to read the vendored Kubernetes version, rendering Helm chart for the default",
			helpers.String("chart", hc.GetName()), helpers.Error(err))
		return nil
	}
	major := strconv.FormatUint(uint64(newest.Major()), 10)
	for minor := int(newest.Minor()); minor >= 0; minor-- {
		candidate := helmchartutil.KubeVersion{
			Version: fmt.Sprintf("v%s.%d.0", major, minor),
			Major:   major,
			Minor:   strconv.Itoa(minor),
		}
		if helmchartutil.IsCompatibleRange(constraint, candidate.Version) {
			return &candidate
		}
	}
	return nil
}

// kubeVersionConstraint returns the chart's kubeVersion constraint from Chart.yaml, or "".
func (hc *HelmChart) kubeVersionConstraint() string {
	if hc.chart.Metadata == nil {
		return ""
	}
	return hc.chart.Metadata.KubeVersion
}

// newestKubeVersion returns the Kubernetes version of the vendored Kubernetes libraries,
// major and minor only.
func newestKubeVersion() (*k8sversion.Version, error) {
	return k8sversion.ParseGeneric(componentversion.DefaultKubeBinaryVersion)
}

// HelmCapabilityOptions describes the cluster a Helm chart is rendered for. It mirrors the
// `helm template` flags of the same names.
type HelmCapabilityOptions struct {
	KubeVersion string   // --kube-version: Kubernetes version exposed as .Capabilities.KubeVersion
	APIVersions []string // --api-versions: API versions added to .Capabilities.APIVersions
}

// IsEmpty reports whether the chart is to be rendered with Helm's default capabilities.
func (o HelmCapabilityOptions) IsEmpty() bool {
	return o.KubeVersion == "" && len(o.APIVersions) == 0
}

// ValidateHelmKubeVersion reports whether version can be used as HelmCapabilityOptions.KubeVersion.
// An empty version is valid and selects the default.
func ValidateHelmKubeVersion(version string) error {
	if version == "" {
		return nil
	}
	if _, err := helmchartutil.ParseKubeVersion(version); err != nil {
		return fmt.Errorf("%q is not a Kubernetes version: %w", version, err)
	}
	return nil
}

// HelmValueOptions describes the user-supplied Helm value overrides, release identity and
// target cluster capabilities to apply when rendering Helm charts during a scan. It mirrors
// the inputs accepted by `helm install` and `helm template` so the kubescape CLI flags and
// the helm-kubescape plugin can pass values through verbatim.
type HelmValueOptions struct {
	ValueFiles       []string // -f / --values
	Values           []string // --set
	StringValues     []string // --set-string
	FileValues       []string // --set-file
	ReleaseName      string
	ReleaseNamespace string
	KubeVersion      string   // --kube-version
	APIVersions      []string // --api-versions
}

// IsEmpty reports whether no Helm value overrides, release identity or capabilities have been set.
func (o HelmValueOptions) IsEmpty() bool {
	return len(o.ValueFiles) == 0 &&
		len(o.Values) == 0 &&
		len(o.StringValues) == 0 &&
		len(o.FileValues) == 0 &&
		o.ReleaseName == "" &&
		o.ReleaseNamespace == "" &&
		o.CapabilityOptions().IsEmpty()
}

// CapabilityOptions returns the capabilities to render charts with.
func (o HelmValueOptions) CapabilityOptions() HelmCapabilityOptions {
	return HelmCapabilityOptions{
		KubeVersion: o.KubeVersion,
		APIVersions: o.APIVersions,
	}
}

// protectHelmFileValues applies the same path protection as ParseHelmFileValuePaths
// so that Helm's strvals parser reads the exact paths validated by containment and collision checks.
func protectHelmFileValues(values []string) []string {
	if len(values) == 0 {
		return values
	}
	protected := make([]string, len(values))
	for i, fv := range values {
		protected[i] = ProtectHelmPathSeparators(fv)
	}
	return protected
}

// MergeValues parses and merges the user-supplied value overrides using Helm's own
// merger (the same code path used by `helm install -f ... --set ...`). The resulting
// map is the final user-supplied values that should be merged over the chart defaults.
func (o HelmValueOptions) MergeValues() (map[string]any, error) {
	return mergeBoundedHelmValues(o, os.Stdin)
}

// ReleaseOptions returns the Helm ReleaseOptions for use with chartutil.ToRenderValues.
func (o HelmValueOptions) ReleaseOptions() helmchartutil.ReleaseOptions {
	return helmchartutil.ReleaseOptions{
		Name:      o.ReleaseName,
		Namespace: o.ReleaseNamespace,
	}
}
