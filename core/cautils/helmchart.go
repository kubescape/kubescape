package cautils

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/helmprovenance"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"gopkg.in/yaml.v3"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	helmvalues "helm.sh/helm/v3/pkg/cli/values"
	helmengine "helm.sh/helm/v3/pkg/engine"
	helmgetter "helm.sh/helm/v3/pkg/getter"
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
	chart, err := helmloader.Load(path)
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
// allowing the available templates to render. No repository reference is resolved.
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
// Charts that reference .Release.Name or .Release.Namespace require these options to render.
func (hc *HelmChart) GetWorkloadsWithOptions(values map[string]any, releaseOpts helmchartutil.ReleaseOptions) (map[string][]workloadinterface.IMetadata, []error) {
	vals, err := helmchartutil.ToRenderValues(hc.chart, values, releaseOpts, nil)
	if err != nil {
		return nil, []error{err}
	}
	sourceToFile, err := helmengine.Render(hc.chart, vals)
	if err != nil {
		return nil, []error{err}
	}

	workloads := make(map[string][]workloadinterface.IMetadata)
	var errs []error

	for path, renderedYaml := range sourceToFile {
		if !IsYaml(strings.ToLower(path)) {
			continue
		}

		firstPathSeparatorIndex := strings.Index(path, "/")
		if firstPathSeparatorIndex == -1 {
			continue
		}
		absPath := filepath.Join(hc.path, path[firstPathSeparatorIndex:])

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

		workloads[absPath] = []workloadinterface.IMetadata{}
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
	obj, ok := convertYamlToJson(decoded).(map[string]any)
	if !ok {
		return false
	}
	_, isList, err := listEnvelopeKind(obj)
	return isList || err != nil
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
	content, err := os.ReadFile(absPath)
	if err != nil {
		return false, err
	}
	return !bytes.Contains(content, []byte("{{")), nil
}

// HelmValueOptions describes the user-supplied Helm value overrides and release identity
// to apply when rendering Helm charts during a scan. It mirrors the inputs accepted by
// `helm install` so the kubescape CLI flags and the helm-kubescape plugin can pass values
// through verbatim.
type HelmValueOptions struct {
	ValueFiles       []string // -f / --values
	Values           []string // --set
	StringValues     []string // --set-string
	FileValues       []string // --set-file
	ReleaseName      string
	ReleaseNamespace string
}

// IsEmpty reports whether no Helm value overrides or release identity have been set.
func (o HelmValueOptions) IsEmpty() bool {
	return len(o.ValueFiles) == 0 &&
		len(o.Values) == 0 &&
		len(o.StringValues) == 0 &&
		len(o.FileValues) == 0 &&
		o.ReleaseName == "" &&
		o.ReleaseNamespace == ""
}

// MergeValues parses and merges the user-supplied value overrides using Helm's own
// merger (the same code path used by `helm install -f ... --set ...`). The resulting
// map is the final user-supplied values that should be merged over the chart defaults.
func (o HelmValueOptions) MergeValues() (map[string]any, error) {
	opts := helmvalues.Options{
		ValueFiles:   o.ValueFiles,
		Values:       o.Values,
		StringValues: o.StringValues,
		FileValues:   o.FileValues,
	}
	return opts.MergeValues(helmgetter.All(cli.New()))
}

// ReleaseOptions returns the Helm ReleaseOptions for use with chartutil.ToRenderValues.
func (o HelmValueOptions) ReleaseOptions() helmchartutil.ReleaseOptions {
	return helmchartutil.ReleaseOptions{
		Name:      o.ReleaseName,
		Namespace: o.ReleaseNamespace,
	}
}
