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
	helmdownloader "helm.sh/helm/v3/pkg/downloader"
	helmengine "helm.sh/helm/v3/pkg/engine"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmregistry "helm.sh/helm/v3/pkg/registry"
	"k8s.io/client-go/util/homedir"
)

type HelmChart struct {
	chart *helmchart.Chart
	path  string
}

func IsHelmDirectory(path string) (bool, error) {
	return helmchartutil.IsChartDir(path)
}

// newRegistryClient creates a Helm registry client for chart authentication.
//
// Only plainHTTP and basic-auth credentials are exposed here, because those
// are the only options the sole call site (buildDependencies, below) ever
// varies - it currently always passes plainHTTP=false and empty credentials.
// An earlier version of this function also accepted certFile, keyFile,
// caFile, and insecureSkipTLS, but those were broken rather than merely
// unused: certFile/keyFile/caFile were passed to
// helmregistry.ClientOptCredentialsFile, which sets the client's
// *credentials store* path (e.g. ~/.docker/config.json), not TLS material -
// caFile silently clobbered whatever certFile/keyFile had set (same
// underlying field), and any of the three made helmregistry.NewClient fail
// outright on a real PEM path ("invalid config format"). insecureSkipTLS was
// left unwired entirely. Wiring TLS material correctly requires either
// building a *tls.Config locally and passing it via
// helmregistry.ClientOptHTTPClient, or using helm's own
// registry.NewRegistryClientWithTLS(...) (helm.sh/helm/v3/pkg/registry/util.go)
// for the whole client construction. Add that machinery back if a caller
// ever needs cert/key/CA/insecureSkipTLS again, rather than reintroducing
// unwired or miswired parameters.
func newRegistryClient(plainHTTP bool, username, password string) (*helmregistry.Client, error) {
	// Basic client options with debug disabled
	opts := []helmregistry.ClientOption{
		helmregistry.ClientOptDebug(false),
		helmregistry.ClientOptWriter(io.Discard),
	}

	if plainHTTP {
		opts = append(opts, helmregistry.ClientOptPlainHTTP())
	}

	// Add basic auth credentials if provided
	if username != "" && password != "" {
		opts = append(opts, helmregistry.ClientOptBasicAuth(username, password))
	}

	registryClient, err := helmregistry.NewClient(opts...)
	if err != nil {
		return nil, err
	}

	return registryClient, nil
}

// defaultKeyring returns the default GPG keyring path for chart verification
func defaultKeyring() string {
	if v, ok := os.LookupEnv("GNUPGHOME"); ok {
		return filepath.Join(v, "pubring.gpg")
	}
	return filepath.Join(homedir.HomeDir(), ".gnupg", "pubring.gpg")
}

func NewHelmChart(path string) (*HelmChart, error) {
	// Build chart dependencies before loading if Chart.lock exists
	if err := buildDependencies(path); err != nil {
		logger.L().Warning("Failed to build chart dependencies", helpers.String("path", path), helpers.Error(err))
	}

	chart, err := helmloader.Load(path)
	if err != nil {
		return nil, err
	}

	return &HelmChart{
		chart: chart,
		path:  path,
	}, nil
}

// buildDependencies builds chart dependencies using the downloader manager
func buildDependencies(chartPath string) error {
	// Create registry client for authentication
	registryClient, err := newRegistryClient(false, "", "")
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}

	// Create downloader manager with required configuration
	settings := cli.New()
	manager := &helmdownloader.Manager{
		Out:            io.Discard, // Suppress output during scanning
		ChartPath:      chartPath,
		Keyring:        defaultKeyring(),
		SkipUpdate:     false, // Allow updates to get latest dependencies
		Getters:        helmgetter.All(settings),
		RegistryClient: registryClient,
		Debug:          false,
	}

	// Build dependencies from Chart.lock file
	err = manager.Build()
	if e, ok := err.(helmdownloader.ErrRepoNotFound); ok {
		return fmt.Errorf("%s. Please add missing repos via 'helm repo add'", e.Error())
	}

	return err
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
		// docIndexAt[n] is the raw YAML document index workload n of wls may
		// safely claim. It is only ever populated below for a document that
		// (a) the same yaml.v3 decoder the resolver uses also decoded, at the
		// same position, and (b) produced exactly one workload - so the index
		// and the workload it is attached to name the same thing on both
		// sides, with no room for the mismatch described next to slip in.
		docIndexAt := map[int]int{}
		if static {
			docs, docErr := renderedDocuments([]byte(renderedYaml))
			if docErr != nil {
				logger.L().Debug("failed to align Helm template documents for line resolution, leaving path unindexed",
					helpers.String("file", absPath), helpers.Error(docErr))
				static = false
			} else {
				for _, doc := range docs {
					// A document that produced more than one workload - a
					// List/PodList envelope's items - has no single line of
					// its own to claim: the resolver retains one YAML node
					// per raw document, not one per item inside it, so doc.index
					// cannot tell Pod A's item apart from Pod B's. A document
					// that produced zero (null, comment-only, not a workload)
					// has nothing to attach an index to either. Only the
					// exactly-one case is unambiguous.
					if len(doc.workloads) == 1 {
						docIndexAt[len(wls)] = doc.index
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
			// The map key stays the bare absPath either way - callers that
			// join against Provenance() (keyed the same way) are unaffected.
			if docIndex, ok := docIndexAt[i]; ok {
				lw.SetPath(fmt.Sprintf("%s:%d", absPath, docIndex))
			} else {
				lw.SetPath(absPath)
			}
			workloads[absPath] = append(workloads[absPath], lw)
		}
	}
	return workloads, errs
}

// renderedDocument is one YAML document decoded from a rendered chart
// template, along with the workloads readYamlFile produced from it and the
// position it was decoded at.
type renderedDocument struct {
	index     int
	workloads []workloadinterface.IMetadata
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
		docs = append(docs, renderedDocument{index: i, workloads: wls})
	}
	return docs, nil
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
