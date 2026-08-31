package cautils

import (
	"bytes"
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

		wls, e := ReadFile([]byte(renderedYaml), YAML_FILE_FORMAT)
		if e != nil {
			logger.L().Debug("failed to read rendered yaml file", helpers.String("file", path), helpers.Error(e))
			errs = append(errs, fmt.Errorf("failed to parse rendered Helm template %q: %w", path, e))
		}
		if len(wls) == 0 {
			continue
		}
		if firstPathSeparatorIndex := strings.Index(path, "/"); firstPathSeparatorIndex != -1 {
			absPath := filepath.Join(hc.path, path[firstPathSeparatorIndex:])

			workloads[absPath] = []workloadinterface.IMetadata{}
			for i := range wls {
				lw := localworkload.NewLocalWorkload(wls[i].GetObject())
				lw.SetPath(absPath)
				workloads[absPath] = append(workloads[absPath], lw)
			}
		}
	}
	return workloads, errs
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
