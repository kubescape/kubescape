package cautils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
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

// newRegistryClient creates a Helm registry client for chart authentication
func newRegistryClient(certFile, keyFile, caFile string, insecureSkipTLS, plainHTTP bool, username, password string) (*helmregistry.Client, error) {
	// Basic client options with debug disabled
	opts := []helmregistry.ClientOption{
		helmregistry.ClientOptDebug(false),
		helmregistry.ClientOptWriter(io.Discard),
	}

	// Add TLS certificates if provided
	if certFile != "" && keyFile != "" {
		opts = append(opts, helmregistry.ClientOptCredentialsFile(certFile))
	}

	// Add CA certificate if provided
	if caFile != "" {
		opts = append(opts, helmregistry.ClientOptCredentialsFile(caFile))
	}

	// Enable plain HTTP if needed
	if insecureSkipTLS {
		opts = append(opts, helmregistry.ClientOptPlainHTTP())
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
	registryClient, err := newRegistryClient("", "", "", false, false, "", "")
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

func (hc *HelmChart) GetDefaultValues() map[string]interface{} {
	return hc.chart.Values
}

// GetWorkloadsWithDefaultValues renders chart template using the default values and returns a map of source file to its workloads
func (hc *HelmChart) GetWorkloadsWithDefaultValues() (map[string][]workloadinterface.IMetadata, []error) {
	return hc.GetWorkloads(hc.GetDefaultValues())
}

// GetWorkloads renders chart template using the provided values and returns a map of source (absolute) file path to its workloads
func (hc *HelmChart) GetWorkloads(values map[string]interface{}) (map[string][]workloadinterface.IMetadata, []error) {
	vals, err := helmchartutil.ToRenderValues(hc.chart, values, helmchartutil.ReleaseOptions{}, nil)
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

func (hc *HelmChart) AddCommentToTemplate() {
	for index, t := range hc.chart.Templates {
		if IsYaml(strings.ToLower(t.Name)) {
			var newLines []string
			originalTemplate := string(t.Data)
			lines := strings.Split(originalTemplate, "\n")

			for index, line := range lines {
				comment := " #This is the " + strconv.Itoa(index+1) + " line"
				newLines = append(newLines, line+comment)
			}
			templateWithComment := strings.Join(newLines, "\n")
			hc.chart.Templates[index].Data = []byte(templateWithComment)
		}
	}
}
