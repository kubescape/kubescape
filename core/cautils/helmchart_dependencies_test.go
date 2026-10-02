package cautils

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
)

type helmScanFile struct {
	Mode     fs.FileMode
	Modified time.Time
	Data     string
}

// Include directories and timestamps so even a create-and-remove or same-content
// rewrite by the dependency manager is visible.
func snapshotHelmScanTree(t *testing.T, root string) map[string]helmScanFile {
	t.Helper()
	reader, err := os.OpenRoot(root)
	require.NoError(t, err)
	defer reader.Close()
	files := make(map[string]helmScanFile)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file := helmScanFile{Mode: info.Mode(), Modified: info.ModTime()}
		if !entry.IsDir() {
			data, err := reader.ReadFile(rel)
			if err != nil {
				return err
			}
			file.Data = string(data)
		}
		files[rel] = file
		return nil
	}))
	return files
}

func TestHelmScanUsesOnlyVendoredDependencies(t *testing.T) {
	var requests, connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "dependency fetching is forbidden", http.StatusServiceUnavailable)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	for _, source := range []string{"http", "oci", "file", "alias", "vendored"} {
		for _, locked := range []bool{false, true} {
			for _, vendored := range []string{"missing", "unpacked", "archive"} {
				t.Run(fmt.Sprintf("%s/lock=%t/%s", source, locked, vendored), func(t *testing.T) {
					root := t.TempDir()
					chartPath := filepath.Join(root, "parent")
					require.NoError(t, os.MkdirAll(filepath.Join(chartPath, "templates"), 0o755))
					repository := server.URL
					switch source {
					case "oci":
						repository = "oci://" + strings.TrimPrefix(server.URL, "http://") + "/charts"
					case "file":
						repository = "file://../external"
					case "alias":
						repository = "@unconfigured"
					case "vendored":
						repository = ""
					}
					dependency := &helmchart.Dependency{Name: "child", Version: ">=0.1.0 <1.0.0", Repository: repository}
					metadata, err := yaml.Marshal(&helmchart.Metadata{APIVersion: "v2", Name: "parent", Version: "0.1.0", Dependencies: []*helmchart.Dependency{dependency}})
					require.NoError(t, err)
					writeManifestFixture(t, chartPath, "Chart.yaml", string(metadata))
					parentTemplate := writeManifestFixture(t, filepath.Join(chartPath, "templates"), "pod.yaml", strings.ReplaceAll(validPodManifest, "valid-pod", "parent-pod"))
					child := &helmchart.Chart{
						Metadata:  &helmchart.Metadata{APIVersion: "v2", Name: "child", Version: "0.1.0"},
						Templates: []*helmchart.File{{Name: "templates/pod.yaml", Data: []byte(strings.ReplaceAll(validPodManifest, "valid-pod", "vendored-pod"))}},
					}
					if source == "file" {
						// A file:// dependency outside the chart must not be imported.
						external := *child
						external.Templates = []*helmchart.File{{Name: "templates/pod.yaml", Data: []byte(strings.ReplaceAll(validPodManifest, "valid-pod", "external-pod"))}}
						require.NoError(t, helmchartutil.SaveDir(&external, root))
						require.NoError(t, os.Rename(filepath.Join(root, "child"), filepath.Join(root, "external")))
					}
					if vendored != "missing" {
						destination := filepath.Join(chartPath, "charts")
						require.NoError(t, os.MkdirAll(destination, 0o755))
						if vendored == "archive" {
							_, err := helmchartutil.Save(child, destination)
							require.NoError(t, err)
						} else {
							require.NoError(t, helmchartutil.SaveDir(child, destination))
						}
					}
					if locked {
						// Use Helm's lock digest format so Build cannot stop at an invalid digest.
						resolved := *dependency
						resolved.Version = "0.1.0"
						deps := []*helmchart.Dependency{&resolved}
						data, err := json.Marshal([2][]*helmchart.Dependency{{dependency}, deps})
						require.NoError(t, err)
						lock, err := yaml.Marshal(&helmchart.Lock{Generated: time.Unix(0, 0).UTC(), Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(data)), Dependencies: deps})
						require.NoError(t, err)
						writeManifestFixture(t, chartPath, "Chart.lock", string(lock))
					}
					before := snapshotHelmScanTree(t, root)
					requestCount := requests.Load()
					connectionCount := connections.Load()
					chart, err := NewHelmChart(chartPath)
					require.NoError(t, err)
					workloads, errs := chart.GetWorkloadsWithDefaultValues()
					require.Empty(t, errs)
					require.Len(t, workloads[parentTemplate], 1)
					names := []string{}
					for _, resources := range workloads {
						for _, resource := range resources {
							names = append(names, resource.GetName())
						}
					}
					wantNames := []string{"parent-pod"}
					if vendored != "missing" {
						wantNames = append(wantNames, "vendored-pod")
					}
					require.ElementsMatch(t, wantNames, names)
					// Exercise discovery/rendering through the scan's shared entry point too.
					loaded, _, rendered, err := LoadResourcesFromHelmCharts(context.Background(), chartPath, HelmValueOptions{})
					require.NoError(t, err)
					require.Contains(t, rendered, chartPath)
					require.Len(t, loaded, len(workloads))
					require.Equal(t, requestCount, requests.Load(), "scan must never request dependencies")
					require.Equal(t, connectionCount, connections.Load(), "scan must not even connect to a dependency server")
					require.Equal(t, before, snapshotHelmScanTree(t, root), "scan must not modify chart files, lockfiles, or directories")
				})
			}
		}
	}
}
