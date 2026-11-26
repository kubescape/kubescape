package fixhandler

import (
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func TestFixHandler_RecordedControlsInputs(t *testing.T) {
	t.Run("nil report returns empty string", func(t *testing.T) {
		h := &FixHandler{}
		assert.Equal(t, "", h.RecordedControlsInputs())
	})

	t.Run("empty metadata returns empty string", func(t *testing.T) {
		h := &FixHandler{reportObj: &reporthandlingv2.PostureReport{}}
		assert.Equal(t, "", h.RecordedControlsInputs())
	})

	t.Run("returns recorded controls inputs path", func(t *testing.T) {
		h := &FixHandler{
			reportObj: &reporthandlingv2.PostureReport{
				Metadata: reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ControlsInputs: "/etc/kubescape/controls-inputs.json",
					},
				},
			},
		}
		assert.Equal(t, "/etc/kubescape/controls-inputs.json", h.RecordedControlsInputs())
	})
}

func TestFixHandler_RecordedKubescapeVersion(t *testing.T) {
	t.Run("nil report returns empty string", func(t *testing.T) {
		h := &FixHandler{}
		assert.Equal(t, "", h.RecordedKubescapeVersion())
	})

	t.Run("empty metadata returns empty string", func(t *testing.T) {
		h := &FixHandler{reportObj: &reporthandlingv2.PostureReport{}}
		assert.Equal(t, "", h.RecordedKubescapeVersion())
	})

	t.Run("returns recorded Kubescape version", func(t *testing.T) {
		h := &FixHandler{
			reportObj: &reporthandlingv2.PostureReport{
				Metadata: reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						KubescapeVersion: "v4.0.0",
					},
				},
			},
		}
		assert.Equal(t, "v4.0.0", h.RecordedKubescapeVersion())
	})
}

func TestFixHandler_ScanRoots(t *testing.T) {
	t.Run("nil report returns no scan roots", func(t *testing.T) {
		h := &FixHandler{}
		assert.Empty(t, h.ScanRoots())
	})

	t.Run("empty report returns no scan roots", func(t *testing.T) {
		h := &FixHandler{reportObj: &reporthandlingv2.PostureReport{}}
		assert.Empty(t, h.ScanRoots())
	})

	t.Run("returns sorted distinct local manifest roots", func(t *testing.T) {
		base := t.TempDir()
		rootB := filepath.Join(base, "b-root")
		rootA := filepath.Join(base, "a-root")

		makeResource := func(name, relPath, root string) reporthandling.Resource {
			obj := map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]any{
					"name":      name,
					"namespace": "default",
				},
			}
			lw := localworkload.NewLocalWorkload(obj)
			lw.SetPath(relPath + ":0")
			return reporthandling.Resource{
				ResourceID: lw.GetID(),
				Object:     lw.GetObject(),
				Source: &reporthandling.Source{
					FileType: reporthandling.SourceTypeYaml,
					Path:     root,
				},
			}
		}

		h := &FixHandler{
			reportObj: &reporthandlingv2.PostureReport{
				Resources: []reporthandling.Resource{
					makeResource("app-b1", "b1.yaml", rootB),
					makeResource("app-a1", "a1.yaml", rootA),
					makeResource("app-b2", "b2.yaml", rootB),
				},
			},
		}

		assert.Equal(t, []string{filepath.Clean(rootA), filepath.Clean(rootB)}, h.ScanRoots())
	})
}
