package containerscan

import (
	"strings"
	"testing"

	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGojayUnmarshalScanResultReport(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		want          ScanResultReport
		wantLayerSize int
	}{
		{
			name: "complete report with nested layer data",
			input: `{
				"customerGUID":"customer-1",
				"imageTag":"nginx:1.18",
				"imageHash":"sha256:image",
				"wlid":"wlid://cluster-test/namespace-default/deployment-app",
				"containerName":"nginx",
				"timestamp":42,
				"listOfDangerousArtifcats":["/bin/sh","/usr/bin/curl"],
				"layers":[{
					"layerHash":"sha256:layer",
					"parentLayerHash":"sha256:parent",
					"vulnerabilities":[{
						"name":"CVE-1",
						"imageHash":"sha256:image",
						"imageTag":"nginx:1.18",
						"packageName":"openssl",
						"packageVersion":"1.1.1",
						"link":"https://example.test/cve",
						"description":"remote code execution",
						"severity":"High",
						"metadata":{"score":7},
						"fixedIn":[{"name":"openssl","imageTag":"nginx:fixed","version":"1.1.2"}],
						"relevant":"Relevant"
					}],
					"packageToFile":[{
						"packageName":"openssl",
						"version":"1.1.1",
						"files":[{"name":"/usr/lib/libssl.so"}]
					}]
				}]
			}`,
			want: ScanResultReport{
				CustomerGUID:             "customer-1",
				ImgTag:                   "nginx:1.18",
				ImgHash:                  "sha256:image",
				WLID:                     "wlid://cluster-test/namespace-default/deployment-app",
				ContainerName:            "nginx",
				Timestamp:                42,
				ListOfDangerousArtifcats: []string{"/bin/sh", "/usr/bin/curl"},
			},
			wantLayerSize: 1,
		},
		{
			name: "empty arrays keep zero-value slices",
			input: `{
				"customerGUID":"customer-2",
				"imageTag":"busybox",
				"timestamp":1,
				"layers":[],
				"listOfDangerousArtifcats":[]
			}`,
			want: ScanResultReport{
				CustomerGUID:             "customer-2",
				ImgTag:                   "busybox",
				Timestamp:                1,
				ListOfDangerousArtifcats: nil,
			},
			wantLayerSize: 0,
		},
		{
			name:          "missing optional fields keep zero values",
			input:         `{"customerGUID":"customer-3","timestamp":7}`,
			want:          ScanResultReport{CustomerGUID: "customer-3", Timestamp: 7},
			wantLayerSize: 0,
		},
		{
			name:          "empty object keeps zero values",
			input:         `{}`,
			want:          ScanResultReport{},
			wantLayerSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ScanResultReport
			err := gojay.NewDecoder(strings.NewReader(tt.input)).DecodeObject(&got)
			require.NoError(t, err)
			assert.Equal(t, tt.want.CustomerGUID, got.CustomerGUID)
			assert.Equal(t, tt.want.ImgTag, got.ImgTag)
			assert.Equal(t, tt.want.ImgHash, got.ImgHash)
			assert.Equal(t, tt.want.WLID, got.WLID)
			assert.Equal(t, tt.want.ContainerName, got.ContainerName)
			assert.Equal(t, tt.want.Timestamp, got.Timestamp)
			assert.Equal(t, tt.want.ListOfDangerousArtifcats, got.ListOfDangerousArtifcats)
			assert.Len(t, got.Layers, tt.wantLayerSize)
		})
	}
}

func TestGojayUnmarshalNestedLayerFields(t *testing.T) {
	input := `{
		"layerHash":"sha256:layer",
		"parentLayerHash":"sha256:parent",
		"vulnerabilities":[{
			"name":"CVE-2024-0001",
			"imageHash":"sha256:image",
			"imageTag":"app:v1",
			"packageName":"libssl",
			"packageVersion":"3.0.0",
			"link":"https://example.test/CVE-2024-0001",
			"description":"allows arbitrary code",
			"severity":"Critical",
			"metadata":{"source":"scanner"},
			"fixedIn":[{"name":"libssl","imageTag":"app:v2","version":"3.0.1"}],
			"relevant":"Relevant"
		}],
		"packageToFile":[{
			"packageName":"libssl",
			"version":"3.0.0",
			"files":[{"name":"/usr/lib/libssl.so"},{"name":"/usr/share/doc/libssl"}]
		}]
	}`

	var got ScanResultLayer
	require.NoError(t, gojay.NewDecoder(strings.NewReader(input)).DecodeObject(&got))

	require.Len(t, got.Vulnerabilities, 1)
	require.Len(t, got.Packages, 1)
	assert.Equal(t, "sha256:layer", got.LayerHash)
	assert.Equal(t, "sha256:parent", got.ParentLayerHash)
	assert.Equal(t, "CVE-2024-0001", got.Vulnerabilities[0].Name)
	assert.Equal(t, "libssl", got.Vulnerabilities[0].RelatedPackageName)
	assert.Equal(t, "Critical", got.Vulnerabilities[0].Severity)
	assert.Equal(t, "3.0.1", got.Vulnerabilities[0].Fixes[0].Version)
	assert.Equal(t, "/usr/lib/libssl.so", got.Packages[0].Files[0].Filename)
	assert.Equal(t, "/usr/share/doc/libssl", got.Packages[0].Files[1].Filename)
}

func TestGojayUnmarshalRawNginxScanJSON(t *testing.T) {
	var got ScanResultReport
	require.NoError(t, gojay.NewDecoder(strings.NewReader(nginxScanJSON)).DecodeObject(&got))

	assert.Equal(t, "1e3a88bf-92ce-44f8-914e-cbe71830d566", got.CustomerGUID)
	assert.Equal(t, "nginx:1.18.0", got.ImgTag)
	assert.Equal(t, "nginx-1", got.ContainerName)
	assert.EqualValues(t, 1628091365, got.Timestamp)
	require.NotEmpty(t, got.Layers)
	assert.NotEmpty(t, got.Layers[0].Vulnerabilities)
	assert.Equal(t, []string{"bin/dash", "bin/bash", "usr/bin/curl"}, got.ListOfDangerousArtifcats)
}

func TestGojayUnmarshalInvalidTypesKeepZeroValues(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		assert func(t *testing.T, got ScanResultReport)
	}{
		{
			name:  "numeric fixed version is ignored",
			input: `{"layers":[{"vulnerabilities":[{"fixedIn":[{"version":5}]}]}]}`,
			assert: func(t *testing.T, got ScanResultReport) {
				require.Len(t, got.Layers, 1)
				require.Len(t, got.Layers[0].Vulnerabilities, 1)
				require.Len(t, got.Layers[0].Vulnerabilities[0].Fixes, 1)
				assert.Empty(t, got.Layers[0].Vulnerabilities[0].Fixes[0].Version)
			},
		},
		{
			name:  "numeric package file name is ignored",
			input: `{"layers":[{"packageToFile":[{"packageName":"pkg","files":[{"name":5}]}]}]}`,
			assert: func(t *testing.T, got ScanResultReport) {
				require.Len(t, got.Layers, 1)
				require.Len(t, got.Layers[0].Packages, 1)
				require.Len(t, got.Layers[0].Packages[0].Files, 1)
				assert.Empty(t, got.Layers[0].Packages[0].Files[0].Filename)
			},
		},
		{
			name:  "numeric dangerous artifact decodes to empty string",
			input: `{"listOfDangerousArtifcats":["ok",5]}`,
			assert: func(t *testing.T, got ScanResultReport) {
				assert.Equal(t, []string{"ok", ""}, got.ListOfDangerousArtifcats)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ScanResultReport
			err := gojay.NewDecoder(strings.NewReader(tt.input)).DecodeObject(&got)
			require.NoError(t, err)
			tt.assert(t, got)
		})
	}
}
