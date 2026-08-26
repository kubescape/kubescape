package containerscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateFixed_All(t *testing.T) {
	tests := []struct {
		Fixes []FixedIn
		want  int
	}{
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "1.0.0"},
			},
			want: 1,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: ""},
			},
			want: 0,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "None"},
			},
			want: 0,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "1.0.0"},
				{Version: "2.0.0"},
			},
			want: 1,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "1.0.0"},
				{Version: ""},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.want, CalculateFixed(tt.Fixes))
		})
	}
}

func TestValidate(t *testing.T) {
	validLayer := func() ScanResultLayer {
		return ScanResultLayer{
			LayerHash:       "sha256:abc",
			ParentLayerHash: "",
			Vulnerabilities: VulnerabilitiesList{
				{Name: "CVE-2024-1234"},
			},
		}
	}

	tests := []struct {
		name      string
		scan      ScanResultReport
		wantValid bool
	}{
		{
			name: "valid report",
			scan: ScanResultReport{
				CustomerGUID:  "customer-1",
				ImgTag:        "latest",
				ImgHash:       "sha256:img",
				WLID:          "wlid://cluster/namespace/deployment/app",
				ContainerName: "app",
				Timestamp:     1700000000,
				Layers:        LayersList{validLayer()},
			},
			wantValid: true,
		},
		{
			name: "missing customerGUID",
			scan: ScanResultReport{
				ImgTag:    "latest",
				ImgHash:   "sha256:img",
				Timestamp: 1700000000,
				Layers:    LayersList{validLayer()},
			},
			wantValid: false,
		},
		{
			name: "missing image hash and tag",
			scan: ScanResultReport{
				CustomerGUID: "customer-1",
				Timestamp:    1700000000,
				Layers:       LayersList{validLayer()},
			},
			wantValid: false,
		},
		{
			name: "non-positive timestamp",
			scan: ScanResultReport{
				CustomerGUID: "customer-1",
				ImgTag:       "latest",
				ImgHash:      "sha256:img",
				Timestamp:    0,
				Layers:       LayersList{validLayer()},
			},
			wantValid: false,
		},
		{
			name: "no layers",
			scan: ScanResultReport{
				CustomerGUID: "customer-1",
				ImgTag:       "latest",
				ImgHash:      "sha256:img",
				Timestamp:    1700000000,
				Layers:       LayersList{},
			},
			wantValid: false,
		},
		{
			name: "empty layer hash",
			scan: ScanResultReport{
				CustomerGUID: "customer-1",
				ImgTag:       "latest",
				ImgHash:      "sha256:img",
				Timestamp:    1700000000,
				Layers: LayersList{
					{LayerHash: "", Vulnerabilities: VulnerabilitiesList{{Name: "CVE-2024-1234"}}},
				},
			},
			wantValid: false,
		},
		{
			name: "empty vulnerability name",
			scan: ScanResultReport{
				CustomerGUID: "customer-1",
				ImgTag:       "latest",
				ImgHash:      "sha256:img",
				Timestamp:    1700000000,
				Layers: LayersList{
					{LayerHash: "sha256:abc", Vulnerabilities: VulnerabilitiesList{{Name: ""}}},
				},
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantValid, tt.scan.Validate())
		})
	}
}
