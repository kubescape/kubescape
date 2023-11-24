package containerscan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeScanWIthDangearousArtifacts(t *testing.T) {
	rhs := &ScanResultReport{}
	er := gojay.NewDecoder(strings.NewReader(nginxScanJSON)).DecodeObject(rhs)
	if er != nil {
		t.Errorf("decode failed due to: %v", er.Error())
	}
	sumObj := rhs.Summarize()
	if sumObj.Registry != "" {
		t.Errorf("sumObj.Registry = %v", sumObj.Registry)
	}
	if sumObj.VersionImage != "nginx:1.18.0" {
		t.Errorf("sumObj.VersionImage = %v", sumObj.Registry)
	}
	if sumObj.ImgTag != "nginx:1.18.0" {
		t.Errorf("sumObj.ImgTag = %v", sumObj.ImgTag)
	}
	if sumObj.Status != "Success" {
		t.Errorf("sumObj.Status = %v", sumObj.Status)
	}
	if len(sumObj.ListOfDangerousArtifcats) != 3 {
		t.Errorf("sumObj.ListOfDangerousArtifcats = %v", sumObj.ListOfDangerousArtifcats)
	}
}

func TestUnmarshalScanReport(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	str1 := ds.AsFNVHash()
	rhs := &ScanResultReport{}

	bolB, _ := json.Marshal(ds)
	r := bytes.NewReader(bolB)

	er := gojay.NewDecoder(r).DecodeObject(rhs)
	if er != nil {
		t.Errorf("marshalling failed due to: %v", er.Error())
	}

	if rhs.AsFNVHash() != str1 {
		t.Errorf("marshalling failed different values after marshal:\nOriginal:\n%v\nParsed:\n%v\n\n===\n", string(bolB), rhs)
	}
}

func TestUnmarshalScanReport1(t *testing.T) {
	ds := Vulnerability{}
	if err := GenerateVulnerability(&ds); err != nil {
		t.Errorf("%v\n%v\n", ds, err)
	}
}

func TestGetByPkgNameSuccess(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	a := ds.Layers[0].GetPackagesNames()
	require.Equal(t, 1, len(a))
	assert.Equal(t, []string{"coreutils"}, a)

}

func TestScanResultReportValidate(t *testing.T) {
	tests := []struct {
		name     string
		in       ScanResultReport
		expected bool
	}{
		{
			name:     "empty report should return false",
			in:       ScanResultReport{},
			expected: false,
		},
		{
			name: "report with empty CustomerGUID should return false",
			in: ScanResultReport{
				CustomerGUID: "",
				ImgHash:      "aaa",
				ImgTag:       "bbb",
				Timestamp:    1,
			},
			expected: false,
		},
		{
			name: "report with empty ImgHash and ImgTag should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "",
				ImgTag:       "",
				Timestamp:    1,
			},
			expected: false,
		},
		{
			name: "report with empty ImageHash and non-empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "",
				ImgTag:       "bbb",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with non-empty ImageHash and empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with non-empty ImageHash and non-empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with Timestamp <= 0 should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    0,
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := test.in.Validate()
			assert.Equal(t, test.expected, res)
		})
	}
}
func TestScanElasticContainerScanSummaryResultValidate(t *testing.T) {
	tests := []struct {
		name     string
		in       ElasticContainerScanSummaryResult
		expected bool
	}{
		{
			name:     "empty summary should return false",
			in:       ElasticContainerScanSummaryResult{},
			expected: false,
		},
		{
			name: "summary with empty CustomerGUID should return false",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "",
				ContainerScanID: "aaa",
				ImgHash:         "bbb",
				ImgTag:          "ccc",
				Timestamp:       1,
			},
			expected: false,
		},
		{
			name: "summary with empty ContainerScanID should return false",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "aaa",
				ContainerScanID: "",
				ImgHash:         "bbb",
				ImgTag:          "ccc",
				Timestamp:       1,
			},
			expected: false,
		},
		{
			name: "summary with empty ImgHash and ImgTag should return false",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "aaa",
				ContainerScanID: "bbb",
				ImgHash:         "",
				ImgTag:          "",
				Timestamp:       1,
			},
			expected: false,
		},
		{
			name: "summary with empty ImageHash and non-empty ImgTag should return true",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "aaa",
				ContainerScanID: "bbb",
				ImgHash:         "",
				ImgTag:          "ccc",
				Timestamp:       1,
			},
			expected: true,
		},
		{
			name: "summary with non-empty ImageHash and empty ImgTag should return true",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "aaa",
				ContainerScanID: "bbb",
				ImgHash:         "ccc",
				ImgTag:          "",
				Timestamp:       1,
			},
			expected: true,
		},
		{
			name: "summary with non-empty ImageHash and non-empty ImgTag should return true",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "aaa",
				ContainerScanID: "bbb",
				ImgHash:         "ccc",
				ImgTag:          "ddd",
				Timestamp:       1,
			},
			expected: true,
		},
		{
			name: "summary with Timestamp < 0 should return false",
			in: ElasticContainerScanSummaryResult{
				CustomerGUID:    "aaa",
				ContainerScanID: "bbb",
				ImgHash:         "ccc",
				ImgTag:          "ddd",
				Timestamp:       -1,
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := test.in.Validate()
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestCalculateFixed(t *testing.T) {
	tests := []struct {
		name     string
		in       []FixedIn
		expected int
	}{
		{
			name:     "empty list should return 0",
			in:       []FixedIn{},
			expected: 0,
		},
		{
			name: "None Version value should return 0",
			in: []FixedIn{
				{Version: "None"},
				{Version: "None"},
				{Version: "None"},
			},
			expected: 0,
		},
		{
			name: "empty Version value should return 0",
			in: []FixedIn{
				{Version: ""},
				{Version: ""},
				{Version: ""},
			},
			expected: 0,
		},
		{
			name: "non empty or non None Version value should return 1",
			in: []FixedIn{
				{Version: "1.23"},
				{Version: ""},
				{Version: ""},
			},
			expected: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := CalculateFixed(test.in)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestReturnsHashValueForValidInputValues(t *testing.T) {
	report := ScanResultReport{}
	expectedHash := "7416232187745851261"
	actualHash := report.AsFNVHash()
	if actualHash != expectedHash {
		t.Errorf("Expected hash value %s, but got %s", expectedHash, actualHash)
	}
}
