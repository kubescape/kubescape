package cautils

import (
	"fmt"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"

	"github.com/stretchr/testify/assert"
)

func TestIsControlFitToScanning(t *testing.T) {
	tests := []struct {
		scanInfo     *ScanInfo
		Control      reporthandling.Control
		expected_res bool
	}{
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{
					Matches: []reporthandling.ScanningScopeType{
						reporthandling.ScopeFile,
					},
				},
			},
			expected_res: true,
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: []reporthandling.ScanningScopeType{
						reporthandling.ScopeCluster,
						reporthandling.ScopeFile,
					},
				},
			},
			expected_res: true,
		},
		{
			scanInfo: &ScanInfo{},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: []reporthandling.ScanningScopeType{
						reporthandling.ScopeCluster,
					},
				},
			},
			expected_res: true,
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: []reporthandling.ScanningScopeType{
						reporthandling.ScopeCloudGKE,
					},
				},
			},
			expected_res: false,
		},
		{
			scanInfo: &ScanInfo{},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: []reporthandling.ScanningScopeType{
						reporthandling.ScopeCloudEKS,
					},
				},
			},
			expected_res: false,
		},
		{
			scanInfo: &ScanInfo{},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{
					Matches: []reporthandling.ScanningScopeType{
						reporthandling.ScopeCloud,
					},
				},
			},
			expected_res: false,
		}}
	for i := range tests {
		assert.Equal(t, isControlFitToScanning(tests[i].Control, getScanningScope(tests[i].scanInfo)), tests[i].expected_res, fmt.Sprintf("tests_true index %d", i))
	}
}
