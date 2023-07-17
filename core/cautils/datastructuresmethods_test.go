package cautils

import (
	"fmt"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"

	"github.com/stretchr/testify/assert"
)

func TestIsControlFitToScanning(t *testing.T) {
	tests_true := []struct {
		scanInfo *ScanInfo
		Control  reporthandling.Control
	}{
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{
					Matches: [][]reporthandling.ScanningScopeType{
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeFile,
						},
					},
				},
			},
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: [][]reporthandling.ScanningScopeType{
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeFile,
						},
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeCluster,
							reporthandling.ScopeCloud,
						},
					},
				},
			},
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: [][]reporthandling.ScanningScopeType{
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeFile,
						},
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeCluster,
							reporthandling.ScopeCloud,
							reporthandling.ScopeCloudAKS,
						},
					},
				},
			},
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: [][]reporthandling.ScanningScopeType{
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeFile,
						},
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeCluster,
							reporthandling.ScopeCloud,
							reporthandling.ScopeCloudGKE,
						},
					},
				},
			},
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"./testdata/any_file_for_test.json",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: [][]reporthandling.ScanningScopeType{
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeFile,
						},
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeCluster,
							reporthandling.ScopeCloud,
							reporthandling.ScopeCloudEKS,
						},
					},
				},
			},
		},
		{
			scanInfo: &ScanInfo{
				InputPatterns: []string{
					"",
				},
			},
			Control: reporthandling.Control{
				ScanningScope: reporthandling.ScanningScope{

					Matches: [][]reporthandling.ScanningScopeType{
						[]reporthandling.ScanningScopeType{
							reporthandling.ScopeCluster,
						},
					},
				},
			},
		}}
	for i := range tests_true {
		assert.Equal(t, isControlFitToScanning(tests_true[i].Control, tests_true[i].scanInfo), true, fmt.Sprintf("tests_true index %d", i))
	}
}
