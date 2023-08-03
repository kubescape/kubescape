package scan

import (
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
)

func TestSetWorkloadScanInfo(t *testing.T) {
	test := []struct {
		Description string
		kind        string
		name        string
		want        *cautils.ScanInfo
	}{
		{
			Description: "Set workload scan info",
			kind:        "Deployment",
			name:        "test",
			want: &cautils.ScanInfo{
				PolicyIdentifier: []cautils.PolicyIdentifier{
					{
						Identifier: "workloadscan",
						Kind:       v1.KindFramework,
					},
				},
				ScanType: cautils.ScanTypeWorkload,
				ScanObject: &objectsenvelopes.ScanObject{
					Kind: "Deployment",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name: "test",
					},
				},
			},
		},
	}

	for _, tc := range test {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				scanInfo := &cautils.ScanInfo{}
				setWorkloadScanInfo(scanInfo, tc.kind, tc.name)

				if scanInfo.ScanType != tc.want.ScanType {
					t.Errorf("got: %v, want: %v", scanInfo.ScanType, tc.want.ScanType)
				}

				if scanInfo.ScanObject.Kind != tc.want.ScanObject.Kind {
					t.Errorf("got: %v, want: %v", scanInfo.ScanObject.Kind, tc.want.ScanObject.Kind)
				}

				if scanInfo.ScanObject.Metadata.Name != tc.want.ScanObject.Metadata.Name {
					t.Errorf("got: %v, want: %v", scanInfo.ScanObject.Metadata.Name, tc.want.ScanObject.Metadata.Name)
				}

				if len(scanInfo.PolicyIdentifier) != 1 {
					t.Errorf("got: %v, want: %v", len(scanInfo.PolicyIdentifier), 1)
				}

				if scanInfo.PolicyIdentifier[0].Identifier != tc.want.PolicyIdentifier[0].Identifier {
					t.Errorf("got: %v, want: %v", scanInfo.PolicyIdentifier[0].Identifier, tc.want.PolicyIdentifier[0].Identifier)
				}
			},
		)
	}
}
