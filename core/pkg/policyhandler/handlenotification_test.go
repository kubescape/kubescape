package policyhandler

import (
	"testing"

	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"k8s.io/apimachinery/pkg/version"
)

func Test_getCloudMetadata(t *testing.T) {
	type args struct {
		opaSessionObj *cautils.OPASessionObj
	}
	tests := []struct {
		want apis.ICloudParser
		args args
		name string
	}{
		{
			name: "Test_getCloudMetadata",
			args: args{
				opaSessionObj: &cautils.OPASessionObj{
					Report: &reporthandlingv2.PostureReport{
						ClusterAPIServerInfo: &version.Info{
							GitVersion: "v1.25.4-gke.1600",
						},
					},
				},
			},
			want: helpersv1.NewGKEMetadata(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getCloudMetadata(tt.args.opaSessionObj); got.Provider() != tt.want.Provider() {
				t.Errorf("getCloudMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}
